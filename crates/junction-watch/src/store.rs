//! SQLite store. One database file belongs to exactly one Microsoft 365 tenant:
//! the tenant is bound at creation and every open checks it, so a mis-pointed
//! config can never mix two tenants' telemetry. No tokens or keys are stored.
use crate::{
    capability::{CapabilityState, Reason},
    clock::Instant,
    event::SecurityEvent,
};
use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use std::{
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
};

const SCHEMA_VERSION: i64 = 2;

const MIGRATION_1: &str = r#"
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE capabilities (
    source TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    reason TEXT NOT NULL,
    http_status INTEGER,
    error_code TEXT,
    detail TEXT,
    required_permission TEXT NOT NULL,
    licence_note TEXT NOT NULL,
    docs_url TEXT NOT NULL,
    checked_at TEXT NOT NULL
);

CREATE TABLE checkpoints (
    collector TEXT PRIMARY KEY,
    watermark TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE processed_content (
    content_id TEXT PRIMARY KEY,
    content_type TEXT NOT NULL,
    content_created TEXT NOT NULL,
    content_expiration TEXT,
    processed_at TEXT NOT NULL,
    record_count INTEGER NOT NULL
);
CREATE INDEX processed_content_expiry ON processed_content(content_expiration);

CREATE TABLE events (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    source TEXT NOT NULL,
    source_event_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    actor_id TEXT,
    actor_upn TEXT,
    target_id TEXT,
    target_type TEXT,
    operation TEXT NOT NULL,
    result TEXT,
    ip_address TEXT,
    user_agent TEXT,
    correlation_id TEXT,
    metadata TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL,
    raw_evidence_reference TEXT,
    UNIQUE (tenant_id, source, source_event_id)
);
CREATE INDEX events_time ON events(timestamp);
CREATE INDEX events_actor ON events(actor_upn, timestamp);
CREATE INDEX events_operation ON events(operation, timestamp);
CREATE INDEX events_ingested ON events(ingested_at);

CREATE TABLE collection_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    collector TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    window_start TEXT,
    window_end TEXT,
    content_blobs INTEGER NOT NULL DEFAULT 0,
    events_new INTEGER NOT NULL DEFAULT 0,
    events_duplicate INTEGER NOT NULL DEFAULT 0,
    max_delay_seconds INTEGER,
    rejected_entries INTEGER NOT NULL DEFAULT 0,
    unparseable_records INTEGER NOT NULL DEFAULT 0,
    quarantined_blobs INTEGER NOT NULL DEFAULT 0,
    error TEXT
);
CREATE INDEX collection_runs_recent ON collection_runs(collector, started_at);

CREATE TABLE gaps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    collector TEXT NOT NULL,
    gap_start TEXT NOT NULL,
    gap_end TEXT NOT NULL,
    reason TEXT NOT NULL,
    detected_at TEXT NOT NULL,
    UNIQUE (collector, gap_start, gap_end)
);

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    csrf TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE audit_trail (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    detail TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
"#;

#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
    tenant_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapabilityRecord {
    pub source: String,
    pub state: CapabilityState,
    pub reason: Reason,
    pub http_status: Option<u16>,
    pub error_code: Option<String>,
    pub detail: Option<String>,
    pub required_permission: String,
    pub licence_note: String,
    pub docs_url: String,
    pub checked_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunRecord {
    pub id: i64,
    pub collector: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub status: String,
    pub window_start: Option<String>,
    pub window_end: Option<String>,
    pub content_blobs: i64,
    pub events_new: i64,
    pub events_duplicate: i64,
    pub max_delay_seconds: Option<i64>,
    pub rejected_entries: i64,
    pub unparseable_records: i64,
    pub quarantined_blobs: i64,
    pub error: Option<String>,
}

/// Everything recorded when a collection run ends.
#[derive(Debug, Clone, Copy)]
pub struct RunSummary<'a> {
    pub status: &'a str,
    pub window: Option<(Instant, Instant)>,
    pub content_blobs: u64,
    pub counts: InsertCounts,
    pub max_delay_seconds: Option<i64>,
    pub rejected_entries: u64,
    pub unparseable_records: u64,
    pub quarantined_blobs: u64,
    pub error: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GapRecord {
    pub collector: String,
    pub gap_start: String,
    pub gap_end: String,
    pub reason: String,
    pub detected_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub at: String,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub detail: String,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct InsertCounts {
    pub new: u64,
    pub duplicate: u64,
}

#[derive(Debug, Clone, Default)]
pub struct EventQuery {
    pub actor: Option<String>,
    pub operation: Option<String>,
    pub source: Option<String>,
    pub site: Option<String>,
    pub target: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: u32,
    /// Keyset cursor: `timestamp|id` of the last row on the previous page.
    pub before: Option<(String, String)>,
}

impl Store {
    /// Open (or create) the store for `tenant_id`. Refuses a store bound to
    /// another tenant.
    pub fn open(path: &Path, tenant_id: &str) -> Result<Self> {
        validate_tenant(tenant_id)?;
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty())
            && !dir.exists()
        {
            // Only directories we create are tightened; an operator's existing
            // directory (for example ~/Documents) is never changed.
            std::fs::create_dir_all(dir).context("store directory unavailable")?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                    .context("store directory permissions")?;
            }
        }
        #[cfg(unix)]
        {
            // Create the database file private before SQLite opens it. SQLite gives
            // its -wal and -shm files the main file's mode, so they are private too.
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(path)
                .context("store unavailable")?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .context("store file permissions")?;
        }
        let conn = Connection::open(path).context("store unavailable")?;
        Self::init(conn, tenant_id)
    }

    pub fn in_memory(tenant_id: &str) -> Result<Self> {
        validate_tenant(tenant_id)?;
        Self::init(Connection::open_in_memory()?, tenant_id)
    }

    fn init(conn: Connection, tenant_id: &str) -> Result<Self> {
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON; PRAGMA busy_timeout=5000;",
        )?;
        // Migration and tenant binding commit together. An interrupted first open
        // leaves nothing behind, and a concurrent opener waits (busy_timeout)
        // and then sees the finished schema.
        let mut conn = conn;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let version: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version == 0 {
            tx.execute_batch(MIGRATION_1)?;
            tx.execute(
                "INSERT INTO meta(key, value) VALUES ('tenant_id', ?1)",
                [tenant_id.to_ascii_lowercase()],
            )?;
        }
        if version < 2 {
            tx.execute_batch(crate::incidents::MIGRATION)?;
            tx.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))?;
        }
        tx.commit()?;
        if version > SCHEMA_VERSION {
            bail!("store was created by a newer version of junction");
        }
        let bound: String = conn
            .query_row("SELECT value FROM meta WHERE key = 'tenant_id'", [], |r| {
                r.get(0)
            })
            .context("store tenant binding missing")?;
        if !bound.eq_ignore_ascii_case(tenant_id) {
            bail!("store belongs to a different tenant");
        }
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            tenant_id: bound,
        })
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub(crate) fn db(&self) -> Result<MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| anyhow::anyhow!("store lock poisoned"))
    }

    // ----- metadata -----

    pub fn put_meta(&self, key: &str, value: &str) -> Result<()> {
        if key == "tenant_id" {
            bail!("tenant binding is immutable");
        }
        self.db()?.execute(
            "INSERT INTO meta(key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn delete_meta(&self, key: &str) -> Result<()> {
        if key == "tenant_id" {
            bail!("tenant binding is immutable");
        }
        self.db()?
            .execute("DELETE FROM meta WHERE key = ?1", [key])?;
        Ok(())
    }

    pub fn meta(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .db()?
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()?)
    }

    // ----- capabilities -----

    pub fn put_capability(&self, record: &CapabilityRecord) -> Result<()> {
        self.db()?.execute(
            "INSERT INTO capabilities(source, state, reason, http_status, error_code, detail,
                required_permission, licence_note, docs_url, checked_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(source) DO UPDATE SET state=excluded.state, reason=excluded.reason,
                http_status=excluded.http_status, error_code=excluded.error_code,
                detail=excluded.detail, required_permission=excluded.required_permission,
                licence_note=excluded.licence_note, docs_url=excluded.docs_url,
                checked_at=excluded.checked_at",
            params![
                record.source,
                record.state.as_str(),
                record.reason.as_str(),
                record.http_status,
                record.error_code,
                record.detail,
                record.required_permission,
                record.licence_note,
                record.docs_url,
                record.checked_at
            ],
        )?;
        Ok(())
    }

    pub fn capabilities(&self) -> Result<Vec<CapabilityRecord>> {
        let db = self.db()?;
        let mut stmt = db.prepare(
            "SELECT source, state, reason, http_status, error_code, detail, required_permission,
                    licence_note, docs_url, checked_at FROM capabilities ORDER BY source",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(CapabilityRecord {
                source: r.get(0)?,
                state: CapabilityState::parse(&r.get::<_, String>(1)?),
                reason: reason_from_str(&r.get::<_, String>(2)?),
                http_status: r.get(3)?,
                error_code: r.get(4)?,
                detail: r.get(5)?,
                required_permission: r.get(6)?,
                licence_note: r.get(7)?,
                docs_url: r.get(8)?,
                checked_at: r.get(9)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn capability(&self, source: &str) -> Result<Option<CapabilityRecord>> {
        Ok(self
            .capabilities()?
            .into_iter()
            .find(|c| c.source == source))
    }

    // ----- checkpoints -----

    pub fn checkpoint(&self, collector: &str) -> Result<Option<Instant>> {
        let value: Option<String> = self
            .db()?
            .query_row(
                "SELECT watermark FROM checkpoints WHERE collector = ?1",
                [collector],
                |r| r.get(0),
            )
            .optional()?;
        value.map(|v| Instant::parse(&v)).transpose()
    }

    /// Watermarks only move forward; a stale writer cannot rewind collection.
    pub fn advance_checkpoint(&self, collector: &str, watermark: Instant) -> Result<()> {
        let now = Instant::now().to_rfc3339();
        self.db()?.execute(
            "INSERT INTO checkpoints(collector, watermark, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(collector) DO UPDATE SET watermark = excluded.watermark,
                updated_at = excluded.updated_at
             WHERE excluded.watermark > checkpoints.watermark",
            params![collector, watermark.to_rfc3339(), now],
        )?;
        Ok(())
    }

    // ----- content blobs and events -----

    pub fn content_processed(&self, content_id: &str) -> Result<bool> {
        Ok(self
            .db()?
            .query_row(
                "SELECT 1 FROM processed_content WHERE content_id = ?1",
                [content_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Insert a blob's events and mark the blob processed in one transaction, so an
    /// interrupted run either fully records the blob or retries it next time.
    pub fn ingest_content(
        &self,
        content_id: &str,
        content_type: &str,
        content_created: &str,
        content_expiration: Option<&str>,
        events: &[SecurityEvent],
    ) -> Result<InsertCounts> {
        self.ingest_content_with_raw(
            content_id,
            content_type,
            content_created,
            content_expiration,
            events,
            &[],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn ingest_content_with_raw(
        &self,
        content_id: &str,
        content_type: &str,
        content_created: &str,
        content_expiration: Option<&str>,
        events: &[SecurityEvent],
        raw: &[serde_json::Value],
    ) -> Result<InsertCounts> {
        let key = crate::evidence::EvidenceKey::environment()?;
        let mut sealed = vec![];
        if let Some(key) = &key {
            for record in raw {
                let bytes = serde_json::to_vec(record)?;
                let digest = crate::event::sha256_hex(&bytes);
                if let Some(event) = events.iter().find(|e| e.raw_sha256 == digest) {
                    let (nonce, ciphertext) = key.seal(self.tenant_id(), &event.id, &bytes)?;
                    sealed.push((event.id.clone(), nonce, ciphertext, digest));
                }
            }
        }
        let mut db = self.db()?;
        let tx = db.transaction()?;
        let counts = insert_events(&tx, &self.tenant_id, events)?;
        if let Some(key) = &key {
            for (id, nonce, ciphertext, digest) in sealed {
                tx.execute("INSERT OR IGNORE INTO evidence(event_id,key_id,nonce,ciphertext,sha256) VALUES(?1,?2,?3,?4,?5)", params![id,key.id,nonce,ciphertext,digest])?;
                tx.execute(
                    "UPDATE events SET raw_evidence_reference=?1 WHERE id=?2",
                    params![format!("sqlite:evidence/{id}"), id],
                )?;
            }
        }
        tx.execute(
            "INSERT OR IGNORE INTO processed_content(content_id, content_type, content_created,
                content_expiration, processed_at, record_count) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                content_id,
                content_type,
                content_created,
                content_expiration,
                Instant::now().to_rfc3339(),
                events.len() as i64
            ],
        )?;
        crate::operations::enforce_budget(&tx)?;
        tx.commit()?;
        Ok(counts)
    }

    pub fn insert_events(&self, events: &[SecurityEvent]) -> Result<InsertCounts> {
        let mut db = self.db()?;
        let tx = db.transaction()?;
        let counts = insert_events(&tx, &self.tenant_id, events)?;
        crate::operations::enforce_budget(&tx)?;
        tx.commit()?;
        Ok(counts)
    }

    pub fn events(&self, query: &EventQuery) -> Result<Vec<SecurityEvent>> {
        let mut sql = String::from(
            "SELECT id, tenant_id, source, source_event_id, event_type, timestamp, ingested_at,
                actor_id, actor_upn, target_id, target_type, operation, result, ip_address,
                user_agent, correlation_id, metadata, raw_sha256, raw_evidence_reference
             FROM events WHERE tenant_id = ?1",
        );
        let mut args: Vec<String> = vec![self.tenant_id.clone()];
        let mut push = |clause: &str, value: String, args: &mut Vec<String>| {
            args.push(value);
            sql.push_str(&clause.replace('?', &format!("?{}", args.len())));
        };
        if let Some(v) = &query.actor {
            push(" AND actor_upn = ?", v.to_ascii_lowercase(), &mut args);
        }
        if let Some(v) = &query.operation {
            push(" AND operation = ?", v.clone(), &mut args);
        }
        if let Some(v) = &query.source {
            push(" AND source = ?", v.clone(), &mut args);
        }
        if let Some(v) = &query.site {
            push(
                " AND json_extract(metadata, '$.SiteUrl') = ?",
                v.clone(),
                &mut args,
            );
        }
        if let Some(v) = &query.target {
            push(" AND target_id = ?", v.clone(), &mut args);
        }
        if let Some(v) = &query.since {
            push(" AND timestamp >= ?", v.clone(), &mut args);
        }
        if let Some(v) = &query.until {
            push(" AND timestamp < ?", v.clone(), &mut args);
        }
        if let Some((ts, id)) = &query.before {
            args.push(ts.clone());
            let a = args.len();
            args.push(id.clone());
            let b = args.len();
            sql.push_str(&format!(" AND (timestamp, id) < (?{a}, ?{b})"));
        }
        let limit = query.limit.clamp(1, 500);
        sql.push_str(&format!(" ORDER BY timestamp DESC, id DESC LIMIT {limit}"));
        let db = self.db()?;
        let mut stmt = db.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), row_to_event)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn event_count(&self) -> Result<i64> {
        Ok(self.db()?.query_row(
            "SELECT COUNT(*) FROM events WHERE tenant_id = ?1",
            [&self.tenant_id],
            |r| r.get(0),
        )?)
    }

    /// Distinct actors seen since `since`, for the "monitored users" figure.
    pub fn distinct_actors_since(&self, since: Instant) -> Result<i64> {
        Ok(self.db()?.query_row(
            "SELECT COUNT(DISTINCT actor_upn) FROM events
             WHERE tenant_id = ?1 AND timestamp >= ?2 AND actor_upn LIKE '%@%'",
            params![self.tenant_id, since.to_rfc3339()],
            |r| r.get(0),
        )?)
    }

    /// Observed event coverage for one source since `since`:
    /// (distinct operations, total events).
    pub fn observed_coverage(&self, source: &str, since: Instant) -> Result<(i64, i64)> {
        Ok(self.db()?.query_row(
            "SELECT COUNT(DISTINCT operation), COUNT(*) FROM events
             WHERE tenant_id = ?1 AND source = ?2 AND timestamp >= ?3",
            params![self.tenant_id, source, since.to_rfc3339()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?)
    }

    pub fn distinct_sites_since(&self, since: Instant) -> Result<i64> {
        Ok(self.db()?.query_row(
            "SELECT COUNT(DISTINCT json_extract(metadata, '$.SiteUrl')) FROM events
             WHERE tenant_id = ?1 AND timestamp >= ?2 AND json_extract(metadata, '$.SiteUrl') IS NOT NULL",
            params![self.tenant_id, since.to_rfc3339()],
            |r| r.get(0),
        )?)
    }

    // ----- runs and gaps -----

    pub fn start_run(&self, collector: &str) -> Result<i64> {
        let db = self.db()?;
        db.execute(
            "INSERT INTO collection_runs(collector, started_at, status) VALUES (?1, ?2, 'running')",
            params![collector, Instant::now().to_rfc3339()],
        )?;
        Ok(db.last_insert_rowid())
    }

    pub fn finish_run(&self, id: i64, run: &RunSummary<'_>) -> Result<()> {
        self.db()?.execute(
            "UPDATE collection_runs SET finished_at = ?2, status = ?3, window_start = ?4,
                window_end = ?5, content_blobs = ?6, events_new = ?7, events_duplicate = ?8,
                max_delay_seconds = ?9, rejected_entries = ?10, unparseable_records = ?11,
                quarantined_blobs = ?12, error = ?13 WHERE id = ?1",
            params![
                id,
                Instant::now().to_rfc3339(),
                run.status,
                run.window.map(|w| w.0.to_rfc3339()),
                run.window.map(|w| w.1.to_rfc3339()),
                run.content_blobs as i64,
                run.counts.new as i64,
                run.counts.duplicate as i64,
                run.max_delay_seconds,
                run.rejected_entries as i64,
                run.unparseable_records as i64,
                run.quarantined_blobs as i64,
                run.error
            ],
        )?;
        Ok(())
    }

    /// Mark runs left `running` by a crash or sleep as interrupted.
    pub fn close_abandoned_runs(&self) -> Result<usize> {
        Ok(self.db()?.execute(
            "UPDATE collection_runs SET status = 'interrupted', finished_at = ?1
             WHERE status = 'running'",
            [Instant::now().to_rfc3339()],
        )?)
    }

    pub fn recent_runs(&self, limit: u32) -> Result<Vec<RunRecord>> {
        let db = self.db()?;
        let mut stmt = db.prepare(
            "SELECT id, collector, started_at, finished_at, status, window_start, window_end,
                content_blobs, events_new, events_duplicate, max_delay_seconds,
                rejected_entries, unparseable_records, quarantined_blobs, error
             FROM collection_runs ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit.clamp(1, 500)], row_to_run)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Latest successful run per collector.
    pub fn last_success(&self, collector: &str) -> Result<Option<RunRecord>> {
        let db = self.db()?;
        Ok(db
            .query_row(
                "SELECT id, collector, started_at, finished_at, status, window_start, window_end,
                    content_blobs, events_new, events_duplicate, max_delay_seconds,
                rejected_entries, unparseable_records, quarantined_blobs, error
                 FROM collection_runs WHERE collector = ?1
                   AND status IN ('ok', 'ok_with_warnings', 'partial')
                 ORDER BY id DESC LIMIT 1",
                [collector],
                row_to_run,
            )
            .optional()?)
    }

    pub fn record_gap(
        &self,
        collector: &str,
        start: Instant,
        end: Instant,
        reason: &str,
    ) -> Result<()> {
        let db = self.db()?;
        // A gap that continues an existing one (same feed and cause, starting where
        // it ended or inside it) extends that row instead of adding another.
        let extended = db.execute(
            "UPDATE gaps SET gap_end = MAX(gap_end, ?3), detected_at = ?5
             WHERE id = (SELECT id FROM gaps WHERE collector = ?1 AND reason = ?4
                         AND gap_start <= ?2 AND gap_end >= ?2 ORDER BY gap_end DESC LIMIT 1)",
            params![
                collector,
                start.to_rfc3339(),
                end.to_rfc3339(),
                reason,
                Instant::now().to_rfc3339()
            ],
        )?;
        if extended == 0 {
            db.execute(
                "INSERT OR IGNORE INTO gaps(collector, gap_start, gap_end, reason, detected_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    collector,
                    start.to_rfc3339(),
                    end.to_rfc3339(),
                    reason,
                    Instant::now().to_rfc3339()
                ],
            )?;
        }
        Ok(())
    }

    pub fn gaps(&self) -> Result<Vec<GapRecord>> {
        let db = self.db()?;
        let mut stmt = db.prepare(
            "SELECT collector, gap_start, gap_end, reason, detected_at FROM gaps
             ORDER BY gap_start DESC LIMIT 200",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(GapRecord {
                collector: r.get(0)?,
                gap_start: r.get(1)?,
                gap_end: r.get(2)?,
                reason: r.get(3)?,
                detected_at: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Forget processed-blob markers whose content Microsoft has already expired.
    pub fn prune_processed_content(&self, now: Instant) -> Result<usize> {
        Ok(self.db()?.execute(
            "DELETE FROM processed_content WHERE content_expiration IS NOT NULL
               AND content_expiration < ?1",
            [now.minus(std::time::Duration::from_secs(86_400))
                .to_rfc3339()],
        )?)
    }

    // ----- audit trail -----

    /// Append to the hash-chained audit trail of operator actions.
    pub fn audit(&self, actor: &str, action: &str, target: &str, detail: &str) -> Result<()> {
        let mut db = self.db()?;
        let tx = db.transaction()?;
        let prev: String = tx
            .query_row(
                "SELECT hash FROM audit_trail ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or_else(|| "0".repeat(64));
        let at = Instant::now().to_rfc3339();
        let hash = trail_hash(&prev, &at, actor, action, target, detail);
        tx.execute(
            "INSERT INTO audit_trail(at, actor, action, target, detail, prev_hash, hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![at, actor, action, target, detail, prev, hash],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Recompute the chain. Returns the ID of the first broken entry, if any.
    pub fn verify_audit_trail(&self) -> Result<Option<i64>> {
        let db = self.db()?;
        let mut stmt = db.prepare(
            "SELECT id, at, actor, action, target, detail, prev_hash, hash FROM audit_trail ORDER BY id",
        )?;
        let mut rows = stmt.query([])?;
        let mut prev = "0".repeat(64);
        while let Some(r) = rows.next()? {
            let id: i64 = r.get(0)?;
            let (at, actor, action, target, detail, stored_prev, hash): (
                String,
                String,
                String,
                String,
                String,
                String,
                String,
            ) = (
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
            );
            if stored_prev != prev
                || trail_hash(&prev, &at, &actor, &action, &target, &detail) != hash
            {
                return Ok(Some(id));
            }
            prev = hash;
        }
        Ok(None)
    }

    pub fn audit_entries(&self, limit: u32) -> Result<Vec<AuditEntry>> {
        let db = self.db()?;
        let mut stmt = db.prepare(
            "SELECT at, actor, action, target, detail FROM audit_trail ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit.clamp(1, 500)], |r| {
            Ok(AuditEntry {
                at: r.get(0)?,
                actor: r.get(1)?,
                action: r.get(2)?,
                target: r.get(3)?,
                detail: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Run `f` with the connection; for modules that own their own tables
    /// (users and sessions).
    pub(crate) fn with_conn<T>(&self, f: impl FnOnce(&mut Connection) -> Result<T>) -> Result<T> {
        let mut db = self.db()?;
        f(&mut db)
    }
}

fn insert_events(
    tx: &rusqlite::Transaction<'_>,
    tenant_id: &str,
    events: &[SecurityEvent],
) -> Result<InsertCounts> {
    let mut counts = InsertCounts::default();
    let mut stmt = tx.prepare_cached(
        "INSERT OR IGNORE INTO events(id, tenant_id, source, source_event_id, event_type,
            timestamp, ingested_at, actor_id, actor_upn, target_id, target_type, operation,
            result, ip_address, user_agent, correlation_id, metadata, raw_sha256,
            raw_evidence_reference)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
    )?;
    for e in events {
        if !e.tenant_id.eq_ignore_ascii_case(tenant_id) {
            bail!("event tenant does not match store tenant");
        }
        let changed = stmt.execute(params![
            e.id,
            tenant_id,
            e.source,
            e.source_event_id,
            e.event_type,
            e.timestamp,
            e.ingested_at,
            e.actor_id,
            e.actor_upn,
            e.target_id,
            e.target_type,
            e.operation,
            e.result,
            e.ip_address,
            e.user_agent,
            e.correlation_id,
            serde_json::to_string(&e.metadata)?,
            e.raw_sha256,
            e.raw_evidence_reference
        ])?;
        if changed == 1 {
            counts.new += 1;
        } else {
            counts.duplicate += 1;
        }
    }
    Ok(counts)
}

pub(crate) fn row_to_event(r: &rusqlite::Row<'_>) -> rusqlite::Result<SecurityEvent> {
    let metadata: String = r.get(16)?;
    Ok(SecurityEvent {
        id: r.get(0)?,
        tenant_id: r.get(1)?,
        source: r.get(2)?,
        source_event_id: r.get(3)?,
        event_type: r.get(4)?,
        timestamp: r.get(5)?,
        ingested_at: r.get(6)?,
        actor_id: r.get(7)?,
        actor_upn: r.get(8)?,
        target_id: r.get(9)?,
        target_type: r.get(10)?,
        operation: r.get(11)?,
        result: r.get(12)?,
        ip_address: r.get(13)?,
        user_agent: r.get(14)?,
        correlation_id: r.get(15)?,
        metadata: serde_json::from_str(&metadata).unwrap_or_default(),
        raw_sha256: r.get(17)?,
        raw_evidence_reference: r.get(18)?,
    })
}

fn row_to_run(r: &rusqlite::Row<'_>) -> rusqlite::Result<RunRecord> {
    Ok(RunRecord {
        id: r.get(0)?,
        collector: r.get(1)?,
        started_at: r.get(2)?,
        finished_at: r.get(3)?,
        status: r.get(4)?,
        window_start: r.get(5)?,
        window_end: r.get(6)?,
        content_blobs: r.get(7)?,
        events_new: r.get(8)?,
        events_duplicate: r.get(9)?,
        max_delay_seconds: r.get(10)?,
        rejected_entries: r.get(11)?,
        unparseable_records: r.get(12)?,
        quarantined_blobs: r.get(13)?,
        error: r.get(14)?,
    })
}

fn trail_hash(
    prev: &str,
    at: &str,
    actor: &str,
    action: &str,
    target: &str,
    detail: &str,
) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for part in [prev, at, actor, action, target, detail] {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part.as_bytes());
    }
    crate::event::hex(&h.finalize())
}

fn reason_from_str(value: &str) -> Reason {
    use Reason::*;
    [
        Ok,
        CredentialRejected,
        MissingPermission,
        AccessDeniedDespitePermission,
        ConditionalAccessBlocked,
        LicenceRequired,
        SubscriptionNotStarted,
        SubscriptionDisabled,
        AuditingDisabled,
        UnsupportedOperation,
        Throttled,
        ServiceError,
        NetworkError,
    ]
    .into_iter()
    .find(|r| r.as_str() == value)
    .unwrap_or(Unclassified)
}

pub fn validate_tenant(tenant_id: &str) -> Result<()> {
    if tenant_id.len() != 36
        || !tenant_id.char_indices().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == '-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
    {
        bail!("tenant ID must be the directory (tenant) GUID");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::from_management_record;
    use serde_json::json;

    pub const T1: &str = "11111111-1111-4111-8111-111111111111";
    pub const T2: &str = "22222222-2222-4222-8222-222222222222";

    fn record(id: &str, at: &str) -> serde_json::Value {
        json!({"Id": id, "CreationTime": at, "Operation": "FileDownloaded", "Workload": "SharePoint",
               "UserId": "a@club.example", "RecordType": 6, "SiteUrl": "https://club.sharepoint.com/sites/board"})
    }

    #[test]
    fn tenant_binding_is_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.db");
        drop(Store::open(&path, T1).unwrap());
        let err = Store::open(&path, T2).err().unwrap().to_string();
        assert!(err.contains("different tenant"));
        assert!(Store::open(&path, &T1.to_uppercase()).is_ok());
        assert!(Store::in_memory("contoso.onmicrosoft.com").is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "store is private to the operator");
        }
    }

    #[cfg(unix)]
    #[test]
    fn store_files_are_private_and_existing_directories_untouched() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = dir.path().join("w.db");
        let store = Store::open(&path, T1).unwrap();
        store.put_meta("k", "v").unwrap();
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(dir.path()), 0o755, "existing directory is not changed");
        for suffix in ["", "-wal", "-shm"] {
            let file = dir.path().join(format!("w.db{suffix}"));
            assert!(file.exists(), "{suffix}");
            assert_eq!(mode(&file), 0o600, "w.db{suffix}");
        }
        let created = dir.path().join("new/sub/w.db");
        drop(Store::open(&created, T1).unwrap());
        assert_eq!(
            mode(&dir.path().join("new/sub")),
            0o700,
            "directories we create are private"
        );
    }

    #[test]
    fn tenant_binding_cannot_be_rewritten_through_meta() {
        let store = Store::in_memory(T1).unwrap();
        assert!(store.put_meta("tenant_id", T2).is_err());
        store.put_meta("verified_domains", "[]").unwrap();
        assert_eq!(
            store.meta("verified_domains").unwrap().as_deref(),
            Some("[]")
        );
    }

    #[test]
    fn events_from_another_tenant_are_refused() {
        let store = Store::in_memory(T1).unwrap();
        let e = from_management_record(
            T2,
            "Audit.SharePoint",
            &record("x", "2026-10-25T00:00:00"),
            Instant::now(),
        )
        .unwrap();
        assert!(store.insert_events(&[e]).is_err());
        assert_eq!(store.event_count().unwrap(), 0);
    }

    #[test]
    fn dedup_and_atomic_blob_ingest() {
        let store = Store::in_memory(T1).unwrap();
        let now = Instant::now();
        let events: Vec<_> = ["a", "b", "a"]
            .iter()
            .map(|id| {
                from_management_record(
                    T1,
                    "Audit.SharePoint",
                    &record(id, "2026-10-25T00:00:00"),
                    now,
                )
                .unwrap()
            })
            .collect();
        let counts = store
            .ingest_content(
                "blob-1",
                "Audit.SharePoint",
                "2026-10-25T00:00:00.000Z",
                None,
                &events,
            )
            .unwrap();
        assert_eq!(
            counts,
            InsertCounts {
                new: 2,
                duplicate: 1
            }
        );
        assert!(store.content_processed("blob-1").unwrap());
        let again = store
            .ingest_content(
                "blob-2",
                "Audit.SharePoint",
                "2026-10-25T00:00:00.000Z",
                None,
                &events[..1],
            )
            .unwrap();
        assert_eq!(
            again,
            InsertCounts {
                new: 0,
                duplicate: 1
            },
            "overlapping blobs dedupe"
        );
        assert_eq!(store.event_count().unwrap(), 2);
        assert_eq!(store.distinct_sites_since(Instant(0)).unwrap(), 1);
    }

    #[test]
    fn checkpoints_only_move_forward() {
        let store = Store::in_memory(T1).unwrap();
        assert!(store.checkpoint("c").unwrap().is_none());
        let t = Instant::parse("2026-10-25T00:00:00Z").unwrap();
        store.advance_checkpoint("c", t).unwrap();
        store
            .advance_checkpoint("c", t.minus(std::time::Duration::from_secs(60)))
            .unwrap();
        assert_eq!(store.checkpoint("c").unwrap(), Some(t));
        let later = t.plus(std::time::Duration::from_secs(60));
        store.advance_checkpoint("c", later).unwrap();
        assert_eq!(store.checkpoint("c").unwrap(), Some(later));
    }

    #[test]
    fn event_queries_filter_and_paginate() {
        let store = Store::in_memory(T1).unwrap();
        let now = Instant::now();
        let events: Vec<_> = (0..5)
            .map(|i| {
                from_management_record(
                    T1,
                    "Audit.SharePoint",
                    &record(&format!("e{i}"), &format!("2026-10-25T00:00:0{i}")),
                    now,
                )
                .unwrap()
            })
            .collect();
        store.insert_events(&events).unwrap();
        let page = store
            .events(&EventQuery {
                limit: 2,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].source_event_id, "e4");
        let last = page.last().unwrap();
        let next = store
            .events(&EventQuery {
                limit: 2,
                before: Some((last.timestamp.clone(), last.id.clone())),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(next[0].source_event_id, "e2");
        let filtered = store
            .events(&EventQuery {
                actor: Some("A@CLUB.EXAMPLE".into()),
                operation: Some("FileDownloaded".into()),
                since: Some("2026-10-25T00:00:03.000Z".into()),
                limit: 50,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(filtered.len(), 2);
        let injection = store
            .events(&EventQuery {
                actor: Some("' OR 1=1 --".into()),
                limit: 50,
                ..Default::default()
            })
            .unwrap();
        assert!(injection.is_empty(), "filters are bound parameters");
    }

    #[test]
    fn audit_trail_detects_tampering() {
        let store = Store::in_memory(T1).unwrap();
        store.audit("admin", "login", "session", "{}").unwrap();
        store.audit("admin", "probe", "tenant", "{}").unwrap();
        store
            .audit("admin", "start_subscription", "Audit.Exchange", "{}")
            .unwrap();
        assert_eq!(store.verify_audit_trail().unwrap(), None);
        store
            .with_conn(|c| {
                Ok(c.execute("UPDATE audit_trail SET actor = 'mallory' WHERE id = 2", [])?)
            })
            .unwrap();
        assert_eq!(store.verify_audit_trail().unwrap(), Some(2));
    }

    #[test]
    fn runs_and_gaps() {
        let store = Store::in_memory(T1).unwrap();
        let id = store.start_run("c").unwrap();
        let stale = store.start_run("c").unwrap();
        store
            .finish_run(
                id,
                &RunSummary {
                    status: "ok",
                    window: None,
                    content_blobs: 3,
                    counts: InsertCounts {
                        new: 2,
                        duplicate: 1,
                    },
                    max_delay_seconds: Some(60),
                    rejected_entries: 0,
                    unparseable_records: 0,
                    quarantined_blobs: 0,
                    error: None,
                },
            )
            .unwrap();
        assert_eq!(store.close_abandoned_runs().unwrap(), 1);
        let runs = store.recent_runs(10).unwrap();
        assert_eq!(
            runs.iter().find(|r| r.id == stale).unwrap().status,
            "interrupted"
        );
        assert_eq!(store.last_success("c").unwrap().unwrap().events_new, 2);
        let t = Instant::parse("2026-10-01T00:00:00Z").unwrap();
        store
            .record_gap(
                "c",
                t,
                t.plus(std::time::Duration::from_secs(3600)),
                "expired",
            )
            .unwrap();
        store
            .record_gap(
                "c",
                t,
                t.plus(std::time::Duration::from_secs(3600)),
                "expired",
            )
            .unwrap();
        assert_eq!(store.gaps().unwrap().len(), 1);
    }
}

#[cfg(test)]
mod migration_tests {
    use super::*;
    #[test]
    fn upgrades_phase_one_database_without_rebinding_or_losing_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("watch.db");
        let tenant = "11111111-1111-4111-8111-111111111111";
        let db = Connection::open(&path).unwrap();
        db.execute_batch(MIGRATION_1).unwrap();
        db.execute(
            "INSERT INTO meta(key,value) VALUES('tenant_id',?1)",
            [tenant],
        )
        .unwrap();
        db.execute(
            "INSERT INTO meta(key,value) VALUES('existing','preserved')",
            [],
        )
        .unwrap();
        db.execute_batch("PRAGMA user_version=1").unwrap();
        drop(db);
        let store = Store::open(&path, tenant).unwrap();
        assert_eq!(
            store.meta("existing").unwrap().as_deref(),
            Some("preserved")
        );
        assert!(store.alerts(None, None, None, 10).unwrap().is_empty());
        assert!(Store::open(&path, "22222222-2222-4222-8222-222222222222").is_err());
    }
}
