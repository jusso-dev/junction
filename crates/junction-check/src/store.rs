//! Per-tenant run history and attestation store (SQLite).
//!
//! One database file per tenant (`<tenant-id>.sqlite` in the history
//! directory). The tenant is bound at creation and checked on every open, so a
//! mis-pointed path can never mix two tenants' results. Each tenant has its own
//! file, so runs for different tenants never contend; WAL and a busy timeout
//! cover concurrent writers to the same tenant.
//!
//! Stored: full [`TenantReport`] JSON per run (counts, identifiers and
//! remediation text, never tokens or secrets) and attestations (answer, note,
//! author, times). No credentials are ever stored. Every write appends to a
//! hash-chained audit trail ([`Store::verify_audit_trail`]).
use crate::attest;
use crate::model::{Answer, Attestation, StatusCounts, TenantReport, TenantStatus};
use anyhow::{Context, Result, bail};
use junction_watch::clock::Instant;
use junction_watch::store::validate_tenant;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

const SCHEMA_VERSION: i64 = 1;

const MIGRATION_1: &str = r#"
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE runs (
    run_id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    score REAL,
    pass INTEGER NOT NULL,
    fail INTEGER NOT NULL,
    warn INTEGER NOT NULL,
    unknown INTEGER NOT NULL,
    not_applicable INTEGER NOT NULL,
    status TEXT NOT NULL,
    report TEXT NOT NULL
);
CREATE INDEX runs_finished ON runs(finished_at);

CREATE TABLE attestations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    check_id TEXT NOT NULL,
    answer TEXT NOT NULL,
    note TEXT NOT NULL,
    author TEXT NOT NULL,
    attested_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX attestations_check ON attestations(check_id, id);

CREATE TABLE audit_trail (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    detail TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
"#;

const RUN_COLUMNS: &str =
    "run_id, finished_at, score, pass, fail, warn, unknown, not_applicable, status";

#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
    tenant_id: String,
}

/// One row of `junction check history`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunSummary {
    pub run_id: String,
    pub finished_at: String,
    pub score: Option<f64>,
    pub statuses: StatusCounts,
    pub status: TenantStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredRun {
    pub run_id: String,
    pub finished_at: String,
    pub report: TenantReport,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub at: String,
    pub action: String,
    pub target: String,
    pub detail: String,
}

impl Store {
    /// The store file for `tenant_id` in `directory`.
    pub fn path_for(directory: &Path, tenant_id: &str) -> Result<PathBuf> {
        validate_tenant(tenant_id)?;
        Ok(directory.join(format!("{}.sqlite", tenant_id.to_ascii_lowercase())))
    }

    /// Open (or create) the store for `tenant_id` in `directory`. Refuses a
    /// file bound to another tenant.
    pub fn open(directory: &Path, tenant_id: &str) -> Result<Self> {
        let path = Self::path_for(directory, tenant_id)?;
        if !directory.exists() {
            // Only directories we create are tightened; an existing one is left alone.
            std::fs::create_dir_all(directory).context("history directory unavailable")?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
                    .context("history directory permissions")?;
            }
        }
        #[cfg(unix)]
        {
            // Private before SQLite opens it; the -wal and -shm files inherit the mode.
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(&path)
                .context("history store unavailable")?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .context("history store permissions")?;
        }
        let conn = Connection::open(&path).context("history store unavailable")?;
        Self::init(conn, tenant_id)
    }

    pub fn in_memory(tenant_id: &str) -> Result<Self> {
        validate_tenant(tenant_id)?;
        Self::init(Connection::open_in_memory()?, tenant_id)
    }

    fn init(mut conn: Connection, tenant_id: &str) -> Result<Self> {
        // Busy timeout first: switching to WAL takes a lock another opener may hold.
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA secure_delete=ON;")?;
        // Migration and tenant binding commit together, so an interrupted first
        // open leaves nothing behind and a concurrent opener sees the finished schema.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            bail!("history store was created by a newer version of junction");
        }
        if version == 0 {
            tx.execute_batch(MIGRATION_1)?;
            tx.execute(
                "INSERT INTO meta(key, value) VALUES ('tenant_id', ?1)",
                [tenant_id.to_ascii_lowercase()],
            )?;
            tx.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))?;
        }
        tx.commit()?;
        let bound: String = conn
            .query_row("SELECT value FROM meta WHERE key = 'tenant_id'", [], |r| {
                r.get(0)
            })
            .context("history store tenant binding missing")?;
        if !bound.eq_ignore_ascii_case(tenant_id) {
            bail!("history store belongs to a different tenant");
        }
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            tenant_id: bound,
        })
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub fn schema_version(&self) -> Result<i64> {
        Ok(self
            .db()?
            .query_row("PRAGMA user_version", [], |r| r.get(0))?)
    }

    fn db(&self) -> Result<MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| anyhow::anyhow!("history store lock poisoned"))
    }

    // ----- runs -----

    /// Store one tenant's results. Saving the same `run_id` again replaces it.
    pub fn save_run(
        &self,
        run_id: &str,
        started_at: &str,
        finished_at: &str,
        report: &TenantReport,
    ) -> Result<()> {
        validate_id("run id", run_id)?;
        if !report.tenant_id.eq_ignore_ascii_case(&self.tenant_id) {
            bail!("report tenant does not match history store tenant");
        }
        let started_at = normalise(started_at)?;
        let finished_at = normalise(finished_at)?;
        let s = &report.score.statuses;
        let mut db = self.db()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO runs(run_id, started_at, finished_at, score, pass, fail, warn, unknown,
                not_applicable, status, report)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(run_id) DO UPDATE SET started_at=excluded.started_at,
                finished_at=excluded.finished_at, score=excluded.score, pass=excluded.pass,
                fail=excluded.fail, warn=excluded.warn, unknown=excluded.unknown,
                not_applicable=excluded.not_applicable, status=excluded.status,
                report=excluded.report",
            params![
                run_id,
                started_at,
                finished_at,
                report.score.score,
                s.pass as i64,
                s.fail as i64,
                s.warn as i64,
                s.unknown as i64,
                s.not_applicable as i64,
                tenant_status_str(report.status),
                serde_json::to_string(report)?,
            ],
        )?;
        let score = report
            .score
            .score
            .map_or_else(|| "none".to_owned(), |v| v.to_string());
        append_audit(
            &tx,
            &finished_at,
            "run.save",
            run_id,
            &format!("score={score} fail={} warn={}", s.fail, s.warn),
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Stored runs, newest first.
    pub fn runs(&self, limit: u32) -> Result<Vec<RunSummary>> {
        let db = self.db()?;
        let mut stmt = db.prepare(&format!(
            "SELECT {RUN_COLUMNS} FROM runs ORDER BY finished_at DESC, run_id DESC LIMIT ?1"
        ))?;
        let rows = stmt.query_map([limit.clamp(1, 10_000)], row_to_summary)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn load_run(&self, run_id: &str) -> Result<Option<StoredRun>> {
        self.one_run("WHERE run_id = ?1", &[&run_id])
    }

    pub fn latest(&self) -> Result<Option<StoredRun>> {
        self.one_run("", &[])
    }

    /// The newest run that finished strictly before `finished_at`.
    pub fn latest_before(&self, finished_at: &str) -> Result<Option<StoredRun>> {
        self.one_run("WHERE finished_at < ?1", &[&normalise(finished_at)?])
    }

    /// The newest run that finished on or before `date` (`YYYY-MM-DD`, UTC).
    pub fn run_at_or_before_date(&self, date: &str) -> Result<Option<StoredRun>> {
        let day = Instant::parse(&format!("{date}T00:00:00Z"))
            .ok()
            .filter(|d| date.len() == 10 && d.to_rfc3339().starts_with(date))
            .with_context(|| format!("invalid date {date:?}; expected YYYY-MM-DD"))?;
        let end = day.plus(Duration::from_secs(86_400)).to_rfc3339();
        self.one_run("WHERE finished_at < ?1", &[&end])
    }

    fn one_run(&self, filter: &str, args: &[&dyn rusqlite::ToSql]) -> Result<Option<StoredRun>> {
        let db = self.db()?;
        let row: Option<(String, String, String)> = db
            .query_row(
                &format!(
                    "SELECT run_id, finished_at, report FROM runs {filter}
                     ORDER BY finished_at DESC, run_id DESC LIMIT 1"
                ),
                args,
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        row.map(|(run_id, finished_at, report)| {
            Ok(StoredRun {
                report: serde_json::from_str(&report)
                    .with_context(|| format!("stored run {run_id} is unreadable"))?,
                run_id,
                finished_at,
            })
        })
        .transpose()
    }

    /// Delete runs that finished more than `keep_days` before `now`. The most
    /// recent run is always kept so drift has a baseline. Returns the number removed.
    pub fn prune(&self, keep_days: u32, now: Instant) -> Result<usize> {
        let cutoff = now
            .minus(Duration::from_secs(86_400) * keep_days)
            .to_rfc3339();
        let mut db = self.db()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let removed = tx.execute(
            "DELETE FROM runs WHERE finished_at < ?1 AND run_id <> (
                SELECT run_id FROM runs ORDER BY finished_at DESC, run_id DESC LIMIT 1)",
            [&cutoff],
        )?;
        if removed > 0 {
            append_audit(
                &tx,
                &now.to_rfc3339(),
                "runs.prune",
                &format!("before {cutoff}"),
                &format!("removed={removed} keep_days={keep_days}"),
            )?;
        }
        tx.commit()?;
        Ok(removed)
    }

    // ----- attestations -----

    /// Record an answer. History is append-only; the latest answer per check wins.
    pub fn put_attestation(&self, check_id: &str, attestation: &Attestation) -> Result<()> {
        validate_id("check id", check_id)?;
        attest::validate(attestation)?;
        let attested_at = normalise(&attestation.attested_at)?;
        let expires_at = normalise(&attestation.expires_at)?;
        let mut db = self.db()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO attestations(check_id, answer, note, author, attested_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                check_id,
                attestation.answer.as_str(),
                attestation.note,
                attestation.author,
                attested_at,
                expires_at
            ],
        )?;
        append_audit(
            &tx,
            &attested_at,
            "attestation.put",
            check_id,
            &format!(
                "answer={} author={} expires_at={expires_at}",
                attestation.answer.as_str(),
                attestation.author
            ),
        )?;
        tx.commit()?;
        Ok(())
    }

    /// The latest answer per check, including expired ones (see [`attest::is_current`]).
    pub fn attestations(&self) -> Result<BTreeMap<String, Attestation>> {
        let db = self.db()?;
        let mut stmt = db.prepare(
            "SELECT check_id, answer, note, author, attested_at, expires_at FROM attestations a
             WHERE id = (SELECT MAX(id) FROM attestations WHERE check_id = a.check_id)",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, row_to_attestation(r)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Every answer recorded for `check_id`, newest first.
    pub fn attestation_history(&self, check_id: &str) -> Result<Vec<Attestation>> {
        let db = self.db()?;
        let mut stmt = db.prepare(
            "SELECT check_id, answer, note, author, attested_at, expires_at FROM attestations
             WHERE check_id = ?1 ORDER BY id DESC",
        )?;
        let rows = stmt.query_map([check_id], row_to_attestation)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    // ----- audit trail -----

    /// Append an entry for an operator action that is not itself a store write.
    pub fn audit(&self, action: &str, target: &str, detail: &str, at: Instant) -> Result<()> {
        let mut db = self.db()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        append_audit(&tx, &at.to_rfc3339(), action, target, detail)?;
        tx.commit()?;
        Ok(())
    }

    /// Recompute the chain. Returns the id of the first broken entry, if any.
    pub fn verify_audit_trail(&self) -> Result<Option<i64>> {
        let db = self.db()?;
        let mut stmt = db.prepare(
            "SELECT id, at, action, target, detail, prev_hash, hash FROM audit_trail ORDER BY id",
        )?;
        let mut rows = stmt.query([])?;
        let mut prev = GENESIS.to_owned();
        while let Some(r) = rows.next()? {
            let id: i64 = r.get(0)?;
            let [at, action, target, detail, stored_prev, hash]: [String; 6] = [
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
            ];
            if stored_prev != prev || trail_hash(&prev, &at, &action, &target, &detail) != hash {
                return Ok(Some(id));
            }
            prev = hash;
        }
        Ok(None)
    }

    /// Newest first.
    pub fn audit_entries(&self, limit: u32) -> Result<Vec<AuditEntry>> {
        let db = self.db()?;
        let mut stmt = db.prepare(
            "SELECT at, action, target, detail FROM audit_trail ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit.clamp(1, 500)], |r| {
            Ok(AuditEntry {
                at: r.get(0)?,
                action: r.get(1)?,
                target: r.get(2)?,
                detail: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
}

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn append_audit(
    tx: &Transaction<'_>,
    at: &str,
    action: &str,
    target: &str,
    detail: &str,
) -> Result<()> {
    let prev: String = tx
        .query_row(
            "SELECT hash FROM audit_trail ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or_else(|| GENESIS.to_owned());
    let hash = trail_hash(&prev, at, action, target, detail);
    tx.execute(
        "INSERT INTO audit_trail(at, action, target, detail, prev_hash, hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![at, action, target, detail, prev, hash],
    )?;
    Ok(())
}

fn trail_hash(prev: &str, at: &str, action: &str, target: &str, detail: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for part in [prev, at, action, target, detail] {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part.as_bytes());
    }
    junction_watch::event::hex(&h.finalize())
}

/// Fixed-width UTC form, so text order in SQLite is time order.
fn normalise(timestamp: &str) -> Result<String> {
    Ok(Instant::parse(timestamp)
        .with_context(|| format!("invalid timestamp {timestamp:?}"))?
        .to_rfc3339())
}

fn validate_id(what: &str, id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 200
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
    {
        bail!("{what} must be 1 to 200 letters, digits, '-', '_', '.' or ':'");
    }
    Ok(())
}

fn tenant_status_str(status: TenantStatus) -> &'static str {
    match status {
        TenantStatus::Complete => "complete",
        TenantStatus::Partial => "partial",
        TenantStatus::Failed => "failed",
    }
}

fn row_to_summary(r: &rusqlite::Row<'_>) -> rusqlite::Result<RunSummary> {
    let count = |i: usize| -> rusqlite::Result<usize> { Ok(r.get::<_, i64>(i)?.max(0) as usize) };
    let status: String = r.get(8)?;
    Ok(RunSummary {
        run_id: r.get(0)?,
        finished_at: r.get(1)?,
        score: r.get(2)?,
        statuses: StatusCounts {
            pass: count(3)?,
            fail: count(4)?,
            warn: count(5)?,
            unknown: count(6)?,
            not_applicable: count(7)?,
        },
        status: match status.as_str() {
            "complete" => TenantStatus::Complete,
            "failed" => TenantStatus::Failed,
            _ => TenantStatus::Partial,
        },
    })
}

fn row_to_attestation(r: &rusqlite::Row<'_>) -> rusqlite::Result<Attestation> {
    let answer: String = r.get(1)?;
    Ok(Attestation {
        answer: Answer::parse(&answer).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Text,
                format!("unknown answer {answer:?}").into(),
            )
        })?,
        note: r.get(2)?,
        author: r.get(3)?,
        attested_at: r.get(4)?,
        expires_at: r.get(5)?,
    })
}
