//! Local operational policy, retention and nontechnical reporting.
use crate::{clock::Instant, store::Store};
use anyhow::{Result, bail};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::Duration;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub poll_minutes: u64,
    pub retention_days: u64,
    pub evidence_retention_days: u64,
    pub max_events: u64,
    pub max_evidence_bytes: u64,
    pub bulk_threshold: usize,
    pub approved_external_domains: Vec<String>,
    pub sensitive_sites: Vec<String>,
    pub notifications: crate::notify::NotificationConfig,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            poll_minutes: 15,
            retention_days: 90,
            evidence_retention_days: 30,
            max_events: 1_000_000,
            max_evidence_bytes: 1024 * 1024 * 1024,
            bulk_threshold: 100,
            approved_external_domains: vec![],
            sensitive_sites: vec![],
            notifications: Default::default(),
        }
    }
}
impl Settings {
    pub fn validate(&self, domain: &str) -> Result<()> {
        if !(5..=1440).contains(&self.poll_minutes)
            || !(8..=3650).contains(&self.retention_days)
            || !(1..=self.retention_days).contains(&self.evidence_retention_days)
            || !(1000..=100_000_000).contains(&self.max_events)
            || self.max_evidence_bytes > 100 * 1024 * 1024 * 1024
            || !(2..=10_000).contains(&self.bulk_threshold)
        {
            bail!("settings outside supported limits");
        }
        if self.approved_external_domains.len() > 1000 || self.sensitive_sites.len() > 1000 {
            bail!("too many monitored exceptions");
        }
        for d in &self.approved_external_domains {
            if d.len() > 253
                || !d.contains('.')
                || !d
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            {
                bail!("invalid approved domain");
            }
        }
        for s in &self.sensitive_sites {
            let u = url::Url::parse(s).map_err(|_| anyhow::anyhow!("invalid site URL"))?;
            if u.scheme() != "https" || s.len() > 2048 {
                bail!("invalid site URL");
            }
        }
        self.notifications.validate(domain)
    }
}
impl Store {
    pub fn operational_settings(&self) -> Result<Settings> {
        self.meta("operational_settings")?
            .map(|s| serde_json::from_str(&s).map_err(Into::into))
            .unwrap_or_else(|| Ok(Settings::default()))
    }
    pub fn save_operational_settings(&self, s: &Settings, domain: &str, actor: &str) -> Result<()> {
        s.validate(domain)?;
        self.audit(actor, "settings_changed", "watch", "{}")?;
        self.put_meta("operational_settings", &serde_json::to_string(s)?)?;
        Ok(())
    }
    pub fn storage_usage(&self) -> Result<Value> {
        let db = self.db()?;
        let events: i64 = db.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
        let bytes: i64 = db.query_row(
            "SELECT COALESCE(SUM(length(ciphertext)),0) FROM evidence",
            [],
            |r| r.get(0),
        )?;
        let pending: i64 = db.query_row(
            "SELECT COUNT(*) FROM notification_outbox WHERE delivered_at IS NULL",
            [],
            |r| r.get(0),
        )?;
        Ok(
            json!({"events":events,"encrypted_evidence_bytes":bytes,"pending_notifications":pending}),
        )
    }
    pub fn retain(&self, now: Instant, actor: &str) -> Result<Value> {
        let s = self.operational_settings()?;
        let cutoff = now
            .minus(Duration::from_secs(s.retention_days * 86400))
            .to_rfc3339();
        let raw_cutoff = now
            .minus(Duration::from_secs(s.evidence_retention_days * 86400))
            .to_rfc3339();
        self.audit(
            actor,
            "retention",
            "watch",
            &json!({"events_before":cutoff,"evidence_before":raw_cutoff}).to_string(),
        )?;
        let mut db = self.db()?;
        let tx = db.transaction()?;
        // Active incident evidence is retained for investigation, and counts against
        // quota. Operators must resolve the incident before its telemetry can expire.
        let pinned = "SELECT DISTINCT j.value FROM alerts a, json_each(a.finding,'$.evidence') j WHERE a.status != 'RESOLVED' AND a.suppressed=0";
        let raw=tx.execute(&format!("DELETE FROM evidence WHERE event_id IN (SELECT id FROM events WHERE timestamp<?1) AND event_id NOT IN ({pinned})"),[raw_cutoff])?;
        let events = tx.execute(
            &format!("DELETE FROM events WHERE timestamp<?1 AND id NOT IN ({pinned})"),
            [&cutoff],
        )?;
        tx.execute("UPDATE events SET raw_evidence_reference=NULL WHERE raw_evidence_reference IS NOT NULL AND id NOT IN (SELECT event_id FROM evidence)",[])?;
        tx.execute(
            "DELETE FROM sessions WHERE expires_at<?1",
            [now.to_rfc3339()],
        )?;
        tx.execute("DELETE FROM suppressions WHERE ends_at<?1", [&cutoff])?;
        tx.execute(
            "DELETE FROM alerts WHERE status='RESOLVED' AND updated_at<?1",
            [&cutoff],
        )?;
        tx.execute("DELETE FROM configuration_changes WHERE at<?1", [&cutoff])?;
        tx.execute("DELETE FROM snapshot_sets WHERE collected_at<?1 AND id NOT IN (SELECT s.id FROM snapshot_sets s WHERE s.collected_at=(SELECT MAX(x.collected_at) FROM snapshot_sets x WHERE x.resource_type=s.resource_type)) AND id NOT IN (SELECT s.id FROM snapshot_sets s WHERE s.approved=1 AND s.collected_at=(SELECT MAX(x.collected_at) FROM snapshot_sets x WHERE x.resource_type=s.resource_type AND x.approved=1)) AND id NOT IN (SELECT snapshot_id FROM configuration_changes)",[&cutoff])?;
        tx.execute("DELETE FROM reports WHERE generated_at<?1", [&cutoff])?;
        tx.commit()?;
        drop(db);
        // secure_delete applies to database pages; checkpoint clears obsolete WAL
        // frames. Backups/SSDs still require encrypted storage and backup expiry.
        self.db()?
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        Ok(
            json!({"events_deleted":events,"raw_evidence_deleted":raw,"open_incident_evidence":"retained; still counts against quota"}),
        )
    }
    pub fn report(&self, period: &str, now: Instant) -> Result<Value> {
        let days = match period {
            "daily" => 1,
            "weekly" => 7,
            _ => bail!("report period must be daily or weekly"),
        };
        let since = now.minus(Duration::from_secs(days * 86400)).to_rfc3339();
        let mut counts: Vec<Value> = {
            let db = self.db()?;
            let mut q=db.prepare("SELECT rule_id,severity,status,COUNT(*),SUM(suppressed) FROM alerts WHERE detected_at>=?1 AND detected_at<?2 GROUP BY rule_id,severity,status ORDER BY severity,rule_id")?;
            q.query_map(params![since,now.to_rfc3339()],|r|Ok(json!({"rule":r.get::<_,String>(0)?,"severity":r.get::<_,String>(1)?,"status":r.get::<_,String>(2)?,"count":r.get::<_,i64>(3)?,"suppressed":r.get::<_,i64>(4)?})))?.collect::<rusqlite::Result<_>>()?
        };
        let definitions = crate::rules::registry();
        for row in &mut counts {
            if let Some(rule) = definitions
                .iter()
                .find(|r| row["rule"].as_str() == Some(r.id.as_str()))
            {
                row["name"] = json!(rule.name);
            }
        }
        let actions: Vec<(String, i64)> = {
            let db = self.db()?;
            let mut q=db.prepare("SELECT action,COUNT(*) FROM alert_history WHERE at>=?1 AND action IN ('ACKNOWLEDGED','INVESTIGATING','RESOLVED') GROUP BY action")?;
            q.query_map([&since], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?
        };
        let action_text = if actions.is_empty() {
            "No analyst status changes were recorded during this period.".to_owned()
        } else {
            actions
                .into_iter()
                .map(|(state, n)| format!("{n} incident update(s): {}", state.to_lowercase()))
                .collect::<Vec<_>>()
                .join("; ")
        };
        let open: i64 = self.db()?.query_row(
            "SELECT COUNT(*) FROM alerts WHERE status!='RESOLVED' AND suppressed=0",
            [],
            |r| r.get(0),
        )?;
        let failures:i64=self.db()?.query_row("SELECT COUNT(*) FROM collection_runs WHERE started_at>=?1 AND status NOT IN ('ok','ok_with_warnings')",[&since],|r|r.get(0))?;
        let changes: i64 = self.db()?.query_row(
            "SELECT COUNT(*) FROM configuration_changes WHERE at>=?1",
            [&since],
            |r| r.get(0),
        )?;
        let mut coverage = vec![];
        for c in self.capabilities()? {
            coverage.push(json!({"source":c.source,"state":c.state,"limitation":c.licence_note,"last_probe":c.checked_at}));
        }
        let body = json!({"period":period,"from":since,"until":now.to_rfc3339(),"what_changed":format!("{changes} configuration changes were recorded."),"potentially_dangerous":counts,"action_taken":format!("{action_text} Junction makes no automatic security changes."),"still_needs_attention":format!("{open} unsuppressed incidents remain open; {failures} collection runs need review."),"not_monitored":coverage,"important":"No alerts does not prove safety. Missing sources, delays, unsupported events and an offline host can hide activity.","privacy":"This report omits account names, addresses, document names and raw evidence."});
        Ok(body)
    }
    pub fn scheduled_reports(&self, now: Instant) -> Result<()> {
        for (period, days) in [("daily", 1), ("weekly", 7)] {
            let bucket = now.0.div_euclid(days * 86_400_000);
            let id = format!("{period}:{bucket}");
            let exists: bool = self.db()?.query_row(
                "SELECT EXISTS(SELECT 1 FROM reports WHERE id=?1)",
                [&id],
                |r| r.get(0),
            )?;
            if !exists {
                let report = self.report(period, now)?;
                self.db()?.execute("INSERT OR IGNORE INTO reports(id,period,generated_at,body) VALUES(?1,?2,?3,?4)",params![id,period,now.to_rfc3339(),report.to_string()])?;
            }
        }
        Ok(())
    }
    pub fn reports(&self) -> Result<Vec<Value>> {
        let db = self.db()?;
        let mut q = db.prepare("SELECT body FROM reports ORDER BY generated_at DESC LIMIT 30")?;
        let values: Vec<String> = q
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        values
            .into_iter()
            .map(|s| serde_json::from_str(&s).map_err(Into::into))
            .collect()
    }
}

/// Check actual totals inside the write transaction. Duplicate input consumes no
/// extra quota and concurrent writers cannot both overrun the configured limit.
pub(crate) fn enforce_budget(db: &rusqlite::Transaction<'_>) -> Result<()> {
    use rusqlite::OptionalExtension;
    let text: Option<String> = db
        .query_row(
            "SELECT value FROM meta WHERE key='operational_settings'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let s: Settings = text
        .map(|v| serde_json::from_str(&v))
        .transpose()?
        .unwrap_or_default();
    let events: u64 = db.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
    let bytes: u64 = db.query_row(
        "SELECT COALESCE(SUM(length(ciphertext)),0) FROM evidence",
        [],
        |r| r.get(0),
    )?;
    if events > s.max_events || bytes > s.max_evidence_bytes {
        bail!("storage quota exceeded; transaction rolled back and checkpoint retained");
    }
    Ok(())
}

impl Store {
    /// Re-notify unresolved critical incidents once daily after successful handoff.
    /// Failed handoffs remain in the ordinary retry queue and never disappear.
    pub fn escalate(&self, now: Instant) -> Result<usize> {
        let cutoff = now.minus(Duration::from_secs(86400)).to_rfc3339();
        let ids: Vec<String> = {
            let db = self.db()?;
            let mut q=db.prepare("SELECT a.id FROM alerts a JOIN notification_outbox n ON n.id=a.id WHERE a.severity='CRITICAL' AND a.status!='RESOLVED' AND a.suppressed=0 AND n.delivered_at<?1 LIMIT 100")?;
            q.query_map([cutoff], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?
        };
        for id in &ids {
            self.audit("scheduler", "critical_alert_escalated", id, "{}")?;
            let mut db = self.db()?;
            let tx = db.transaction()?;
            tx.execute(
                "UPDATE notification_outbox SET delivered_at=NULL,next_attempt=?1 WHERE id=?2",
                params![now.to_rfc3339(), id],
            )?;
            tx.execute("INSERT INTO alert_history(alert_id,at,actor,action,note) VALUES(?1,?2,'scheduler','escalated','Unresolved critical incident: independent email reminder queued')",params![id,now.to_rfc3339()])?;
            tx.commit()?;
        }
        Ok(ids.len())
    }
}
