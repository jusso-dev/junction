//! Durable, tenant-bound incident workflow and idempotent detection processing.
use crate::{
    clock::Instant,
    event::{SecurityEvent, event_id},
    rules::{self, Finding, RuleSettings},
    store::{EventQuery, Store},
};
use anyhow::{Result, bail};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub(crate) const MIGRATION: &str = r#"
CREATE INDEX events_source_time ON events(source,timestamp,id);
CREATE INDEX events_target_time ON events(target_id,timestamp);
CREATE INDEX events_site_time ON events(json_extract(metadata,'$.SiteUrl'),timestamp);
CREATE TABLE seen_external_domains(domain TEXT PRIMARY KEY, first_event_id TEXT NOT NULL);
CREATE TABLE detection_deferred(event_id TEXT PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE, retry_at TEXT NOT NULL);
CREATE TABLE detection_processed(event_id TEXT PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE, version INTEGER NOT NULL);
CREATE TABLE alerts(id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, resource TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL, disposition TEXT, assigned_to TEXT, detected_at TEXT NOT NULL, updated_at TEXT NOT NULL, finding TEXT NOT NULL, suppressed INTEGER NOT NULL DEFAULT 0);
CREATE INDEX alerts_time ON alerts(detected_at,id);
CREATE INDEX alerts_state ON alerts(status,severity);
CREATE TABLE alert_history(id INTEGER PRIMARY KEY, alert_id TEXT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE, at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, note TEXT NOT NULL);
CREATE TABLE notification_outbox(id TEXT PRIMARY KEY REFERENCES alerts(id) ON DELETE CASCADE, attempts INTEGER NOT NULL DEFAULT 0, next_attempt TEXT NOT NULL, delivered_at TEXT, last_error TEXT);
CREATE TABLE suppressions(id INTEGER PRIMARY KEY, rule_id TEXT NOT NULL, resource TEXT NOT NULL, starts_at TEXT NOT NULL, ends_at TEXT NOT NULL, reason TEXT NOT NULL, actor TEXT NOT NULL);
CREATE TABLE snapshot_sets(id TEXT PRIMARY KEY, resource_type TEXT NOT NULL, collected_at TEXT NOT NULL, source_api TEXT NOT NULL, status TEXT NOT NULL, approved INTEGER NOT NULL DEFAULT 0, payload TEXT NOT NULL, hash TEXT NOT NULL, effective_payload TEXT);
CREATE INDEX snapshot_sets_latest ON snapshot_sets(resource_type,collected_at);
CREATE TABLE configuration_changes(id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL REFERENCES snapshot_sets(id), resource_type TEXT NOT NULL, resource_id TEXT NOT NULL, kind TEXT NOT NULL, at TEXT NOT NULL, detail TEXT NOT NULL);
CREATE TABLE evidence(event_id TEXT PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE, key_id TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, sha256 TEXT NOT NULL);
CREATE TABLE reports(id TEXT PRIMARY KEY, period TEXT NOT NULL, generated_at TEXT NOT NULL, body TEXT NOT NULL);
"#;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub rule_id: String,
    pub resource: String,
    pub severity: String,
    pub status: String,
    pub disposition: Option<String>,
    pub assigned_to: Option<String>,
    pub detected_at: String,
    pub updated_at: String,
    pub finding: Finding,
    pub suppressed: bool,
}

impl Store {
    pub fn alert(&self, id: &str) -> Result<Option<Alert>> {
        let db = self.db()?;
        Ok(db.query_row("SELECT id,rule_id,resource,severity,status,disposition,assigned_to,detected_at,updated_at,finding,suppressed FROM alerts WHERE id=?1",[id],row_alert).optional()?)
    }
    pub fn alerts(
        &self,
        status: Option<&str>,
        severity: Option<&str>,
        before: Option<&str>,
        limit: u32,
    ) -> Result<Vec<Alert>> {
        self.search_alerts(status, severity, before, None, limit)
    }
    pub fn search_alerts(
        &self,
        status: Option<&str>,
        severity: Option<&str>,
        before: Option<&str>,
        query: Option<&str>,
        limit: u32,
    ) -> Result<Vec<Alert>> {
        let db = self.db()?;
        let mut stmt=db.prepare("SELECT id,rule_id,resource,severity,status,disposition,assigned_to,detected_at,updated_at,finding,suppressed FROM alerts WHERE (?1 IS NULL OR status=?1) AND (?2 IS NULL OR severity=?2) AND (?3 IS NULL OR detected_at||'|'||id < ?3) AND (?5 IS NULL OR instr(lower(resource||' '||rule_id),lower(?5))>0) ORDER BY detected_at DESC,id DESC LIMIT ?4")?;
        Ok(stmt
            .query_map(
                params![status, severity, before, limit.clamp(1, 500), query],
                row_alert,
            )?
            .collect::<rusqlite::Result<_>>()?)
    }
    pub fn event(&self, id: &str) -> Result<Option<SecurityEvent>> {
        Ok(self.db()?.query_row("SELECT id,tenant_id,source,source_event_id,event_type,timestamp,ingested_at,actor_id,actor_upn,target_id,target_type,operation,result,ip_address,user_agent,correlation_id,metadata,raw_sha256,raw_evidence_reference FROM events WHERE id=?1 AND tenant_id=?2",params![id,self.tenant_id()],crate::store::row_to_event).optional()?)
    }
    pub fn pending_detection_events(&self) -> Result<Vec<SecurityEvent>> {
        let db = self.db()?;
        let mut stmt=db.prepare("SELECT id,tenant_id,source,source_event_id,event_type,timestamp,ingested_at,actor_id,actor_upn,target_id,target_type,operation,result,ip_address,user_agent,correlation_id,metadata,raw_sha256,raw_evidence_reference FROM events WHERE tenant_id=?1 AND id NOT IN (SELECT event_id FROM detection_processed) AND id NOT IN (SELECT event_id FROM detection_deferred WHERE retry_at>?2) ORDER BY timestamp,id LIMIT 500")?;
        Ok(stmt
            .query_map(
                params![self.tenant_id(), Instant::now().to_rfc3339()],
                crate::store::row_to_event,
            )?
            .collect::<rusqlite::Result<_>>()?)
    }
    pub fn save_findings(&self, e: &SecurityEvent, findings: &[Finding]) -> Result<usize> {
        self.save_evaluation(e, findings, false)
    }
    fn save_evaluation(
        &self,
        e: &SecurityEvent,
        findings: &[Finding],
        deferred: bool,
    ) -> Result<usize> {
        if e.tenant_id != self.tenant_id() {
            bail!("event tenant mismatch");
        }
        let mut db = self.db()?;
        let tx = db.transaction()?;
        let mut added = 0;
        for f in findings {
            if f.rule_id == "M365-SPO-002"
                && let Some(domain) = e
                    .metadata
                    .get("TargetUserOrGroupName")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|s| s.rsplit_once('@'))
                    .map(|(_, d)| d.trim_matches(['>', ' ']).to_ascii_lowercase())
            {
                tx.execute("INSERT OR IGNORE INTO seen_external_domains(domain,first_event_id) VALUES(?1,?2)",params![domain,e.id])?;
                let first: String = tx.query_row(
                    "SELECT first_event_id FROM seen_external_domains WHERE domain=?1",
                    [domain],
                    |r| r.get(0),
                )?;
                if first != e.id {
                    continue;
                }
            }
            let key =
                if ["M365-SPO-003", "M365-SPO-005", "M365-SPO-007"].contains(&f.rule_id.as_str()) {
                    format!(
                        "{}|{}|{}",
                        e.actor_upn.as_deref().unwrap_or(""),
                        e.metadata
                            .get("SiteUrl")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or(""),
                        Instant::parse(&e.timestamp)?.0.div_euclid(3_600_000)
                    )
                } else if f.rule_id == "M365-EXO-006" {
                    let mut ids = f.evidence.clone();
                    ids.sort();
                    ids.dedup();
                    ids.join("|")
                } else {
                    e.id.clone()
                };
            let id = event_id(self.tenant_id(), &f.rule_id, &key);
            let suppressed:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM suppressions WHERE (rule_id=?1 OR rule_id='*') AND (resource=?2 OR resource='*') AND starts_at<=?3 AND ends_at>?3)",params![f.rule_id,f.resource,e.timestamp],|r|r.get(0))?;
            let at = Instant::now().to_rfc3339();
            let changed=tx.execute("INSERT OR IGNORE INTO alerts(id,rule_id,resource,severity,status,detected_at,updated_at,finding,suppressed) VALUES(?1,?2,?3,?4,'NEW',?5,?5,?6,?7)",params![id,f.rule_id,f.resource,f.severity,at,serde_json::to_string(f)?,suppressed])?;
            if changed == 0 {
                let existing: String =
                    tx.query_row("SELECT finding FROM alerts WHERE id=?1", [&id], |r| {
                        r.get(0)
                    })?;
                let mut grouped: Finding = serde_json::from_str(&existing)?;
                grouped.evidence.extend(f.evidence.iter().cloned());
                grouped.evidence.sort();
                grouped.evidence.dedup();
                tx.execute(
                    "UPDATE alerts SET finding=?1 WHERE id=?2",
                    params![serde_json::to_string(&grouped)?, id],
                )?;
            }
            if changed > 0 {
                added += 1;
                tx.execute("INSERT INTO alert_history(alert_id,at,actor,action,note) VALUES(?1,?2,'detector','created',?3)",params![id,at,if suppressed{"Approved suppression matched"}else{"Rule version 1"}])?;
                if !suppressed && ["HIGH", "CRITICAL"].contains(&f.severity.as_str()) {
                    tx.execute(
                        "INSERT OR IGNORE INTO notification_outbox(id,next_attempt) VALUES(?1,?2)",
                        params![id, at],
                    )?;
                }
            }
        }
        if deferred {
            tx.execute("INSERT INTO detection_deferred(event_id,retry_at) VALUES(?1,?2) ON CONFLICT(event_id) DO UPDATE SET retry_at=excluded.retry_at",params![e.id,Instant::now().plus(Duration::from_secs(3600)).to_rfc3339()])?;
        } else {
            tx.execute(
                "INSERT OR IGNORE INTO detection_processed(event_id,version) VALUES(?1,1)",
                [&e.id],
            )?;
            tx.execute("DELETE FROM detection_deferred WHERE event_id=?1", [&e.id])?;
        }
        tx.commit()?;
        Ok(added)
    }
    pub fn transition_alert(
        &self,
        id: &str,
        status: &str,
        disposition: Option<&str>,
        assignee: Option<&str>,
        note: &str,
        actor: &str,
    ) -> Result<()> {
        if note.len() > 4096 || assignee.is_some_and(|a| a.len() > 128) || actor.len() > 128 {
            bail!("incident input too long");
        }
        if !["NEW", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED"].contains(&status) {
            bail!("invalid incident status");
        }
        if disposition
            .is_some_and(|d| !["false_positive", "accepted_risk", "remediated"].contains(&d))
        {
            bail!("invalid disposition");
        }
        if status == "RESOLVED" && (disposition.is_none() || note.trim().is_empty()) {
            bail!("resolution needs a disposition and note");
        }
        let old = self
            .alert(id)?
            .ok_or_else(|| anyhow::anyhow!("alert not found"))?;
        let valid = old.status == status
            || matches!(
                (old.status.as_str(), status),
                ("NEW", "ACKNOWLEDGED")
                    | ("ACKNOWLEDGED", "INVESTIGATING")
                    | ("INVESTIGATING", "RESOLVED")
                    | ("RESOLVED", "INVESTIGATING")
            );
        if !valid {
            bail!("invalid incident transition");
        }
        // Audit intent before mutation: failures remain visible and no successful
        // mutation can omit an audit entry. Transaction records the final history.
        self.audit(
            actor,
            "alert_transition",
            id,
            &serde_json::json!({"from":old.status,"to":status,"disposition":disposition})
                .to_string(),
        )?;
        let mut db = self.db()?;
        let tx = db.transaction()?;
        let at = Instant::now().to_rfc3339();
        let n=tx.execute("UPDATE alerts SET status=?1,disposition=?2,assigned_to=?3,updated_at=?4 WHERE id=?5 AND updated_at=?6",params![status,if status=="RESOLVED"{disposition}else{None},assignee,at,id,old.updated_at])?;
        if n != 1 {
            bail!("incident changed concurrently; reload");
        }
        tx.execute(
            "INSERT INTO alert_history(alert_id,at,actor,action,note) VALUES(?1,?2,?3,?4,?5)",
            params![id, at, actor, status, crate::event::clean(note, 4096)],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn alert_history(&self, id: &str) -> Result<Vec<serde_json::Value>> {
        let db = self.db()?;
        let mut stmt=db.prepare("SELECT at,actor,action,note FROM alert_history WHERE alert_id=?1 ORDER BY id DESC LIMIT 500")?;
        Ok(stmt.query_map([id],|r|Ok(serde_json::json!({"at":r.get::<_,String>(0)?,"actor":r.get::<_,String>(1)?,"action":r.get::<_,String>(2)?,"note":r.get::<_,String>(3)?})))?.collect::<rusqlite::Result<_>>()?)
    }
    pub fn suppress(
        &self,
        rule: &str,
        resource: &str,
        start: Instant,
        end: Instant,
        reason: &str,
        actor: &str,
    ) -> Result<()> {
        if rule != "*" && !rules::registry().iter().any(|r| r.id == rule) {
            bail!("unknown rule");
        }
        if end <= start
            || end.0 - start.0 > 30 * 86_400_000
            || reason.trim().is_empty()
            || reason.len() > 1024
            || resource.is_empty()
            || resource.len() > 2048
        {
            bail!("invalid suppression (maximum 30 days, reason required)");
        }
        self.audit(actor,"suppression",rule,&serde_json::json!({"resource":resource,"start":start.to_rfc3339(),"end":end.to_rfc3339(),"reason":reason}).to_string())?;
        self.db()?.execute("INSERT INTO suppressions(rule_id,resource,starts_at,ends_at,reason,actor) VALUES(?1,?2,?3,?4,?5,?6)",params![rule,resource,start.to_rfc3339(),end.to_rfc3339(),reason,actor])?;
        Ok(())
    }
}
fn row_alert(r: &rusqlite::Row<'_>) -> rusqlite::Result<Alert> {
    let text: String = r.get(9)?;
    let finding = serde_json::from_str(&text).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(9, rusqlite::types::Type::Text, Box::new(e))
    })?;
    Ok(Alert {
        id: r.get(0)?,
        rule_id: r.get(1)?,
        resource: r.get(2)?,
        severity: r.get(3)?,
        status: r.get(4)?,
        disposition: r.get(5)?,
        assigned_to: r.get(6)?,
        detected_at: r.get(7)?,
        updated_at: r.get(8)?,
        finding,
        suppressed: r.get(10)?,
    })
}

pub fn detect(store: &Store, settings: &RuleSettings) -> Result<usize> {
    detect_with_budget(store, settings, 50_000)
}
fn history_query(e: &SecurityEvent, now: Instant) -> Option<EventQuery> {
    let mut q = EventQuery {
        limit: 500,
        ..Default::default()
    };
    if e.source == "o365:Audit.SharePoint"
        && e.actor_upn.is_some()
        && e.metadata
            .get("SiteUrl")
            .and_then(serde_json::Value::as_str)
            .is_some()
        && [
            "FileDownloaded",
            "FileDeleted",
            "FileRecycled",
            "AnonymousLinkCreated",
            "SharingInvitationCreated",
            "SiteCollectionAdminAdded",
        ]
        .contains(&e.operation.as_str())
    {
        q.source = Some(e.source.clone());
        q.actor = e.actor_upn.clone();
        q.site = e
            .metadata
            .get("SiteUrl")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        q.since = Some(now.minus(Duration::from_secs(7 * 86400)).to_rfc3339());
        q.until = Some(now.plus(Duration::from_millis(1)).to_rfc3339());
    } else if ["o365:Audit.Exchange", "snapshot:exchange"].contains(&e.source.as_str())
        && ["New-InboxRule", "Set-InboxRule", "UpdateInboxRules"].contains(&e.operation.as_str())
        && e.target_id.is_some()
    {
        q.source = Some(
            if e.source == "snapshot:exchange" {
                "o365:Audit.Exchange"
            } else {
                "snapshot:exchange"
            }
            .into(),
        );
        q.target = e.target_id.clone();
        q.since = Some(now.minus(Duration::from_secs(3600)).to_rfc3339());
        q.until = Some(now.plus(Duration::from_secs(3600)).to_rfc3339());
    } else {
        return None;
    }
    Some(q)
}
fn detect_with_budget(store: &Store, settings: &RuleSettings, budget: usize) -> Result<usize> {
    let events = store.pending_detection_events()?;
    let mut added = 0;
    for e in events {
        let now = Instant::parse(&e.timestamp)?;
        let mut history = Vec::new();
        let mut deferred = false;
        if let Some(mut query) = history_query(&e, now) {
            loop {
                let page = store.events(&query)?;
                let n = page.len();
                if let Some(last) = page.last() {
                    query.before = Some((last.timestamp.clone(), last.id.clone()));
                }
                history.extend(page);
                if history.len() > budget {
                    deferred = true;
                    history.clear(); // Never evaluate volume/correlation against truncated evidence.
                    store.record_gap("detection:history",now,now.plus(Duration::from_millis(1)),"History evaluation budget exceeded; dependent rules deferred for retry. Single-event detections continue.")?;
                    break;
                }
                if n < 500 {
                    break;
                }
            }
        }
        let mut findings = rules::evaluate(&e, &history, settings);
        let gaps: Vec<String> = store
            .capabilities()?
            .into_iter()
            .filter(|c| !c.state.usable())
            .map(|c| format!("{}: {}", c.source, c.state.as_str()))
            .collect();
        for finding in &mut findings {
            finding.coverage_limitations.extend(gaps.iter().cloned());
            if deferred {
                finding.coverage_limitations.push(
                    "History-dependent evaluation deferred because its budget was exceeded.".into(),
                );
            }
        }
        added += store.save_evaluation(&e, &findings, deferred)?;
    }
    Ok(added)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[tokio::test]
    async fn oversized_history_defers_only_dependent_rules_and_outbox_progresses() {
        let tenant = "11111111-1111-4111-8111-111111111111";
        let store = Store::in_memory(tenant).unwrap();
        let make =
            |id: &str, operation: &str, source: &str| {
                crate::event::from_management_record(tenant, source, &json!({
                "Id":id,"CreationTime":"2026-10-20T00:00:00Z","Operation":operation,
                "UserId":"user@club.example","SiteUrl":"https://club.example/board",
                "ObjectId":"resource","ResultStatus":"Success",
                "Parameters":[{"Name":"ForwardingSmtpAddress","Value":"evil@outside.example"}]
            }),Instant::now()).unwrap()
            };
        for i in 0..3 {
            let e = make(
                &format!("history-{i}"),
                "FileDownloaded",
                "Audit.SharePoint",
            );
            store.insert_events(std::slice::from_ref(&e)).unwrap();
            store.save_findings(&e, &[]).unwrap();
        }
        let overloaded = make("overloaded", "AnonymousLinkCreated", "Audit.SharePoint");
        let critical = make("critical", "Set-Mailbox", "Audit.Exchange");
        store
            .insert_events(&[overloaded.clone(), critical])
            .unwrap();
        assert_eq!(
            detect_with_budget(&store, &Default::default(), 2).unwrap(),
            2
        );
        assert!(
            store
                .gaps()
                .unwrap()
                .iter()
                .any(|g| g.collector == "detection:history")
        );
        assert!(store.pending_detection_events().unwrap().is_empty());
        assert_eq!(
            store
                .db()
                .unwrap()
                .query_row("SELECT COUNT(*) FROM detection_deferred", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            detect_with_budget(&store, &Default::default(), 2).unwrap(),
            0
        );
        let config = crate::notify::NotificationConfig {
            external_email: Some("security@independent.example".into()),
            from_email: Some("monitor@host.example".into()),
            independent_destination_confirmed: true,
        };
        let delivery = crate::notify::deliver_with(
            &store,
            &config,
            &["club.example".into()],
            Instant::now().plus(Duration::from_secs(1)),
            |_| async { Ok(()) },
        )
        .await
        .unwrap();
        assert_eq!(delivery["accepted"], 2);
        // Retry remains durable and can finish once the full scope fits its budget.
        store
            .db()
            .unwrap()
            .execute(
                "UPDATE detection_deferred SET retry_at='2000-01-01T00:00:00.000Z'",
                [],
            )
            .unwrap();
        assert_eq!(
            detect_with_budget(&store, &Default::default(), 10).unwrap(),
            0
        );
        assert_eq!(
            store
                .db()
                .unwrap()
                .query_row("SELECT COUNT(*) FROM detection_deferred", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    #[test]
    fn single_event_rules_never_request_tenant_wide_history() {
        let e=crate::event::from_management_record("11111111-1111-4111-8111-111111111111","Audit.Exchange",&json!({"Id":"x","CreationTime":"2026-10-20T00:00:00Z","Operation":"Set-Mailbox","ResultStatus":"Success"}),Instant::now()).unwrap();
        assert!(history_query(&e, Instant::now()).is_none());
        let mut snapshot = e;
        snapshot.source = "snapshot:exchange".into();
        assert!(history_query(&snapshot, Instant::now()).is_none());
    }
    #[tokio::test]
    async fn sixty_thousand_unrelated_events_do_not_block_snapshot_alert_delivery() {
        let tenant = "11111111-1111-4111-8111-111111111111";
        let store = Store::in_memory(tenant).unwrap();
        let mut seed=crate::event::from_management_record(tenant,"Audit.Exchange",&json!({"Id":"seed","CreationTime":"2026-10-20T00:00:00Z","Operation":"Unrelated","ResultStatus":"Success"}),Instant::now()).unwrap();
        seed.source = "graph:signIns".into();
        let events: Vec<_> = (0..60_000)
            .map(|n| {
                let mut e = seed.clone();
                e.source_event_id = n.to_string();
                e.id = event_id(tenant, &e.source, &e.source_event_id);
                e
            })
            .collect();
        store.insert_events(&events).unwrap();
        store
            .db()
            .unwrap()
            .execute(
                "INSERT INTO detection_processed(event_id,version) SELECT id,1 FROM events",
                [],
            )
            .unwrap();
        let mut snapshot=crate::event::from_management_record(tenant,"configuration",&json!({"Id":"snapshot","CreationTime":"2026-10-20T01:00:00Z","Operation":"Set-Mailbox","ObjectId":"mailbox","ResultStatus":"Success","Parameters":[{"Name":"ForwardingSmtpAddress","Value":"evil@outside.example"}]}),Instant::now()).unwrap();
        snapshot.source = "snapshot:exchange".into();
        snapshot.id = event_id(tenant, &snapshot.source, &snapshot.source_event_id);
        store.insert_events(&[snapshot]).unwrap();
        assert_eq!(detect(&store, &Default::default()).unwrap(), 1);
        let config = crate::notify::NotificationConfig {
            external_email: Some("security@independent.example".into()),
            from_email: Some("monitor@host.example".into()),
            independent_destination_confirmed: true,
        };
        let sent = crate::notify::deliver_with(
            &store,
            &config,
            &[],
            Instant::now().plus(Duration::from_secs(1)),
            |_| async { Ok(()) },
        )
        .await
        .unwrap();
        assert_eq!(sent["accepted"], 1);
    }
}
