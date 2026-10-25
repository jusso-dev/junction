//! Approved complete snapshots only. Partial/failed collections are retained for
//! health, never compared. Missing fields are unknown, not disabled/deleted.
use crate::{
    clock::Instant,
    event::{SecurityEvent, event_id, sha256_hex},
    store::Store,
};
use anyhow::{Result, bail};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub tenant_id: String,
    pub resource_type: String,
    pub collected_at: String,
    pub source_api: String,
    pub status: String,
    pub resources: BTreeMap<String, Value>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Change {
    pub resource_id: String,
    pub kind: String,
    pub properties: BTreeMap<String, Value>,
    #[serde(default)]
    pub effective_configuration: Option<Value>,
}
/// Arrays are sets for configuration snapshots. Object keys are canonicalised.
pub fn canonical(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            Value::Object(m.iter().map(|(k, v)| (k.clone(), canonical(v))).collect())
        }
        Value::Array(a) => {
            let mut a: Vec<_> = a.iter().map(canonical).collect();
            a.sort_by_key(Value::to_string);
            a.dedup();
            Value::Array(a)
        }
        _ => v.clone(),
    }
}
pub fn diff(
    old: &BTreeMap<String, Value>,
    new: &BTreeMap<String, Value>,
    confirm_deletions: bool,
) -> Vec<Change> {
    let mut changes = vec![];
    for (id, v) in new {
        match old.get(id) {
            None => changes.push(Change {
                resource_id: id.clone(),
                kind: "created".into(),
                effective_configuration: Some(v.clone()),
                properties: v
                    .as_object()
                    .map(|m| {
                        m.iter()
                            .map(|(k, v)| (k.clone(), json!({"new":v})))
                            .collect()
                    })
                    .unwrap_or_default(),
            }),
            Some(previous) => {
                let mut props = BTreeMap::new();
                if let (Some(a), Some(b)) = (previous.as_object(), v.as_object()) {
                    for (k, new) in b {
                        if let Some(old) = a.get(k)
                            && !new.is_null()
                            && !old.is_null()
                            && canonical(old) != canonical(new)
                        {
                            props.insert(k.clone(), json!({"old":old,"new":new}));
                        }
                    }
                }
                if !props.is_empty() {
                    changes.push(Change {
                        resource_id: id.clone(),
                        kind: "modified".into(),
                        effective_configuration: Some(v.clone()),
                        properties: props,
                    });
                }
            }
        }
    }
    if confirm_deletions {
        for id in old.keys() {
            if !new.contains_key(id) {
                changes.push(Change {
                    resource_id: id.clone(),
                    kind: "deleted".into(),
                    effective_configuration: None,
                    properties: BTreeMap::new(),
                });
            }
        }
    }
    changes
}
const TYPES: &[&str] = &[
    "mailboxes",
    "inbox_rules",
    "delegation",
    "transport_rules",
    "accepted_domains",
    "remote_domains",
    "anti_spam",
    "audit_configuration",
    "audit_bypass",
    "sharepoint_settings",
];
impl Snapshot {
    pub fn validate(&self, tenant: &str) -> Result<()> {
        if !self.tenant_id.eq_ignore_ascii_case(tenant)
            || !TYPES.contains(&self.resource_type.as_str())
        {
            bail!("snapshot tenant or resource type mismatch");
        }
        if !["exchange_online_powershell", "graph:sharepointSettings"]
            .contains(&self.source_api.as_str())
            || !["complete", "partial", "failed"].contains(&self.status.as_str())
        {
            bail!("invalid snapshot source/status");
        }
        let at = Instant::parse(&self.collected_at)?;
        if at > Instant::now().plus(std::time::Duration::from_secs(300)) {
            bail!("snapshot timestamp is in the future");
        }
        if self.resources.len() > 100_000
            || serde_json::to_vec(&self.resources)?.len() > 16 * 1024 * 1024
        {
            bail!("snapshot exceeds collection budget");
        }
        let allowed: &[&str] = match self.resource_type.as_str() {
            "mailboxes" => &[
                "forwardingsmtpaddress",
                "forwardingaddress",
                "grantsendonbehalfto",
                "auditenabled",
                "auditadmin",
                "auditdelegate",
                "auditowner",
            ],
            "inbox_rules" => &[
                "enabled",
                "forwardto",
                "redirectto",
                "forwardasattachmentto",
                "deletemessage",
                "movetofolder",
                "markasread",
                "stopprocessingrules",
            ],
            "delegation" => &["accessrights", "user"],
            "transport_rules" => &[
                "state",
                "mode",
                "redirectmessageto",
                "deletemessage",
                "blindcopyto",
                "addtorecipients",
                "setheadername",
            ],
            "accepted_domains" => &["domainname", "domaintype"],
            "remote_domains" => &["domainname", "autoforwardenabled"],
            "anti_spam" => &["autoforwardingmode", "bccsuspiciousoutboundmail"],
            "audit_configuration" => &["auditdisabled", "unifiedauditlogingestionenabled"],
            "audit_bypass" => &["auditbypassenabled"],
            "sharepoint_settings" => &[
                "sharingcapability",
                "defaultsharinglinktype",
                "defaultlinkpermission",
                "isanonymouslinkexpirationrequired",
                "anonymouslinkexpirationindays",
                "sharingdomainrestrictionmode",
                "sharingalloweddomainlist",
                "sharingblockeddomainlist",
            ],
            _ => &[],
        };
        for (id, value) in &self.resources {
            if value.as_object().is_some_and(|m| {
                m.keys()
                    .any(|k| !allowed.contains(&k.to_ascii_lowercase().as_str()))
            }) {
                bail!("snapshot contains unsupported configuration fields");
            }
            if id.is_empty() || id.len() > 2048 || !value.is_object() {
                bail!("invalid snapshot resource");
            }
        }
        Ok(())
    }
}
impl Store {
    pub fn import_snapshot(&self, snapshot: &Snapshot) -> Result<(String, Vec<Change>)> {
        snapshot.validate(self.tenant_id())?;
        let payload = serde_json::to_string(&canonical(&serde_json::to_value(snapshot)?))?;
        let hash = sha256_hex(
            serde_json::to_string(&canonical(&serde_json::to_value(&snapshot.resources)?))?
                .as_bytes(),
        );
        let id = event_id(
            self.tenant_id(),
            "snapshot",
            &sha256_hex(payload.as_bytes()),
        );
        let mut db = self.db()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM snapshot_sets WHERE id=?1)",
            [&id],
            |r| r.get(0),
        )?;
        if exists {
            tx.commit()?;
            drop(db);
            self.reconcile_snapshot_events()?;
            return Ok((id, vec![]));
        }

        let old:Option<String>=tx.query_row("SELECT COALESCE(effective_payload,payload) FROM snapshot_sets WHERE resource_type=?1 AND approved=1 ORDER BY collected_at DESC LIMIT 1",[&snapshot.resource_type],|r|r.get(0)).optional()?;
        let previous:Option<String>=tx.query_row("SELECT payload FROM snapshot_sets WHERE resource_type=?1 AND status='complete' ORDER BY collected_at DESC LIMIT 1",[&snapshot.resource_type],|r|r.get(0)).optional()?;
        if let Some(ref old) = old {
            let old: Snapshot = serde_json::from_str(old)?;
            if Instant::parse(&snapshot.collected_at)? <= Instant::parse(&old.collected_at)? {
                bail!("snapshot must be newer than approved baseline");
            }
        }
        let baseline = old
            .as_deref()
            .map(serde_json::from_str::<Snapshot>)
            .transpose()?;
        let prior = previous
            .as_deref()
            .map(serde_json::from_str::<Snapshot>)
            .transpose()?;
        // Keep observed payload/hash immutable. Unknown fields cannot erase the
        // last-known comparison state. Missing resources still use two observations.
        let mut effective = snapshot.clone();
        if let Some(baseline) = &baseline {
            for (id, value) in &mut effective.resources {
                if let (Some(old), Some(new)) = (
                    baseline.resources.get(id).and_then(Value::as_object),
                    value.as_object_mut(),
                ) {
                    for (key, known) in old {
                        if new.get(key).is_none_or(Value::is_null) {
                            new.insert(key.clone(), known.clone());
                        }
                    }
                }
            }
        }
        // Carry each unconfirmed missing resource forward independently. This lets
        // observed modifications advance without replaying while deletion waits.
        if let Some(baseline) = &baseline {
            for (id, value) in &baseline.resources {
                if !snapshot.resources.contains_key(id)
                    && !prior
                        .as_ref()
                        .is_some_and(|p| !p.resources.contains_key(id))
                {
                    effective.resources.insert(id.clone(), value.clone());
                }
            }
        }
        let at = Instant::parse(&snapshot.collected_at)?.to_rfc3339();
        effective.collected_at = at.clone();
        let effective_payload = serde_json::to_string(&effective)?;
        let complete = snapshot.status == "complete";
        let changes = if complete {
            baseline
                .as_ref()
                .map(|b| diff(&b.resources, &effective.resources, true))
                .unwrap_or_default()
        } else {
            vec![]
        };
        let added=tx.execute("INSERT OR IGNORE INTO snapshot_sets(id,resource_type,collected_at,source_api,status,approved,payload,hash,effective_payload) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![id,snapshot.resource_type,Instant::parse(&snapshot.collected_at)?.to_rfc3339(),snapshot.source_api,snapshot.status,complete&&baseline.is_some(),payload,hash,effective_payload])?;
        if added == 0 {
            return Ok((id, vec![]));
        }
        for change in &changes {
            let detail = serde_json::to_string(change)?;
            let change_id = event_id(self.tenant_id(), &id, &change.resource_id);
            tx.execute("INSERT INTO configuration_changes(id,snapshot_id,resource_type,resource_id,kind,at,detail) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![change_id,id,snapshot.resource_type,change.resource_id,change.kind,at,detail])?;
        }
        tx.commit()?;
        drop(db);
        // If interrupted before event insertion, retry regenerates events from stored
        // changes through reconcile_snapshot_events, called each daemon pass.
        self.put_capability(&crate::store::CapabilityRecord {
            source:format!("snapshot:{}",snapshot.resource_type),
            state:if complete && baseline.is_some(){crate::capability::CapabilityState::AvailableWithLimitations}else{crate::capability::CapabilityState::Unknown},
            reason:if complete{crate::capability::Reason::Ok}else{crate::capability::Reason::Unclassified},
            http_status:None,error_code:None,detail:Some(if baseline.is_none(){"Awaiting approved initial baseline"}else if !complete{"Partial snapshot; previous baseline preserved"}else{"Complete configuration export; scope depends on runner roles"}.into()),
            required_permission:if snapshot.source_api=="graph:sharepointSettings"{"SharePointTenantSettings.Read.All"}else{"Exchange.ManageAsApp plus scoped read-only Exchange roles"}.into(),
            licence_note:"Actual successful configuration collection required. Missing cmdlets and fields remain coverage gaps.".into(),
            docs_url:"https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2".into(),checked_at:at,
        })?;
        self.reconcile_snapshot_events()?;
        Ok((id, changes))
    }
    pub fn approve_baseline(&self, id: &str, actor: &str) -> Result<()> {
        let kind: Option<String> = self
            .db()?
            .query_row(
                "SELECT resource_type FROM snapshot_sets WHERE id=?1 AND status='complete'",
                [id],
                |r| r.get(0),
            )
            .optional()?;
        let Some(kind) = kind else {
            bail!("complete snapshot not found")
        };
        self.audit(
            actor,
            "baseline_approved",
            id,
            &json!({"resource_type":kind}).to_string(),
        )?;
        self.db()?
            .execute("UPDATE snapshot_sets SET approved=1 WHERE id=?1", [id])?;
        Ok(())
    }
    pub fn snapshots(&self) -> Result<Vec<Value>> {
        let db = self.db()?;
        let mut q=db.prepare("SELECT id,resource_type,collected_at,status,approved,hash FROM snapshot_sets ORDER BY collected_at DESC LIMIT 100")?;
        Ok(q.query_map([],|r|Ok(json!({"id":r.get::<_,String>(0)?,"resource_type":r.get::<_,String>(1)?,"collected_at":r.get::<_,String>(2)?,"status":r.get::<_,String>(3)?,"approved":r.get::<_,bool>(4)?,"hash":r.get::<_,String>(5)?})))?.collect::<rusqlite::Result<_>>()?)
    }
    pub fn changes(&self, before: Option<&str>) -> Result<Vec<Value>> {
        let db = self.db()?;
        let mut q=db.prepare("SELECT id,resource_type,resource_id,kind,at,detail FROM configuration_changes WHERE (?1 IS NULL OR at||'|'||id<?1) ORDER BY at DESC,id DESC LIMIT 100")?;
        Ok(q.query_map([before],|r|Ok(json!({"id":r.get::<_,String>(0)?,"resource_type":r.get::<_,String>(1)?,"resource_id":r.get::<_,String>(2)?,"kind":r.get::<_,String>(3)?,"at":r.get::<_,String>(4)?,"detail":r.get::<_,String>(5)?})))?.collect::<rusqlite::Result<_>>()?)
    }
    pub fn reconcile_snapshot_events(&self) -> Result<()> {
        let rows: Vec<(String, String, String, String)> = {
            let db = self.db()?;
            let mut q=db.prepare("SELECT c.id,c.resource_type,c.at,c.detail FROM configuration_changes c WHERE NOT EXISTS(SELECT 1 FROM events e WHERE e.source_event_id=c.id AND e.source LIKE 'snapshot:%') ORDER BY c.at LIMIT 500")?;
            q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                .collect::<rusqlite::Result<_>>()?
        };
        for (id, kind, at, detail) in rows {
            let change: Change = serde_json::from_str(&detail)?;
            let source = if kind == "sharepoint_settings" {
                "snapshot:sharepoint"
            } else {
                "snapshot:exchange"
            };
            let operation = match kind.as_str() {
                "mailboxes" => "Set-Mailbox",
                "inbox_rules" => "Set-InboxRule",
                "transport_rules" => "Set-TransportRule",
                "audit_configuration" => "Set-OrganizationConfig",
                "audit_bypass" => "Set-MailboxAuditBypassAssociation",
                "delegation"
                    if change.properties.get("AccessRights").is_some_and(|v| {
                        v["new"].to_string().to_lowercase().contains("sendas")
                    }) =>
                {
                    "Add-RecipientPermission"
                }
                "delegation" => "Add-MailboxPermission",
                "sharepoint_settings" => "SharingPolicyChanged",
                _ => "ConfigurationChanged",
            };
            // Activating an existing inbox rule enables all its retained actions.
            // ModifiedProperties still records only the fields actually changed.
            let activated = kind == "inbox_rules"
                && change
                    .properties
                    .iter()
                    .any(|(k, v)| k.eq_ignore_ascii_case("enabled") && v["new"] == true);
            let parameters: Vec<_> = if activated {
                change
                    .effective_configuration
                    .as_ref()
                    .and_then(Value::as_object)
                    .into_iter()
                    .flat_map(|m| m.iter())
                    .map(|(k, v)| json!({"Name":k,"Value":v}))
                    .collect()
            } else if change.kind == "deleted" {
                vec![]
            } else {
                change
                    .properties
                    .iter()
                    .map(|(k, v)| json!({"Name":k,"Value":v.get("new")}))
                    .collect()
            };
            let modified: Vec<_> = change
                .properties
                .iter()
                .map(|(k, v)| json!({"Name":k,"OldValue":v.get("old"),"NewValue":v.get("new")}))
                .collect();
            let raw = json!({"ModifiedProperties":modified,"Id":id,"CreationTime":at,"Operation":operation,"ResultStatus":"Success","ObjectId":change.resource_id,"Parameters":parameters});
            let mut e: SecurityEvent = crate::event::from_management_record(
                self.tenant_id(),
                "configuration",
                &raw,
                Instant::now(),
            )
            .ok_or_else(|| anyhow::anyhow!("invalid snapshot event"))?;
            e.source = source.into();
            e.id = event_id(self.tenant_id(), source, &id);
            e.metadata.insert("ChangeKind".into(), json!(change.kind));
            self.insert_events(&[e])?;
        }
        Ok(())
    }
}

pub fn read_snapshot(path: &std::path::Path) -> Result<Snapshot> {
    use std::io::Read;
    let file =
        std::fs::File::open(path).map_err(|_| anyhow::anyhow!("snapshot file unavailable"))?;
    let mut bytes = vec![];
    file.take(16 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 16 * 1024 * 1024 {
        bail!("snapshot file too large");
    }
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("snapshot format invalid"))
}
pub fn import_directory(store: &Store, directory: &std::path::Path) -> Result<()> {
    for kind in TYPES {
        let path = directory.join(format!("{kind}.json"));
        if !path.exists() {
            continue;
        }
        match read_snapshot(&path).and_then(|s| store.import_snapshot(&s)) {
            Ok(_) => {}
            Err(_) => {
                store
                    .audit("collector", "snapshot_import_failed", kind, "{}")
                    .ok();
            }
        }
    }
    Ok(())
}
async fn collect_sharepoint_inner(
    up: &impl crate::upstream::Upstream,
    store: &Store,
) -> Result<serde_json::Value> {
    if !store
        .capability("graph:sharepointSettings")?
        .is_some_and(|c| c.state.usable())
    {
        return Ok(json!({"status":"skipped"}));
    }
    let reply = crate::backoff::Backoff::default()
        .run(|| {
            up.get(
                crate::upstream::Api::Graph,
                crate::probe::graph_url(up, "/v1.0/admin/sharepoint/settings", &[]),
            )
        })
        .await?;
    let mut props = serde_json::Map::new();
    for key in [
        "sharingCapability",
        "defaultSharingLinkType",
        "defaultLinkPermission",
        "isAnonymousLinkExpirationRequired",
        "anonymousLinkExpirationInDays",
        "sharingDomainRestrictionMode",
        "sharingAllowedDomainList",
        "sharingBlockedDomainList",
    ] {
        if let Some(v) = reply.body.get(key) {
            props.insert(key.into(), v.clone());
        }
    }
    let status = if props.contains_key("sharingCapability") {
        "complete"
    } else {
        "partial"
    };
    let snapshot = Snapshot {
        tenant_id: store.tenant_id().into(),
        resource_type: "sharepoint_settings".into(),
        collected_at: Instant::now().to_rfc3339(),
        source_api: "graph:sharepointSettings".into(),
        status: status.into(),
        resources: BTreeMap::from([("tenant".into(), Value::Object(props))]),
    };
    let (id, changes) = store.import_snapshot(&snapshot)?;
    Ok(json!({"id":id,"status":status,"changes":changes.len()}))
}

pub async fn collect_sharepoint(
    up: &impl crate::upstream::Upstream,
    store: &Store,
) -> Result<Value> {
    if !store
        .capability("graph:sharepointSettings")?
        .is_some_and(|c| c.state.usable())
    {
        return Ok(json!({"status":"skipped"}));
    }
    let run = store.start_run("graph:sharepointSettings")?;
    let result = collect_sharepoint_inner(up, store).await;
    let error = result
        .as_ref()
        .err()
        .map(|_| "SharePoint configuration collection failed; previous baseline preserved");
    let status = match &result {
        Ok(v) if v["status"] == "complete" => "ok",
        Ok(_) => "partial",
        Err(_) => "failed",
    };
    store.finish_run(
        run,
        &crate::store::RunSummary {
            status,
            window: None,
            content_blobs: 0,
            counts: Default::default(),
            max_delay_seconds: None,
            rejected_entries: 0,
            unparseable_records: 0,
            quarantined_blobs: 0,
            error,
        },
    )?;
    match result {
        Ok(v) => Ok(v),
        Err(_) => Ok(json!({"status":"failed","error":error})),
    }
}

impl Store {
    pub fn snapshot(&self, id: &str) -> Result<Option<Snapshot>> {
        let payload: Option<String> = self
            .db()?
            .query_row("SELECT payload FROM snapshot_sets WHERE id=?1", [id], |r| {
                r.get(0)
            })
            .optional()?;
        payload
            .map(|s| serde_json::from_str(&s).map_err(Into::into))
            .transpose()
    }
}
