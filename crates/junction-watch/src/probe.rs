//! Capability discovery by live, read-only probes.
//!
//! Each probe is a single bounded GET. Subscriptions are only *listed* here;
//! starting one is a separate, explicit operator action ([`start_subscriptions`]).
use crate::{
    capability::{CapabilityState, Reason, classify},
    catalog::{self, CONTENT_TYPES, SourceSpec},
    clock::Instant,
    store::{CapabilityRecord, Store},
    upstream::{Api, CallError, Reply, Upstream},
};
use anyhow::Result;
use serde::Serialize;
use serde_json::{Value, json};
use std::{collections::BTreeMap, time::Duration};
use url::Url;

pub fn graph_url(up: &impl Upstream, path: &str, query: &[(&str, &str)]) -> Url {
    let mut url = up.base(Api::Graph);
    url.set_path(path);
    if !query.is_empty() {
        url.query_pairs_mut().extend_pairs(query);
    }
    url
}

/// `https://manage.office.com/api/v1.0/{tenant}/activity/feed/{tail}` with the
/// publisher identifier set, so requests use this tenant's own quota.
pub fn feed_url(up: &impl Upstream, tail: &[&str], query: &[(&str, &str)]) -> Url {
    let mut url = up.base(Api::ManagementActivity);
    {
        let mut segments = url.path_segments_mut().expect("https base URL");
        segments.clear();
        segments.extend(["api", "v1.0", up.tenant_id(), "activity", "feed"]);
        segments.extend(tail);
    }
    url.query_pairs_mut()
        .extend_pairs(query)
        .append_pair("PublisherIdentifier", up.tenant_id());
    url
}

#[derive(Debug, Serialize)]
pub struct ProbeReport {
    pub tenant_id: String,
    pub checked_at: String,
    pub granted_graph_roles: Vec<String>,
    pub granted_management_roles: Vec<String>,
    pub capabilities: Vec<CapabilityRecord>,
    pub verified_domains: Vec<String>,
    pub subscriptions: Vec<SkuSummary>,
    pub runnable_detections: Vec<String>,
    pub blocked_detections: Vec<String>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct SkuSummary {
    pub sku_part_number: String,
    pub capability_status: String,
    pub service_plans: Vec<String>,
}

fn record(
    spec: &SourceSpec,
    reason: Reason,
    error: Option<&CallError>,
    detail: Option<String>,
) -> CapabilityRecord {
    CapabilityRecord {
        source: spec.id.to_owned(),
        state: reason.state(),
        reason,
        http_status: error
            .and_then(|e| e.status)
            .or_else(|| (reason == Reason::Ok).then_some(200)),
        error_code: error.and_then(|e| e.code.clone()),
        detail: detail.or_else(|| error.and_then(|e| e.message.clone())),
        required_permission: spec.permission.to_owned(),
        licence_note: spec.licence_note.to_owned(),
        docs_url: spec.docs_url.to_owned(),
        checked_at: Instant::now().to_rfc3339(),
    }
}

fn spec(id: &str) -> &'static SourceSpec {
    catalog::source(id).expect("catalogued source")
}

/// Probe every source and persist the results.
pub async fn probe_all(up: &impl Upstream, store: &Store) -> Result<ProbeReport> {
    let graph_roles = up.granted_roles(Api::Graph).await;
    let mgmt_roles = up.granted_roles(Api::ManagementActivity).await;
    let has = |roles: &Result<Vec<String>, CallError>, name: &str| -> Option<bool> {
        roles.as_ref().ok().map(|r| r.iter().any(|x| x == name))
    };
    let mut records = vec![];
    let mut domains = vec![];
    let mut skus = vec![];

    // Organisation and verified domains.
    let org = spec("graph:organization");
    match up
        .get(
            Api::Graph,
            graph_url(
                up,
                "/v1.0/organization",
                &[("$select", "id,displayName,verifiedDomains")],
            ),
        )
        .await
    {
        Ok(reply) => {
            domains = verified_domains(&reply.body);
            store.put_meta("verified_domains", &serde_json::to_string(&domains)?)?;
            records.push(record(
                org,
                Reason::Ok,
                None,
                Some(format!("{} verified domain(s)", domains.len())),
            ));
        }
        Err(e) => records.push(record(
            org,
            classify(&e, has(&graph_roles, org.permission)),
            Some(&e),
            None,
        )),
    }

    // Subscriptions: context only, never used to decide capability.
    let sku = spec("graph:subscribedSkus");
    match up
        .get(
            Api::Graph,
            graph_url(
                up,
                "/v1.0/subscribedSkus",
                &[("$select", "skuPartNumber,capabilityStatus,servicePlans")],
            ),
        )
        .await
    {
        Ok(reply) => {
            skus = sku_summaries(&reply.body);
            store.put_meta("subscribed_skus", &serde_json::to_string(&skus)?)?;
            records.push(record(
                sku,
                Reason::Ok,
                None,
                Some(format!("{} subscription(s)", skus.len())),
            ));
        }
        Err(e) => records.push(record(
            sku,
            classify(&e, has(&graph_roles, sku.permission)),
            Some(&e),
            None,
        )),
    }

    // Directory audits: available on Free, retention varies by Entra edition.
    let da = spec("graph:directoryAudits");
    match up
        .get(
            Api::Graph,
            graph_url(up, "/v1.0/auditLogs/directoryAudits", &[("$top", "1")]),
        )
        .await
    {
        Ok(_) => {
            let mut r = record(da, Reason::Ok, None, Some("Retention is 7 days on Entra ID Free, 30 days on P1/P2; collected every run so retention does not limit coverage while collection keeps up.".into()));
            r.state = CapabilityState::AvailableWithLimitations;
            records.push(r);
        }
        Err(e) => records.push(record(
            da,
            classify(&e, has(&graph_roles, da.permission)),
            Some(&e),
            None,
        )),
    }

    // Sign-ins: premium-dependent. A licence failure here disables M365-ID-007 only.
    let si = spec("graph:signIns");
    let since = Instant::now()
        .minus(Duration::from_secs(3600))
        .to_api_seconds()
        + "Z";
    let filter = format!("createdDateTime ge {since}");
    match up
        .get(
            Api::Graph,
            graph_url(
                up,
                "/v1.0/auditLogs/signIns",
                &[("$top", "1"), ("$filter", &filter)],
            ),
        )
        .await
    {
        Ok(_) => records.push(record(si, Reason::Ok, None, None)),
        Err(e) => records.push(record(
            si,
            classify(&e, has(&graph_roles, si.permission)),
            Some(&e),
            None,
        )),
    }

    let sp = spec("graph:sharepointSettings");
    match up
        .get(
            Api::Graph,
            graph_url(up, "/v1.0/admin/sharepoint/settings", &[]),
        )
        .await
    {
        Ok(reply) => {
            store.put_meta(
                "sharepoint_settings_probe",
                &sharing_summary(&reply.body).to_string(),
            )?;
            records.push(record(sp, Reason::Ok, None, None));
        }
        Err(e) => records.push(record(
            sp,
            classify(&e, has(&graph_roles, sp.permission)),
            Some(&e),
            None,
        )),
    }

    // Management Activity API: list subscriptions, then sample each enabled feed.
    let mgmt_has = has(&mgmt_roles, "ActivityFeed.Read");
    match up
        .get(
            Api::ManagementActivity,
            feed_url(up, &["subscriptions", "list"], &[]),
        )
        .await
    {
        Err(e) => {
            let reason = classify(&e, mgmt_has);
            for ct in CONTENT_TYPES {
                records.push(record(spec(&format!("o365:{ct}")), reason, Some(&e), None));
            }
        }
        Ok(reply) => {
            let statuses = subscription_statuses(&reply);
            for ct in CONTENT_TYPES {
                let s = spec(&format!("o365:{ct}"));
                let rec = match statuses.get(ct).map(String::as_str) {
                    None => record(s, Reason::SubscriptionNotStarted, None, None),
                    Some(status) if !status.eq_ignore_ascii_case("enabled") => record(
                        s,
                        Reason::SubscriptionDisabled,
                        None,
                        Some(format!("subscription status: {status}")),
                    ),
                    Some(_) => {
                        let end = Instant::now();
                        let start = end.minus(Duration::from_secs(3600));
                        let url = feed_url(
                            up,
                            &["subscriptions", "content"],
                            &[
                                ("contentType", ct),
                                ("startTime", &start.to_api_seconds()),
                                ("endTime", &end.to_api_seconds()),
                            ],
                        );
                        match up.get(Api::ManagementActivity, url).await {
                            Ok(_) => record(s, Reason::Ok, None, None),
                            Err(e) => record(s, classify(&e, mgmt_has), Some(&e), None),
                        }
                    }
                };
                records.push(rec);
            }
        }
    }

    for r in &records {
        store.put_capability(r)?;
    }
    store.put_meta("last_probe_at", &Instant::now().to_rfc3339())?;
    let (runnable, blocked) = detection_coverage(&records);
    Ok(ProbeReport {
        tenant_id: up.tenant_id().to_owned(),
        checked_at: Instant::now().to_rfc3339(),
        granted_graph_roles: graph_roles.unwrap_or_default(),
        granted_management_roles: mgmt_roles.unwrap_or_default(),
        capabilities: records,
        verified_domains: domains,
        subscriptions: skus,
        runnable_detections: runnable,
        blocked_detections: blocked,
    })
}

/// Re-probe when the last probe is older than a day, so settled-negative sources
/// are re-tested even if nobody presses Re-test. Returns None when not due.
pub async fn probe_if_due(up: &impl Upstream, store: &Store) -> Option<Result<ProbeReport>> {
    let due = store
        .meta("last_probe_at")
        .ok()
        .flatten()
        .and_then(|t| Instant::parse(&t).ok())
        .is_none_or(|t| Instant::now().since(t) > Duration::from_secs(86_400));
    if due {
        Some(probe_all(up, store).await)
    } else {
        None
    }
}

/// A detection has data if at least one *collected* source that feeds it is
/// usable. Probe-only and enrichment sources never count, so coverage is not
/// claimed for telemetry this release does not ingest. Returns (with data, without).
pub fn detection_coverage(records: &[CapabilityRecord]) -> (Vec<String>, Vec<String>) {
    let mut status: BTreeMap<&str, bool> = BTreeMap::new();
    for s in catalog::SOURCES {
        let usable = s.collected && records.iter().any(|r| r.source == s.id && r.state.usable());
        for d in s.detections {
            *status.entry(d).or_default() |= usable;
        }
    }
    // Audit/configuration correlation needs both independent inputs, not either.
    let snapshot_ready = records
        .iter()
        .any(|r| r.source == "snapshot:inbox_rules" && r.state.usable());
    if let Some(ready) = status.get_mut("M365-EXO-006") {
        *ready &= snapshot_ready;
    }
    // The sharing-settings probe alone is not a comparison baseline.
    let sharing_audit = records
        .iter()
        .any(|r| r.source == "o365:Audit.SharePoint" && r.state.usable());
    let sharing_snapshot = records
        .iter()
        .any(|r| r.source == "snapshot:sharepoint_settings" && r.state.usable());
    status.insert("M365-SPO-006", sharing_audit || sharing_snapshot);
    let runnable = status
        .iter()
        .filter(|(_, ok)| **ok)
        .map(|(d, _)| d.to_string())
        .collect();
    let blocked = status
        .iter()
        .filter(|(_, ok)| !**ok)
        .map(|(d, _)| d.to_string())
        .collect();
    (runnable, blocked)
}

/// Start feed subscriptions. This is the only write the watchdog makes to a
/// tenant: it enables delivery of audit data already being recorded and changes
/// no tenant configuration. Microsoft asks for 15 minutes between start requests.
pub async fn start_subscriptions(
    up: &impl Upstream,
    store: &Store,
    actor: &str,
    content_types: &[&str],
) -> Result<Vec<(String, Result<(), String>)>> {
    let mut out = vec![];
    for ct in content_types {
        if !CONTENT_TYPES.contains(ct) {
            out.push((ct.to_string(), Err("unsupported content type".into())));
            continue;
        }
        let key = format!("subscription_start_attempt:{ct}");
        if let Some(last) = store.meta(&key)?.and_then(|v| Instant::parse(&v).ok())
            && Instant::now().since(last) < Duration::from_secs(15 * 60)
        {
            out.push((
                ct.to_string(),
                Err("started less than 15 minutes ago; wait before retrying".into()),
            ));
            continue;
        }
        store.put_meta(&key, &Instant::now().to_rfc3339())?;
        let url = feed_url(up, &["subscriptions", "start"], &[("contentType", ct)]);
        let result = up.post(Api::ManagementActivity, url, None).await;
        let summary = match &result {
            Ok(_) => "ok".to_owned(),
            Err(e) => e.summary(),
        };
        store.audit(
            actor,
            "start_subscription",
            ct,
            &json!({"result": summary}).to_string(),
        )?;
        if result.is_ok() {
            // Collection may resume immediately; otherwise the stale "not started"
            // state would keep the collector skipping this feed until a re-probe.
            store.put_capability(&record(
                spec(&format!("o365:{ct}")),
                Reason::Ok,
                None,
                Some("Subscription started. Microsoft can take up to 12 hours to deliver the first content.".into()),
            ))?;
        }
        out.push((ct.to_string(), result.map(|_| ()).map_err(|e| e.summary())));
    }
    Ok(out)
}

fn subscription_statuses(reply: &Reply) -> BTreeMap<String, String> {
    reply
        .body
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|i| {
                    Some((
                        i.get("contentType")?.as_str()?.to_owned(),
                        i.get("status")?.as_str()?.to_owned(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn verified_domains(body: &Value) -> Vec<String> {
    let mut out: Vec<String> = body
        .get("value")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|org| {
            org.get("verifiedDomains")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter_map(|d| d.get("name").and_then(Value::as_str))
        .filter(|d| {
            d.len() <= 253
                && d.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        })
        .map(str::to_ascii_lowercase)
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Summarise `subscribedSkus`: enabled service plans per SKU. Shared with
/// `junction-check` licence detection.
pub fn sku_summaries(body: &Value) -> Vec<SkuSummary> {
    body.get("value")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(100)
        .map(|s| SkuSummary {
            sku_part_number: crate::event::clean(
                s.get("skuPartNumber")
                    .and_then(Value::as_str)
                    .unwrap_or("?"),
                128,
            ),
            capability_status: crate::event::clean(
                s.get("capabilityStatus")
                    .and_then(Value::as_str)
                    .unwrap_or("?"),
                32,
            ),
            service_plans: s
                .get("servicePlans")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(|p| p.get("provisioningStatus").and_then(Value::as_str) == Some("Success"))
                .filter_map(|p| p.get("servicePlanName").and_then(Value::as_str))
                .take(200)
                .map(|n| crate::event::clean(n, 128))
                .collect(),
        })
        .collect()
}

fn sharing_summary(body: &Value) -> Value {
    json!({
        "sharingCapability": body.get("sharingCapability"),
        "sharingDomainRestrictionMode": body.get("sharingDomainRestrictionMode"),
        "isResharingByExternalUsersEnabled": body.get("isResharingByExternalUsersEnabled"),
    })
}
