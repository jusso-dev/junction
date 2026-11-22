//! A small, justified set of Defender XDR records.
//!
//! Only two Graph security resources are archived, both opt-in:
//!
//! - `graph:alerts_v2`: the unified alert record across Defender for
//!   Endpoint, Office 365, Identity, Cloud Apps and Entra ID Protection. It is
//!   the primary evidence of what was detected, when, how severe it was and how
//!   it was classified.
//! - `graph:incidents`: the correlated investigation record (classification,
//!   determination, assignment, resolution), which assessors and incident
//!   reviewers ask for.
//!
//! Both are windowed on `lastUpdateDateTime`, and each update is archived as a
//! new version (`id@lastUpdateDateTime`), so status and resolution changes are
//! kept rather than lost to deduplication.
//!
//! Not collected: advanced hunting tables (high volume, better kept in
//! Sentinel or Defender), Defender for Cloud Apps activity (Bower owns it), and
//! machine inventory or vulnerabilities (posture, covered by `junction check`).
//!
//! Alert evidence is reduced to an allow-list of entity fields. Process command
//! lines, file paths, registry values, analyst comments and long vendor text
//! are dropped. Incidents keep the resolving comment, which is part of the
//! investigation record, bounded and stripped of control characters.
use crate::{collect::GraphSpec, record::ArchiveRecord};
use junction_watch::{
    clock::Instant,
    event::{SecurityEvent, clean, event_id, normalise_ip, sanitise, sha256_hex},
};
use serde_json::{Map, Value};

pub const SOURCES: &[GraphSpec] = &[
    GraphSpec {
        source: "graph:alerts_v2",
        path: "/v1.0/security/alerts_v2",
        time_field: "lastUpdateDateTime",
        page_size: "500",
        versioned: true,
    },
    GraphSpec {
        source: "graph:incidents",
        path: "/v1.0/security/incidents",
        time_field: "lastUpdateDateTime",
        page_size: "50",
        versioned: true,
    },
];

/// Top-level alert fields kept. `description` and `recommendedActions` are
/// long vendor text, and `comments` can hold analyst notes about people.
const ALERT_FIELDS: &[&str] = &[
    "id",
    "providerAlertId",
    "incidentId",
    "status",
    "severity",
    "classification",
    "determination",
    "serviceSource",
    "detectionSource",
    "detectorId",
    "tenantId",
    "title",
    "category",
    "assignedTo",
    "alertWebUrl",
    "incidentWebUrl",
    "threatDisplayName",
    "threatFamilyName",
    "mitreTechniques",
    "createdDateTime",
    "lastUpdateDateTime",
    "resolvedDateTime",
    "firstActivityDateTime",
    "lastActivityDateTime",
    "systemTags",
];

const INCIDENT_FIELDS: &[&str] = &[
    "id",
    "tenantId",
    "status",
    "severity",
    "classification",
    "determination",
    "displayName",
    "incidentWebUrl",
    "redirectIncidentId",
    "assignedTo",
    "customTags",
    "systemTags",
    "createdDateTime",
    "lastUpdateDateTime",
    "lastModifiedBy",
    "resolvingComment",
    "priorityScore",
];

/// Evidence entity fields kept: what the entity was and what happened to it,
/// with stable identifiers for correlation. Command lines, paths, registry
/// values, logged-on users and IP lists are dropped.
const EVIDENCE_FIELDS: &[&str] = &[
    "@odata.type",
    "createdDateTime",
    "verdict",
    "remediationStatus",
    "roles",
    "mdeDeviceId",
    "azureAdDeviceId",
    "deviceDnsName",
    "osPlatform",
    "onboardingStatus",
    "ipAddress",
    "url",
    "networkMessageId",
    "senderIp",
];

const MAX_EVIDENCE: usize = 50;

fn keep(raw: &Value, fields: &[&str]) -> Map<String, Value> {
    let mut out = Map::new();
    for f in fields {
        if let Some(v) = raw.get(*f) {
            out.insert((*f).to_owned(), sanitise(v));
        }
    }
    out
}

fn reduce_evidence(item: &Value) -> Value {
    let mut out = keep(item, EVIDENCE_FIELDS);
    // Identify accounts by Entra object id and UPN only.
    if let Some(account) = item.get("userAccount") {
        let mut a = Map::new();
        for f in ["azureAdUserId", "userPrincipalName"] {
            if let Some(v) = account.get(f) {
                a.insert(f.to_owned(), sanitise(v));
            }
        }
        if !a.is_empty() {
            out.insert("userAccount".into(), Value::Object(a));
        }
    }
    // Files by hash and name only; never the path.
    for key in ["fileDetails", "imageFile"] {
        if let Some(file) = item.get(key) {
            let mut f = Map::new();
            for field in ["sha1", "sha256", "fileName"] {
                if let Some(v) = file.get(field) {
                    f.insert(field.to_owned(), sanitise(v));
                }
            }
            if !f.is_empty() {
                out.insert(key.to_owned(), Value::Object(f));
            }
        }
    }
    Value::Object(out)
}

/// The allow-listed form of an alert or incident that is archived.
pub fn reduce(source: &str, raw: &Value) -> Value {
    if source == "graph:incidents" {
        return Value::Object(keep(raw, INCIDENT_FIELDS));
    }
    let mut out = keep(raw, ALERT_FIELDS);
    if let Some(evidence) = raw.get("evidence").and_then(Value::as_array) {
        out.insert(
            "evidence".into(),
            Value::Array(
                evidence
                    .iter()
                    .take(MAX_EVIDENCE)
                    .map(reduce_evidence)
                    .collect(),
            ),
        );
        if evidence.len() > MAX_EVIDENCE {
            out.insert("evidenceTruncated".into(), Value::from(evidence.len()));
        }
    }
    Value::Object(out)
}

/// Normalise one alert or incident. Returns None for malformed records or
/// records naming another tenant.
pub fn record(tenant: &str, spec: &GraphSpec, raw: &Value, now: Instant) -> Option<ArchiveRecord> {
    if raw
        .get("tenantId")
        .and_then(Value::as_str)
        .is_some_and(|t| !t.eq_ignore_ascii_case(tenant))
    {
        return None;
    }
    let id = raw.get("id")?.as_str()?;
    if id.is_empty() || id.len() > 256 || id.chars().any(char::is_control) {
        return None;
    }
    let updated = Instant::parse(raw.get("lastUpdateDateTime")?.as_str()?).ok()?;
    let created = raw
        .get("createdDateTime")
        .and_then(Value::as_str)
        .and_then(|t| Instant::parse(t).ok())
        .unwrap_or(updated);
    let incident = spec.source == "graph:incidents";
    let text = |k: &str, n: usize| raw.get(k).and_then(Value::as_str).map(|s| clean(s, n));
    let operation = if incident {
        format!(
            "Incident:{}",
            text("status", 64).unwrap_or_else(|| "unknown".into())
        )
    } else {
        format!(
            "Alert:{}",
            text("category", 64).unwrap_or_else(|| "Uncategorised".into())
        )
    };
    // The account named in evidence, if any, is the actor for search.
    let actor_upn = raw
        .get("evidence")
        .and_then(Value::as_array)
        .and_then(|e| {
            e.iter()
                .find_map(|i| i.pointer("/userAccount/userPrincipalName")?.as_str())
        })
        .map(|u| clean(u, 256).to_lowercase());
    let ip_address = raw
        .get("evidence")
        .and_then(Value::as_array)
        .and_then(|e| e.iter().find_map(|i| i.get("ipAddress")?.as_str()))
        .and_then(normalise_ip);
    let mut metadata = Map::new();
    for k in [
        "severity",
        "serviceSource",
        "classification",
        "determination",
    ] {
        if let Some(v) = raw.get(k) {
            metadata.insert(k.into(), sanitise(v));
        }
    }
    let event = SecurityEvent {
        id: event_id(tenant, spec.source, id),
        tenant_id: tenant.to_owned(),
        source: spec.source.to_owned(),
        source_event_id: id.to_owned(),
        event_type: if incident { "incident" } else { "alert" }.into(),
        // Alerts and incidents are placed in the archive by when they were
        // raised, so every version of one alert lands in the same partition
        // range as its first detection.
        timestamp: created.to_rfc3339(),
        ingested_at: now.to_rfc3339(),
        actor_id: None,
        actor_upn,
        target_id: text("incidentId", 64),
        target_type: None,
        operation,
        result: text("severity", 32),
        ip_address,
        user_agent: None,
        correlation_id: text(if incident { "id" } else { "incidentId" }, 64),
        metadata,
        raw_sha256: sha256_hex(&serde_json::to_vec(raw).ok()?),
        raw_evidence_reference: None,
    };
    Some(ArchiveRecord::from_reduced(
        &event,
        raw,
        reduce(spec.source, raw),
        &updated.to_rfc3339(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    const T: &str = "11111111-1111-4111-8111-111111111111";

    fn alert(updated: &str) -> Value {
        json!({
            "id": "da-alert-1", "incidentId": "42", "tenantId": T,
            "status": "new", "severity": "high", "category": "CredentialAccess",
            "serviceSource": "microsoftDefenderForEndpoint",
            "description": "long vendor text", "recommendedActions": "steps",
            "comments": [{"comment": "analyst note about a person"}],
            "mitreTechniques": ["T1003"],
            "createdDateTime": "2026-11-20T01:00:00Z", "lastUpdateDateTime": updated,
            "evidence": [
                {"@odata.type": "#microsoft.graph.security.processEvidence",
                 "processCommandLine": "secret.exe --password hunter2",
                 "imageFile": {"fileName": "secret.exe", "filePath": "C:\\Users\\a\\secret.exe", "sha256": "ab"},
                 "userAccount": {"accountName": "a", "userPrincipalName": "Person@Example.Test", "userSid": "S-1"}},
                {"@odata.type": "#microsoft.graph.security.ipEvidence", "ipAddress": "203.0.113.7"}
            ]
        })
    }

    #[test]
    fn alerts_are_reduced_and_versioned() {
        let spec = &SOURCES[0];
        let now = Instant::parse("2026-11-22T00:00:00Z").unwrap();
        let v1 = record(T, spec, &alert("2026-11-20T02:00:00Z"), now).unwrap();
        let v2 = record(T, spec, &alert("2026-11-21T02:00:00Z"), now).unwrap();
        assert_ne!(v1.record_id, v2.record_id, "each update is a new version");
        assert_eq!(
            v1.event_time, v2.event_time,
            "versions share the detection time"
        );
        assert!(v1.raw_reduced);
        let kept = serde_json::to_string(&v1.raw).unwrap();
        for dropped in [
            "hunter2",
            "filePath",
            "secret.exe --password",
            "analyst note",
            "long vendor text",
            "S-1",
        ] {
            assert!(
                !kept.contains(dropped),
                "{dropped} must not be archived: {kept}"
            );
        }
        assert!(kept.contains("T1003") && kept.contains("\"sha256\":\"ab\""));
        assert_eq!(v1.actor_upn.as_deref(), Some("person@example.test"));
        assert_eq!(v1.ip_address.as_deref(), Some("203.0.113.7"));
        assert_eq!(v1.operation, "Alert:CredentialAccess");
        assert_eq!(
            v1.raw_sha256.len(),
            64,
            "the full record's hash is kept for integrity"
        );
    }

    #[test]
    fn foreign_and_malformed_records_are_rejected() {
        let spec = &SOURCES[0];
        let now = Instant::parse("2026-11-22T00:00:00Z").unwrap();
        let mut foreign = alert("2026-11-20T02:00:00Z");
        foreign["tenantId"] = json!("22222222-2222-4222-8222-222222222222");
        assert!(record(T, spec, &foreign, now).is_none());
        let mut no_update = alert("x");
        no_update["lastUpdateDateTime"] = json!(null);
        assert!(record(T, spec, &no_update, now).is_none());
    }

    #[test]
    fn incidents_keep_the_investigation_record_only() {
        let raw = json!({"id": "42", "tenantId": T, "status": "resolved", "severity": "high",
            "classification": "truePositive", "displayName": "Multi-stage incident",
            "resolvingComment": "free text", "comments": [{"comment": "x"}], "summary": "s",
            "createdDateTime": "2026-11-20T01:00:00Z", "lastUpdateDateTime": "2026-11-21T01:00:00Z"});
        let r = record(
            T,
            &SOURCES[1],
            &raw,
            Instant::parse("2026-11-22T00:00:00Z").unwrap(),
        )
        .unwrap();
        assert_eq!(r.operation, "Incident:resolved");
        assert!(r.raw.get("comments").is_none() && r.raw.get("summary").is_none());
        assert_eq!(r.raw["resolvingComment"], "free text");
        assert_eq!(r.raw["classification"], "truePositive");
    }
}
