//! Common event schema and normalisers.
//!
//! Audit content is attacker-influenced (inbox rule names, file names, display
//! names). It is treated as inert data: bounded, stripped of control characters,
//! never interpreted, and rendered only through auto-escaping templates.
use crate::clock::Instant;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityEvent {
    pub id: String,
    pub tenant_id: String,
    pub source: String,
    pub source_event_id: String,
    pub event_type: String,
    pub timestamp: String,
    pub ingested_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_upn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_type: Option<String>,
    pub operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    pub metadata: Map<String, Value>,
    /// SHA-256 of the raw record as received, for evidence integrity.
    pub raw_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_evidence_reference: Option<String>,
}

/// Stable event ID: same tenant, source and upstream ID always map to one row.
pub fn event_id(tenant_id: &str, source: &str, source_event_id: &str) -> String {
    let mut h = Sha256::new();
    for part in [tenant_id, source, source_event_id] {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part.as_bytes());
    }
    hex(&h.finalize()[..16])
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

const MAX_STRING: usize = 2048;
const MAX_ARRAY: usize = 200;
const MAX_DEPTH: usize = 8;
const MAX_KEYS: usize = 200;

/// Bound and clean an untrusted JSON value.
pub fn sanitise(value: &Value) -> Value {
    sanitise_at(value, 0)
}
fn sanitise_at(value: &Value, depth: usize) -> Value {
    if depth > MAX_DEPTH {
        return Value::String("[truncated]".into());
    }
    match value {
        Value::String(s) => Value::String(clean(s, MAX_STRING)),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .take(MAX_ARRAY)
                .map(|v| sanitise_at(v, depth + 1))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .take(MAX_KEYS)
                .map(|(k, v)| (clean(k, 128), sanitise_at(v, depth + 1)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Strip control characters (including bidi overrides) and bound length.
pub fn clean(value: &str, max_chars: usize) -> String {
    value
        .chars()
        .filter(|c| {
            !c.is_control() && !matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .take(max_chars)
        .collect()
}

fn text(record: &Value, key: &str, max: usize) -> Option<String> {
    record
        .get(key)
        .and_then(Value::as_str)
        .map(|s| clean(s, max))
        .filter(|s| !s.is_empty())
}

/// Strip a port from `1.2.3.4:5678` or `[2001:db8::1]:443`; leave bare IPv6 alone.
pub fn normalise_ip(value: &str) -> Option<String> {
    let v = value.trim();
    if v.is_empty() {
        return None;
    }
    let host = if let Some(rest) = v.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else if v.matches(':').count() == 1 {
        v.split(':').next().unwrap_or(v)
    } else {
        v
    };
    host.parse::<std::net::IpAddr>()
        .ok()
        .map(|ip| ip.to_string())
}

/// Fields kept from Management Activity records. Anything else (notably message
/// subjects and item lists in mailbox access records) is dropped at ingestion.
const KEPT_FIELDS: &[&str] = &[
    "RecordType",
    "Workload",
    "UserType",
    "ObjectId",
    "Parameters",
    "ModifiedProperties",
    "OrganizationName",
    "OriginatingServer",
    "ExternalAccess",
    "LogonType",
    "MailboxOwnerUPN",
    "SiteUrl",
    "SourceRelativeUrl",
    "SourceFileName",
    "SourceFileExtension",
    "ItemType",
    "ListItemUniqueId",
    "TargetUserOrGroupName",
    "TargetUserOrGroupType",
    "EventData",
    "EventSource",
    "SharingLinkScope",
    "Permission",
    "UniqueSharingId",
    "Target",
    "Actor",
    "ActorContextId",
    "TargetContextId",
    "AzureActiveDirectoryEventType",
    "ExtendedProperties",
    "ApplicationId",
    "AppAccessContext",
    "IsManagedDevice",
    "Platform",
    "DeviceDisplayName",
];

/// Normalise one Management Activity API audit record. Returns None if the record
/// lacks the identity needed for deduplication.
pub fn from_management_record(
    tenant_id: &str,
    content_type: &str,
    raw: &Value,
    ingested_at: Instant,
) -> Option<SecurityEvent> {
    let source_event_id = text(raw, "Id", 128)?;
    let operation = text(raw, "Operation", 256).unwrap_or_else(|| "Unknown".into());
    let timestamp = raw
        .get("CreationTime")
        .and_then(Value::as_str)
        .and_then(|t| Instant::parse(t).ok())?;
    let source = format!("o365:{content_type}");
    let workload = text(raw, "Workload", 64).unwrap_or_else(|| "Unknown".into());
    let user = text(raw, "UserId", 256);
    let mut metadata = Map::new();
    for key in KEPT_FIELDS {
        if let Some(v) = raw.get(*key) {
            metadata.insert((*key).to_owned(), sanitise(v));
        }
    }
    let ip = text(raw, "ClientIP", 64)
        .or_else(|| text(raw, "ClientIPAddress", 64))
        .and_then(|ip| normalise_ip(&ip));
    let user_agent = text(raw, "UserAgent", 512).or_else(|| extended(raw, "UserAgent"));
    let raw_bytes = serde_json::to_vec(raw).unwrap_or_default();
    Some(SecurityEvent {
        id: event_id(tenant_id, &source, &source_event_id),
        tenant_id: tenant_id.to_owned(),
        source,
        source_event_id,
        event_type: workload.to_ascii_lowercase(),
        timestamp: timestamp.to_rfc3339(),
        ingested_at: ingested_at.to_rfc3339(),
        actor_id: text(raw, "UserKey", 256),
        actor_upn: user.map(|u| u.to_ascii_lowercase()),
        target_id: text(raw, "ObjectId", 1024),
        target_type: raw
            .get("RecordType")
            .and_then(Value::as_i64)
            .map(|t| record_type_name(t).to_owned()),
        operation,
        result: text(raw, "ResultStatus", 64),
        ip_address: ip,
        user_agent,
        correlation_id: text(raw, "CorrelationId", 128)
            .or_else(|| text(raw, "InterSystemsId", 128)),
        metadata,
        raw_sha256: sha256_hex(&raw_bytes),
        raw_evidence_reference: None,
    })
}

fn extended(raw: &Value, name: &str) -> Option<String> {
    raw.get("ExtendedProperties")?
        .as_array()?
        .iter()
        .find(|p| p.get("Name").and_then(Value::as_str) == Some(name))?
        .get("Value")?
        .as_str()
        .map(|s| clean(s, 512))
}

/// Documented `RecordType` values relevant to the watchdog; others keep their number.
pub fn record_type_name(value: i64) -> &'static str {
    match value {
        1 => "ExchangeAdmin",
        2 => "ExchangeItem",
        3 => "ExchangeItemGroup",
        4 => "SharePoint",
        6 => "SharePointFileOperation",
        7 => "OneDrive",
        8 => "AzureActiveDirectory",
        9 => "AzureActiveDirectoryAccountLogon",
        14 => "SharePointSharingOperation",
        15 => "AzureActiveDirectoryStsLogon",
        18 => "SecurityComplianceCenterEOPCmdlet",
        25 => "MicrosoftTeams",
        54 => "SharePointListItemOperation",
        36 => "SharePointListOperation",
        50 => "ExchangeItemAggregated",
        _ => "Other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn inbox_rule() -> Value {
        json!({
            "Id": "6f1a0c3e-0000-4000-8000-000000000001",
            "RecordType": 1,
            "CreationTime": "2026-10-25T01:02:03",
            "Operation": "New-InboxRule",
            "OrganizationId": "t",
            "UserType": 2,
            "UserKey": "1003BFFD8A0B1C2D",
            "Workload": "Exchange",
            "ResultStatus": "True",
            "ObjectId": "treasurer@club.example\\Forward all",
            "UserId": "Treasurer@Club.Example",
            "ClientIP": "203.0.113.9:51234",
            "Parameters": [
                {"Name": "ForwardTo", "Value": "attacker@evil.example"},
                {"Name": "Name", "Value": "\u{202e}lla drawroF\u{0007}"}
            ],
            "Subject": "private board minutes"
        })
    }

    #[test]
    fn normalises_exchange_admin_record() {
        let now = Instant::parse("2026-10-25T02:00:00Z").unwrap();
        let e = from_management_record("t", "Audit.Exchange", &inbox_rule(), now).unwrap();
        assert_eq!(e.source, "o365:Audit.Exchange");
        assert_eq!(e.operation, "New-InboxRule");
        assert_eq!(e.timestamp, "2026-10-25T01:02:03.000Z");
        assert_eq!(e.actor_upn.as_deref(), Some("treasurer@club.example"));
        assert_eq!(e.ip_address.as_deref(), Some("203.0.113.9"));
        assert_eq!(e.target_type.as_deref(), Some("ExchangeAdmin"));
        assert!(
            !e.metadata.contains_key("Subject"),
            "non-allowlisted fields are dropped"
        );
        let name = e.metadata["Parameters"][1]["Value"].as_str().unwrap();
        assert_eq!(
            name, "lla drawroF",
            "bidi and control characters are stripped"
        );
        assert_eq!(e.raw_sha256.len(), 64);
        let again = from_management_record("t", "Audit.Exchange", &inbox_rule(), now).unwrap();
        assert_eq!(e.id, again.id, "same record yields same ID");
        let other_tenant =
            from_management_record("u", "Audit.Exchange", &inbox_rule(), now).unwrap();
        assert_ne!(e.id, other_tenant.id);
    }

    #[test]
    fn rejects_records_without_identity_and_bounds_payloads() {
        let now = Instant::now();
        assert!(
            from_management_record("t", "Audit.Exchange", &json!({"Operation":"x"}), now).is_none()
        );
        assert!(
            from_management_record(
                "t",
                "Audit.Exchange",
                &json!({"Id":"a","CreationTime":"bad"}),
                now
            )
            .is_none()
        );
        let mut deep = json!("x");
        for _ in 0..50 {
            deep = json!([deep]);
        }
        let huge = json!({"s": "a".repeat(100_000), "deep": deep, "list": vec![1; 10_000]});
        let s = sanitise(&huge);
        assert_eq!(s["s"].as_str().unwrap().len(), MAX_STRING);
        assert_eq!(s["list"].as_array().unwrap().len(), MAX_ARRAY);
        assert!(serde_json::to_string(&s).unwrap().contains("[truncated]"));
    }

    #[test]
    fn ip_normalisation() {
        assert_eq!(
            normalise_ip("203.0.113.9:443").as_deref(),
            Some("203.0.113.9")
        );
        assert_eq!(
            normalise_ip("[2001:db8::1]:443").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(normalise_ip("2001:db8::1").as_deref(), Some("2001:db8::1"));
        assert_eq!(normalise_ip("<script>").as_deref(), None);
        assert_eq!(normalise_ip("").as_deref(), None);
    }
}
