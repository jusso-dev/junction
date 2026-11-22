//! Optional forward of high-value events to Sentinel or Bower.
//!
//! The archive is not a firehose. Only records matched by the built-in,
//! versioned [`SELECTOR`] are forwarded, and only when the operator runs
//! `junction archive forward`. Operators can narrow the selector (`--only`)
//! but cannot widen it: there is no "forward everything" option.
//!
//! Destinations:
//!
//! - **Sentinel**: the Logs Ingestion API through the same single-operation,
//!   policy-checked path as `junction check run --push-sentinel`. Rows carry
//!   redacted summary columns only, never raw records.
//! - **Bower**: the collector's existing `POST /v1/events`, one Bower envelope
//!   1.0.0 per event, with a producer bearer token. Bower is not changed; see
//!   `docs/archive/BOWER-CONTRACT.md`.
//!
//! Delivery is at least once per destination. A local cursor per destination
//! records forwarded record ids; Bower deduplicates on `eventId` and the
//! Sentinel rows carry the record id for KQL deduplication.
use crate::{
    record::ArchiveRecord,
    search::{pseudonym, truncate_ip},
};
use anyhow::{Context, Result, bail};
use junction_watch::event::sha256_hex;
use serde::Serialize;
use serde_json::{Value, json};

/// Version of the selector; recorded on every forwarded event.
pub const SELECTOR_VERSION: &str = "1";

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Rule {
    pub id: &'static str,
    pub sources: &'static [&'static str],
    /// Operations matched case-insensitively. Empty means any operation.
    pub operations: &'static [&'static str],
    pub category: &'static str,
    pub severity: &'static str,
    pub why: &'static str,
}

const EXO: &[&str] = &["o365:Audit.Exchange"];
const AAD: &[&str] = &["graph:directoryAudits", "o365:Audit.AzureActiveDirectory"];

/// High-value events and why each one is worth a SIEM's attention.
pub const SELECTOR: &[Rule] = &[
    Rule {
        id: "role-assignment-added",
        sources: AAD,
        operations: &[
            "Add member to role",
            "Add member to role.",
            "Add eligible member to role",
            "Add member to role completed (PIM activation)",
        ],
        category: "authorisation",
        severity: "high",
        why: "Privileged role grants are the most common persistence step after an account takeover.",
    },
    Rule {
        id: "app-consent-granted",
        sources: AAD,
        operations: &["Consent to application", "Consent to application."],
        category: "authorisation",
        severity: "high",
        why: "Illicit consent grants give attackers durable mailbox and file access without a password.",
    },
    Rule {
        id: "app-credential-added",
        sources: AAD,
        operations: &[
            "Add service principal credentials",
            "Add service principal credentials.",
            // Microsoft's own spelling uses an en dash; both forms are matched.
            "Update application \u{2013} Certificates and secrets management",
            "Update application - Certificates and secrets management",
        ],
        category: "identity-management",
        severity: "high",
        why: "A new secret or certificate on an app or service principal is a classic backdoor.",
    },
    Rule {
        id: "mailbox-forwarding-or-rule",
        sources: EXO,
        operations: &[
            "New-InboxRule",
            "Set-InboxRule",
            "UpdateInboxRules",
            "Set-Mailbox",
            "New-TransportRule",
            "Set-TransportRule",
        ],
        category: "administrative-activity",
        severity: "medium",
        why: "Forwarding and inbox rules are used to hide and exfiltrate mail in business email compromise.",
    },
    Rule {
        id: "mailbox-permission-added",
        sources: EXO,
        operations: &["Add-MailboxPermission", "Add-RecipientPermission"],
        category: "authorisation",
        severity: "medium",
        why: "Full Access and Send As grants let one account read or impersonate another.",
    },
    Rule {
        id: "audit-logging-reduced",
        sources: EXO,
        operations: &[
            "Set-AdminAuditLogConfig",
            "Set-MailboxAuditBypassAssociation",
            "Set-OrganizationConfig",
        ],
        category: "administrative-activity",
        severity: "high",
        why: "Turning audit logging down is defence evasion and degrades this archive itself.",
    },
    Rule {
        id: "defender-high-severity-alert",
        sources: &["graph:alerts_v2"],
        operations: &[],
        category: "application-security",
        severity: "high",
        why: "High-severity Defender alerts and their resolution are the events a SOC acts on.",
    },
    Rule {
        id: "risky-sign-in-success",
        sources: &["graph:signIns"],
        operations: &[],
        category: "authentication",
        severity: "high",
        why: "A successful sign-in rated medium or high risk is likely account compromise.",
    },
];

fn rule_matches(rule: &Rule, r: &ArchiveRecord) -> bool {
    if !rule.sources.contains(&r.source.as_str()) {
        return false;
    }
    if !rule.operations.is_empty()
        && !rule
            .operations
            .iter()
            .any(|op| op.eq_ignore_ascii_case(&r.operation))
    {
        return false;
    }
    match rule.id {
        "defender-high-severity-alert" => r
            .result
            .as_deref()
            .is_some_and(|s| s.eq_ignore_ascii_case("high")),
        "risky-sign-in-success" => {
            r.result.as_deref() == Some("success")
                && ["riskLevelDuringSignIn", "riskLevelAggregated"]
                    .iter()
                    .any(|k| {
                        r.raw
                            .get(*k)
                            .and_then(Value::as_str)
                            .is_some_and(|v| matches!(v, "medium" | "high"))
                    })
        }
        // Admin writes must have succeeded.
        _ => !r.result.as_deref().is_some_and(|s| {
            let s = s.to_ascii_lowercase();
            s.contains("fail") || s == "false"
        }),
    }
}

/// Every source at least one active rule reads.
pub fn selectable_sources(only: &[String]) -> Vec<String> {
    let mut out: Vec<String> = SELECTOR
        .iter()
        .filter(|rule| only.is_empty() || only.iter().any(|o| o == rule.id))
        .flat_map(|rule| rule.sources.iter().map(|s| s.to_string()))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Sources whose records are versioned by `lastUpdateDateTime`.
pub const VERSIONED_SOURCES: [&str; 2] = ["graph:alerts_v2", "graph:incidents"];
/// How far before a forward range versioned records are looked for. An alert
/// raised more than this before its update is not forwarded by that update.
pub const VERSION_LOOKBACK: std::time::Duration = std::time::Duration::from_secs(30 * 86_400);

/// Forwarded ids are remembered this long per destination. Older ids are
/// dropped so the cursor stays bounded; re-forwarding a range older than
/// this may resend events, which Bower and KQL deduplicate on the stable id.
pub const CURSOR_DAYS: u64 = 400;

/// The first rule matching `r`, limited to `only` when given.
pub fn select<'a>(r: &ArchiveRecord, only: &[String]) -> Option<&'a Rule> {
    SELECTOR
        .iter()
        .filter(|rule| only.is_empty() || only.iter().any(|o| o == rule.id))
        .find(|rule| rule_matches(rule, r))
}

pub fn validate_only(only: &[String]) -> Result<()> {
    for o in only {
        if !SELECTOR.iter().any(|r| r.id == o) {
            bail!("unknown selector rule {o:?}; see `junction archive forward --list`");
        }
    }
    Ok(())
}

/// A Sentinel row: redacted summary columns only.
pub fn sentinel_row(r: &ArchiveRecord, rule: &Rule) -> Value {
    json!({
        "TimeGenerated": r.event_time,
        "RecordId": r.record_id,
        "EntraTenantId": r.tenant_id,
        "Source": r.source,
        "Operation": r.operation,
        "Result": r.result,
        "ActorPseudonym": r.actor_upn.as_deref().or(r.actor_id.as_deref()).map(pseudonym),
        "IpNetwork": r.ip_address.as_deref().map(truncate_ip),
        "Rule": rule.id,
        "RuleSeverity": rule.severity,
        "SelectorVersion": SELECTOR_VERSION,
        "RawSha256": r.raw_sha256,
    })
}

fn bower_result(r: &ArchiveRecord) -> &'static str {
    match r.result.as_deref().map(str::to_ascii_lowercase).as_deref() {
        Some("success" | "succeeded" | "true") => "success",
        Some(s) if s.contains("fail") || s == "false" => "failure",
        _ => "unknown",
    }
}

fn bounded(value: &str, max: usize) -> String {
    junction_watch::event::clean(value, max)
}

/// A Bower security event envelope 1.0.0 for `r`.
///
/// Identifiers are pseudonymised (Bower's privacy profile can still redact
/// further); the raw record is not sent, only its hash.
pub fn bower_event(r: &ArchiveRecord, rule: &Rule, environment: &str) -> Value {
    let event_type = format!("m365_{}", rule.id.replace('-', "_"));
    json!({
        "schemaVersion": "1.0.0",
        "eventId": format!("junction-archive-{}", r.record_id),
        "eventOriginalId": bounded(&r.source_event_id, 256),
        "timeGenerated": r.event_time,
        "timeObserved": r.ingested_at,
        "eventCategory": rule.category,
        "eventType": event_type,
        "eventAction": bounded(&r.operation, 128),
        "eventResult": bower_result(r),
        "eventSeverity": rule.severity,
        "application": {
            "name": "junction-archive",
            "version": env!("CARGO_PKG_VERSION"),
            "environment": environment,
            "tenantId": r.tenant_id,
        },
        "actor": {
            "userId": r.actor_upn.as_deref().or(r.actor_id.as_deref()).map(pseudonym),
            "type": "unknown",
        },
        "target": r.target_id.as_deref().map(|t| json!({"type": "m365_object", "id": pseudonym(t)})),
        "source": r.ip_address.as_deref().map(|ip| json!({"ipAddress": truncate_ip(ip)})),
        "request": {"correlationId": r.correlation_id.as_deref().map(|c| bounded(c, 256))},
        "labels": {
            "junction.source": r.source,
            "junction.rule": rule.id,
            "junction.selector_version": SELECTOR_VERSION,
            "junction.raw_sha256": r.raw_sha256,
        },
    })
}

// ---------------------------------------------------------------------------
// Bower delivery

/// Posts one envelope; tests script replies, production uses HTTPS.
pub trait BowerSender: Send + Sync {
    fn post<'a>(&'a self, event: &'a Value) -> crate::store::BoxFut<'a, Result<u16>>;
}

pub const BOWER_TOKEN_ENV: &str = "JUNCTION_BOWER_INGEST_TOKEN";

pub struct LiveBower {
    endpoint: url::Url,
    token: zeroize::Zeroizing<String>,
    client: reqwest::Client,
}

impl LiveBower {
    /// `endpoint` is the collector's base URL. HTTPS is required except for loopback.
    pub fn new(endpoint: &str) -> Result<Self> {
        let mut url = url::Url::parse(endpoint).context("--endpoint must be a URL")?;
        let loopback = url
            .host_str()
            .is_some_and(|h| h == "localhost" || h == "127.0.0.1" || h == "[::1]");
        if !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            bail!(
                "--endpoint must be an https URL (http only for loopback) with no credentials or query"
            );
        }
        url.set_path("/v1/events");
        let token = std::env::var(BOWER_TOKEN_ENV)
            .ok()
            .filter(|t| t.len() >= 32)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "{BOWER_TOKEN_ENV} must hold the Bower producer token (32+ characters)"
                )
            })?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        Ok(Self {
            endpoint: url,
            token: zeroize::Zeroizing::new(token),
            client,
        })
    }
}

impl BowerSender for LiveBower {
    fn post<'a>(&'a self, event: &'a Value) -> crate::store::BoxFut<'a, Result<u16>> {
        Box::pin(async move {
            let mut auth =
                reqwest::header::HeaderValue::from_str(&format!("Bearer {}", self.token.as_str()))
                    .map_err(|_| anyhow::anyhow!("invalid Bower token"))?;
            auth.set_sensitive(true);
            let response = self
                .client
                .post(self.endpoint.clone())
                .header(reqwest::header::AUTHORIZATION, auth)
                .json(event)
                .send()
                .await
                .map_err(|_| anyhow::anyhow!("Bower request failed"))?;
            Ok(response.status().as_u16())
        })
    }
}

/// Send one envelope, retrying Bower's backpressure (429, 503).
pub async fn send_bower(
    sender: &dyn BowerSender,
    event: &Value,
    retry: crate::store::Retry,
) -> Result<()> {
    let mut attempt = 0u32;
    loop {
        let status = sender.post(event).await?;
        match status {
            // 202 accepted, 200 duplicate (already queued): both are delivered.
            200 | 202 => return Ok(()),
            429 | 503 if attempt + 1 < retry.attempts => {
                let delay = retry
                    .base
                    .saturating_mul(1 << attempt.min(16))
                    .min(retry.cap);
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                attempt += 1;
            }
            401 => bail!("Bower refused the producer token (HTTP 401)"),
            403 => bail!(
                "Bower refused this producer for application junction-archive (HTTP 403); add a producer scope, see docs/archive/BOWER-CONTRACT.md"
            ),
            409 => bail!("Bower reports an event identity conflict (HTTP 409)"),
            422 => bail!("Bower's policy rejected the event (HTTP 422)"),
            other => bail!("Bower ingest failed: HTTP {other}"),
        }
    }
}

/// Stable cursor key for a destination, without secrets.
pub fn destination_id(kind: &str, target: &str) -> String {
    format!("{kind}-{}", &sha256_hex(target.as_bytes())[..16])
}

#[cfg(test)]
mod tests {
    use super::*;
    use junction_watch::clock::Instant;

    fn audit(op: &str, result: &str) -> ArchiveRecord {
        let raw = json!({"id": op, "activityDateTime": "2026-11-01T10:00:00Z", "activityDisplayName": op,
                         "result": result, "initiatedBy": {"user": {"userPrincipalName": "admin@example.test"}}});
        let e = junction_watch::graph::normalise(
            "11111111-1111-4111-8111-111111111111",
            "graph:directoryAudits",
            &raw,
            Instant::parse("2026-11-02T00:00:00Z").unwrap(),
        )
        .unwrap();
        ArchiveRecord::from_event(&e, &raw, None)
    }

    #[test]
    fn selector_is_narrow() {
        assert_eq!(
            select(&audit("Add member to role", "success"), &[])
                .unwrap()
                .id,
            "role-assignment-added"
        );
        assert!(
            select(&audit("Add member to role", "failure"), &[]).is_none(),
            "failed writes are not forwarded"
        );
        assert!(
            select(&audit("Update user", "success"), &[]).is_none(),
            "ordinary changes stay in the archive"
        );
        assert!(
            select(
                &audit("Add member to role", "success"),
                &["app-consent-granted".into()]
            )
            .is_none()
        );
        assert!(validate_only(&["everything".into()]).is_err());
        for rule in SELECTOR {
            assert!(
                !rule.why.is_empty() && !rule.sources.is_empty(),
                "{}",
                rule.id
            );
        }
    }

    #[test]
    fn rows_and_envelopes_carry_no_direct_identifiers() {
        let r = audit("Consent to application", "success");
        let rule = select(&r, &[]).unwrap();
        for v in [sentinel_row(&r, rule), bower_event(&r, rule, "production")] {
            let text = v.to_string();
            assert!(!text.contains("admin@example.test"), "{text}");
            assert!(!text.contains("\"raw\""), "{text}");
        }
        let e = bower_event(&r, rule, "production");
        assert_eq!(e["eventType"], "m365_app_consent_granted");
        assert_eq!(e["eventResult"], "success");
    }

    #[test]
    fn bower_endpoint_is_validated() {
        // SAFETY: tests in this module run single-threaded with respect to this env var.
        unsafe { std::env::remove_var(BOWER_TOKEN_ENV) };
        assert!(
            LiveBower::new("http://collector.example:4319").is_err(),
            "plain http off loopback"
        );
        assert!(LiveBower::new("https://user:pw@collector.example").is_err());
        assert!(
            LiveBower::new("https://collector.example").is_err(),
            "token required"
        );
    }
}

// ---------------------------------------------------------------------------
// One forward pass

/// Where a forward pass sends events.
pub enum Destination<'a> {
    Sentinel {
        target: &'a junction_check::push::PushTarget,
        sender: &'a dyn junction_check::push::Sender,
    },
    Bower {
        sender: &'a dyn BowerSender,
        environment: &'a str,
    },
}

#[derive(Debug, Default, Serialize)]
pub struct ForwardSummary {
    pub scanned: usize,
    pub selected: usize,
    pub already_forwarded: usize,
    pub sent: usize,
    pub by_rule: std::collections::BTreeMap<String, usize>,
}

/// Forward selected records in `[from, to)` that this destination has not
/// received yet. The cursor (record ids per destination) is saved after each
/// successful batch, so a failure resends at most one batch.
#[allow(clippy::too_many_arguments)]
pub async fn forward(
    store: &dyn crate::store::ObjectStore,
    checkpoint: &mut crate::checkpoint::Checkpoint,
    destination_key: &str,
    query: &crate::search::Query,
    only: &[String],
    destination: Destination<'_>,
    retry: crate::store::Retry,
    backoff: junction_watch::backoff::Backoff,
) -> Result<ForwardSummary> {
    validate_only(only)?;
    let tenant = checkpoint.state.tenant_id.clone();
    // Only sources a selected rule can match are read, so busy sources that
    // never forward (SharePoint, General) cannot exhaust the scan limit.
    let mut query = query.clone();
    query.sources = selectable_sources(only);
    let (from, to) = query.range()?;
    // Defender alerts are filed by when they were raised, so an alert raised
    // earlier and escalated or resolved inside the range sits in an earlier
    // partition. Versioned sources are read from VERSION_LOOKBACK before the
    // range and their updates selected by lastUpdateDateTime.
    let mut scan = query.clone();
    if query
        .sources
        .iter()
        .any(|s| VERSIONED_SOURCES.contains(&s.as_str()))
    {
        scan.from = from.minus(VERSION_LOOKBACK).to_rfc3339();
    }
    let in_range = |r: &ArchiveRecord| {
        let at = if VERSIONED_SOURCES.contains(&r.source.as_str()) {
            r.version
                .as_deref()
                .and_then(|v| junction_watch::clock::Instant::parse(v).ok())
        } else {
            r.event_instant()
        };
        at.is_some_and(|t| t >= from && t < to)
    };
    let mut results =
        crate::search::search(store, &tenant, &scan, crate::search::MAX_LIMIT).await?;
    results.records.retain(in_range);
    if results.truncated {
        bail!(
            "more than {} records in range; forward a shorter range",
            crate::search::MAX_LIMIT
        );
    }
    let cursor_source = format!("forward:{destination_key}");
    {
        let keep_from = junction_watch::clock::Instant::now()
            .minus(std::time::Duration::from_secs(CURSOR_DAYS * 86_400))
            .to_rfc3339();
        checkpoint
            .source(&cursor_source)
            .recent_records
            .retain(|_, at| *at >= keep_from);
    }
    let mut summary = ForwardSummary {
        scanned: results.records.len(),
        ..ForwardSummary::default()
    };
    let mut pending: Vec<(&ArchiveRecord, &Rule)> = vec![];
    for r in &results.records {
        let Some(rule) = select(r, only) else {
            continue;
        };
        summary.selected += 1;
        if checkpoint
            .source(&cursor_source)
            .recent_records
            .contains_key(&r.record_id)
        {
            summary.already_forwarded += 1;
            continue;
        }
        pending.push((r, rule));
    }
    const BATCH: usize = 500;
    for chunk in pending.chunks(BATCH) {
        match &destination {
            Destination::Sentinel { target, sender } => {
                let rows = chunk
                    .iter()
                    .map(|(r, rule)| sentinel_row(r, rule))
                    .collect();
                junction_check::push::push_rows(target, rows, *sender, backoff).await?;
            }
            Destination::Bower {
                sender,
                environment,
            } => {
                for (r, rule) in chunk {
                    let event = bower_event(r, rule, environment);
                    if let Err(e) = send_bower(*sender, &event, retry).await {
                        // Save what was delivered before stopping.
                        checkpoint.save()?;
                        return Err(
                            e.context(format!("after {} event(s) were delivered", summary.sent))
                        );
                    }
                    checkpoint
                        .source(&cursor_source)
                        .recent_records
                        .insert(r.record_id.clone(), r.event_time.clone());
                    summary.sent += 1;
                    *summary.by_rule.entry(rule.id.to_owned()).or_default() += 1;
                }
                checkpoint.save()?;
                continue;
            }
        }
        let state = checkpoint.source(&cursor_source);
        for (r, rule) in chunk {
            state
                .recent_records
                .insert(r.record_id.clone(), r.event_time.clone());
            summary.sent += 1;
            *summary.by_rule.entry(rule.id.to_owned()).or_default() += 1;
        }
        checkpoint.save()?;
    }
    Ok(summary)
}
