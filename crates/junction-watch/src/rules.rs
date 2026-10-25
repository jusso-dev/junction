//! Deterministic rules. Matching is restricted to documented operations and
//! structured values; arbitrary display names never act as detection commands.
use crate::{clock::Instant, event::SecurityEvent};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize)]
pub struct Rule {
    pub id: String,
    pub name: &'static str,
    pub description: &'static str,
    pub severity: &'static str,
    pub mitre: &'static str,
    pub required_sources: Vec<&'static str>,
    pub source_requirement: &'static str,
    pub supported_operations: Vec<&'static str>,
    pub required_permissions: &'static str,
    pub licence_dependencies: &'static str,
    pub logic: &'static str,
    pub window_seconds: u64,
    pub threshold: u64,
    pub suppression: &'static str,
    pub evidence_requirements: &'static str,
    pub remediation: &'static str,
    pub confidence: u8,
    pub version: u32,
}

pub fn registry() -> Vec<Rule> {
    let rows = [
        (
            "EXO",
            1,
            "External mailbox forwarding created",
            "CRITICAL",
            "T1114.003",
            "A successful mailbox update adds an external forwarding address.",
        ),
        (
            "EXO",
            2,
            "Suspicious inbox rule",
            "HIGH",
            "T1114.003",
            "A new or modified inbox rule forwards, redirects, deletes or hides messages.",
        ),
        (
            "EXO",
            3,
            "Mailbox delegation changed",
            "HIGH",
            "T1098.002",
            "Full Access, Send As or Send on Behalf access was granted.",
        ),
        (
            "EXO",
            4,
            "Transport rule changed",
            "HIGH",
            "T1114.003",
            "A transport rule redirects, deletes or modifies mail.",
        ),
        (
            "EXO",
            5,
            "Mailbox auditing weakened",
            "CRITICAL",
            "T1562.008",
            "Auditing was disabled or an audit bypass was enabled.",
        ),
        (
            "EXO",
            6,
            "Suspicious mailbox rule activity",
            "HIGH",
            "T1114.003",
            "An audit rule change agrees with a suspicious complete configuration snapshot.",
        ),
        (
            "SPO",
            1,
            "Anonymous sharing link created",
            "HIGH",
            "T1567.002",
            "An anonymous sharing link was created; review intended public access.",
        ),
        (
            "SPO",
            2,
            "Unexpected external sharing",
            "HIGH",
            "T1537",
            "Sharing targets a domain absent from the approved domain baseline.",
        ),
        (
            "SPO",
            3,
            "Bulk file downloads",
            "HIGH",
            "T1530",
            "Download volume exceeds the configured minimum and the actor/site baseline.",
        ),
        (
            "SPO",
            4,
            "Permission escalation",
            "HIGH",
            "T1098",
            "Site administrator or owner permissions were granted.",
        ),
        (
            "SPO",
            5,
            "Bulk deletion",
            "HIGH",
            "T1485",
            "File deletion volume exceeds the configured minimum and actor/site baseline.",
        ),
        (
            "SPO",
            6,
            "Sharing policy weakened",
            "HIGH",
            "T1562.001",
            "Sharing configuration was changed to allow broader external access.",
        ),
        (
            "SPO",
            7,
            "Suspicious activity correlation",
            "HIGH",
            "T1530",
            "Multiple distinct suspicious activity types involve the same actor and site.",
        ),
        (
            "ID",
            1,
            "Global Administrator assigned",
            "CRITICAL",
            "T1098.003",
            "A Global Administrator role assignment succeeded.",
        ),
        (
            "ID",
            2,
            "Privileged role assignment",
            "HIGH",
            "T1098.003",
            "A privileged directory role assignment succeeded.",
        ),
        (
            "ID",
            3,
            "OAuth consent grant",
            "HIGH",
            "T1098.003",
            "New delegated or application permission consent succeeded.",
        ),
        (
            "ID",
            4,
            "Application credentials changed",
            "HIGH",
            "T1098.001",
            "Application or service principal credentials were added or changed.",
        ),
        (
            "ID",
            5,
            "Authentication methods changed",
            "HIGH",
            "T1098.005",
            "An authentication method registration, update or removal succeeded.",
        ),
        (
            "ID",
            6,
            "Security configuration weakened",
            "CRITICAL",
            "T1562.001",
            "A structured security policy change disables a protective control.",
        ),
        (
            "ID",
            7,
            "Suspicious sign-in",
            "HIGH",
            "T1078.004",
            "Graph reports medium/high sign-in risk; hidden risk fields are not evidence.",
        ),
    ];
    rows.into_iter().map(|(family,n,name,severity,mitre,logic)| {
        let sources=match family {"EXO" if n==6=>vec!["o365:Audit.Exchange","snapshot:inbox_rules"],"EXO"=>vec!["o365:Audit.Exchange"],"SPO"=>vec!["o365:Audit.SharePoint"],_ if n==7=>vec!["graph:signIns"],_=>vec!["graph:directoryAudits","o365:Audit.AzureActiveDirectory"]};
        Rule {id:format!("M365-{family}-{n:03}"),name,description:logic,severity,mitre,required_sources:sources,supported_operations:operations(family,n),source_requirement:if family=="EXO"&&n==6{"all"}else{"any"},
            required_permissions:if family=="ID" {"AuditLog.Read.All or ActivityFeed.Read; sign-ins require AuditLog.Read.All"}else{"ActivityFeed.Read; snapshot correlation additionally requires scoped Exchange runner"},
            licence_dependencies:if family=="ID" && n==7 {"Entra P1/P2 for sign-in retrieval; risk detail can additionally require P2. Positive capability probe required."}else{"Actual source capability probe and observed event coverage required; no entitlement inferred from plan names."},
            logic,window_seconds:3600,threshold:if family=="SPO" && (n==3||n==5){100}else{1},
            suppression:"Exact rule/resource exceptions and bounded maintenance windows, approved by an administrator; matches retained as suppressed.",
            evidence_requirements:"Successful source event and structured changed values; volume/correlation requires distinct source event IDs. Missing fields do not prove a change.",
            remediation:match family {"EXO"=>"Confirm change with mailbox owner through a trusted channel. Review forwarding, rules and delegates; if unauthorised, revoke sessions and credentials and remove persistence using Microsoft administration tools.","SPO"=>"Confirm the sharing or file operation with the site owner. Review link permissions and scope, revoke unauthorised access, and preserve evidence. A download alone does not prove exfiltration.",_=>"Confirm with an authorised administrator through a trusted channel. Review the affected role, app grant or method, preserve evidence, and revoke unauthorised access using Microsoft administration tools."},confidence:85,version:1}
    }).collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuleSettings {
    pub internal_domains: Vec<String>,
    pub approved_external_domains: Vec<String>,
    pub sensitive_sites: Vec<String>,
    pub bulk_threshold: usize,
    pub baseline_multiplier: usize,
}
impl Default for RuleSettings {
    fn default() -> Self {
        Self {
            internal_domains: vec![],
            approved_external_domains: vec![],
            sensitive_sites: vec![],
            bulk_threshold: 100,
            baseline_multiplier: 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub rule_version: u32,
    #[serde(default)]
    pub coverage_limitations: Vec<String>,
    pub severity: String,
    pub resource: String,
    pub evidence: Vec<String>,
    pub explanation: String,
    pub confidence: u8,
}

pub fn successful(e: &SecurityEvent) -> bool {
    e.result.as_deref().is_some_and(|r| {
        [
            "success",
            "succeeded",
            "true",
            "0",
            "successfully completed",
        ]
        .contains(&r.to_ascii_lowercase().as_str())
    })
}
fn props(e: &SecurityEvent) -> BTreeMap<String, Value> {
    let mut result = BTreeMap::new();
    for key in ["Parameters", "ModifiedProperties"] {
        if let Some(items) = e.metadata.get(key).and_then(Value::as_array) {
            for p in items {
                if let Some(name) = p.get("Name").and_then(Value::as_str)
                    && let Some(value) = p.get("NewValue").or_else(|| p.get("Value"))
                {
                    result.insert(name.to_ascii_lowercase(), decode(value));
                }
            }
        }
    }
    if let Some(targets) = e.metadata.get("targetResources").and_then(Value::as_array) {
        for t in targets {
            if let Some(items) = t.get("modifiedProperties").and_then(Value::as_array) {
                for p in items {
                    if let (Some(name), Some(v)) = (
                        p.get("displayName").and_then(Value::as_str),
                        p.get("newValue"),
                    ) {
                        result.insert(name.to_ascii_lowercase(), decode(v));
                    }
                }
            }
        }
    }
    result
}
fn decode(v: &Value) -> Value {
    v.as_str()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_else(|| v.clone())
}
fn active(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::String(s) => !s.is_empty() && !s.eq_ignore_ascii_case("false") && s != "[]",
        Value::Array(a) => !a.is_empty(),
        _ => true,
    }
}
fn strings(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.to_ascii_lowercase()],
        Value::Array(a) => a.iter().flat_map(strings).collect(),
        _ => vec![],
    }
}
fn has(p: &BTreeMap<String, Value>, names: &[&str]) -> bool {
    names.iter().any(|n| p.get(*n).is_some_and(active))
}
fn is_false(v: Option<&Value>) -> bool {
    v.is_some_and(|v| {
        v == &Value::Bool(false) || v.as_str().is_some_and(|s| s.eq_ignore_ascii_case("false"))
    })
}
pub fn external_domain(address: &str, settings: &RuleSettings) -> Option<String> {
    let (_, domain) = address.trim().rsplit_once('@')?;
    let d = domain.trim_matches(['>', ' ']).to_ascii_lowercase();
    if d.is_empty()
        || !d.contains('.')
        || !d
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return None;
    }
    (!settings
        .internal_domains
        .iter()
        .any(|x| x.eq_ignore_ascii_case(&d)))
    .then_some(d)
}
fn same_scope(a: &SecurityEvent, b: &SecurityEvent) -> bool {
    a.actor_upn.is_some()
        && a.actor_upn == b.actor_upn
        && a.metadata.get("SiteUrl").is_some()
        && a.metadata.get("SiteUrl") == b.metadata.get("SiteUrl")
}
fn volume(e: &SecurityEvent, history: &[SecurityEvent], settings: &RuleSettings) -> Vec<String> {
    let Ok(now) = Instant::parse(&e.timestamp) else {
        return vec![];
    };
    let mut current = BTreeSet::new();
    let mut buckets = BTreeMap::<i64, usize>::new();
    for other in history.iter().chain(std::iter::once(e)) {
        if other.source != e.source || other.operation != e.operation || !same_scope(e, other) {
            continue;
        }
        let Ok(t) = Instant::parse(&other.timestamp) else {
            continue;
        };
        let age = now.0 - t.0;
        if (0..3_600_000).contains(&age) {
            current.insert(other.id.clone());
        } else if (3_600_000..7 * 86_400_000).contains(&age) {
            *buckets.entry(age / 3_600_000).or_default() += 1;
        }
    }
    let max = buckets.values().copied().max().unwrap_or(0);
    if current.len() >= settings.bulk_threshold.max(2)
        && current.len() > max.saturating_mul(settings.baseline_multiplier.max(2))
    {
        current.into_iter().collect()
    } else {
        vec![]
    }
}

pub fn evaluate(
    e: &SecurityEvent,
    history: &[SecurityEvent],
    settings: &RuleSettings,
) -> Vec<Finding> {
    // Read-only SharePoint operation records sometimes omit ResultStatus; their
    // documented operations themselves describe completion. Admin writes must succeed.
    let spo = ["o365:Audit.SharePoint", "snapshot:sharepoint"].contains(&e.source.as_str());
    if !successful(e) && !(spo && e.result.is_none()) {
        return vec![];
    }
    let p = props(e);
    let op = e.operation.as_str();
    let mut matches = Vec::<(&str, Vec<String>)>::new();
    let mut hit = |id: &'static str, yes: bool| {
        if yes {
            matches.push((id, vec![e.id.clone()]));
        }
    };
    if ["o365:Audit.Exchange", "snapshot:exchange"].contains(&e.source.as_str()) {
        hit(
            "M365-EXO-001",
            op == "Set-Mailbox"
                && ["forwardingsmtpaddress", "forwardingaddress"]
                    .iter()
                    .any(|n| {
                        p.get(*n).is_some_and(|v| {
                            strings(v)
                                .iter()
                                .any(|s| external_domain(s, settings).is_some())
                        })
                    }),
        );
        hit(
            "M365-EXO-002",
            ["New-InboxRule", "Set-InboxRule", "UpdateInboxRules"].contains(&op)
                && !is_false(p.get("enabled"))
                && has(
                    &p,
                    &[
                        "forwardto",
                        "redirectto",
                        "forwardasattachmentto",
                        "deletemessage",
                        "movetofolder",
                        "markasread",
                    ],
                ),
        );
        hit(
            "M365-EXO-003",
            (op == "Add-MailboxPermission"
                && p.get("accessrights")
                    .is_some_and(|v| strings(v).iter().any(|s| s.contains("fullaccess"))))
                || (op == "Add-RecipientPermission"
                    && p.get("accessrights")
                        .is_some_and(|v| strings(v).iter().any(|s| s.contains("sendas"))))
                || (op == "Set-Mailbox" && has(&p, &["grantsendonbehalfto"])),
        );
        hit(
            "M365-EXO-004",
            ["New-TransportRule", "Set-TransportRule"].contains(&op)
                && has(
                    &p,
                    &[
                        "redirectmessageto",
                        "deletemessage",
                        "blindcopyto",
                        "addtorecipients",
                        "setheadername",
                        "prependSubject".to_ascii_lowercase().as_str(),
                    ],
                ),
        );
        hit(
            "M365-EXO-005",
            (op == "Set-Mailbox" && (is_false(p.get("auditenabled")) || audit_reduced(e)))
                || (op == "Set-OrganizationConfig"
                    && (has(&p, &["auditdisabled"])
                        || is_false(p.get("unifiedauditlogingestionenabled"))))
                || (op == "Set-MailboxAuditBypassAssociation" && has(&p, &["auditbypassenabled"])),
        );
    }
    // Only correlate distinct successful audit and configuration records.
    let rule_ops = ["New-InboxRule", "Set-InboxRule", "UpdateInboxRules"];
    let suspicious_rule = |record: &SecurityEvent| {
        let p = props(record);
        !is_false(p.get("enabled"))
            && has(
                &p,
                &[
                    "forwardto",
                    "redirectto",
                    "forwardasattachmentto",
                    "deletemessage",
                    "movetofolder",
                    "markasread",
                ],
            )
    };
    let correlated: Vec<String> = history
        .iter()
        .filter(|h| {
            h.id != e.id
                && successful(h)
                && e.target_id.is_some()
                && h.target_id == e.target_id
                && ((e.source == "o365:Audit.Exchange"
                    && rule_ops.contains(&op)
                    && h.source == "snapshot:exchange"
                    && h.operation == "Set-InboxRule"
                    && suspicious_rule(h))
                    || (e.source == "snapshot:exchange"
                        && op == "Set-InboxRule"
                        && suspicious_rule(e)
                        && h.source == "o365:Audit.Exchange"
                        && rule_ops.contains(&h.operation.as_str())))
                && Instant::parse(&h.timestamp)
                    .ok()
                    .zip(Instant::parse(&e.timestamp).ok())
                    .is_some_and(|(a, b)| (a.0 - b.0).abs() <= 3_600_000)
        })
        .map(|h| h.id.clone())
        .collect();
    if spo {
        hit("M365-SPO-001", op == "AnonymousLinkCreated");
        hit(
            "M365-SPO-002",
            [
                "SharingInvitationCreated",
                "SharingSet",
                "AddedToSecureLink",
            ]
            .contains(&op)
                && e.metadata
                    .get("TargetUserOrGroupName")
                    .and_then(Value::as_str)
                    .and_then(|s| external_domain(s, settings))
                    .is_some_and(|d| {
                        !settings
                            .approved_external_domains
                            .iter()
                            .any(|x| x.eq_ignore_ascii_case(&d))
                    }),
        );
        hit(
            "M365-SPO-004",
            [
                "SiteCollectionAdminAdded",
                "SiteCollectionAdminAddedByApplication",
            ]
            .contains(&op)
                || (op == "AddedToGroup"
                    && e.metadata
                        .get("Permission")
                        .and_then(Value::as_str)
                        .is_some_and(|s| ["FullControl", "Owner"].contains(&s))),
        );
        hit(
            "M365-SPO-006",
            ["SharingPolicyChanged", "Set-SPOTenant", "Set-SPOSite"].contains(&op)
                && (e.source != "snapshot:sharepoint" || sharing_weakened(e))
                && p.get("sharingcapability").is_some_and(|v| {
                    strings(v).iter().any(|s| {
                        [
                            "externaluserandguestsharing",
                            "externalusersharingonly",
                            "externaluserandexistingguestsharing",
                            "existingexternalusersharingonly",
                        ]
                        .contains(&s.as_str())
                    })
                }),
        );
    }
    if ["graph:directoryAudits", "o365:Audit.AzureActiveDirectory"].contains(&e.source.as_str()) {
        let role_change = [
            "Add member to role",
            "Add member to role.",
            "Add eligible member to role",
            "Add member to role completed (PIM activation)",
        ]
        .contains(&op);
        let role = p
            .get("role.displayname")
            .or_else(|| p.get("rolename"))
            .map(strings)
            .unwrap_or_default();
        let global = role
            .iter()
            .any(|r| r == "global administrator" || r == "company administrator")
            || p.get("role.templateid").is_some_and(|v| {
                strings(v)
                    .iter()
                    .any(|s| s == "62e90394-69f5-4237-9190-012177145e10")
            });
        hit("M365-ID-001", role_change && global);
        hit(
            "M365-ID-002",
            role_change
                && !global
                && role
                    .iter()
                    .any(|r| r.ends_with("administrator") || r == "privileged role administrator"),
        );
        hit(
            "M365-ID-003",
            [
                "Consent to application",
                "Consent to application.",
                "Add delegated permission grant",
                "Add app role assignment to service principal",
            ]
            .contains(&op),
        );
        hit(
            "M365-ID-004",
            [
                "Add service principal credentials",
                "Add application password",
                "Add application certificate",
                "Update application – Certificates and secrets management",
            ]
            .contains(&op)
                || (["Update application", "Update service principal"].contains(&op)
                    && has(
                        &p,
                        &["keydescription", "keycredentials", "passwordcredentials"],
                    )),
        );
        hit(
            "M365-ID-005",
            [
                "User registered security info",
                "User deleted security info",
                "User changed default security info",
                "Admin registered security info",
                "Admin deleted security info",
            ]
            .contains(&op),
        );
        hit(
            "M365-ID-006",
            [
                "Update security defaults",
                "Update conditional access policy",
                "Update authorization policy",
            ]
            .contains(&op)
                && ((is_false(p.get("isenabled"))
                    || p.get("conditionalaccesspolicy")
                        .is_some_and(|v| v["state"] == "disabled"))
                    || p.get("state")
                        .is_some_and(|v| v.as_str() == Some("disabled"))),
        );
    }
    if e.source == "graph:signIns" {
        hit(
            "M365-ID-007",
            ["riskLevelDuringSignIn", "riskLevelAggregated"]
                .iter()
                .any(|k| {
                    e.metadata
                        .get(*k)
                        .and_then(Value::as_str)
                        .is_some_and(|v| ["medium", "high"].contains(&v))
                }),
        );
    }
    // One finding per independent pair gives a stable deduplication identity
    // regardless of which source arrives or is evaluated first.
    for other in &correlated {
        matches.push(("M365-EXO-006", vec![e.id.clone(), other.clone()]));
    }
    if spo && ["FileDownloaded", "FileDeleted", "FileRecycled"].contains(&op) {
        let evidence = volume(e, history, settings);
        if !evidence.is_empty() {
            matches.push((
                if op == "FileDownloaded" {
                    "M365-SPO-003"
                } else {
                    "M365-SPO-005"
                },
                evidence,
            ));
        }
    }
    if spo {
        let suspicious = [
            "AnonymousLinkCreated",
            "SharingInvitationCreated",
            "SiteCollectionAdminAdded",
            "FileDeleted",
        ];
        if suspicious.contains(&op) {
            let now = Instant::parse(&e.timestamp).ok();
            let related: Vec<_> = history
                .iter()
                .filter(|h| {
                    same_scope(e, h)
                        && suspicious.contains(&h.operation.as_str())
                        && Instant::parse(&h.timestamp)
                            .ok()
                            .zip(now)
                            .is_some_and(|(t, n)| t <= n && n.0 - t.0 < 3_600_000)
                })
                .collect();
            if related
                .iter()
                .map(|h| h.operation.as_str())
                .chain(std::iter::once(op))
                .collect::<BTreeSet<_>>()
                .len()
                >= 3
            {
                matches.push((
                    "M365-SPO-007",
                    related
                        .iter()
                        .map(|h| h.id.clone())
                        .chain(std::iter::once(e.id.clone()))
                        .collect(),
                ));
            }
        }
    }
    let registry = registry();
    matches
        .into_iter()
        .map(|(id, evidence)| {
            let r = registry.iter().find(|r| r.id == id).unwrap();
            Finding {
                rule_id: id.into(),
                source:e.source.clone(),rule_version:r.version,
                coverage_limitations:vec!["Only supported operations and fields are evaluated. Missing, delayed or inaccessible data can hide activity.".into()],
                severity: if (id == "M365-EXO-002"
                    && has(&p, &["forwardto", "redirectto", "forwardasattachmentto"]))
                    || (id == "M365-SPO-001"
                        && e.metadata
                            .get("SiteUrl")
                            .and_then(Value::as_str)
                            .is_some_and(|s| settings.sensitive_sites.iter().any(|x| x == s)))
                {
                    "CRITICAL".into()
                } else {
                    r.severity.into()
                },
                resource: e
                    .target_id
                    .clone()
                    .or_else(|| e.actor_upn.clone())
                    .unwrap_or_else(|| "unknown resource".into()),
                evidence,
                explanation: r.description.into(),
                confidence: r.confidence,
            }
        })
        .collect()
}

fn sharing_weakened(e: &SecurityEvent) -> bool {
    let rank = |v: &Value| match v.as_str().unwrap_or("").to_ascii_lowercase().as_str() {
        "disabled" => Some(0),
        "existingexternalusersharingonly" => Some(1),
        "externalusersharingonly" => Some(2),
        "externaluserandguestsharing" => Some(3),
        _ => None,
    };
    e.metadata
        .get("ModifiedProperties")
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items.iter().any(|p| {
                p["Name"]
                    .as_str()
                    .is_some_and(|n| n.eq_ignore_ascii_case("sharingCapability"))
                    && rank(&p["NewValue"])
                        .zip(rank(&p["OldValue"]))
                        .is_some_and(|(new, old)| new > old)
            })
        })
}

fn audit_reduced(e: &SecurityEvent) -> bool {
    e.metadata
        .get("ModifiedProperties")
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items.iter().any(|p| {
                if !p["Name"].as_str().is_some_and(|n| {
                    ["auditadmin", "auditdelegate", "auditowner"]
                        .contains(&n.to_ascii_lowercase().as_str())
                }) {
                    return false;
                }
                let old = strings(&decode(&p["OldValue"]));
                let new = strings(&decode(&p["NewValue"]));
                !p["NewValue"].is_null() && old.iter().any(|s| !new.contains(s))
            })
        })
}

/// Operation registry is versioned with each rule. Entitlement and observed
/// delivery are tracked separately by capability records and stored events.
fn operations(family: &str, n: u32) -> Vec<&'static str> {
    match (family, n) {
        ("EXO", 1) => vec!["Set-Mailbox"],
        ("EXO", 2 | 6) => vec!["New-InboxRule", "Set-InboxRule", "UpdateInboxRules"],
        ("EXO", 3) => vec![
            "Add-MailboxPermission",
            "Add-RecipientPermission",
            "Set-Mailbox",
        ],
        ("EXO", 4) => vec!["New-TransportRule", "Set-TransportRule"],
        ("EXO", 5) => vec![
            "Set-Mailbox",
            "Set-OrganizationConfig",
            "Set-MailboxAuditBypassAssociation",
        ],
        ("SPO", 1) => vec!["AnonymousLinkCreated"],
        ("SPO", 2) => vec![
            "SharingInvitationCreated",
            "SharingSet",
            "AddedToSecureLink",
        ],
        ("SPO", 3) => vec!["FileDownloaded"],
        ("SPO", 4) => vec![
            "SiteCollectionAdminAdded",
            "SiteCollectionAdminAddedByApplication",
            "AddedToGroup",
        ],
        ("SPO", 5) => vec!["FileDeleted", "FileRecycled"],
        ("SPO", 6) => vec!["SharingPolicyChanged", "Set-SPOTenant", "Set-SPOSite"],
        ("SPO", 7) => vec![
            "AnonymousLinkCreated",
            "SharingInvitationCreated",
            "SiteCollectionAdminAdded",
            "FileDeleted",
        ],
        ("ID", 1 | 2) => vec![
            "Add member to role",
            "Add member to role.",
            "Add eligible member to role",
            "Add member to role completed (PIM activation)",
        ],
        ("ID", 3) => vec![
            "Consent to application",
            "Consent to application.",
            "Add delegated permission grant",
            "Add app role assignment to service principal",
        ],
        ("ID", 4) => vec![
            "Add service principal credentials",
            "Add application password",
            "Add application certificate",
            "Update application – Certificates and secrets management",
            "Update application",
            "Update service principal",
        ],
        ("ID", 5) => vec![
            "User registered security info",
            "User deleted security info",
            "User changed default security info",
            "Admin registered security info",
            "Admin deleted security info",
        ],
        ("ID", 6) => vec![
            "Update security defaults",
            "Update conditional access policy",
            "Update authorization policy",
        ],
        ("ID", 7) => vec!["SignIn"],
        _ => vec![],
    }
}
