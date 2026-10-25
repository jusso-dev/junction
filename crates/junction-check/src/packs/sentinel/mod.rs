//! `sentinel` pack: is Microsoft Sentinel set up, watched and affordable.
//!
//! Workspaces come from [`workspaces::discover`]. Every check except
//! `sentinel.workspace` is `not_applicable` when no workspace in scope has
//! Sentinel (Sentinel has no Microsoft 365 licence to declare).
use crate::check::{ApiRequirement, Check, CheckMeta, Evaluation, Finding, Requirements};
use crate::context::CheckContext;
use crate::model::{CheckKind, Level, Pack, Severity};
use junction_watch::clock::Instant;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

pub mod workspaces;

use workspaces::{
    ONBOARDING, RESOURCE_GRAPH, discover, invalid_config, readable_subscriptions, scope,
};

pub fn checks() -> Vec<Arc<dyn Check>> {
    vec![
        Arc::new(SentinelWorkspace),
        Arc::new(Connectors),
        Arc::new(RulesEnabled),
        Arc::new(IncidentsStale),
        Arc::new(IngestionCost),
        Arc::new(Retention),
        Arc::new(HealthAuditing),
        Arc::new(Automation),
    ]
}

const DATA_CONNECTORS: ApiRequirement = ApiRequirement {
    operation: "sentinel.securityinsights.data_connectors.list",
    permissions: &["Microsoft Sentinel Reader"],
};
const ALERT_RULES: ApiRequirement = ApiRequirement {
    operation: "sentinel.securityinsights.alert_rules.list",
    permissions: &["Microsoft Sentinel Reader"],
};
const INCIDENTS: ApiRequirement = ApiRequirement {
    operation: "sentinel.securityinsights.incidents.list",
    permissions: &["Microsoft Sentinel Reader"],
};
const AUTOMATION_RULES: ApiRequirement = ApiRequirement {
    operation: "sentinel.securityinsights.automation_rules.list",
    permissions: &["Microsoft Sentinel Reader"],
};
const TABLES: ApiRequirement = ApiRequirement {
    operation: "azure.log_analytics.tables.list_by_workspace",
    permissions: &["Log Analytics Reader"],
};
const LOG_QUERY: ApiRequirement = ApiRequirement {
    operation: "azure.log_analytics_query.query.execute",
    permissions: &["Log Analytics Reader"],
};

const CONNECTOR_TABLES_KQL: &str = include_str!("../../../queries/sentinel/connector_tables.kql");
const RULE_HEALTH_KQL: &str = include_str!("../../../queries/sentinel/rule_health.kql");
const USAGE_KQL: &str = include_str!("../../../queries/sentinel/usage.kql");
const HEALTH_AUDIT_KQL: &str = include_str!("../../../queries/sentinel/health_audit.kql");

fn plural(n: usize, word: &str) -> String {
    format!("{n} {word}{}", if n == 1 { "" } else { "s" })
}

/// Return early with the finding when no Sentinel workspace is in scope.
macro_rules! sentinel_workspaces {
    ($ctx:expr) => {
        match scope($ctx).await? {
            Ok(workspaces) => workspaces,
            Err(finding) => return Ok(finding),
        }
    };
}

/// The workspace GUID for Log Analytics queries; returns `unknown` early when missing.
macro_rules! customer_id {
    ($workspace:expr) => {
        match $workspace.customer_id.as_deref() {
            Some(guid) => guid,
            None => {
                return Ok(Finding::unknown(
                    "workspace_id_missing",
                    format!(
                        "Resource Graph did not return the workspace id (customerId) of {}, so its logs cannot be queried.",
                        $workspace.name
                    ),
                ));
            }
        }
    };
}

/// String values of the first column named `column`.
fn column(rows: &[Value], column: &str) -> Vec<String> {
    rows.iter()
        .filter_map(|r| r.get(column).and_then(Value::as_str).map(str::to_owned))
        .collect()
}

// ---------------------------------------------------------------- workspace

pub const WORKSPACE: CheckMeta = CheckMeta {
    id: "sentinel.workspace",
    title: "Microsoft Sentinel is onboarded to a Log Analytics workspace",
    pack: Pack::Sentinel,
    kind: CheckKind::Automated,
    severity: Severity::High,
    effort: Level::Medium,
    impact: Level::High,
    description: "Finds Log Analytics workspaces in the selected subscriptions ([packs.sentinel] subscriptions or workspaces, else every subscription Resource Graph can read) and reads each workspace's Sentinel onboarding state. Without a SIEM, sign-in, audit and alert data is not kept or correlated in one place.",
    requires: Requirements {
        apis: &[RESOURCE_GRAPH, ONBOARDING],
        licences: &[],
    },
    remediation: "Onboard Microsoft Sentinel to a central Log Analytics workspace (Microsoft Sentinel > Create > select the workspace), ideally one workspace per tenant in the region that holds your data. If Sentinel lives in a subscription this identity cannot read, grant Reader there or list the workspace in [packs.sentinel] workspaces.",
    links: &[
        "https://learn.microsoft.com/azure/sentinel/quickstart-onboard",
        "https://learn.microsoft.com/azure/sentinel/best-practices-workspace-architecture",
    ],
    references: &[],
    manual: None,
};

crate::check!(SentinelWorkspace, &WORKSPACE, workspace);

async fn workspace(ctx: &CheckContext) -> Evaluation {
    let d = discover(ctx).await?;
    if !d.invalid.is_empty() {
        return Ok(invalid_config(&d.invalid));
    }
    let listed: Vec<Value> = d
        .workspaces
        .iter()
        .map(|w| {
            json!({
                "workspace": w.name,
                "subscription": w.subscription_id,
                "resource_group": w.resource_group,
                "sentinel": d.sentinel.contains(w),
            })
        })
        .collect();
    let data = json!({
        "workspaces": listed,
        "sentinel_workspaces": d.sentinel.len(),
        "not_found": d.not_found,
        "unreadable": d.unreadable,
    });
    if d.workspaces.is_empty() {
        if !d.not_found.is_empty() {
            return Ok(Finding::unknown(
                "workspace_not_found",
                format!(
                    "Resource Graph returned none of the configured workspaces ({}). Check the ids in [packs.sentinel] workspaces and grant Reader on them.",
                    d.not_found.join(", ")
                ),
            )
            .data(data));
        }
        let subscriptions = readable_subscriptions(ctx).await?;
        if subscriptions == 0 {
            return Ok(Finding::unknown(
                "no_subscriptions",
                "No Azure subscriptions are readable, so Sentinel workspaces cannot be found. Grant Reader on the subscriptions that hold the Sentinel workspace and re-run.",
            )
            .data(data));
        }
        return Ok(Finding::fail(format!(
            "No Log Analytics workspace in {} readable subscription{}, so Microsoft Sentinel is not set up.",
            subscriptions,
            if subscriptions == 1 { "" } else { "s" }
        ))
        .data(data));
    }
    let mut notes = String::new();
    if !d.not_found.is_empty() {
        notes.push_str(&format!(" Not found: {}.", d.not_found.join(", ")));
    }
    if !d.unreadable.is_empty() {
        notes.push_str(&format!(
            " Onboarding state not readable for {}.",
            d.unreadable.join(", ")
        ));
    }
    let finding = if d.sentinel.is_empty() {
        Finding::fail(format!(
            "{} in scope, none with Microsoft Sentinel.{notes}",
            plural(d.workspaces.len(), "Log Analytics workspace")
        ))
    } else {
        let names: Vec<&str> = d.sentinel.iter().map(|w| w.name.as_str()).collect();
        Finding::pass(format!(
            "Microsoft Sentinel is onboarded to {} of {}: {}.{notes}",
            d.sentinel.len(),
            plural(d.workspaces.len(), "workspace"),
            names.join(", ")
        ))
    };
    Ok(finding.data(data))
}

// ---------------------------------------------------------------- connectors

pub const CONNECTORS: CheckMeta = CheckMeta {
    id: "sentinel.connectors",
    title: "Entra ID, Defender XDR, Office 365 and Azure Activity data reach Sentinel",
    pack: Pack::Sentinel,
    kind: CheckKind::Automated,
    severity: Severity::High,
    effort: Level::Low,
    impact: Level::High,
    description: "Reads each Sentinel workspace's data connectors and checks which key tables received data in the last 7 days (configurable `days`): Entra ID sign-in (SigninLogs) and audit (AuditLogs) logs, Microsoft Defender XDR, Office 365 (OfficeActivity) and Azure Activity. A source counts as connected when its connector exists or its tables have data. These are the core Microsoft sources; most are free to ingest.",
    requires: Requirements {
        apis: &[RESOURCE_GRAPH, ONBOARDING, DATA_CONNECTORS, LOG_QUERY],
        licences: &[],
    },
    remediation: "In Microsoft Sentinel > Content hub, install the Microsoft Entra ID, Microsoft Defender XDR, Microsoft 365 and Azure Activity solutions, then open each data connector and connect it. Entra ID sign-in and audit logs are sent through Entra ID diagnostic settings; Azure Activity through an Azure Policy assignment. Azure Activity, Office 365 audit logs and Defender XDR incidents and alerts are free to ingest; Entra ID logs and raw Defender XDR events are billed, offset by the Microsoft 365 E5 data grant.",
    links: &[
        "https://learn.microsoft.com/azure/sentinel/connect-data-sources",
        "https://learn.microsoft.com/azure/sentinel/billing#free-data-sources",
        "https://learn.microsoft.com/azure/sentinel/connect-azure-active-directory",
    ],
    references: &[],
    manual: None,
};

crate::check!(Connectors, &CONNECTORS, connectors);

/// A data source the check expects, found by connector kind or table activity.
struct Feed {
    name: &'static str,
    kinds: &'static [&'static str],
    tables: &'static [&'static str],
    cost: &'static str,
}

const ENTRA_COST: &str = "billed per GB; the Microsoft 365 E5, A5, F5 and G5 data grant covers it up to 5 MB per user per day";

const FEEDS: &[Feed] = &[
    Feed {
        name: "Entra ID sign-in logs",
        kinds: &[],
        tables: &["SigninLogs"],
        cost: ENTRA_COST,
    },
    Feed {
        name: "Entra ID audit logs",
        kinds: &[],
        tables: &["AuditLogs"],
        cost: ENTRA_COST,
    },
    Feed {
        name: "Microsoft Defender XDR",
        kinds: &["MicrosoftThreatProtection"],
        tables: &[
            "AlertInfo",
            "DeviceEvents",
            "EmailEvents",
            "IdentityLogonEvents",
            "CloudAppEvents",
        ],
        cost: "incidents and alerts are free; raw advanced hunting events are billed per GB",
    },
    Feed {
        name: "Office 365",
        kinds: &["Office365"],
        tables: &["OfficeActivity"],
        cost: "free to ingest",
    },
    Feed {
        name: "Azure Activity",
        kinds: &[],
        tables: &["AzureActivity"],
        cost: "free to ingest",
    },
];

async fn connectors(ctx: &CheckContext) -> Evaluation {
    let id = CONNECTORS.id;
    let days: u32 = ctx.setting(id, "days", 7);
    let span = format!("P{days}D");
    let workspaces = sentinel_workspaces!(ctx);
    // feed name -> workspaces where it was seen (and how).
    let mut seen: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let mut kinds_by_ws = BTreeMap::new();
    for w in &workspaces {
        let connectors = ctx.list_with(DATA_CONNECTORS.operation, w.params()).await?;
        let kinds: BTreeSet<String> = column(&connectors, "kind").into_iter().collect();
        let guid = customer_id!(w);
        let tables: BTreeSet<String> = column(
            &ctx.log_query(guid, CONNECTOR_TABLES_KQL, Some(&span))
                .await?,
            "TableName",
        )
        .into_iter()
        .collect();
        for feed in FEEDS {
            let by_kind = feed.kinds.iter().any(|k| kinds.contains(*k));
            let by_table = feed.tables.iter().any(|t| tables.contains(*t));
            if by_kind || by_table {
                let via = match (by_kind, by_table) {
                    (true, true) => "connector and data",
                    (true, false) => "connector",
                    _ => "data",
                };
                seen.entry(feed.name)
                    .or_default()
                    .push(format!("{} ({via})", w.name));
            }
        }
        kinds_by_ws.insert(w.name.clone(), kinds);
    }
    let feeds: Vec<Value> = FEEDS
        .iter()
        .map(|f| {
            json!({
                "source": f.name,
                "connected": seen.contains_key(f.name),
                "workspaces": seen.get(f.name).cloned().unwrap_or_default(),
                "cost": f.cost,
            })
        })
        .collect();
    let missing: Vec<&Feed> = FEEDS
        .iter()
        .filter(|f| !seen.contains_key(f.name))
        .collect();
    let data = json!({ "sources": feeds, "connector_kinds": kinds_by_ws, "days": days });
    let finding = if missing.is_empty() {
        Finding::pass(format!(
            "All {} key Microsoft sources reach Sentinel.",
            FEEDS.len()
        ))
    } else {
        let list: Vec<String> = missing
            .iter()
            .map(|f| format!("{} ({})", f.name, f.cost))
            .collect();
        Finding::fail(format!(
            "No connector or data in the last {days} days for {}: {}.",
            plural(missing.len(), "source"),
            list.join("; ")
        ))
    };
    Ok(finding.data(data).affected(missing.iter().map(|f| f.name)))
}

// ---------------------------------------------------------------- rules

pub const RULES_ENABLED: CheckMeta = CheckMeta {
    id: "sentinel.rules_enabled",
    title: "At least ten analytics rules are enabled in Sentinel",
    pack: Pack::Sentinel,
    kind: CheckKind::Automated,
    severity: Severity::High,
    effort: Level::Medium,
    impact: Level::High,
    description: "Counts enabled Scheduled and near-real-time (NRT) analytics rules and the Fusion rule across Sentinel workspaces, and lists rules whose latest SentinelHealth run failed (when health monitoring is on). Sentinel only raises incidents for what its rules look for. Threshold `min` (default 10).",
    requires: Requirements {
        apis: &[RESOURCE_GRAPH, ONBOARDING, ALERT_RULES, LOG_QUERY],
        licences: &[],
    },
    remediation: "In Microsoft Sentinel > Content hub, install the solutions for your connected sources (Microsoft Entra ID, Microsoft 365, Microsoft Defender XDR) and enable their analytics rule templates; keep the Fusion (advanced multistage attack detection) rule on. Fix or disable rules that fail, as shown in Analytics > Rule health once health monitoring is enabled.",
    links: &[
        "https://learn.microsoft.com/azure/sentinel/detect-threats-built-in",
        "https://learn.microsoft.com/azure/sentinel/monitor-analytics-rule-integrity",
    ],
    references: &[],
    manual: None,
};

crate::check!(RulesEnabled, &RULES_ENABLED, rules_enabled);

async fn rules_enabled(ctx: &CheckContext) -> Evaluation {
    let id = RULES_ENABLED.id;
    let min: usize = ctx.setting(id, "min", 10);
    let workspaces = sentinel_workspaces!(ctx);
    let mut counts: BTreeMap<&str, usize> = [("Scheduled", 0), ("NRT", 0), ("Fusion", 0)].into();
    let mut disabled = 0;
    let mut per_ws = vec![];
    let mut failing = vec![];
    let mut health_read = true;
    for w in &workspaces {
        let rules = ctx.list_with(ALERT_RULES.operation, w.params()).await?;
        let mut enabled = 0;
        for rule in &rules {
            let kind = rule.get("kind").and_then(Value::as_str).unwrap_or("");
            let on = rule.pointer("/properties/enabled").and_then(Value::as_bool) == Some(true);
            match counts.get_mut(kind) {
                Some(count) if on => {
                    *count += 1;
                    enabled += 1;
                }
                Some(_) => disabled += 1,
                None => {}
            }
        }
        per_ws.push(json!({"workspace": w.name, "enabled": enabled, "rules": rules.len()}));
        // Rule health is supporting evidence only: unreadable health never changes the status.
        let health = match w.customer_id.as_deref() {
            Some(guid) => ctx.log_query(guid, RULE_HEALTH_KQL, Some("P7D")).await.ok(),
            None => None,
        };
        match health {
            Some(rows) => failing.extend(
                column(&rows, "RuleName")
                    .into_iter()
                    .map(|r| format!("{}/{r}", w.name)),
            ),
            None => health_read = false,
        }
    }
    let total: usize = counts.values().sum();
    let data = json!({
        "enabled_scheduled": counts["Scheduled"],
        "enabled_nrt": counts["NRT"],
        "fusion_enabled": counts["Fusion"] > 0,
        "enabled_total": total,
        "disabled": disabled,
        "min": min,
        "workspaces": per_ws,
        "failing_rules": failing,
        "rule_health_read": health_read,
    });
    let detail = format!(
        "{} enabled ({} Scheduled, {} NRT, Fusion {})",
        plural(total, "analytics rule"),
        counts["Scheduled"],
        counts["NRT"],
        if counts["Fusion"] > 0 { "on" } else { "off" }
    );
    let finding = if total == 0 {
        Finding::fail("No analytics rules are enabled, so Sentinel raises no incidents of its own.")
    } else if total < min {
        Finding::warn(format!("{detail}; at least {min} are expected."))
    } else if !failing.is_empty() {
        Finding::warn(format!(
            "{detail}, but {} failed on the latest run.",
            plural(failing.len(), "rule")
        ))
    } else {
        Finding::pass(format!("{detail}."))
    };
    Ok(finding.data(data).affected(failing))
}

// ---------------------------------------------------------------- incidents

pub const INCIDENTS_STALE: CheckMeta = CheckMeta {
    id: "sentinel.incidents_stale",
    title: "Open Sentinel incidents are assigned and worked within 48 hours",
    pack: Pack::Sentinel,
    kind: CheckKind::Automated,
    severity: Severity::Medium,
    effort: Level::Low,
    impact: Level::Medium,
    description: "Lists incidents that are not Closed and flags those unassigned for longer than 48 hours (configurable `hours`) after creation, or not updated for longer than that, by severity. Stale High or Medium incidents fail; stale Low or Informational incidents warn. Alerts nobody looks at do not protect anyone.",
    requires: Requirements {
        apis: &[RESOURCE_GRAPH, ONBOARDING, INCIDENTS],
        licences: &[],
    },
    remediation: "Triage the listed incidents in Microsoft Sentinel > Incidents: assign an owner, set the status and close what is benign. Add an automation rule that assigns new High and Medium incidents to the on-call analyst, and review the queue daily.",
    links: &[
        "https://learn.microsoft.com/azure/sentinel/investigate-incidents",
        "https://learn.microsoft.com/azure/sentinel/automate-incident-handling-with-automation-rules",
    ],
    references: &[],
    manual: None,
};

crate::check!(IncidentsStale, &INCIDENTS_STALE, incidents_stale);

const SEVERITIES: [&str; 4] = ["High", "Medium", "Low", "Informational"];

fn has_owner(properties: &Value) -> bool {
    ["objectId", "assignedTo", "email", "userPrincipalName"]
        .iter()
        .any(|k| {
            properties
                .pointer(&format!("/owner/{k}"))
                .and_then(Value::as_str)
                .is_some_and(|v| !v.is_empty())
        })
}

async fn incidents_stale(ctx: &CheckContext) -> Evaluation {
    let id = INCIDENTS_STALE.id;
    let hours: u64 = ctx.setting(id, "hours", 48);
    let limit = Duration::from_secs(hours * 3600);
    let now = ctx.now();
    let workspaces = sentinel_workspaces!(ctx);
    let mut open: BTreeMap<&str, usize> = SEVERITIES.iter().map(|s| (*s, 0)).collect();
    let mut stale: BTreeMap<&str, usize> = open.clone();
    let mut affected = vec![];
    let mut undated = 0;
    for w in &workspaces {
        let mut parameters = w.params();
        parameters["$filter"] = json!("properties/status ne 'Closed'");
        let incidents = ctx.list_with(INCIDENTS.operation, parameters).await?;
        for incident in &incidents {
            let p = &incident["properties"];
            if p.get("status").and_then(Value::as_str) == Some("Closed") {
                continue;
            }
            let severity = p.get("severity").and_then(Value::as_str).unwrap_or("");
            let Some(severity) = SEVERITIES.iter().copied().find(|s| *s == severity) else {
                continue;
            };
            *open.get_mut(severity).expect("severity") += 1;
            let age = |key: &str| {
                p.get(key)
                    .and_then(Value::as_str)
                    .and_then(|t| Instant::parse(t).ok())
                    .map(|t| now.since(t))
            };
            let (Some(created), Some(modified)) =
                (age("createdTimeUtc"), age("lastModifiedTimeUtc"))
            else {
                undated += 1;
                continue;
            };
            let reason = if !has_owner(p) && created > limit {
                "unassigned"
            } else if modified > limit {
                "untouched"
            } else {
                continue;
            };
            *stale.get_mut(severity).expect("severity") += 1;
            let number = p
                .get("incidentNumber")
                .map(|n| n.to_string())
                .unwrap_or_else(|| "?".into());
            affected.push(format!("{} #{number} ({severity}, {reason})", w.name));
        }
    }
    let total_open: usize = open.values().sum();
    let total_stale: usize = stale.values().sum();
    let by_severity: BTreeMap<&str, Value> = SEVERITIES
        .iter()
        .map(|s| (*s, json!({"open": open[s], "stale": stale[s]})))
        .collect();
    let data = json!({
        "open": total_open,
        "stale": total_stale,
        "hours": hours,
        "by_severity": by_severity,
        "undated": undated,
    });
    let urgent = stale["High"] + stale["Medium"];
    let breakdown: Vec<String> = SEVERITIES
        .iter()
        .filter(|s| stale[*s] > 0)
        .map(|s| format!("{} {s}", stale[s]))
        .collect();
    let finding = if total_stale == 0 {
        Finding::pass(format!(
            "{} open; none unassigned or untouched for more than {hours} hours.",
            plural(total_open, "incident")
        ))
    } else {
        let text = format!(
            "{} of {total_open} open incidents unassigned or untouched for more than {hours} hours ({}).",
            total_stale,
            breakdown.join(", ")
        );
        if urgent > 0 {
            Finding::fail(text)
        } else {
            Finding::warn(text)
        }
    };
    Ok(finding.data(data).affected(affected))
}

// ---------------------------------------------------------------- cost

pub const INGESTION_COST: CheckMeta = CheckMeta {
    id: "sentinel.ingestion_cost",
    title: "Sentinel ingestion cost is known and noisy tables use cheaper log plans",
    pack: Pack::Sentinel,
    kind: CheckKind::Automated,
    severity: Severity::Low,
    effort: Level::Medium,
    impact: Level::Low,
    description: "Sums billable GB per table over 30 days from the Usage table, estimates the monthly cost at the pay-as-you-go analytics price (data/sentinel-pricing.yaml, or [packs.sentinel] price_per_gb and currency), and suggests noisy tables on the Analytics plan (for example CommonSecurityLog, Syslog and custom _CL tables, over `min_gb`, default 1 GB) that could move to Basic or Auxiliary logs. Warns when there are suggestions or the estimate exceeds `monthly_budget`. Estimate only: Junction never changes table plans.",
    requires: Requirements {
        apis: &[RESOURCE_GRAPH, ONBOARDING, LOG_QUERY, TABLES],
        licences: &[],
    },
    remediation: "Review the suggested tables. If no analytics rule depends on them, move them to the Basic or Auxiliary plan (Log Analytics workspace > Tables > Manage table) or filter them with a data collection rule transformation. Basic and Auxiliary logs cost less to ingest but charge per query, keep 30 days interactive and cannot drive most analytics rules. Consider a commitment tier once daily ingestion is steady above 100 GB.",
    links: &[
        "https://learn.microsoft.com/azure/sentinel/billing",
        "https://learn.microsoft.com/azure/azure-monitor/logs/data-platform-logs#table-plans",
        "https://learn.microsoft.com/azure/sentinel/billing-reduce-costs",
    ],
    references: &[],
    manual: None,
};

crate::check!(IngestionCost, &INGESTION_COST, ingestion_cost);

/// The bundled price data (`data/sentinel-pricing.yaml`).
#[derive(Debug, Clone, Deserialize)]
pub struct Pricing {
    pub currency: String,
    pub region: String,
    pub meter: String,
    pub price_per_gb: f64,
    pub basic_per_gb: f64,
    pub auxiliary_per_gb: f64,
    pub source: String,
    pub pricing_page: String,
    pub as_of: String,
}

pub fn pricing() -> &'static Pricing {
    static PARSED: OnceLock<Pricing> = OnceLock::new();
    PARSED.get_or_init(|| {
        serde_saphyr::from_str(include_str!("../../../data/sentinel-pricing.yaml"))
            .expect("data/sentinel-pricing.yaml")
    })
}

/// Built-in tables that commonly carry high-volume, low-value events and
/// support the Basic and Auxiliary plans. Custom `_CL` tables also qualify.
const PLAN_CANDIDATES: &[&str] = &[
    "CommonSecurityLog",
    "Syslog",
    "ContainerLogV2",
    "AppTraces",
    "StorageBlobLogs",
];

fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

async fn ingestion_cost(ctx: &CheckContext) -> Evaluation {
    let id = INGESTION_COST.id;
    let prices = pricing();
    let configured: Option<f64> = ctx.pack_setting("sentinel", "price_per_gb", None);
    let price = configured.unwrap_or(prices.price_per_gb);
    let currency: String = ctx.pack_setting("sentinel", "currency", prices.currency.clone());
    let min_gb: f64 = ctx.setting(id, "min_gb", 1.0);
    let budget: Option<f64> = ctx.setting(id, "monthly_budget", None);
    let workspaces = sentinel_workspaces!(ctx);
    let mut tables = vec![];
    let mut suggestions = vec![];
    for w in &workspaces {
        let guid = customer_id!(w);
        let usage = ctx.log_query(guid, USAGE_KQL, Some("P30D")).await?;
        let plans: BTreeMap<String, String> = ctx
            .list_with(TABLES.operation, w.params())
            .await?
            .iter()
            .filter_map(|t| {
                Some((
                    t.get("name")?.as_str()?.to_owned(),
                    t.pointer("/properties/plan")?.as_str()?.to_owned(),
                ))
            })
            .collect();
        for row in &usage {
            let (Some(table), Some(gb)) = (
                row.get("DataType").and_then(Value::as_str),
                row.get("BillableGB").and_then(Value::as_f64),
            ) else {
                continue;
            };
            let plan = plans.get(table).map(String::as_str);
            let candidate = PLAN_CANDIDATES.contains(&table) || table.ends_with("_CL");
            if candidate && plan == Some("Analytics") && gb >= min_gb {
                suggestions.push(format!(
                    "{}/{table}: {gb:.1} GB, about {currency} {:.0} a month at the analytics price",
                    w.name,
                    gb * price
                ));
            }
            tables.push((
                w.name.clone(),
                table.to_owned(),
                gb,
                plan.map(str::to_owned),
            ));
        }
    }
    tables.sort_by(|a, b| b.2.total_cmp(&a.2).then_with(|| a.1.cmp(&b.1)));
    let total_gb: f64 = tables.iter().map(|t| t.2).sum();
    let monthly = total_gb * price;
    let top: Vec<Value> = tables
        .iter()
        .take(10)
        .map(|(ws, table, gb, plan)| {
            json!({
                "workspace": ws,
                "table": table,
                "billable_gb_30d": round2(*gb),
                "plan": plan,
                "estimated_monthly": round2(gb * price),
            })
        })
        .collect();
    let data = json!({
        "billable_gb_30d": round2(total_gb),
        "estimated_monthly": round2(monthly),
        "currency": currency,
        "top_tables": top,
        "suggestions": suggestions,
        "monthly_budget": budget,
        "price": {
            "price_per_gb": price,
            "source": if configured.is_some() { "configuration ([packs.sentinel] price_per_gb)".to_owned() } else { format!("data/sentinel-pricing.yaml: {}, {}, retail price as of {}", prices.meter, prices.region, prices.as_of) },
            "basic_per_gb": prices.basic_per_gb,
            "auxiliary_per_gb": prices.auxiliary_per_gb,
            "price_data_currency": prices.currency,
            "price_data_as_of": prices.as_of,
            "price_data_source": prices.source,
            "pricing_page": prices.pricing_page,
        },
        "note": "Estimate only: pay-as-you-go analytics price for 30 days of billable ingestion. Commitment tiers, agreements and data grants are not applied. Junction never changes table plans.",
    });
    let assumption = if configured.is_some() {
        format!("{currency} {price}/GB (configured)")
    } else {
        format!(
            "{currency} {price}/GB, {} pay-as-you-go retail price as of {}",
            prices.region, prices.as_of
        )
    };
    let summary = format!(
        "{total_gb:.1} GB billable in 30 days, an estimated {currency} {monthly:.2} a month at {assumption}."
    );
    let over_budget = budget.is_some_and(|b| monthly > b);
    let finding = if !suggestions.is_empty() {
        Finding::warn(format!(
            "{summary} {} could move to Basic or Auxiliary logs.",
            plural(suggestions.len(), "noisy table")
        ))
    } else if over_budget {
        Finding::warn(format!(
            "{summary} This is over the configured budget of {currency} {}.",
            budget.unwrap_or_default()
        ))
    } else {
        Finding::pass(summary)
    };
    Ok(finding.data(data).affected(suggestions))
}

// ---------------------------------------------------------------- retention

pub const RETENTION: CheckMeta = CheckMeta {
    id: "sentinel.retention",
    title: "Sentinel workspaces keep data for at least 90 days",
    pack: Pack::Sentinel,
    kind: CheckKind::Automated,
    severity: Severity::Medium,
    effort: Level::Low,
    impact: Level::Medium,
    description: "Compares each Sentinel workspace's default retention, and every table with its own retention, with a minimum (`min_days`, default 90). Analytics tables are judged on interactive retention; Basic and Auxiliary tables on total retention. Intrusions are often found weeks later, and evidence older than retention is gone.",
    requires: Requirements {
        apis: &[RESOURCE_GRAPH, ONBOARDING, TABLES],
        licences: &[],
    },
    remediation: "Set the workspace's data retention to at least 90 days (Log Analytics workspace > Usage and estimated costs > Data retention; Sentinel workspaces include 90 days at no extra cost) and raise the listed tables in Tables > Manage table. Use total (long-term) retention to keep logs 12 months or more, as the ISM expects, at a lower price.",
    links: &[
        "https://learn.microsoft.com/azure/azure-monitor/logs/data-retention-configure",
        "https://learn.microsoft.com/azure/sentinel/billing#data-retention-and-archived-logs-costs",
    ],
    references: &[],
    manual: None,
};

crate::check!(Retention, &RETENTION, retention);

async fn retention(ctx: &CheckContext) -> Evaluation {
    let id = RETENTION.id;
    let min_days: i64 = ctx.setting(id, "min_days", 90);
    let workspaces = sentinel_workspaces!(ctx);
    let mut short = vec![];
    let mut per_ws = vec![];
    for w in &workspaces {
        let Some(days) = w.retention_days else {
            return Ok(Finding::unknown(
                "retention_unreadable",
                format!("Resource Graph did not return the retention of {}.", w.name),
            ));
        };
        if days < min_days {
            short.push(format!("{} ({days} days)", w.name));
        }
        let tables = ctx.list_with(TABLES.operation, w.params()).await?;
        let mut short_tables = 0;
        for t in &tables {
            let p = &t["properties"];
            let name = t.get("name").and_then(Value::as_str).unwrap_or("?");
            let plan = p.get("plan").and_then(Value::as_str).unwrap_or("Analytics");
            let days = if plan == "Analytics" {
                // Tables on the workspace default are covered by the workspace figure.
                if p.get("retentionInDaysAsDefault").and_then(Value::as_bool) != Some(false) {
                    continue;
                }
                p.get("retentionInDays").and_then(Value::as_i64)
            } else {
                p.get("totalRetentionInDays").and_then(Value::as_i64)
            };
            if let Some(days) = days.filter(|d| *d < min_days) {
                short_tables += 1;
                short.push(format!("{}/{name} ({plan}, {days} days)", w.name));
            }
        }
        per_ws.push(json!({
            "workspace": w.name,
            "retention_days": days,
            "tables": tables.len(),
            "short_tables": short_tables,
        }));
    }
    let data = json!({ "min_days": min_days, "workspaces": per_ws });
    let finding = Finding::pass_if(
        short.is_empty(),
        format!("Every Sentinel workspace and table keeps data for at least {min_days} days."),
        format!(
            "Retention is below {min_days} days in {} place{}: {}.",
            short.len(),
            if short.len() == 1 { "" } else { "s" },
            short.join(", ")
        ),
    );
    Ok(finding.data(data).affected(short))
}

// ---------------------------------------------------------------- health

pub const HEALTH_AUDITING: CheckMeta = CheckMeta {
    id: "sentinel.health_auditing",
    title: "Sentinel health and audit monitoring is enabled",
    pack: Pack::Sentinel,
    kind: CheckKind::Automated,
    severity: Severity::Medium,
    effort: Level::Low,
    impact: Level::Medium,
    description: "Queries the SentinelHealth and SentinelAudit tables of each Sentinel workspace for data in the last 30 days (configurable `days`). Without health monitoring, failing connectors and analytics rules go unnoticed; without auditing, changes to rules and settings leave no trail. SentinelAudit only records changes, so a quiet workspace with health data but no audit rows warns rather than fails.",
    requires: Requirements {
        apis: &[RESOURCE_GRAPH, ONBOARDING, LOG_QUERY],
        licences: &[],
    },
    remediation: "In Microsoft Sentinel > Settings > Settings > Auditing and health monitoring, enable it for all resource types (data collection, automation and analytics rules). The data lands in the SentinelHealth and SentinelAudit tables; add an analytics rule that alerts on connector or rule failures.",
    links: &[
        "https://learn.microsoft.com/azure/sentinel/enable-monitoring",
        "https://learn.microsoft.com/azure/sentinel/health-audit",
    ],
    references: &[],
    manual: None,
};

crate::check!(HealthAuditing, &HEALTH_AUDITING, health_auditing);

async fn health_auditing(ctx: &CheckContext) -> Evaluation {
    let id = HEALTH_AUDITING.id;
    let days: u32 = ctx.setting(id, "days", 30);
    let span = format!("P{days}D");
    let workspaces = sentinel_workspaces!(ctx);
    let mut no_health = vec![];
    let mut no_audit = vec![];
    let mut per_ws = vec![];
    for w in &workspaces {
        let guid = customer_id!(w);
        let tables: BTreeSet<String> = column(
            &ctx.log_query(guid, HEALTH_AUDIT_KQL, Some(&span)).await?,
            "TableName",
        )
        .into_iter()
        .collect();
        let health = tables.contains("SentinelHealth");
        let audit = tables.contains("SentinelAudit");
        if !health {
            no_health.push(w.name.clone());
        }
        if !audit {
            no_audit.push(w.name.clone());
        }
        per_ws
            .push(json!({"workspace": w.name, "sentinel_health": health, "sentinel_audit": audit}));
    }
    let data = json!({ "days": days, "workspaces": per_ws });
    let finding = if !no_health.is_empty() {
        Finding::fail(format!(
            "No SentinelHealth data in the last {days} days for {}: health monitoring is off.",
            no_health.join(", ")
        ))
        .affected(no_health)
    } else if !no_audit.is_empty() {
        Finding::warn(format!(
            "Health monitoring is on, but there is no SentinelAudit data in the last {days} days for {}. Auditing is off, or nothing changed.",
            no_audit.join(", ")
        ))
        .affected(no_audit)
    } else {
        Finding::pass(format!(
            "SentinelHealth and SentinelAudit both have data in the last {days} days."
        ))
    };
    Ok(finding.data(data))
}

// ---------------------------------------------------------------- automation

pub const AUTOMATION: CheckMeta = CheckMeta {
    id: "sentinel.automation",
    title: "High severity incidents are routed to a person automatically",
    pack: Pack::Sentinel,
    kind: CheckKind::Automated,
    severity: Severity::Low,
    effort: Level::Low,
    impact: Level::Medium,
    description: "Looks for an enabled automation rule, per Sentinel workspace, that runs on incidents, covers High severity and assigns an owner or runs a playbook. Warn only: a playbook may notify people in ways Junction cannot see, and routing can live outside Sentinel.",
    requires: Requirements {
        apis: &[RESOURCE_GRAPH, ONBOARDING, AUTOMATION_RULES],
        licences: &[],
    },
    remediation: "In Microsoft Sentinel > Automation, create an automation rule triggered when an incident is created, with the condition Severity equals High, that assigns the on-call owner or runs a playbook that pages the on-call analyst (Teams, e-mail or your paging tool).",
    links: &[
        "https://learn.microsoft.com/azure/sentinel/automate-incident-handling-with-automation-rules",
        "https://learn.microsoft.com/azure/sentinel/create-manage-use-automation-rules",
    ],
    references: &[],
    manual: None,
};

crate::check!(Automation, &AUTOMATION, automation);

/// Does an automation rule's top-level severity condition (if any) include High?
fn covers_high(rule: &Value) -> bool {
    let conditions = rule
        .pointer("/properties/triggeringLogic/conditions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    conditions.iter().all(|c| {
        let p = &c["conditionProperties"];
        if p.get("propertyName").and_then(Value::as_str) != Some("IncidentSeverity") {
            return true;
        }
        let high = p
            .get("propertyValues")
            .and_then(Value::as_array)
            .is_some_and(|v| v.iter().any(|s| s.as_str() == Some("High")));
        match p.get("operator").and_then(Value::as_str) {
            Some("Equals") => high,
            Some("NotEquals") => !high,
            _ => true,
        }
    })
}

/// Does the rule assign an owner or run a playbook?
fn routes(rule: &Value) -> bool {
    rule.pointer("/properties/actions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|a| match a.get("actionType").and_then(Value::as_str) {
            Some("RunPlaybook") => true,
            Some("ModifyProperties") => has_owner(&a["actionConfiguration"]),
            _ => false,
        })
}

async fn automation(ctx: &CheckContext) -> Evaluation {
    let workspaces = sentinel_workspaces!(ctx);
    let mut unrouted = vec![];
    let mut per_ws = vec![];
    for w in &workspaces {
        let rules = ctx
            .list_with(AUTOMATION_RULES.operation, w.params())
            .await?;
        let enabled: Vec<&Value> = rules
            .iter()
            .filter(|r| {
                r.pointer("/properties/triggeringLogic/isEnabled")
                    .and_then(Value::as_bool)
                    == Some(true)
                    && r.pointer("/properties/triggeringLogic/triggersOn")
                        .and_then(Value::as_str)
                        == Some("Incidents")
            })
            .collect();
        let routing: Vec<&str> = enabled
            .iter()
            .filter(|r| covers_high(r) && routes(r))
            .map(|r| {
                r.pointer("/properties/displayName")
                    .and_then(Value::as_str)
                    .unwrap_or("?")
            })
            .collect();
        if routing.is_empty() {
            unrouted.push(w.name.clone());
        }
        per_ws.push(json!({
            "workspace": w.name,
            "automation_rules": rules.len(),
            "enabled_incident_rules": enabled.len(),
            "routing_rules": routing,
        }));
    }
    let data = json!({ "workspaces": per_ws });
    let finding = if unrouted.is_empty() {
        Finding::pass(
            "An enabled automation rule assigns an owner or runs a playbook for High severity incidents.",
        )
    } else {
        Finding::warn(format!(
            "No enabled automation rule assigns an owner or runs a playbook for High severity incidents in {}.",
            unrouted.join(", ")
        ))
    };
    Ok(finding.data(data).affected(unrouted))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pricing_data_parses_and_states_its_date() {
        let p = pricing();
        assert!(p.price_per_gb > p.basic_per_gb && p.basic_per_gb > p.auxiliary_per_gb);
        assert_eq!(p.as_of.len(), 10);
        assert!(!p.currency.is_empty() && !p.region.is_empty());
    }

    #[test]
    fn severity_conditions_decide_high_coverage() {
        let rule = |op: &str, values: &[&str]| {
            json!({"properties": {"triggeringLogic": {"conditions": [{
                "conditionType": "Property",
                "conditionProperties": {"propertyName": "IncidentSeverity", "operator": op, "propertyValues": values}
            }]}}})
        };
        assert!(covers_high(&rule("Equals", &["High", "Medium"])));
        assert!(!covers_high(&rule("Equals", &["Low"])));
        assert!(!covers_high(&rule("NotEquals", &["High"])));
        assert!(covers_high(&json!({"properties": {"triggeringLogic": {}}})));
    }
}
