//! Endpoint pack: Defender for Endpoint protection settings.
//!
//! Per-device settings (tamper, real-time, cloud-delivered and network
//! protection) come from the Defender Vulnerability Management secure
//! configuration assessment; `data/tvm-scids.yaml` maps each setting to its
//! configuration ids. Antivirus mode, EDR in block mode and security
//! intelligence age come from advanced hunting (`queries/endpoint/*.kql`).
//! The automated investigation level has no API and is attested.
use crate::check::{
    ApiRequirement, Check, CheckMeta, Evaluation, Finding, ManualCheck, ManualSpec, Requirements,
};
use crate::context::{CallFailure, CheckContext};
use crate::model::{CheckKind, Level, Pack, Severity};
use junction_watch::clock::Instant;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

pub fn checks() -> Vec<Arc<dyn Check>> {
    vec![
        Arc::new(TamperProtection),
        Arc::new(CloudProtection),
        Arc::new(RealtimeProtection),
        Arc::new(NetworkProtection),
        Arc::new(EdrBlockMode),
        Arc::new(ManualCheck(&AIR_LEVEL)),
        Arc::new(AvDefinitionAge),
        Arc::new(AvMode),
    ]
}

const TVM_ASSESSMENT: ApiRequirement = ApiRequirement {
    operation: "defender.endpoint.machines.list_secure_configurations_assessment_by_machine",
    permissions: &["Vulnerability.Read.All"],
};
const XDR_HUNTING: ApiRequirement = ApiRequirement {
    operation: "defender.xdr.advancedhunting.run",
    permissions: &["AdvancedHunting.Read.All"],
};
/// Fallback used by `ctx.hunt` when the Defender XDR API is refused.
const GRAPH_HUNTING: ApiRequirement = ApiRequirement {
    operation: "graph.security.run_hunting_query",
    permissions: &["ThreatHunting.Read.All"],
};

const TVM_LICENCES: &[&str] = &["defender_endpoint", "defender_vulnerability_management"];
const HUNTING_LICENCES: &[&str] = &[
    "defender_endpoint",
    "defender_vulnerability_management",
    "defender_xdr_hunting",
];

const AV_HEALTH_KQL: &str = include_str!("../../../queries/endpoint/av_health.kql");
const NETWORK_PROTECTION_EVENTS_KQL: &str =
    include_str!("../../../queries/endpoint/network_protection_events.kql");

const DEVICE_HEALTH_LINK: &str = "https://learn.microsoft.com/defender-endpoint/device-health-microsoft-defender-antivirus-health";

// ---------------------------------------------------------------------------
// TVM configuration ids (data)

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScidTable {
    pub settings: BTreeMap<String, ScidSetting>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScidSetting {
    pub title: String,
    pub source: String,
    pub ids: Vec<ScidEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScidEntry {
    pub id: String,
    pub platform: String,
    pub name: String,
}

/// `data/tvm-scids.yaml`.
pub fn scid_table() -> &'static ScidTable {
    static TABLE: OnceLock<ScidTable> = OnceLock::new();
    TABLE.get_or_init(|| {
        serde_saphyr::from_str(include_str!("../../../data/tvm-scids.yaml"))
            .expect("embedded TVM configuration ids are valid")
    })
}

fn setting(name: &str) -> &'static ScidSetting {
    scid_table()
        .settings
        .get(name)
        .unwrap_or_else(|| panic!("data/tvm-scids.yaml has no setting {name}"))
}

// ---------------------------------------------------------------------------
// Row helpers (the TVM export uses camelCase, hunting uses PascalCase)

fn field<'a>(row: &'a Value, camel: &str) -> Option<&'a Value> {
    row.get(camel).filter(|v| !v.is_null()).or_else(|| {
        let mut pascal = camel.to_owned();
        pascal[..1].make_ascii_uppercase();
        row.get(&pascal).filter(|v| !v.is_null())
    })
}

fn text<'a>(row: &'a Value, camel: &str) -> Option<&'a str> {
    field(row, camel)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

fn truthy(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_i64() == Some(1),
        Some(Value::String(s)) => s.eq_ignore_ascii_case("true") || s == "1",
        _ => false,
    }
}

fn device(row: &Value) -> Option<String> {
    text(row, "deviceName")
        .or_else(|| text(row, "deviceId"))
        .map(str::to_owned)
}

/// "all 3 devices", or "the 1 device".
fn all(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("the 1 {noun}")
    } else {
        format!("all {n} {noun}s")
    }
}

/// Whole percent, rounded down so a single failure never shows as 100%.
fn percent(part: usize, total: usize) -> usize {
    (part * 100).checked_div(total).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Settings from the secure configuration assessment

/// Per-device compliance for one setting.
struct Coverage {
    ids: Vec<&'static str>,
    compliant: Vec<String>,
    failing: Vec<String>,
    truncated: bool,
}

impl Coverage {
    fn total(&self) -> usize {
        self.compliant.len() + self.failing.len()
    }
    fn data(&self) -> Value {
        json!({
            "configuration_ids": self.ids,
            "devices_assessed": self.total(),
            "compliant": self.compliant.len(),
            "non_compliant": self.failing.len(),
            "percent_compliant": percent(self.compliant.len(), self.total()),
            "truncated": self.truncated,
        })
    }
}

async fn coverage(ctx: &CheckContext, name: &str) -> Result<Coverage, CallFailure> {
    let ids: Vec<&'static str> = setting(name).ids.iter().map(|e| e.id.as_str()).collect();
    let listing = ctx.list(TVM_ASSESSMENT.operation, json!({})).await?;
    let mut devices: BTreeMap<String, bool> = BTreeMap::new();
    for row in &listing.items {
        let applies = text(row, "configurationId")
            .is_some_and(|id| ids.iter().any(|s| s.eq_ignore_ascii_case(id)))
            && truthy(field(row, "isApplicable"));
        let Some(name) = device(row).filter(|_| applies) else {
            continue;
        };
        let ok = truthy(field(row, "isCompliant"));
        *devices.entry(name).or_insert(true) &= ok;
    }
    let (compliant, failing): (Vec<_>, Vec<_>) = devices.into_iter().partition(|(_, ok)| *ok);
    Ok(Coverage {
        ids,
        compliant: compliant.into_iter().map(|(d, _)| d).collect(),
        failing: failing.into_iter().map(|(d, _)| d).collect(),
        truncated: listing.truncated,
    })
}

/// `fail` when any device is off; `unknown` when nothing was assessed or the
/// listing was cut short; otherwise `None` (every assessed device is on).
fn coverage_problem(c: &Coverage, title: &str) -> Option<Finding> {
    let total = c.total();
    let finding = if total == 0 {
        Finding::unknown(
            "no_assessment",
            format!(
                "No device has a Defender Vulnerability Management assessment for {} ({}). Check that devices are onboarded and have reported in the last day.",
                title.to_lowercase(),
                c.ids.join(", ")
            ),
        )
    } else if !c.failing.is_empty() {
        Finding::fail(format!(
            "{title} is off on {} of {total} devices ({}% compliant).",
            c.failing.len(),
            percent(c.compliant.len(), total)
        ))
        .affected(c.failing.clone())
    } else if c.truncated {
        Finding::unknown(
            "truncated",
            format!(
                "{title} is on for every device read ({total}), but the assessment listing was cut short at the page limit, so the rest are unknown."
            ),
        )
    } else {
        return None;
    };
    Some(finding.data(c.data()))
}

async fn tvm_setting(ctx: &CheckContext, name: &str) -> Evaluation {
    let title = &setting(name).title;
    let c = coverage(ctx, name).await?;
    Ok(coverage_problem(&c, title).unwrap_or_else(|| {
        Finding::pass(format!(
            "{title} is on for {} (100% compliant).",
            all(c.total(), "assessed device")
        ))
        .data(c.data())
    }))
}

pub const TAMPER_PROTECTION: CheckMeta = CheckMeta {
    id: "endpoint.tamper_protection",
    title: "Tamper protection is on for every onboarded device",
    pack: Pack::Endpoint,
    kind: CheckKind::Automated,
    severity: Severity::High,
    effort: Level::Low,
    impact: Level::High,
    description: "Reads the Defender Vulnerability Management secure configuration assessment (GET /api/machines/SecureConfigurationsAssessmentByMachine) for tamper protection (scid-2003 Windows, scid-5092 macOS; see data/tvm-scids.yaml) and reports the percentage of assessed devices compliant. Without tamper protection, malware or a local administrator can switch off Defender Antivirus before acting.",
    requires: Requirements {
        apis: &[TVM_ASSESSMENT],
        licences: TVM_LICENCES,
    },
    remediation: "Turn on tamper protection tenant-wide in the Microsoft Defender portal (Settings > Endpoints > Advanced features > Tamper protection), or with an Intune Endpoint security > Antivirus policy (Windows Security experience profile, TamperProtection = On) for the affected devices.",
    links: &[
        "https://learn.microsoft.com/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection",
    ],
    references: &["M365-Secure MDE-TAMPER-001"],
    manual: None,
};

crate::check!(TamperProtection, &TAMPER_PROTECTION, tamper_protection);

async fn tamper_protection(ctx: &CheckContext) -> Evaluation {
    tvm_setting(ctx, "tamper_protection").await
}

pub const CLOUD_PROTECTION: CheckMeta = CheckMeta {
    id: "endpoint.cloud_protection",
    title: "Cloud-delivered protection is on for every onboarded device",
    pack: Pack::Endpoint,
    kind: CheckKind::Automated,
    severity: Severity::High,
    effort: Level::Low,
    impact: Level::High,
    description: "Reads the Defender Vulnerability Management secure configuration assessment (GET /api/machines/SecureConfigurationsAssessmentByMachine) for cloud-delivered protection (scid-2016 Windows, scid-5094 macOS, scid-6094 Linux; see data/tvm-scids.yaml) and reports the percentage of assessed devices compliant. Cloud protection blocks new malware within seconds; without it Defender relies on local signatures only. The cloud block level is not reported per device by any documented API, so it is named in the remediation rather than scored.",
    requires: Requirements {
        apis: &[TVM_ASSESSMENT],
        licences: TVM_LICENCES,
    },
    remediation: "In an Intune Endpoint security > Antivirus policy, set Allow Cloud Protection = Allowed, Submit Samples Consent = Send safe samples automatically, and Cloud Block Level = High, with Cloud Extended Timeout of 50 seconds. Assign it to the affected devices.",
    links: &[
        "https://learn.microsoft.com/defender-endpoint/enable-cloud-protection-microsoft-defender-antivirus",
        "https://learn.microsoft.com/defender-endpoint/specify-cloud-protection-level-microsoft-defender-antivirus",
    ],
    references: &[],
    manual: None,
};

crate::check!(CloudProtection, &CLOUD_PROTECTION, cloud_protection);

async fn cloud_protection(ctx: &CheckContext) -> Evaluation {
    tvm_setting(ctx, "cloud_protection").await
}

pub const REALTIME_PROTECTION: CheckMeta = CheckMeta {
    id: "endpoint.realtime_protection",
    title: "Real-time protection is on for every onboarded device",
    pack: Pack::Endpoint,
    kind: CheckKind::Automated,
    severity: Severity::High,
    effort: Level::Low,
    impact: Level::High,
    description: "Reads the Defender Vulnerability Management secure configuration assessment (GET /api/machines/SecureConfigurationsAssessmentByMachine) for real-time protection (scid-2012 Windows, scid-5090 macOS, scid-6090 Linux; see data/tvm-scids.yaml) and reports the percentage of assessed devices compliant. Without real-time protection, files are only scanned on demand.",
    requires: Requirements {
        apis: &[TVM_ASSESSMENT],
        licences: TVM_LICENCES,
    },
    remediation: "In an Intune Endpoint security > Antivirus policy, set Allow Realtime Monitoring = Allowed and Allow On Access Protection = Allowed, assign it to the affected devices, and turn on tamper protection so it cannot be switched off locally.",
    links: &[
        "https://learn.microsoft.com/defender-endpoint/configure-real-time-protection-microsoft-defender-antivirus",
    ],
    references: &[],
    manual: None,
};

crate::check!(
    RealtimeProtection,
    &REALTIME_PROTECTION,
    realtime_protection
);

async fn realtime_protection(ctx: &CheckContext) -> Evaluation {
    tvm_setting(ctx, "realtime_protection").await
}

pub const NETWORK_PROTECTION: CheckMeta = CheckMeta {
    id: "endpoint.network_protection",
    title: "Network protection is on in block mode",
    pack: Pack::Endpoint,
    kind: CheckKind::Automated,
    severity: Severity::Medium,
    effort: Level::Low,
    impact: Level::Medium,
    description: "Reads the Defender Vulnerability Management secure configuration assessment (GET /api/machines/SecureConfigurationsAssessmentByMachine) for network protection (scid-96; see data/tvm-scids.yaml). That assessment is compliant in audit and block mode alike, so the check also runs advanced hunting (queries/endpoint/network_protection_events.kql) for ExploitGuardNetworkProtectionAudited events in the last 30 days: a device that logs them is in audit mode (warn). Network protection blocks connections to phishing, malware and command-and-control hosts from any process, not only the browser.",
    requires: Requirements {
        apis: &[TVM_ASSESSMENT, XDR_HUNTING, GRAPH_HUNTING],
        licences: HUNTING_LICENCES,
    },
    remediation: "In an Intune Endpoint security > Antivirus policy (or an attack surface reduction policy), set Enable Network Protection = Enabled (block mode) and assign it to the affected devices. Move audit-mode devices to block mode once the audit events have been reviewed.",
    links: &["https://learn.microsoft.com/defender-endpoint/enable-network-protection"],
    references: &[],
    manual: None,
};

crate::check!(NetworkProtection, &NETWORK_PROTECTION, network_protection);

async fn network_protection(ctx: &CheckContext) -> Evaluation {
    let title = &setting("network_protection").title;
    let c = coverage(ctx, "network_protection").await?;
    if let Some(problem) = coverage_problem(&c, title) {
        return Ok(problem);
    }
    let events = ctx.hunt(NETWORK_PROTECTION_EVENTS_KQL).await?;
    let mut audit = BTreeSet::new();
    let mut blocking = BTreeSet::new();
    for row in &events {
        let Some(name) = device(row) else { continue };
        let count = |key: &str| field(row, key).and_then(Value::as_u64).unwrap_or(0);
        if count("audited") > 0 {
            audit.insert(name);
        } else if count("blocked") > 0 {
            blocking.insert(name);
        }
    }
    let total = c.total();
    let mut data = c.data();
    data["audit_mode"] = json!(audit.len());
    data["block_events_seen"] = json!(blocking.len());
    // The assessment counts audit mode as compliant, so a pass needs positive
    // evidence of block mode: block events and no audit events.
    let finding = if audit.is_empty() && !blocking.is_empty() {
        Finding::pass(format!(
            "Network protection is on for {} (100% compliant); {} logged block events and none logged audit-mode events in the last 30 days.",
            all(total, "assessed device"),
            blocking.len()
        ))
    } else if audit.is_empty() {
        Finding::warn(format!(
            "Network protection is on for {}, but no device logged block or audit events in the last 30 days, so block mode (rather than audit) is not confirmed. Check the policy sets Enabled (block mode).",
            all(total, "assessed device")
        ))
    } else {
        Finding::warn(format!(
            "Network protection is on for {}, but {} of them logged audit-mode events in the last 30 days, so it only audits there. {}% show no audit-mode events.",
            all(total, "assessed device"),
            audit.len(),
            percent(total.saturating_sub(audit.len()), total)
        ))
        .affected(audit)
    };
    Ok(finding.data(data))
}

// ---------------------------------------------------------------------------
// Antivirus state from advanced hunting

/// Defender Antivirus mode, as reported by the device antivirus health data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AvState {
    Active,
    Passive,
    Disabled,
    EdrBlocked,
    PassiveAudit,
    Other,
}

impl AvState {
    fn parse(mode: &str) -> Self {
        match mode {
            "0" => Self::Active,
            "1" => Self::Passive,
            "2" => Self::Disabled,
            "4" => Self::EdrBlocked,
            "5" => Self::PassiveAudit,
            _ => Self::Other,
        }
    }
}

/// One device row from `av_health.kql`.
struct AvDevice {
    name: String,
    mode: Option<AvState>,
    signature_updated: Option<Instant>,
}

async fn av_health(ctx: &CheckContext) -> Result<Vec<AvDevice>, CallFailure> {
    let rows = ctx.hunt(AV_HEALTH_KQL).await?;
    Ok(rows
        .iter()
        .filter_map(|row| {
            let mode = field(row, "avMode").and_then(|v| match v {
                Value::String(s) if !s.is_empty() => Some(AvState::parse(s)),
                Value::Number(n) => Some(AvState::parse(&n.to_string())),
                _ => None,
            });
            Some(AvDevice {
                name: device(row)?,
                mode,
                signature_updated: text(row, "avSignatureUpdateTime")
                    .and_then(|t| Instant::parse(t).ok()),
            })
        })
        .collect())
}

fn no_av_data(what: &str) -> Finding {
    Finding::unknown(
        "no_av_data",
        format!(
            "No device reported {what} in Defender Vulnerability Management (DeviceTvmInfoGathering) in the last 7 days. Check that devices are onboarded and reporting."
        ),
    )
}

pub const EDR_BLOCK_MODE: CheckMeta = CheckMeta {
    id: "endpoint.edr_block_mode",
    title: "EDR in block mode covers devices where Defender Antivirus is passive",
    pack: Pack::Endpoint,
    kind: CheckKind::Automated,
    severity: Severity::Medium,
    effort: Level::Low,
    impact: Level::Medium,
    description: "Runs advanced hunting (queries/endpoint/av_health.kql) over DeviceTvmInfoGathering for each device's Defender Antivirus mode (0 active, 1 passive, 4 EDR in block mode, 5 passive audit). Where a non-Microsoft antivirus is primary, Defender runs passive and EDR in block mode lets Defender still remediate what EDR detects; a device in plain passive or passive audit mode fails. When Defender Antivirus is active everywhere the check passes with a note.",
    requires: Requirements {
        apis: &[XDR_HUNTING, GRAPH_HUNTING],
        licences: &[
            "defender_endpoint_p2",
            "defender_vulnerability_management",
            "defender_xdr_hunting",
        ],
    },
    remediation: "Turn on EDR in block mode in the Microsoft Defender portal (Settings > Endpoints > Advanced features > Enable EDR in block mode). Microsoft recommends it even where Defender Antivirus is the primary antivirus.",
    links: &["https://learn.microsoft.com/defender-endpoint/edr-in-block-mode"],
    references: &[],
    manual: None,
};

crate::check!(EdrBlockMode, &EDR_BLOCK_MODE, edr_block_mode);

async fn edr_block_mode(ctx: &CheckContext) -> Evaluation {
    let devices = av_health(ctx).await?;
    let reported: Vec<&AvDevice> = devices.iter().filter(|d| d.mode.is_some()).collect();
    if reported.is_empty() {
        return Ok(no_av_data("an antivirus mode"));
    }
    let passive: Vec<String> = reported
        .iter()
        .filter(|d| matches!(d.mode, Some(AvState::Passive | AvState::PassiveAudit)))
        .map(|d| d.name.clone())
        .collect();
    let blocked = reported
        .iter()
        .filter(|d| d.mode == Some(AvState::EdrBlocked))
        .count();
    let needing = passive.len() + blocked;
    let data = json!({
        "devices_reporting": reported.len(),
        "passive_without_edr_block": passive.len(),
        "edr_block_mode": blocked,
        "percent_compliant": (needing > 0).then(|| percent(blocked, needing)),
    });
    let finding = if !passive.is_empty() {
        Finding::fail(format!(
            "{} of {needing} devices with Defender Antivirus in passive mode do not run EDR in block mode ({}% compliant).",
            passive.len(),
            percent(blocked, needing)
        ))
        .affected(passive)
    } else if blocked > 0 {
        Finding::pass(format!(
            "EDR in block mode is active on {} where Defender Antivirus is passive (100% compliant).",
            all(blocked, "device")
        ))
    } else {
        Finding::pass(format!(
            "Defender Antivirus is not passive on any of the {} reporting devices, so EDR in block mode is not needed as a fallback. Microsoft still recommends turning it on.",
            reported.len()
        ))
    };
    Ok(finding.data(data))
}

pub const AV_MODE: CheckMeta = CheckMeta {
    id: "endpoint.av_mode",
    title: "Defender Antivirus is active, or another antivirus is declared",
    pack: Pack::Endpoint,
    kind: CheckKind::Automated,
    severity: Severity::High,
    effort: Level::Medium,
    impact: Level::High,
    description: "Runs advanced hunting (queries/endpoint/av_health.kql) over DeviceTvmInfoGathering for each device's Defender Antivirus mode. Devices in passive, passive audit, EDR block or disabled mode rely on another antivirus, which no Defender API reports reliably. Set `third_party_av = true` under [checks.\"endpoint.av_mode\"] when another antivirus is deployed (those devices then pass), or `false` when none is (they fail); left unset, they warn.",
    requires: Requirements {
        apis: &[XDR_HUNTING, GRAPH_HUNTING],
        licences: HUNTING_LICENCES,
    },
    remediation: "Where no other antivirus protects the device, return Defender Antivirus to active mode: remove ForceDefenderPassiveMode (Windows Server) or the expired third-party product, and check that no policy turns Defender Antivirus off. Where another antivirus is primary, turn on EDR in block mode.",
    links: &[
        "https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-compatibility",
        DEVICE_HEALTH_LINK,
    ],
    references: &[],
    manual: None,
};

crate::check!(AvMode, &AV_MODE, av_mode);

async fn av_mode(ctx: &CheckContext) -> Evaluation {
    let third_party: Option<bool> = ctx.setting(AV_MODE.id, "third_party_av", None);
    let devices = av_health(ctx).await?;
    let reported: Vec<&AvDevice> = devices.iter().filter(|d| d.mode.is_some()).collect();
    if reported.is_empty() {
        return Ok(no_av_data("an antivirus mode"));
    }
    let count = |state: AvState| reported.iter().filter(|d| d.mode == Some(state)).count();
    let not_active: Vec<String> = reported
        .iter()
        .filter(|d| !matches!(d.mode, Some(AvState::Active | AvState::Other)))
        .map(|d| d.name.clone())
        .collect();
    let active = count(AvState::Active);
    let known = active + not_active.len();
    let data = json!({
        "devices_reporting": reported.len(),
        "active": active,
        "passive": count(AvState::Passive) + count(AvState::PassiveAudit),
        "edr_block_mode": count(AvState::EdrBlocked),
        "disabled": count(AvState::Disabled),
        "other": count(AvState::Other),
        "percent_active": percent(active, known),
        "third_party_av": third_party,
    });
    let n = not_active.len();
    let finding = if n == 0 {
        Finding::pass(format!(
            "Defender Antivirus is active on {} that report a mode (100%).",
            all(known, "device")
        ))
    } else {
        match third_party {
            Some(true) => Finding::pass(format!(
                "Defender Antivirus is active on {active} of {known} devices ({}%); the other {n} rely on the declared third-party antivirus.",
                percent(active, known)
            )),
            Some(false) => Finding::fail(format!(
                "Defender Antivirus is passive or disabled on {n} of {known} devices and no other antivirus is declared ({}% active).",
                percent(active, known)
            )),
            None => Finding::warn(format!(
                "Defender Antivirus is passive or disabled on {n} of {known} devices ({}% active). Confirm another antivirus protects them and set third_party_av.",
                percent(active, known)
            )),
        }
        .affected(not_active)
    };
    Ok(finding.data(data))
}

pub const AV_DEFINITION_AGE: CheckMeta = CheckMeta {
    id: "endpoint.av_definition_age",
    title: "Antivirus security intelligence is no more than three days old",
    pack: Pack::Endpoint,
    kind: CheckKind::Automated,
    severity: Severity::High,
    effort: Level::Low,
    impact: Level::High,
    description: "Runs advanced hunting (queries/endpoint/av_health.kql) over DeviceTvmInfoGathering for when each device last updated Defender Antivirus security intelligence, and fails any device whose update is older than `max_days` (default 3, set under [checks.\"endpoint.av_definition_age\"]). Stale signatures miss current malware.",
    requires: Requirements {
        apis: &[XDR_HUNTING, GRAPH_HUNTING],
        licences: HUNTING_LICENCES,
    },
    remediation: "Check that the affected devices can reach Microsoft Update or the configured security intelligence source, and that an Intune Antivirus policy sets Signature Update Interval (for example every 4 hours). Investigate devices that have not checked in recently.",
    links: &[
        "https://learn.microsoft.com/defender-endpoint/manage-protection-updates-microsoft-defender-antivirus",
        DEVICE_HEALTH_LINK,
    ],
    references: &[],
    manual: None,
};

crate::check!(AvDefinitionAge, &AV_DEFINITION_AGE, av_definition_age);

async fn av_definition_age(ctx: &CheckContext) -> Evaluation {
    let max_days: u64 = ctx.setting(AV_DEFINITION_AGE.id, "max_days", 3);
    let devices = av_health(ctx).await?;
    let now = ctx.now();
    let ages: Vec<(String, u64)> = devices
        .iter()
        .filter_map(|d| Some((d.name.clone(), d.signature_updated?)))
        .map(|(name, at)| (name, now.since(at).as_secs() / 86_400))
        .collect();
    if ages.is_empty() {
        return Ok(no_av_data("a security intelligence update time"));
    }
    let limit = Duration::from_secs(max_days * 86_400);
    let stale: Vec<String> = devices
        .iter()
        .filter(|d| d.signature_updated.is_some_and(|at| now.since(at) > limit))
        .map(|d| d.name.clone())
        .collect();
    let total = ages.len();
    let current = total - stale.len();
    let data = json!({
        "devices_reporting": total,
        "stale": stale.len(),
        "max_days": max_days,
        "oldest_days": ages.iter().map(|(_, days)| *days).max(),
        "percent_compliant": percent(current, total),
    });
    let finding = if stale.is_empty() {
        Finding::pass(format!(
            "Security intelligence is no more than {max_days} days old on {} (100% compliant).",
            all(total, "reporting device")
        ))
    } else {
        Finding::fail(format!(
            "Security intelligence is older than {max_days} days on {} of {total} devices ({}% compliant).",
            stale.len(),
            percent(current, total)
        ))
        .affected(stale)
    };
    Ok(finding.data(data))
}

// ---------------------------------------------------------------------------
// Automated investigation level (attested)

pub const AIR_LEVEL: CheckMeta = CheckMeta {
    severity: Severity::Medium,
    effort: Level::Low,
    impact: Level::Medium,
    description: "Manual attestation. The automation level of each Defender for Endpoint device group (Full or Semi) and the Automated Investigation advanced feature are portal settings with no public read API, so a person confirms them. Full automation remediates threats without waiting for an analyst; Semi requires approval and is acceptable where someone reviews the Action center daily. No automated response is a gap.",
    requires: Requirements {
        apis: &[],
        licences: &["defender_endpoint_p2"],
    },
    links: &[
        "https://learn.microsoft.com/defender-endpoint/automation-levels",
        "https://learn.microsoft.com/defender-endpoint/configure-automated-investigations-remediation",
    ],
    ..CheckMeta::manual(
        "endpoint.air_level",
        "Automated investigation and remediation runs at Full or Semi automation",
        Pack::Endpoint,
        ManualSpec {
            question: "Is Automated Investigation turned on, and is every Defender for Endpoint device group (including Ungrouped devices) set to Full or Semi automation?",
            guidance: "In the Microsoft Defender portal: 1) Settings > Endpoints > Advanced features: confirm Automated Investigation is On (and Automatically resolve alerts if you use it). 2) Settings > Endpoints > Permissions > Device groups: open each group, including Ungrouped devices, and check Automation level is 'Full - remediate threats automatically' (recommended) or a 'Semi - require approval' level. 'No automated response' fails. In Defender for Business, check Settings > Endpoints > Advanced features > Automated investigation. Answer yes only when every group is Full or Semi.",
            why_manual: "Microsoft publishes no API (Defender for Endpoint, Defender XDR or Microsoft Graph) that reads the device group automation level or the Automated Investigation toggle.",
        },
    )
};
