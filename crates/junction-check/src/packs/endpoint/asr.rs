//! Endpoint pack: attack surface reduction (ASR) rules.
//!
//! Rule modes come from assigned Intune policies (settings catalog, endpoint
//! security templates and security baselines). When Intune sets no rules, they
//! come from the ASR events devices report to advanced hunting, which covers
//! rules set by Group Policy or other tools. Rules that raise no event cannot be
//! read from device reports, so they are reported as not observed, never as off.
use crate::check::{ApiRequirement, Check, CheckMeta, Evaluation, Finding, Requirements};
use crate::context::{CallFailure, CheckContext};
use crate::model::{CheckKind, Level, Pack, Severity};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

pub fn checks() -> Vec<Arc<dyn Check>> {
    vec![
        Arc::new(AsrRuleState),
        Arc::new(AsrQuickWins),
        Arc::new(AsrAuditNoise),
    ]
}

/// One rule from `data/asr-rules.yaml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsrRule {
    pub guid: String,
    pub name: String,
    /// Settings catalog child setting (after [`CATALOG_PREFIX`]).
    pub intune_setting: String,
    /// Endpoint security template properties, preferred first.
    #[serde(default)]
    pub intune_intent: Vec<String>,
    /// `DeviceEvents` ActionType stem.
    #[serde(default)]
    pub hunting: Option<String>,
    #[serde(default)]
    pub quick_win: bool,
    #[serde(default)]
    pub standard: bool,
    #[serde(default)]
    pub servers_only: bool,
    pub source: String,
}

#[derive(Deserialize)]
struct RuleTable {
    rules: Vec<AsrRule>,
}

/// Every ASR rule, in table order.
pub fn rules() -> &'static [AsrRule] {
    static RULES: OnceLock<Vec<AsrRule>> = OnceLock::new();
    RULES.get_or_init(|| {
        serde_saphyr::from_str::<RuleTable>(include_str!("../../../data/asr-rules.yaml"))
            .expect("embedded ASR rule table is valid")
            .rules
    })
}

fn rule_by_hunting(stem: &str) -> Option<usize> {
    rules()
        .iter()
        .position(|r| r.hunting.as_deref() == Some(stem))
}

/// A rule's mode, weakest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Mode {
    Off,
    Audit,
    Warn,
    Block,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Audit => "audit",
            Self::Warn => "warn",
            Self::Block => "block",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "off" => Some(Self::Off),
            "audit" => Some(Self::Audit),
            "warn" => Some(Self::Warn),
            "block" => Some(Self::Block),
            _ => None,
        }
    }
}

pub const CATALOG_PREFIX: &str =
    "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_";

/// Rule modes set anywhere in a settings catalog policy's `settings`.
pub fn catalog_modes(settings: &Value, out: &mut BTreeMap<usize, Mode>) {
    match settings {
        Value::Object(map) => {
            let id = map.get("settingDefinitionId").and_then(Value::as_str);
            let value = map
                .get("choiceSettingValue")
                .and_then(|c| c.get("value"))
                .and_then(Value::as_str);
            if let (Some(id), Some(value)) = (id, value) {
                let rule = id
                    .strip_prefix(CATALOG_PREFIX)
                    .and_then(|name| rules().iter().position(|r| r.intune_setting == name));
                let mode = value
                    .strip_prefix(id)
                    .and_then(|s| s.strip_prefix('_'))
                    .and_then(Mode::parse);
                if let (Some(rule), Some(mode)) = (rule, mode) {
                    out.insert(rule, mode);
                }
            }
            map.values().for_each(|v| catalog_modes(v, out));
        }
        Value::Array(items) => items.iter().for_each(|v| catalog_modes(v, out)),
        _ => {}
    }
}

/// Rule modes in an endpoint security template's (intent's) settings. Values
/// are `defenderAttackSurfaceType` or `defenderProtectionType`; `userDefined`
/// and `notConfigured` leave the rule unset.
pub fn intent_modes(settings: &[Value]) -> BTreeMap<usize, Mode> {
    let mut found: BTreeMap<usize, (usize, Mode)> = BTreeMap::new();
    for setting in settings {
        let Some(property) = setting
            .get("definitionId")
            .and_then(Value::as_str)
            .and_then(|d| d.rsplit('_').next())
        else {
            continue;
        };
        let Some((rule, priority)) = rules().iter().enumerate().find_map(|(i, r)| {
            r.intune_intent
                .iter()
                .position(|p| p.eq_ignore_ascii_case(property))
                .map(|p| (i, p))
        }) else {
            continue;
        };
        let value = setting
            .get("value")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| {
                let json = setting.get("valueJson").and_then(Value::as_str)?;
                serde_json::from_str::<String>(json).ok()
            });
        let mode = match value.as_deref() {
            Some("block" | "enable") => Mode::Block,
            Some("auditMode") => Mode::Audit,
            Some("warn") => Mode::Warn,
            Some("disable") => Mode::Off,
            _ => continue,
        };
        let slot = found.entry(rule).or_insert((priority, mode));
        if priority < slot.0 {
            *slot = (priority, mode);
        }
    }
    found.into_iter().map(|(r, (_, m))| (r, m)).collect()
}

const CONFIG_POLICIES: ApiRequirement = ApiRequirement {
    operation: "graph.device_management.configuration_policies.list",
    permissions: &["DeviceManagementConfiguration.Read.All"],
};
const INTENTS: ApiRequirement = ApiRequirement {
    operation: "graph.device_management.intents.list",
    permissions: &["DeviceManagementConfiguration.Read.All"],
};
const INTENT_SETTINGS: ApiRequirement = ApiRequirement {
    operation: "graph.device_management.intents.settings.list",
    permissions: &["DeviceManagementConfiguration.Read.All"],
};
const HUNTING: ApiRequirement = ApiRequirement {
    operation: "defender.xdr.advancedhunting.run",
    permissions: &["AdvancedHunting.Read.All"],
};
const GRAPH_HUNTING: ApiRequirement = ApiRequirement {
    operation: "graph.security.run_hunting_query",
    permissions: &["ThreatHunting.Read.All"],
};

const DEVICE_STATE_KQL: &str = include_str!("../../../queries/endpoint/asr_device_state.kql");
const AUDIT_NOISE_KQL: &str = include_str!("../../../queries/endpoint/asr_audit_noise.kql");

/// Endpoint security templates whose settings are read; more are reported as truncated.
const MAX_INTENTS: usize = 50;

const LINKS: &[&str] = &[
    "https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference",
    "https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-deployment",
    "https://learn.microsoft.com/intune/intune-service/protect/endpoint-security-asr-policy",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Intune,
    Devices,
}

/// Where rule modes came from and, per rule, how many policies (Intune) or
/// devices (hunting) are in each mode.
struct Posture {
    source: Source,
    counts: Vec<BTreeMap<Mode, usize>>,
    /// Assigned Intune policies that set at least one rule.
    policies: Vec<String>,
    /// Unassigned settings catalog policies that set rules (they apply to no device).
    unassigned: usize,
    /// Intune was read and sets no rules.
    intune_empty: bool,
    truncated: bool,
}

fn assigned(item: &Value) -> bool {
    item.get("isAssigned").and_then(Value::as_bool) != Some(false)
}

impl Posture {
    fn new(source: Source) -> Self {
        Self {
            source,
            counts: vec![BTreeMap::new(); rules().len()],
            policies: vec![],
            unassigned: 0,
            intune_empty: false,
            truncated: false,
        }
    }

    fn add_policy(&mut self, policy: &Value, modes: BTreeMap<usize, Mode>) {
        if modes.is_empty() {
            return;
        }
        if !assigned(policy) {
            self.unassigned += 1;
            return;
        }
        let name = ["name", "displayName", "id"]
            .iter()
            .find_map(|k| policy.get(*k).and_then(Value::as_str))
            .unwrap_or("(unnamed)");
        self.policies.push(name.to_owned());
        for (rule, mode) in modes {
            *self.counts[rule].entry(mode).or_default() += 1;
        }
    }

    fn modes(&self, rule: usize) -> Vec<Mode> {
        self.counts[rule]
            .iter()
            .filter(|(_, n)| **n > 0)
            .map(|(m, _)| *m)
            .collect()
    }

    fn state(&self, rule: usize) -> &'static str {
        match self.modes(rule).as_slice() {
            [] if self.source == Source::Intune => "not_configured",
            [] => "not_observed",
            [one] => one.as_str(),
            _ => "mixed",
        }
    }

    fn has(&self, rule: usize, mode: Mode) -> bool {
        self.counts[rule].get(&mode).is_some_and(|n| *n > 0)
    }

    fn only_block(&self, rule: usize) -> bool {
        self.modes(rule) == [Mode::Block]
    }

    fn observed(&self) -> bool {
        self.counts.iter().any(|c| c.values().any(|n| *n > 0))
    }

    fn source_name(&self) -> &'static str {
        match self.source {
            Source::Intune => "intune",
            Source::Devices => "device_events",
        }
    }

    fn rule_rows(&self) -> Vec<Value> {
        let unit = match self.source {
            Source::Intune => "policies",
            Source::Devices => "devices",
        };
        rules()
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let counts: Map<String, Value> = self.counts[i]
                    .iter()
                    .map(|(m, n)| (m.as_str().to_owned(), json!(n)))
                    .collect();
                let mut row = json!({
                    "guid": r.guid,
                    "name": r.name,
                    "quick_win": r.quick_win,
                    "state": self.state(i),
                });
                row[unit] = Value::Object(counts);
                row
            })
            .collect()
    }

    fn data(&self, extra: Value) -> Value {
        let mut data = json!({
            "source": self.source_name(),
            "policies": self.policies,
            "unassigned_policies": self.unassigned,
            "truncated": self.truncated,
            "rules": self.rule_rows(),
        });
        if let (Some(d), Value::Object(extra)) = (data.as_object_mut(), extra) {
            d.extend(extra);
        }
        data
    }
}

async fn intune_posture(ctx: &CheckContext) -> Result<Posture, CallFailure> {
    let mut posture = Posture::new(Source::Intune);
    let policies = ctx
        .list(
            CONFIG_POLICIES.operation,
            json!({ "parameters": { "$expand": ["settings"] } }),
        )
        .await?;
    posture.truncated |= policies.truncated;
    for policy in &policies.items {
        let mut modes = BTreeMap::new();
        catalog_modes(policy.get("settings").unwrap_or(&Value::Null), &mut modes);
        posture.add_policy(policy, modes);
    }
    let intents = ctx.list(INTENTS.operation, json!({})).await?;
    posture.truncated |= intents.truncated;
    let intents: Vec<&Value> = intents.items.iter().filter(|i| assigned(i)).collect();
    posture.truncated |= intents.len() > MAX_INTENTS;
    for intent in intents.into_iter().take(MAX_INTENTS) {
        let Some(id) = intent.get("id").and_then(Value::as_str) else {
            continue;
        };
        let settings = ctx
            .list_with(
                INTENT_SETTINGS.operation,
                json!({ "deviceManagementIntent-id": id }),
            )
            .await?;
        posture.add_policy(intent, intent_modes(&settings));
    }
    Ok(posture)
}

async fn device_posture(ctx: &CheckContext) -> Result<Posture, CallFailure> {
    let mut posture = Posture::new(Source::Devices);
    for row in ctx.hunt(DEVICE_STATE_KQL).await? {
        let rule = row
            .get("Rule")
            .and_then(Value::as_str)
            .and_then(rule_by_hunting);
        let mode = row
            .get("Mode")
            .and_then(Value::as_str)
            .and_then(Mode::parse);
        let devices = row.get("Devices").and_then(Value::as_u64).unwrap_or(0) as usize;
        if let (Some(rule), Some(mode)) = (rule, mode) {
            *posture.counts[rule].entry(mode).or_default() += devices;
        }
    }
    Ok(posture)
}

/// Read rule modes from Intune, falling back to device events when Intune is
/// not licensed or sets no rules. `Err(finding)` when neither source can answer.
async fn gather(ctx: &CheckContext) -> Result<Result<Posture, Finding>, CallFailure> {
    let intune = ctx.has_feature("intune") != Some(false);
    let hunting = ctx.has_feature("defender_endpoint") != Some(false)
        && ctx.has_feature("defender_xdr_hunting") != Some(false);
    if !intune && !hunting {
        return Ok(Err(Finding::not_applicable(
            "licence_required",
            "The tenant has neither Microsoft Intune nor Defender for Endpoint with advanced hunting, so ASR rule modes cannot be read.",
        )));
    }
    let mut intune_empty = false;
    if intune {
        let posture = intune_posture(ctx).await?;
        if !posture.policies.is_empty() {
            return Ok(Ok(posture));
        }
        intune_empty = true;
    }
    if !hunting {
        return Ok(Err(Finding::unknown(
            "no_device_source",
            "No assigned Intune policy sets ASR rules. Rules set by Group Policy or other tools can only be read from device events, which need Defender for Endpoint with advanced hunting.",
        )));
    }
    let mut posture = device_posture(ctx).await?;
    posture.intune_empty = intune_empty;
    Ok(Ok(posture))
}

/// GUIDs from `[packs.endpoint] asr_ignore_rules`, lower case.
fn ignored(ctx: &CheckContext) -> Vec<String> {
    ctx.pack_setting::<Vec<String>>("endpoint", "asr_ignore_rules", vec![])
        .into_iter()
        .map(|g| g.to_ascii_lowercase())
        .collect()
}

/// Rules expected on Windows workstations: not server-only and not ignored.
fn applicable(ignored: &[String]) -> Vec<usize> {
    rules()
        .iter()
        .enumerate()
        .filter(|(_, r)| !r.servers_only && !ignored.contains(&r.guid))
        .map(|(i, _)| i)
        .collect()
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

pub const ASR_RULE_STATE: CheckMeta = CheckMeta {
    id: "endpoint.asr_rule_state",
    title: "Attack surface reduction rules are in block mode",
    pack: Pack::Endpoint,
    kind: CheckKind::Automated,
    severity: Severity::Medium,
    effort: Level::Medium,
    impact: Level::High,
    description: "Reports each attack surface reduction rule's mode (block, audit, warn, off) and how many assigned Intune policies set it, read from settings catalog policies, endpoint security templates and security baselines. When Intune sets no rules (for example they come from Group Policy), it reads the latest mode each device reported in advanced hunting over 30 days instead. ASR rules stop the behaviours phishing payloads and macro malware depend on.",
    requires: Requirements {
        apis: &[
            CONFIG_POLICIES,
            INTENTS,
            INTENT_SETTINGS,
            HUNTING,
            GRAPH_HUNTING,
        ],
        licences: &[],
    },
    remediation: "In the Intune admin centre, under Endpoint security > Attack surface reduction, create an Attack Surface Reduction Rules policy for Windows, set every rule to Audit, review the events in the Defender portal for two to four weeks, add narrow per-rule exclusions, then set the rules to Block and assign the policy to all Windows devices. Rules that do not suit the organisation can be listed in `[packs.endpoint] asr_ignore_rules` by GUID.",
    links: LINKS,
    references: &[],
    manual: None,
};

crate::check!(AsrRuleState, &ASR_RULE_STATE, asr_rule_state);

async fn asr_rule_state(ctx: &CheckContext) -> Evaluation {
    let posture = match gather(ctx).await? {
        Ok(p) => p,
        Err(finding) => return Ok(finding),
    };
    let ignored = ignored(ctx);
    let applicable = applicable(&ignored);
    let not_block: Vec<usize> = applicable
        .iter()
        .copied()
        .filter(|i| !posture.only_block(*i))
        .collect();
    let in_block = applicable.len() - not_block.len();
    let any_block = (0..rules().len()).any(|i| posture.has(i, Mode::Block));
    let unobserved = not_block
        .iter()
        .filter(|i| posture.modes(**i).is_empty())
        .count();
    let n = applicable.len();
    let finding = match posture.source {
        Source::Intune if !any_block => Finding::fail(format!(
            "{} ASR rules, but no rule is in block.",
            plural(
                posture.policies.len(),
                "assigned Intune policy sets",
                "assigned Intune policies set"
            )
        )),
        Source::Devices if !posture.observed() && posture.intune_empty => Finding::fail(
            "No assigned Intune policy sets ASR rules and no device reported an ASR event in 30 days, so ASR rules appear to be off.",
        ),
        Source::Devices if !posture.observed() => Finding::warn(
            "No device reported an ASR event in 30 days, so rule modes set outside Intune could not be confirmed.",
        ),
        _ if not_block.is_empty() => Finding::pass(format!(
            "All {n} applicable ASR rules are in block{}.",
            match posture.source {
                Source::Intune => " in assigned Intune policies",
                Source::Devices => " on every device that reported them",
            }
        )),
        Source::Intune => Finding::warn(format!(
            "{in_block} of {n} applicable ASR rules are in block in assigned Intune policies; {} in audit, warn, off, mixed or not configured.",
            plural(not_block.len(), "rule is", "rules are")
        )),
        Source::Devices => Finding::warn(format!(
            "Rules are not set in Intune; device events show {in_block} of {n} applicable ASR rules in block, {} in audit, warn or mixed, and {} with no events in 30 days.",
            not_block.len() - unobserved,
            unobserved
        )),
    };
    let affected: Vec<&str> = not_block
        .iter()
        .map(|i| rules()[*i].name.as_str())
        .collect();
    Ok(finding
        .data(posture.data(json!({ "ignored_rules": ignored })))
        .affected(affected))
}

pub const ASR_QUICK_WINS: CheckMeta = CheckMeta {
    id: "endpoint.asr_quick_wins",
    title: "Quick-win attack surface reduction rules are in block mode",
    pack: Pack::Endpoint,
    kind: CheckKind::Automated,
    severity: Severity::High,
    effort: Level::Low,
    impact: Level::High,
    description: "Checks that five low-impact, high-value ASR rules are in block on Windows devices: block all Office applications from creating child processes, block credential stealing from LSASS, block executable content from email client and webmail, block Win32 API calls from Office macros, and block JavaScript or VBScript from launching downloaded executable content. Other rules warn when off and pass in audit or block. Reads Intune policies, or device events in advanced hunting when Intune sets no rules.",
    requires: Requirements {
        apis: &[
            CONFIG_POLICIES,
            INTENTS,
            INTENT_SETTINGS,
            HUNTING,
            GRAPH_HUNTING,
        ],
        licences: &[],
    },
    remediation: "In the Intune admin centre, under Endpoint security > Attack surface reduction, set the five quick-win rules to Block in a policy assigned to all Windows devices (run them in Audit for a week or two first if you need to find exclusions). Where ASR is set by Group Policy, set the same rule GUIDs to 1 (block) under Microsoft Defender Antivirus > Microsoft Defender Exploit Guard > Attack Surface Reduction. Then turn on the remaining rules, at least in audit.",
    links: LINKS,
    references: &[],
    manual: None,
};

crate::check!(AsrQuickWins, &ASR_QUICK_WINS, asr_quick_wins);

async fn asr_quick_wins(ctx: &CheckContext) -> Evaluation {
    let posture = match gather(ctx).await? {
        Ok(p) => p,
        Err(finding) => return Ok(finding),
    };
    let ignored = ignored(ctx);
    let applicable = applicable(&ignored);
    let device_level = posture.source == Source::Devices;
    // Intune sets nothing and no device raised any ASR event: the rules are off.
    let all_off = device_level && posture.intune_empty && !posture.observed();
    let (mut failing, mut partial, mut unobserved, mut others_off) =
        (vec![], vec![], vec![], vec![]);
    let mut quick = vec![];
    for (i, rule) in rules().iter().enumerate() {
        let state = posture.state(i);
        if rule.quick_win {
            quick.push(json!({ "guid": rule.guid, "name": rule.name, "state": state }));
            let label = format!("{} ({})", rule.name, state.replace('_', " "));
            match state {
                "block" => {}
                "not_observed" if all_off => {
                    failing.push(format!("{} (not configured)", rule.name))
                }
                "not_observed" => unobserved.push(rule.name.clone()),
                // Policies may target different groups; devices are facts.
                "mixed" if posture.has(i, Mode::Block) && !device_level => partial.push(label),
                _ => failing.push(label),
            }
        } else if !device_level
            && applicable.contains(&i)
            && matches!(state, "off" | "not_configured")
        {
            others_off.push(rule.name.clone());
        }
    }
    let total = quick.len();
    let finding = if !failing.is_empty() {
        Finding::fail(format!(
            "{} of {total} quick-win ASR rules not in block{}: {}.",
            failing.len(),
            if device_level && !all_off {
                " on every device"
            } else {
                ""
            },
            failing.join("; ")
        ))
    } else if !unobserved.is_empty() {
        Finding::unknown(
            "not_observed",
            format!(
                "Rules are not set in Intune and {} raised no device events in 30 days, so their mode cannot be read: {}.",
                plural(unobserved.len(), "quick-win rule", "quick-win rules"),
                unobserved.join("; ")
            ),
        )
    } else if !partial.is_empty() {
        Finding::warn(format!(
            "Quick-win rules are in block in some assigned policies but not others: {}.{}",
            partial.join("; "),
            if others_off.is_empty() {
                String::new()
            } else {
                format!(
                    " {} off or not configured.",
                    plural(others_off.len(), "other rule is", "other rules are")
                )
            }
        ))
    } else if !others_off.is_empty() {
        Finding::warn(format!(
            "All {total} quick-win ASR rules are in block; {} off or not configured.",
            plural(others_off.len(), "other rule is", "other rules are")
        ))
    } else {
        Finding::pass(format!("All {total} quick-win ASR rules are in block."))
    };
    let affected: Vec<String> = failing
        .iter()
        .chain(&partial)
        .chain(&unobserved)
        .chain(&others_off)
        .cloned()
        .collect();
    Ok(finding
        .data(json!({
            "source": posture.source_name(),
            "policies": posture.policies,
            "quick_wins": quick,
            "other_rules_off": others_off,
            "ignored_rules": ignored,
            "truncated": posture.truncated,
        }))
        .affected(affected))
}

pub const ASR_AUDIT_NOISE: CheckMeta = CheckMeta {
    id: "endpoint.asr_audit_noise",
    title: "No attack surface reduction rules left in audit mode",
    pack: Pack::Endpoint,
    kind: CheckKind::Automated,
    severity: Severity::Low,
    effort: Level::Low,
    impact: Level::Medium,
    description: "Counts ASR audit events per rule over 7 days from DeviceEvents in advanced hunting, with the devices and top initiating processes. Rules that audit rarely are ready to move to block; noisy rules need exclusions first. A rule in audit only reports what it would have stopped.",
    requires: Requirements {
        apis: &[HUNTING, GRAPH_HUNTING],
        licences: &["defender_endpoint", "defender_xdr_hunting"],
    },
    remediation: "In the Defender portal, open Reports > Attack surface reduction rules and review the audited detections per rule. Add narrow per-rule exclusions for legitimate line-of-business processes, then switch quiet rules to Block in Intune (Endpoint security > Attack surface reduction) or Group Policy. The `quiet_below` setting sets how many weekly events still count as quiet (default 20).",
    links: LINKS,
    references: &[],
    manual: None,
};

crate::check!(AsrAuditNoise, &ASR_AUDIT_NOISE, asr_audit_noise);

async fn asr_audit_noise(ctx: &CheckContext) -> Evaluation {
    let quiet_below: u64 = ctx.setting(ASR_AUDIT_NOISE.id, "quiet_below", 20);
    let rows = ctx.hunt(AUDIT_NOISE_KQL).await?;
    let mut total = 0;
    let mut quiet = vec![];
    let mut audited = vec![];
    let mut summary = vec![];
    for row in &rows {
        let stem = row.get("Rule").and_then(Value::as_str).unwrap_or_default();
        let rule = rule_by_hunting(stem).map(|i| &rules()[i]);
        let name = rule.map_or(stem, |r| r.name.as_str()).to_owned();
        let events = row.get("Events").and_then(Value::as_u64).unwrap_or(0);
        total += events;
        if events < quiet_below {
            quiet.push(name.clone());
        }
        summary.push(json!({
            "guid": rule.map(|r| r.guid.as_str()),
            "name": name,
            "events": events,
            "devices": row.get("Devices").and_then(Value::as_u64).unwrap_or(0),
            "processes": row.get("Processes").cloned().unwrap_or(json!([])),
        }));
        audited.push(name);
    }
    let finding = if audited.is_empty() {
        Finding::pass("No ASR audit events in the last 7 days.")
    } else {
        let next = if quiet.is_empty() {
            "Review the events and add narrow exclusions before moving them to block.".to_owned()
        } else {
            format!(
                "{} fewer than {quiet_below} and can likely move to block: {}.",
                plural(quiet.len(), "rule raised", "rules raised"),
                quiet.join("; ")
            )
        };
        Finding::warn(format!(
            "{} raised {total} audit events in 7 days. {next}",
            plural(
                audited.len(),
                "ASR rule in audit mode",
                "ASR rules in audit mode"
            )
        ))
    };
    Ok(finding
        .data(json!({
            "days": 7,
            "audit_events": total,
            "quiet_below": quiet_below,
            "rules": summary,
            "ready_for_block": quiet,
        }))
        .affected(audited))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_table_is_complete_and_well_formed() {
        let rules = rules();
        assert_eq!(rules.len(), 19);
        let guid =
            regex::Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
                .unwrap();
        let mut seen = std::collections::BTreeSet::new();
        for r in rules {
            assert!(guid.is_match(&r.guid), "{}", r.guid);
            assert!(seen.insert(r.guid.clone()), "duplicate {}", r.guid);
            assert!(
                r.source.starts_with("https://learn.microsoft.com/"),
                "{}",
                r.name
            );
        }
        let quick: Vec<&str> = rules
            .iter()
            .filter(|r| r.quick_win)
            .map(|r| r.guid.as_str())
            .collect();
        assert_eq!(
            quick,
            [
                "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
                "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
                "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",
                "d3e037e1-3eb8-44c8-a917-57927947596d",
                "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b",
            ]
        );
    }

    #[test]
    fn settings_catalog_values_map_to_modes() {
        let base = format!("{CATALOG_PREFIX}blockwin32apicallsfromofficemacros");
        let settings = json!([{
            "settingInstance": {
                "settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules",
                "groupSettingCollectionValue": [{"children": [{
                    "settingDefinitionId": base,
                    "choiceSettingValue": {"value": format!("{base}_audit"), "children": [
                        {"settingDefinitionId": format!("{base}_perruleexclusions"),
                         "simpleSettingCollectionValue": [{"value": "C:\\tools"}]}
                    ]}
                }]}]
            }
        }]);
        let mut modes = BTreeMap::new();
        catalog_modes(&settings, &mut modes);
        let win32 = rules()
            .iter()
            .position(|r| r.guid == "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b")
            .unwrap();
        assert_eq!(
            modes.into_iter().collect::<Vec<_>>(),
            [(win32, Mode::Audit)]
        );
    }

    #[test]
    fn intent_values_map_to_modes_and_prefer_the_newer_property() {
        let def =
            |p: &str| format!("deviceConfiguration--windows10EndpointProtectionConfiguration_{p}");
        let modes = intent_modes(&[
            json!({"definitionId": def("defenderOfficeAppsLaunchChildProcess"), "valueJson": "\"auditMode\""}),
            json!({"definitionId": def("defenderOfficeAppsLaunchChildProcessType"), "value": "block"}),
            json!({"definitionId": def("defenderPreventCredentialStealingType"), "valueJson": "\"enable\""}),
            json!({"definitionId": def("defenderEmailContentExecutionType"), "valueJson": "\"userDefined\""}),
            json!({"definitionId": def("defenderScriptObfuscatedMacroCodeType"), "valueJson": "\"disable\""}),
        ]);
        let named: Vec<(&str, Mode)> = modes
            .into_iter()
            .map(|(i, m)| (rules()[i].guid.as_str(), m))
            .collect();
        assert_eq!(
            named,
            [
                ("d4f940ab-401b-4efc-aadc-ad5f3c50688a", Mode::Block),
                ("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", Mode::Block),
                ("5beb7efe-fd9a-4556-801d-275e5ffc04cc", Mode::Off),
            ]
        );
    }
}
