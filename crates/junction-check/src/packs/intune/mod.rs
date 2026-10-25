//! `intune` pack: patching, local admin rights, disk encryption, macro policy and
//! compliance, read from Intune, Entra ID and Defender Vulnerability Management.
//!
//! Intune reads are gated in code rather than through `requires.licences`, so a
//! tenant without Intune gets `not_applicable` that points at attestation (Group
//! Policy or another MDM may enforce the control), or the attested answer.
//! LAPS passwords and BitLocker keys are never requested: only metadata lists.
use crate::check::{ApiRequirement, Check, Finding};
use crate::context::{CallFailure, CheckContext};
use junction_watch::clock::Instant;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

mod builds;
mod hardening;
mod patching;
mod secrets;

pub use builds::{Release, Update, WindowsBuilds};

pub fn checks() -> Vec<Arc<dyn Check>> {
    vec![
        Arc::new(patching::UpdateRings),
        Arc::new(patching::PatchAge),
        Arc::new(patching::BrowserUpdates),
        Arc::new(secrets::Laps),
        Arc::new(secrets::BitlockerEscrow),
        Arc::new(hardening::LocalAdmin),
        Arc::new(hardening::OfficeMacros),
        Arc::new(hardening::CompliancePolicy),
    ]
}

pub(crate) const PACK: &str = "intune";

const MANAGED_DEVICES: ApiRequirement = ApiRequirement {
    operation: "graph.device_management.managed_devices.list",
    permissions: &["DeviceManagementManagedDevices.Read.All"],
};
const CONFIG_POLICIES: ApiRequirement = ApiRequirement {
    operation: "graph.device_management.configuration_policies.list",
    permissions: &["DeviceManagementConfiguration.Read.All"],
};
const POLICY_SETTINGS: ApiRequirement = ApiRequirement {
    operation: "graph.device_management.configuration_policies.settings.list",
    permissions: &["DeviceManagementConfiguration.Read.All"],
};

/// Managed device properties every check reads (one shared, memoised call).
const DEVICE_FIELDS: &[&str] = &[
    "id",
    "deviceName",
    "operatingSystem",
    "osVersion",
    "complianceState",
    "isEncrypted",
    "azureADDeviceId",
    "lastSyncDateTime",
];

/// Settings of at most this many assigned Windows policies are read.
const POLICY_SETTINGS_LIMIT: usize = 150;

/// `not_applicable` (or the attested answer) when the tenant has no Intune.
fn without_intune(ctx: &CheckContext, id: &str) -> Option<Finding> {
    if ctx.has_feature("intune") != Some(false) {
        return None;
    }
    Some(match ctx.attestation(id) {
        Some(a) => Finding::from_attestation(a),
        None => Finding::not_applicable(
            "licence_required",
            format!(
                "The tenant has no Microsoft Intune licence, so this cannot be read from Intune. If Group Policy or another device manager enforces it, record that with `junction check attest {id}`."
            ),
        ),
    })
}

#[derive(Debug, Clone)]
struct Device {
    name: String,
    os: String,
    os_version: String,
    encrypted: Option<bool>,
    entra_id: String,
    compliance: String,
    last_sync: Option<Instant>,
}

impl Device {
    fn is_windows(&self) -> bool {
        self.os.to_ascii_lowercase().contains("windows")
    }
}

fn text(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn name_of(v: &Value) -> String {
    v.get("displayName")
        .or_else(|| v.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("(unnamed)")
        .to_owned()
}

/// Every Intune managed device.
async fn managed_devices(ctx: &CheckContext) -> Result<Vec<Device>, CallFailure> {
    let rows = ctx
        .list_with(
            MANAGED_DEVICES.operation,
            json!({ "$select": DEVICE_FIELDS }),
        )
        .await?;
    Ok(rows
        .iter()
        .map(|d| Device {
            name: d
                .get("deviceName")
                .or_else(|| d.get("id"))
                .and_then(Value::as_str)
                .unwrap_or("(unnamed)")
                .to_owned(),
            os: text(d, "operatingSystem"),
            os_version: text(d, "osVersion"),
            encrypted: d.get("isEncrypted").and_then(Value::as_bool),
            entra_id: text(d, "azureADDeviceId").to_ascii_lowercase(),
            compliance: text(d, "complianceState"),
            last_sync: d
                .get("lastSyncDateTime")
                .and_then(Value::as_str)
                .and_then(|t| Instant::parse(t).ok()),
        })
        .collect())
}

/// Windows devices that checked in within `[packs.intune] stale_days` (default
/// 30), and how many older ones were left out. Stale devices report stale state.
fn active_windows(ctx: &CheckContext, devices: &[Device]) -> (Vec<Device>, usize) {
    let stale_days: u64 = ctx.pack_setting(PACK, "stale_days", 30);
    let cutoff = ctx.now().minus(days(stale_days));
    let windows = devices.iter().filter(|d| d.is_windows());
    let (active, stale): (Vec<&Device>, Vec<&Device>) =
        windows.partition(|d| d.last_sync.is_none_or(|t| t >= cutoff));
    (active.into_iter().cloned().collect(), stale.len())
}

fn days(n: u64) -> Duration {
    Duration::from_secs(n * 86_400)
}

/// A `YYYY-MM-DD` date or RFC 3339 timestamp.
fn parse_date(value: &str) -> Option<Instant> {
    if value.len() == 10 {
        Instant::parse(&format!("{value}T00:00:00Z")).ok()
    } else {
        Instant::parse(value).ok()
    }
}

/// Who a policy is assigned to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Scope {
    None,
    Groups,
    All,
}

impl Scope {
    fn as_str(self) -> &'static str {
        match self {
            Scope::None => "unassigned",
            Scope::Groups => "groups",
            Scope::All => "all devices or users",
        }
    }
}

/// From a policy's expanded `assignments` (exclusions do not count).
fn scope(policy: &Value) -> Scope {
    let targets = policy
        .get("assignments")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|a| a.pointer("/target/@odata.type").and_then(Value::as_str));
    let mut best = Scope::None;
    for t in targets {
        let s = if t.ends_with("allDevicesAssignmentTarget")
            || t.ends_with("allLicensedUsersAssignmentTarget")
        {
            Scope::All
        } else if t.ends_with("exclusionGroupAssignmentTarget") {
            Scope::None
        } else {
            Scope::Groups
        };
        best = best.max(s);
    }
    best
}

fn template_family(p: &Value) -> String {
    p.pointer("/templateReference/templateFamily")
        .and_then(Value::as_str)
        .unwrap_or("none")
        .to_ascii_lowercase()
}

/// An assigned settings catalog or account protection policy for Windows, with
/// its settings.
struct WindowsPolicy {
    name: String,
    scope: Scope,
    family: String,
    /// `(parent definition id, definition id, value)`, lower case.
    settings: Vec<(String, String, String)>,
}

/// Assigned Windows settings catalog and account protection policies with their
/// settings (shared by the LAPS, local admin and macro checks).
async fn windows_policies(ctx: &CheckContext) -> Result<Vec<WindowsPolicy>, CallFailure> {
    let policies = ctx
        .list_with(
            CONFIG_POLICIES.operation,
            json!({ "$expand": ["assignments"] }),
        )
        .await?;
    let candidates: Vec<&Value> = policies
        .iter()
        .filter(|p| scope(p) != Scope::None)
        .filter(|p| {
            text(p, "platforms")
                .to_ascii_lowercase()
                .contains("windows")
                && matches!(
                    template_family(p).as_str(),
                    "none" | "endpointsecurityaccountprotection"
                )
        })
        .take(POLICY_SETTINGS_LIMIT)
        .collect();
    let fetched = futures_util::future::try_join_all(candidates.iter().map(|p| async move {
        let id = text(p, "id");
        let settings = ctx
            .list_with(
                POLICY_SETTINGS.operation,
                json!({ "deviceManagementConfigurationPolicy-id": id }),
            )
            .await?;
        Ok::<_, CallFailure>(WindowsPolicy {
            name: name_of(p),
            scope: scope(p),
            family: template_family(p),
            settings: flatten_settings(&settings),
        })
    }))
    .await?;
    Ok(fetched)
}

/// Every setting definition id and value in a settings catalog policy, with the
/// parent definition id for context (choice and group children are nested).
fn flatten_settings(settings: &[Value]) -> Vec<(String, String, String)> {
    fn walk(v: &Value, parent: &str, own: &str, out: &mut Vec<(String, String, String)>) {
        match v {
            Value::Array(a) => a.iter().for_each(|x| walk(x, parent, own, out)),
            Value::Object(o) => {
                let (parent, own) = match o.get("settingDefinitionId").and_then(Value::as_str) {
                    Some(d) => (own.to_owned(), d.to_ascii_lowercase()),
                    None => (parent.to_owned(), own.to_owned()),
                };
                if let Some(val) = o.get("value").and_then(Value::as_str) {
                    out.push((parent.clone(), own.clone(), val.to_ascii_lowercase()));
                }
                for (k, child) in o {
                    if k != "value" {
                        walk(child, &parent, &own, out);
                    }
                }
            }
            _ => {}
        }
    }
    let mut out = vec![];
    for s in settings {
        walk(s, "", "", &mut out);
    }
    out
}

/// Dotted numeric version (`130.0.2849.80`), for ordering.
fn version_key(v: &str) -> Vec<u64> {
    v.split('.')
        .map(|p| {
            p.chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .parse()
                .unwrap_or(0)
        })
        .collect()
}

/// `1 device`, `2 devices`.
fn plural(n: usize, noun: &str) -> String {
    format!("{n} {noun}{}", if n == 1 { "" } else { "s" })
}

/// Cap long evidence lists.
const EVIDENCE_CAP: usize = 50;

fn capped<T: Clone>(items: &[T]) -> Vec<T> {
    items.iter().take(EVIDENCE_CAP).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_prefers_all_and_ignores_exclusions() {
        let p = |types: &[&str]| json!({"assignments": types.iter().map(|t| json!({"target": {"@odata.type": t}})).collect::<Vec<_>>()});
        assert_eq!(scope(&p(&[])), Scope::None);
        assert_eq!(
            scope(&p(&["#microsoft.graph.exclusionGroupAssignmentTarget"])),
            Scope::None
        );
        assert_eq!(
            scope(&p(&["#microsoft.graph.groupAssignmentTarget"])),
            Scope::Groups
        );
        assert_eq!(
            scope(&p(&[
                "#microsoft.graph.groupAssignmentTarget",
                "#microsoft.graph.allDevicesAssignmentTarget"
            ])),
            Scope::All
        );
    }

    #[test]
    fn versions_order_numerically() {
        assert!(version_key("130.0.10.1") > version_key("130.0.9.99"));
        assert!(version_key("99.1") < version_key("100.0"));
    }

    #[test]
    fn settings_flatten_with_parents() {
        let flat = flatten_settings(&[json!({"settingInstance": {
            "settingDefinitionId": "a",
            "choiceSettingValue": {"value": "a_1", "children": [
                {"settingDefinitionId": "a_b", "choiceSettingValue": {"value": "a_b_4"}}
            ]}
        }})]);
        assert_eq!(
            flat,
            [
                ("".into(), "a".into(), "a_1".into()),
                ("a".into(), "a_b".into(), "a_b_4".into())
            ]
        );
    }
}
