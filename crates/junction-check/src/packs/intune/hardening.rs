//! Local administrator rights, Office macro policy and device compliance.
use super::*;
use crate::check::{CheckMeta, Evaluation, Requirements};
use crate::model::{CheckKind, Level, Pack, Severity};
use std::collections::{BTreeMap, BTreeSet};

const DEVICE_REGISTRATION: ApiRequirement = ApiRequirement {
    operation: "graph.policies.device_registration_policy.get",
    permissions: &["Policy.Read.DeviceConfiguration", "Policy.Read.All"],
};
const COMPLIANCE_POLICIES: ApiRequirement = ApiRequirement {
    operation: "graph.device_management.device_compliance_policies.list",
    permissions: &["DeviceManagementConfiguration.Read.All"],
};
const CATALOG_COMPLIANCE: ApiRequirement = ApiRequirement {
    operation: "graph.device_management.compliance_policies.list",
    permissions: &["DeviceManagementConfiguration.Read.All"],
};
const DEVICE_MANAGEMENT: ApiRequirement = ApiRequirement {
    operation: "graph.device_management.get",
    permissions: &[
        "DeviceManagementConfiguration.Read.All",
        "DeviceManagementServiceConfig.Read.All",
    ],
};
const CA_POLICIES: ApiRequirement = ApiRequirement {
    operation: "graph.identity.conditional_access.policies.list",
    permissions: &["Policy.Read.All"],
};

// ---------------------------------------------------------------- local admin

pub const LOCAL_ADMIN: CheckMeta = CheckMeta {
    id: "intune.local_admin",
    title: "Users are not made local administrators of their devices",
    pack: Pack::Intune,
    kind: CheckKind::Automated,
    severity: Severity::High,
    effort: Level::Low,
    impact: Level::High,
    description: "Reads the Entra ID device registration policy (`azureADJoin.localAdmins.registeringUsers`): by default the user who joins a device to Entra ID becomes a local administrator on it. When registering users are still added, it looks for an assigned Intune account protection or settings catalog policy that replaces the local Administrators group (Local users and groups, action 'Add (Replace)'), which removes them again. Everyday accounts with local admin rights can turn off protections and install anything.",
    requires: Requirements {
        apis: &[DEVICE_REGISTRATION, CONFIG_POLICIES, POLICY_SETTINGS],
        licences: &[],
    },
    remediation: "In Entra ID > Devices > Device settings, set 'Registering user is added as local administrator on the device during Microsoft Entra join' to None, and grant admin rights through 'Microsoft Entra Joined Device Local Administrator' or Windows LAPS instead. With Intune, assign an Account protection > Local user group membership policy that replaces the Administrators group with the approved members.",
    links: &[
        "https://learn.microsoft.com/entra/identity/devices/assign-local-admin",
        "https://learn.microsoft.com/intune/intune-service/protect/endpoint-security-account-protection-policy",
    ],
    references: &[],
    manual: None,
};

crate::check!(LocalAdmin, &LOCAL_ADMIN, local_admin);

/// A policy that replaces (not adds to) the local Administrators group.
fn replaces_administrators(p: &WindowsPolicy) -> bool {
    let lugm = p
        .settings
        .iter()
        .any(|(_, d, _)| d.contains("localusersandgroups_configure"));
    let admins = p
        .settings
        .iter()
        .any(|(_, _, v)| v.ends_with("_desc_administrators"));
    let replace = p
        .settings
        .iter()
        .any(|(_, _, v)| v.ends_with("_action_add_restrict"));
    lugm && admins && replace
}

async fn local_admin(ctx: &CheckContext) -> Evaluation {
    let policy = ctx.get(DEVICE_REGISTRATION.operation, json!({})).await?;
    let Some(local_admins) = policy.pointer("/azureADJoin/localAdmins") else {
        return Ok(Finding::unknown(
            "no_data",
            "The device registration policy did not include azureADJoin.localAdmins.",
        ));
    };
    let membership = local_admins
        .pointer("/registeringUsers/@odata.type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let registering = if membership.ends_with("noDeviceRegistrationMembership") {
        "none"
    } else if membership.ends_with("enumeratedDeviceRegistrationMembership") {
        "selected"
    } else if membership.ends_with("allDeviceRegistrationMembership") {
        "all"
    } else {
        "unknown"
    };
    let selected: Vec<String> = ["users", "groups"]
        .iter()
        .flat_map(|k| {
            local_admins
                .pointer(&format!("/registeringUsers/{k}"))
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        })
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    let mut data = json!({
        "registering_users_added": registering,
        "selected_principals": selected.len(),
        "global_admins_added": local_admins.get("enableGlobalAdmins").and_then(Value::as_bool),
    });
    if registering == "none" {
        return Ok(Finding::pass(
            "Users who join a device to Entra ID are not added as local administrators.",
        )
        .data(data));
    }
    if registering == "unknown" {
        return Ok(Finding::unknown(
            "no_data",
            format!("Unrecognised registeringUsers setting `{membership}`."),
        )
        .data(data));
    }
    // Registering users are added; an Intune policy may replace the group.
    let mut replacing = vec![];
    if ctx.has_feature("intune") != Some(false) {
        let policies = windows_policies(ctx).await?;
        replacing = policies
            .iter()
            .filter(|p| replaces_administrators(p))
            .map(|p| (p.name.clone(), p.scope))
            .collect();
        data["replacing_policies"] = json!(
            replacing
                .iter()
                .map(|(n, s)| json!({"name": n, "assigned_to": s.as_str()}))
                .collect::<Vec<_>>()
        );
    }
    let all_scope: Vec<&String> = replacing
        .iter()
        .filter(|(_, s)| *s == Scope::All)
        .map(|(n, _)| n)
        .collect();
    let who = if registering == "all" {
        "every user who joins a device".to_owned()
    } else {
        format!("{} selected users or groups", selected.len())
    };
    let finding = if !all_scope.is_empty() {
        Finding::pass(format!(
            "Entra ID adds {who} as local administrator, but Intune policy {} replaces the local Administrators group on all devices.",
            all_scope[0]
        ))
    } else if !replacing.is_empty() {
        Finding::warn(format!(
            "Entra ID adds {who} as local administrator; Intune policies replacing the Administrators group are assigned only to groups ({}).",
            replacing
                .iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    } else if registering == "selected" {
        Finding::warn(format!(
            "Entra ID adds {who} as local administrators of the devices they join."
        ))
    } else {
        Finding::fail(format!(
            "Entra ID adds {who} as a local administrator of it, and no Intune policy replaces the local Administrators group."
        ))
    };
    Ok(finding.data(data))
}

// ---------------------------------------------------------------- macros

pub const OFFICE_MACROS: CheckMeta = CheckMeta {
    id: "intune.office_macros",
    title: "Office blocks internet macros and only runs trusted or signed macros",
    pack: Pack::Intune,
    kind: CheckKind::Automated,
    severity: Severity::High,
    effort: Level::Low,
    impact: Level::High,
    description: "Reads the Office settings in assigned Intune settings catalog policies for Word, Excel and PowerPoint: 'Block macros from running in Office files from the Internet' must be enabled and 'VBA Macro Notification Settings' must be 'Disable all without notification' (only Trusted Locations run) or 'Disable all except digitally signed macros'. Administrative template (ADMX) profiles, Cloud Policy and Group Policy are not read: attest with `junction check attest intune.office_macros` if macros are controlled there. Needs Microsoft Intune Plan 1.",
    requires: Requirements {
        apis: &[CONFIG_POLICIES, POLICY_SETTINGS],
        licences: &[],
    },
    remediation: "Create a settings catalog policy (Microsoft Word, Excel and PowerPoint > Options > Security > Trust Center) that enables 'Block macros from running in Office files from the Internet' and sets 'VBA Macro Notification Settings' to 'Disable all without notification' (or 'Disable all except digitally signed macros' for users with a business need), assign it to all users, and keep a small, reviewed exception group.",
    links: &[
        "https://learn.microsoft.com/microsoft-365-apps/security/internet-macros-blocked",
        "https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/essential-eight-maturity-model",
    ],
    references: &["M365-Secure INTUNE-MACRO-001"],
    manual: None,
};

crate::check!(OfficeMacros, &OFFICE_MACROS, office_macros);

const OFFICE_APPS: &[&str] = &[
    "word",
    "excel",
    "powerpoint",
    "access",
    "visio",
    "outlook",
    "publisher",
    "project",
];
const MACRO_CORE_APPS: &[&str] = &["word", "excel", "powerpoint"];

fn office_app(def: &str) -> Option<&'static str> {
    OFFICE_APPS
        .iter()
        .copied()
        .find(|app| def.contains(&format!("{app}16")) || def.contains(&format!("microsoft{app}")))
}

#[derive(Debug, Default)]
struct MacroPosture {
    block_internet: BTreeSet<&'static str>,
    /// 1 enable all, 2 disable with notification, 3 disable except signed,
    /// 4 disable without notification. The strictest assigned value wins.
    vba_mode: BTreeMap<&'static str, u8>,
    policies: Vec<String>,
}

impl MacroPosture {
    fn read(&mut self, p: &WindowsPolicy) {
        let mut touched = false;
        for (parent, def, val) in &p.settings {
            if def.contains("blockmacroexecutionfrominternet")
                && !parent.contains("blockmacroexecutionfrominternet")
                && let Some(app) = office_app(def)
            {
                touched = true;
                if val.ends_with("_1") {
                    self.block_internet.insert(app);
                }
            }
            // The dropdown is a child choice of the vbawarningspolicy toggle.
            if def.contains("vbawarningspolicy")
                && parent.contains("vbawarningspolicy")
                && let Some(app) = office_app(def)
                && let Some(n) = val.rsplit('_').next().and_then(|n| n.parse::<u8>().ok())
                && (1..=4).contains(&n)
            {
                touched = true;
                let e = self.vba_mode.entry(app).or_insert(n);
                *e = (*e).max(n);
            }
        }
        if touched {
            self.policies.push(p.name.clone());
        }
    }
}

async fn office_macros(ctx: &CheckContext) -> Evaluation {
    let id = OFFICE_MACROS.id;
    if let Some(finding) = without_intune(ctx, id) {
        return Ok(finding);
    }
    let policies = windows_policies(ctx).await?;
    let mut posture = MacroPosture::default();
    for p in policies.iter().filter(|p| p.family == "none") {
        posture.read(p);
    }
    let mut no_internet_block = vec![];
    let mut weak_vba = vec![];
    for app in MACRO_CORE_APPS {
        if !posture.block_internet.contains(app) {
            no_internet_block.push(*app);
        }
        match posture.vba_mode.get(app) {
            Some(3 | 4) => {}
            Some(2) => weak_vba.push(format!("{app}: disabled with notification")),
            Some(_) => weak_vba.push(format!("{app}: all macros enabled")),
            None => weak_vba.push(format!("{app}: not set")),
        }
    }
    let data = json!({
        "policies": posture.policies,
        "internet_macros_blocked": posture.block_internet,
        "vba_notification": posture.vba_mode,
    });
    let finding = if posture.policies.is_empty() {
        Finding::fail(format!(
            "No assigned Intune settings catalog policy sets Office macro security. If Cloud Policy or Group Policy controls macros, record that with `junction check attest {id}`."
        ))
    } else if !no_internet_block.is_empty() {
        Finding::fail(format!(
            "Macros in files from the internet are not blocked for {}.",
            no_internet_block.join(", ")
        ))
    } else if !weak_vba.is_empty() {
        Finding::warn(format!(
            "Internet macros are blocked, but VBA macro notification still allows untrusted macros ({}).",
            weak_vba.join("; ")
        ))
    } else {
        Finding::pass(format!(
            "Word, Excel and PowerPoint block internet macros and only run trusted or signed macros ({}).",
            posture.policies.join(", ")
        ))
    };
    let affected: Vec<String> = no_internet_block.iter().map(|a| (*a).to_owned()).collect();
    Ok(finding.data(data).affected(affected))
}

// ---------------------------------------------------------------- compliance

pub const COMPLIANCE_POLICY: CheckMeta = CheckMeta {
    id: "intune.compliance_policy",
    title: "Every platform has a compliance policy and Conditional Access requires compliant devices",
    pack: Pack::Intune,
    kind: CheckKind::Automated,
    severity: Severity::High,
    effort: Level::Medium,
    impact: Level::High,
    description: "Checks that every platform with Intune-managed devices has an assigned compliance policy, that devices with no compliance policy are marked not compliant (`secureByDefault`), and, with Entra ID P1, that an enabled Conditional Access policy for all users and all (or Office 365) apps requires a compliant device. Without that Conditional Access policy noncompliant devices still reach company data. Needs Microsoft Intune Plan 1.",
    requires: Requirements {
        apis: &[
            MANAGED_DEVICES,
            COMPLIANCE_POLICIES,
            CATALOG_COMPLIANCE,
            DEVICE_MANAGEMENT,
            CA_POLICIES,
        ],
        licences: &[],
    },
    remediation: "In Intune > Devices > Compliance, create a compliance policy for each platform in use (minimum OS, encryption, Defender risk level) and assign it to all devices; under Compliance settings mark devices with no compliance policy as Not compliant. Then create a Conditional Access policy for all users and all resources that grants access only to compliant (or hybrid joined) devices, test it in report-only mode and turn it on.",
    links: &[
        "https://learn.microsoft.com/intune/intune-service/protect/device-compliance-get-started",
        "https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-device-compliance",
    ],
    references: &[
        "CIS M365 4.1",
        "M365-Secure INTUNE-COMPLIANCE-001",
        "M365-Secure INTUNE-COMPLIANCE-002",
    ],
    manual: None,
};

crate::check!(CompliancePolicy, &COMPLIANCE_POLICY, compliance_policy);

/// Platform of a device (`operatingSystem`) or policy (`@odata.type`, `platforms`).
fn platform(s: &str) -> Option<&'static str> {
    let s = s.to_ascii_lowercase();
    if s.contains("windows") {
        Some("Windows")
    } else if s.contains("ios") || s.contains("ipados") {
        Some("iOS/iPadOS")
    } else if s.contains("android") || s.contains("aosp") {
        Some("Android")
    } else if s.contains("macos") || s.contains("mac os") {
        Some("macOS")
    } else if s.contains("linux") || s.contains("ubuntu") {
        Some("Linux")
    } else {
        None
    }
}

fn has(v: &Value, pointer: &str, wanted: &[&str]) -> bool {
    v.pointer(pointer)
        .and_then(Value::as_array)
        .is_some_and(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .any(|x| wanted.iter().any(|w| x.eq_ignore_ascii_case(w)))
        })
}

async fn compliance_policy(ctx: &CheckContext) -> Evaluation {
    let id = COMPLIANCE_POLICY.id;
    if let Some(finding) = without_intune(ctx, id) {
        return Ok(finding);
    }
    let devices = managed_devices(ctx).await?;
    let mut in_use: BTreeMap<&str, usize> = BTreeMap::new();
    for d in &devices {
        if let Some(p) = platform(&d.os) {
            *in_use.entry(p).or_default() += 1;
        }
    }
    let classic = ctx
        .list_with(
            COMPLIANCE_POLICIES.operation,
            json!({ "$expand": ["assignments"] }),
        )
        .await?;
    let mut covered: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for p in classic.iter().filter(|p| scope(p) != Scope::None) {
        if let Some(plat) = platform(&text(p, "@odata.type")) {
            covered.entry(plat).or_default().push(name_of(p));
        }
    }
    // Linux compliance policies exist only in the settings catalog (beta).
    if in_use.contains_key("Linux") {
        let catalog = ctx
            .list_with(
                CATALOG_COMPLIANCE.operation,
                json!({ "$expand": ["assignments"] }),
            )
            .await?;
        for p in catalog.iter().filter(|p| scope(p) != Scope::None) {
            if let Some(plat) = platform(&text(p, "platforms")) {
                covered.entry(plat).or_default().push(name_of(p));
            }
        }
    }
    let uncovered: Vec<String> = in_use
        .iter()
        .filter(|(p, _)| !covered.contains_key(*p))
        .map(|(p, n)| format!("{p} ({})", plural(*n, "device")))
        .collect();
    let settings = ctx
        .get(
            DEVICE_MANAGEMENT.operation,
            json!({ "parameters": { "$select": ["settings"] } }),
        )
        .await?;
    let secure_by_default = settings
        .pointer("/settings/secureByDefault")
        .and_then(Value::as_bool);

    // Conditional Access requiring a compliant device (Entra ID P1).
    let ca = if ctx.has_feature("entra_id_p1") == Some(false) {
        None
    } else {
        let policies = ctx.list(CA_POLICIES.operation, json!({})).await?.items;
        let requiring: Vec<&Value> = policies
            .iter()
            .filter(|p| has(p, "/grantControls/builtInControls", &["compliantDevice"]))
            .collect();
        let broad = |p: &&Value| {
            has(p, "/conditions/users/includeUsers", &["All"])
                && has(
                    p,
                    "/conditions/applications/includeApplications",
                    &["All", "Office365"],
                )
        };
        let enforced: Vec<String> = requiring
            .iter()
            .filter(|p| text(p, "state") == "enabled" && broad(p))
            .map(|p| name_of(p))
            .collect();
        let partial: Vec<String> = requiring
            .iter()
            .filter(|p| text(p, "state") != "disabled" && !enforced.contains(&name_of(p)))
            .map(|p| format!("{} ({})", name_of(p), text(p, "state")))
            .collect();
        Some((enforced, partial))
    };

    let noncompliant: Vec<String> = devices
        .iter()
        .filter(|d| d.compliance.eq_ignore_ascii_case("noncompliant"))
        .map(|d| d.name.clone())
        .collect();
    let data = json!({
        "managed_devices": devices.len(),
        "noncompliant_devices": noncompliant.len(),
        "noncompliant": capped(&noncompliant),
        "platforms_in_use": in_use,
        "covered": covered,
        "uncovered": uncovered,
        "secure_by_default": secure_by_default,
        "conditional_access": ca.as_ref().map(|(e, p)| json!({"enforced": e, "partial": p})),
    });
    let mut failures = vec![];
    if covered.is_empty() {
        failures.push("no compliance policy is assigned".to_owned());
    } else if !uncovered.is_empty() {
        failures.push(format!(
            "platforms without an assigned compliance policy: {}",
            uncovered.join(", ")
        ));
    }
    if secure_by_default == Some(false) {
        failures.push("devices with no compliance policy are marked compliant".to_owned());
    }
    let mut warnings = vec![];
    match &ca {
        Some((enforced, partial)) if enforced.is_empty() && partial.is_empty() => failures
            .push("no Conditional Access policy requires a compliant device".to_owned()),
        Some((enforced, partial)) if enforced.is_empty() => warnings.push(format!(
            "Conditional Access requires a compliant device only in report-only or narrowly scoped policies: {}",
            partial.join(", ")
        )),
        _ => {}
    }
    let finding = if !failures.is_empty() {
        Finding::fail(format!("Compliance gaps: {}.", failures.join("; ")))
    } else if !warnings.is_empty() {
        Finding::warn(format!("{}.", warnings.join("; ")))
    } else {
        let gate = match &ca {
            Some((enforced, _)) => format!(
                "; Conditional Access policy {} requires a compliant device",
                enforced[0]
            ),
            None => "; no Entra ID P1, so Conditional Access cannot require compliance".to_owned(),
        };
        Finding::pass(format!(
            "Every platform in use has an assigned compliance policy ({}){gate}.",
            covered.keys().copied().collect::<Vec<_>>().join(", ")
        ))
    };
    let affected: Vec<String> = in_use
        .keys()
        .filter(|p| !covered.contains_key(*p))
        .map(|p| (*p).to_owned())
        .collect();
    Ok(finding.data(data).affected(affected))
}
