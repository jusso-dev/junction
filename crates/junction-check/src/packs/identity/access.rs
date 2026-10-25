//! Security Defaults and Conditional Access: legacy authentication, the
//! baseline, and the break-glass account.
use super::ca;
use super::{
    CA_POLICIES, GLOBAL_ADMIN, GROUP_MEMBERS, PRIVILEGED_ROLES, ROLE_ASSIGNMENTS,
    SECURITY_DEFAULTS, ca_policies, full_list, plural, privileged_users, security_defaults_enabled,
    str_of,
};
use crate::check::{ApiRequirement, CheckMeta, Evaluation, Finding, ManualSpec, Requirements};
use crate::context::CheckContext;
use crate::model::{CheckKind, Level, Pack, Severity};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

const MEMBER_OF: ApiRequirement = ApiRequirement {
    operation: "graph.users.transitive_member_of.list",
    permissions: &["GroupMember.Read.All", "Directory.Read.All"],
};

fn names(policies: &[&Value]) -> Vec<String> {
    policies.iter().map(|p| ca::name(p)).collect()
}

pub const LEGACY_AUTH_BLOCKED: CheckMeta = CheckMeta {
    id: "identity.legacy_auth_blocked",
    title: "Legacy authentication is blocked",
    pack: Pack::Identity,
    kind: CheckKind::Automated,
    severity: Severity::High,
    effort: Level::Low,
    impact: Level::High,
    description: "Passes when Security Defaults are on, or an enabled Conditional Access policy blocks the 'Exchange ActiveSync' and 'Other clients' client app types for all users and all resources. Legacy protocols (IMAP, POP, SMTP AUTH, older Office clients) cannot do MFA, so password spraying against them succeeds even where MFA is required. A report-only or partially scoped policy is a `warn`.",
    requires: Requirements {
        apis: &[SECURITY_DEFAULTS, CA_POLICIES],
        licences: &[],
    },
    remediation: "With Entra ID P1, create a Conditional Access policy: Users = All users (exclude the break-glass account), Target resources = All resources, Conditions > Client apps = Exchange ActiveSync clients and Other clients, Grant = Block access, state On. Without P1, turn on Security Defaults.",
    links: &[
        "https://learn.microsoft.com/entra/identity/conditional-access/policy-block-legacy-authentication",
        "https://learn.microsoft.com/entra/fundamentals/security-defaults",
    ],
    references: &["CIS M365 5.2.2.3"],
    manual: None,
};

crate::check!(LegacyAuthBlocked, &LEGACY_AUTH_BLOCKED, legacy_auth_blocked);

async fn legacy_auth_blocked(ctx: &CheckContext) -> Evaluation {
    if security_defaults_enabled(ctx).await? {
        return Ok(
            Finding::pass("Security Defaults are on, which block legacy authentication.")
                .data(json!({ "security_defaults": true })),
        );
    }
    if ctx.has_feature("entra_id_p1") == Some(false) {
        return Ok(Finding::fail(
            "Security Defaults are off and the tenant has no Entra ID P1 for Conditional Access, so nothing blocks legacy authentication.",
        )
        .data(json!({ "security_defaults": false })));
    }
    let policies = ca_policies(ctx).await?;
    let blocking = |p: &&Value| ca::blocks_legacy_auth(p);
    let full = |p: &&Value| ca::targets_all_users(p) && ca::targets_all_apps(p);
    let enforced: Vec<&Value> = policies
        .iter()
        .filter(|p| ca::is_enabled(p))
        .filter(blocking)
        .collect();
    let complete: Vec<&Value> = enforced.iter().copied().filter(full).collect();
    let report_only: Vec<&Value> = policies
        .iter()
        .filter(|p| ca::is_report_only(p))
        .filter(blocking)
        .collect();
    let data = json!({
        "security_defaults": false,
        "blocking_policies": names(&complete),
        "partial_policies": names(&enforced.iter().copied().filter(|p| !full(p)).collect::<Vec<_>>()),
        "report_only_policies": names(&report_only),
    });
    let finding = if !complete.is_empty() {
        Finding::pass(format!(
            "Legacy authentication is blocked for all users by {}.",
            names(&complete).join(", ")
        ))
    } else if !enforced.is_empty() {
        Finding::warn(format!(
            "Legacy authentication is blocked, but not for all users and all resources ({}).",
            names(&enforced).join(", ")
        ))
    } else if !report_only.is_empty() {
        Finding::warn(format!(
            "The policy blocking legacy authentication is report-only ({}), so nothing is blocked yet.",
            names(&report_only).join(", ")
        ))
    } else {
        Finding::fail(
            "Security Defaults are off and no enabled Conditional Access policy blocks legacy authentication.",
        )
    };
    Ok(finding.data(data))
}

pub const BASELINE: CheckMeta = CheckMeta {
    id: "identity.baseline",
    title: "Security Defaults or a Conditional Access baseline is enforced",
    pack: Pack::Identity,
    kind: CheckKind::Automated,
    severity: Severity::Critical,
    effort: Level::Medium,
    impact: Level::High,
    description: "Without Entra ID P1, Security Defaults must be on. Otherwise, either Security Defaults are on or enabled Conditional Access policies cover the baseline: MFA for all users on all resources, legacy authentication blocked, MFA for every privileged role and, with Entra ID P2, MFA or block on high-risk sign-ins. Parts covered only by report-only policies give `warn`.",
    requires: Requirements {
        apis: &[SECURITY_DEFAULTS, CA_POLICIES],
        licences: &[],
    },
    remediation: "Without Entra ID P1, turn on Security Defaults (Entra admin center > Identity > Overview > Properties > Manage security defaults). With P1, build the baseline from Microsoft's Conditional Access templates (require MFA for all users, block legacy authentication, require MFA for administrators and, with P2, require MFA for risky sign-ins), test in report-only, then switch each policy On and exclude only the break-glass account.",
    links: &[
        "https://learn.microsoft.com/entra/fundamentals/security-defaults",
        "https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-policy-common",
    ],
    references: &[
        "CIS M365 5.2.2.1",
        "CIS M365 5.2.2.2",
        "CIS M365 5.2.2.3",
        "CIS M365 5.2.2.7",
    ],
    manual: None,
};

crate::check!(Baseline, &BASELINE, baseline);

/// One baseline element: met by enabled policies, only with report-only ones
/// counted too, or not at all.
fn element(policies: &[Value], met: impl Fn(&[&Value]) -> bool) -> &'static str {
    let enabled: Vec<&Value> = policies.iter().filter(|p| ca::is_enabled(p)).collect();
    let with_report_only: Vec<&Value> = policies
        .iter()
        .filter(|p| ca::is_enabled(p) || ca::is_report_only(p))
        .collect();
    if met(&enabled) {
        "enforced"
    } else if met(&with_report_only) {
        "report_only"
    } else {
        "missing"
    }
}

async fn baseline(ctx: &CheckContext) -> Evaluation {
    let defaults = security_defaults_enabled(ctx).await?;
    if defaults {
        return Ok(Finding::pass(
            "Security Defaults are on: MFA registration and challenge for all users, admin MFA and legacy authentication blocking.",
        )
        .data(json!({ "security_defaults": true })));
    }
    if ctx.has_feature("entra_id_p1") == Some(false) {
        return Ok(Finding::fail(
            "Security Defaults are off and the tenant has no Entra ID P1 for Conditional Access, so no baseline protects sign-ins.",
        )
        .data(json!({ "security_defaults": false })));
    }
    let policies = ca_policies(ctx).await?;
    let mut elements: Vec<(&str, &str, &str)> = vec![
        (
            "mfa_all_users",
            "MFA for all users",
            element(&policies, |set| {
                set.iter().any(|p| {
                    ca::targets_all_users(p) && ca::targets_all_apps(p) && ca::requires_mfa(p)
                })
            }),
        ),
        (
            "block_legacy_auth",
            "legacy authentication blocked",
            element(&policies, |set| {
                set.iter().any(|p| {
                    ca::blocks_legacy_auth(p) && ca::targets_all_users(p) && ca::targets_all_apps(p)
                })
            }),
        ),
        (
            "mfa_admins",
            "MFA for every privileged role",
            element(&policies, |set| {
                PRIVILEGED_ROLES.iter().all(|(role, _)| {
                    set.iter().any(|p| {
                        ca::targets_all_apps(p) && ca::requires_mfa(p) && ca::covers_role(p, role)
                    })
                })
            }),
        ),
    ];
    if ctx.has_feature("entra_id_p2") == Some(true) {
        elements.push((
            "risky_sign_ins",
            "MFA or block for high-risk sign-ins",
            element(&policies, |set| {
                set.iter().any(|p| {
                    ca::targets_all_users(p)
                        && ca::sign_in_risk_levels(p).contains(&"high")
                        && (ca::requires_mfa(p) || ca::blocks(p))
                })
            }),
        ));
    }
    let of = |state: &str| -> Vec<&str> {
        elements
            .iter()
            .filter(|(_, _, s)| *s == state)
            .map(|(_, label, _)| *label)
            .collect()
    };
    let (missing, report_only) = (of("missing"), of("report_only"));
    let data = json!({
        "security_defaults": false,
        "enabled_policies": policies.iter().filter(|p| ca::is_enabled(p)).count(),
        "report_only_policies": policies.iter().filter(|p| ca::is_report_only(p)).count(),
        "elements": elements
            .iter()
            .map(|(key, _, state)| (key.to_string(), json!(state)))
            .collect::<serde_json::Map<_, _>>(),
    });
    let finding = if !missing.is_empty() {
        Finding::fail(format!(
            "Security Defaults are off and Conditional Access does not enforce: {}.",
            missing.join(", ")
        ))
    } else if !report_only.is_empty() {
        Finding::warn(format!(
            "The Conditional Access baseline is in place, but only in report-only mode for: {}.",
            report_only.join(", ")
        ))
    } else {
        Finding::pass(format!(
            "Conditional Access enforces the baseline ({}).",
            elements
                .iter()
                .map(|(_, label, _)| *label)
                .collect::<Vec<_>>()
                .join(", ")
        ))
    };
    Ok(finding.data(data))
}

pub const BREAK_GLASS: CheckMeta = CheckMeta {
    id: "identity.break_glass",
    title: "An emergency access account is excluded from Conditional Access",
    pack: Pack::Identity,
    kind: CheckKind::Automated,
    severity: Severity::Medium,
    effort: Level::Low,
    impact: Level::Medium,
    description: "Looks for a Global Administrator that no enabled Conditional Access policy applies to (excluded directly, through a group or role, or never included), so the tenant can be recovered when a policy, MFA provider or federation fails. Settings: `accounts` limits the search to the named break-glass UPNs; `min` (default 1) is how many such accounts must exist. Sign-in monitoring for the account is the separate manual check identity.break_glass_monitored.",
    requires: Requirements {
        apis: &[CA_POLICIES, ROLE_ASSIGNMENTS, GROUP_MEMBERS, MEMBER_OF],
        licences: &["entra_id_p1"],
    },
    remediation: "Create two cloud-only emergency access accounts on the tenant's onmicrosoft.com domain with permanent Global Administrator, register FIDO2 security keys for them, and exclude them (ideally through one dedicated group) from every Conditional Access policy. Store the credentials offline, alert on every sign-in and test the accounts regularly.",
    links: &[
        "https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access",
    ],
    references: &["CIS M365 1.1.2"],
    manual: None,
};

crate::check!(BreakGlass, &BREAK_GLASS, break_glass);

async fn break_glass(ctx: &CheckContext) -> Evaluation {
    let id = BREAK_GLASS.id;
    let min: usize = ctx.setting(id, "min", 1);
    let accounts: Vec<String> = ctx.setting(id, "accounts", vec![]);
    let policies = ca_policies(ctx).await?;
    let enabled: Vec<&Value> = policies.iter().filter(|p| ca::is_enabled(p)).collect();
    if enabled.is_empty() {
        return Ok(Finding::not_applicable(
            "no_enabled_policies",
            "No Conditional Access policy is enabled, so there is nothing to exclude an emergency account from (identity.baseline reports the missing policies).",
        ));
    }
    let candidates: Vec<_> = privileged_users(ctx)
        .await?
        .into_iter()
        .filter(|a| a.has_role(GLOBAL_ADMIN))
        .filter(|a| accounts.is_empty() || accounts.iter().any(|u| u.eq_ignore_ascii_case(&a.upn)))
        .collect();
    let groups_used: BTreeSet<&str> = enabled
        .iter()
        .flat_map(|p| ca::referenced_groups(p))
        .collect();
    let mut emergency = vec![];
    let mut covered: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for admin in &candidates {
        let groups: BTreeSet<String> = if groups_used.is_empty() {
            BTreeSet::new()
        } else {
            full_list(
                ctx,
                MEMBER_OF.operation,
                json!({ "user-id": admin.id, "$select": ["id"] }),
            )
            .await?
            .iter()
            .filter_map(|g| str_of(g, "id").map(str::to_owned))
            .collect()
        };
        let applying: Vec<String> = enabled
            .iter()
            .filter(|p| ca::applies_to(p, &admin.id, &admin.roles, &groups))
            .map(|p| ca::name(p))
            .collect();
        if applying.is_empty() {
            emergency.push(admin.upn.clone());
        } else {
            covered.insert(admin.upn.clone(), applying);
        }
    }
    let data = json!({
        "enabled_policies": enabled.len(),
        "global_admins_checked": candidates.len(),
        "configured_accounts": accounts,
        "emergency_accounts": emergency,
        "min": min,
        "policies_applying": covered,
    });
    let finding = if candidates.is_empty() {
        Finding::fail(if accounts.is_empty() {
            "No user holds an active Global Administrator assignment to act as an emergency account.".to_owned()
        } else {
            "None of the configured break-glass accounts holds an active Global Administrator assignment.".to_owned()
        })
    } else if emergency.len() >= min {
        Finding::pass(format!(
            "{} excluded from every enabled Conditional Access policy: {}.",
            plural(
                emergency.len(),
                "Global Administrator is",
                "Global Administrators are"
            ),
            emergency.join(", ")
        ))
    } else {
        Finding::fail(format!(
            "{} excluded from every enabled Conditional Access policy; at least {min} needed. {} checked.",
            plural(
                emergency.len(),
                "Global Administrator is",
                "Global Administrators are"
            ),
            plural(candidates.len(), "account", "accounts"),
        ))
    };
    let affected: Vec<String> = if emergency.len() >= min {
        vec![]
    } else {
        covered.into_keys().collect()
    };
    Ok(finding.data(data).affected(affected))
}

pub const BREAK_GLASS_MONITORED: CheckMeta = CheckMeta {
    severity: Severity::Medium,
    effort: Level::Low,
    impact: Level::Medium,
    links: &[
        "https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access#monitor-sign-in-and-audit-logs",
    ],
    references: &["CIS M365 1.1.2"],
    ..CheckMeta::manual(
        "identity.break_glass_monitored",
        "Break-glass account sign-ins raise an alert",
        Pack::Identity,
        ManualSpec {
            question: "Does every sign-in by an emergency access (break-glass) account raise an alert that someone responds to?",
            guidance: "Send Entra ID sign-in logs to Log Analytics or Microsoft Sentinel and create an alert rule on any successful or failed sign-in by the break-glass accounts (by object id), routed to people who will respond out of hours. Test it whenever the accounts are tested.",
            why_manual: "Alert rules can live in Azure Monitor, Sentinel, Defender XDR or a third-party SIEM; no single API shows whether break-glass sign-ins reach a person.",
        },
    )
};
