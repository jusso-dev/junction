//! Administrator accounts: how many Global Administrators, whether admin
//! accounts are separate from daily-use ones, and whether PIM is used.
use super::{
    GLOBAL_ADMIN, GROUP_MEMBERS, ROLE_ASSIGNMENTS, USERS, enabled_users, full_list, plural,
    privileged_role, privileged_users, role_name, str_of,
};
use crate::check::{ApiRequirement, CheckMeta, Evaluation, Finding, Requirements};
use crate::context::CheckContext;
use crate::licensing::LicensingData;
use crate::model::{CheckKind, Level, Pack, Severity};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const GLOBAL_ADMIN_COUNT: CheckMeta = CheckMeta {
    id: "identity.global_admin_count",
    title: "Between two and four Global Administrators",
    pack: Pack::Identity,
    kind: CheckKind::Automated,
    severity: Severity::High,
    effort: Level::Low,
    impact: Level::High,
    description: "Counts active Global Administrator role assignments. One leaves no one to recover the tenant; more than four widens the blast radius of a stolen admin account.",
    requires: Requirements {
        apis: &[ROLE_ASSIGNMENTS],
        licences: &[],
    },
    remediation: "Keep two to four Global Administrators, including a monitored break-glass account. Move day-to-day admins to least-privileged roles (for example User Administrator or Security Administrator) and, with Entra ID P2, make Global Administrator eligible through PIM rather than permanent.",
    links: &["https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices"],
    references: &["CIS M365 1.1.3"],
    manual: None,
};

crate::check!(GlobalAdminCount, &GLOBAL_ADMIN_COUNT, global_admin_count);

async fn global_admin_count(ctx: &CheckContext) -> Evaluation {
    let id = GLOBAL_ADMIN_COUNT.id;
    let min: usize = ctx.setting(id, "min", 2);
    let max: usize = ctx.setting(id, "max", 4);
    let assignments = ctx
        .list_with(
            ROLE_ASSIGNMENTS.operation,
            json!({
                "$filter": format!("roleDefinitionId eq '{GLOBAL_ADMIN}'"),
                "$expand": ["principal"],
            }),
        )
        .await?;
    let mut principals: Vec<String> = assignments
        .iter()
        .filter_map(|a| {
            let p = a.get("principal")?;
            p.get("userPrincipalName")
                .or_else(|| p.get("displayName"))
                .or_else(|| a.get("principalId"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect();
    principals.sort();
    principals.dedup();
    let groups = assignments
        .iter()
        .filter(|a| {
            a.pointer("/principal/@odata.type").and_then(Value::as_str)
                == Some("#microsoft.graph.group")
        })
        .count();
    let count = principals.len();
    let data =
        json!({ "global_admins": count, "group_assignments": groups, "min": min, "max": max });
    let finding = if count < min {
        Finding::fail(format!(
            "{count} Global Administrator{}; at least {min} are needed so the tenant can be recovered.",
            if count == 1 { "" } else { "s" }
        ))
    } else if count > max {
        Finding::fail(format!(
            "{count} Global Administrators; keep no more than {max}."
        ))
    } else if groups > 0 {
        Finding::warn(format!(
            "{count} Global Administrator assignments, {groups} through a group whose members were not counted."
        ))
    } else {
        Finding::pass(format!("{count} Global Administrators."))
    };
    Ok(finding.data(data).affected(principals))
}

const SUBSCRIBED_SKUS: ApiRequirement = ApiRequirement {
    operation: "graph.subscribed_skus.list",
    permissions: &["LicenseAssignment.Read.All", "Organization.Read.All"],
};

pub const SEPARATE_ADMIN_ACCOUNTS: CheckMeta = CheckMeta {
    id: "identity.separate_admin_accounts",
    title: "Admin accounts have no mailbox or Office apps",
    pack: Pack::Identity,
    kind: CheckKind::Automated,
    severity: Severity::Medium,
    effort: Level::Medium,
    impact: Level::Medium,
    description: "Heuristic for dedicated admin accounts: flags privileged role holders licensed for an Exchange Online mailbox or Microsoft 365 Apps (service plans from assigned licences, minus disabled plans). An admin account that reads mail and opens documents is exposed to phishing and malicious attachments every day. A licence is not proof of daily use, so findings are `warn`.",
    requires: Requirements {
        apis: &[ROLE_ASSIGNMENTS, GROUP_MEMBERS, USERS, SUBSCRIBED_SKUS],
        licences: &[],
    },
    remediation: "Give each administrator a separate cloud-only admin account used only for administration, and remove Exchange Online and Microsoft 365 Apps from it (assign Entra ID P1 or P2 only, or disable those service plans). Keep mail and documents on the person's ordinary account.",
    links: &[
        "https://learn.microsoft.com/microsoft-365/admin/add-users/about-admin-roles#security-guidelines-for-assigning-roles",
        "https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices",
    ],
    references: &["CIS M365 1.1.1", "CIS M365 1.1.4"],
    manual: None,
};

crate::check!(
    SeparateAdminAccounts,
    &SEPARATE_ADMIN_ACCOUNTS,
    separate_admin_accounts
);

async fn separate_admin_accounts(ctx: &CheckContext) -> Evaluation {
    let admins = privileged_users(ctx).await?;
    let users: BTreeMap<String, Value> = enabled_users(ctx)
        .await?
        .into_iter()
        .filter_map(|u| Some((str_of(&u, "id")?.to_owned(), u)))
        .collect();
    // skuId -> [(servicePlanId, servicePlanName)]
    let skus: BTreeMap<String, Vec<(String, String)>> =
        full_list(ctx, SUBSCRIBED_SKUS.operation, json!({}))
            .await?
            .iter()
            .filter_map(|sku| {
                let plans = sku
                    .get("servicePlans")?
                    .as_array()?
                    .iter()
                    .filter_map(|p| {
                        Some((
                            str_of(p, "servicePlanId")?.to_ascii_lowercase(),
                            str_of(p, "servicePlanName")?.to_owned(),
                        ))
                    })
                    .collect();
                Some((str_of(sku, "skuId")?.to_ascii_lowercase(), plans))
            })
            .collect();
    let data = LicensingData::embedded();
    let plans_of = |feature: &str| -> Vec<String> {
        data.features
            .get(feature)
            .map(|f| f.service_plans.clone())
            .unwrap_or_default()
    };
    let (mailbox, office) = (plans_of("exchange_online"), plans_of("office_apps"));
    let mut flagged = vec![];
    let (mut checked, mut with_mailbox, mut with_office) = (0, 0, 0);
    for admin in &admins {
        // Disabled accounts are not in the listing and cannot be used.
        let Some(user) = users.get(&admin.id) else {
            continue;
        };
        checked += 1;
        let mut enabled: BTreeSet<&str> = BTreeSet::new();
        for licence in user
            .get("assignedLicenses")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let disabled: BTreeSet<String> = licence
                .get("disabledPlans")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_ascii_lowercase)
                .collect();
            let sku = str_of(licence, "skuId")
                .unwrap_or_default()
                .to_ascii_lowercase();
            for (plan_id, plan) in skus.get(&sku).into_iter().flatten() {
                if !disabled.contains(plan_id) {
                    enabled.insert(plan);
                }
            }
        }
        let has_mailbox = mailbox.iter().any(|p| enabled.contains(p.as_str()));
        let has_office = office.iter().any(|p| enabled.contains(p.as_str()));
        with_mailbox += usize::from(has_mailbox);
        with_office += usize::from(has_office);
        if has_mailbox || has_office {
            flagged.push(admin.upn.clone());
        }
    }
    let data = json!({
        "admins": checked,
        "with_mailbox": with_mailbox,
        "with_office_apps": with_office,
    });
    let finding = if flagged.is_empty() {
        Finding::pass(format!(
            "None of {} has a mailbox or Office apps licence.",
            plural(
                checked,
                "enabled privileged account",
                "enabled privileged accounts"
            )
        ))
    } else {
        Finding::warn(format!(
            "{} of {checked} privileged accounts {} licensed for a mailbox or Office apps, which suggests daily use ({with_mailbox} with a mailbox, {with_office} with Office apps).",
            flagged.len(),
            if flagged.len() == 1 { "is" } else { "are" }
        ))
    };
    Ok(finding.data(data).affected(flagged))
}

const ELIGIBILITY_SCHEDULES: ApiRequirement = ApiRequirement {
    operation: "graph.role_management.directory.role_eligibility_schedules.list",
    permissions: &[
        "RoleEligibilitySchedule.Read.Directory",
        "RoleManagement.Read.Directory",
    ],
};
const ASSIGNMENT_SCHEDULES: ApiRequirement = ApiRequirement {
    operation: "graph.role_management.directory.role_assignment_schedules.list",
    permissions: &[
        "RoleAssignmentSchedule.Read.Directory",
        "RoleManagement.Read.Directory",
    ],
};

pub const PIM_USED: CheckMeta = CheckMeta {
    id: "identity.pim_used",
    title: "Privileged roles are eligible through PIM, not permanent",
    pack: Pack::Identity,
    kind: CheckKind::Automated,
    severity: Severity::High,
    effort: Level::Medium,
    impact: Level::High,
    description: "With Entra ID P2, reads PIM eligibility and assignment schedules for the privileged directory roles. Fails when no privileged role is assigned as eligible, or when more principals hold a permanent active privileged assignment than the allowance for emergency accounts. Just-in-time activation means a stolen admin password does not carry standing privilege. Settings: `max_permanent` (default 2, for break-glass accounts) and `allow_permanent` (UPNs or names not counted).",
    requires: Requirements {
        apis: &[ELIGIBILITY_SCHEDULES, ASSIGNMENT_SCHEDULES],
        licences: &["entra_id_p2"],
    },
    remediation: "In Privileged Identity Management > Microsoft Entra roles > Assignments, convert active privileged assignments to eligible, require MFA and justification on activation and keep activation short (for example 8 hours or less). Leave only the break-glass accounts as permanent Global Administrators.",
    links: &[
        "https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure",
        "https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-how-to-add-role-to-user",
    ],
    references: &["CIS M365 5.3.1"],
    manual: None,
};

crate::check!(PimUsed, &PIM_USED, pim_used);

fn principal_label(schedule: &Value) -> String {
    let p = schedule.get("principal").unwrap_or(&Value::Null);
    str_of(p, "userPrincipalName")
        .or_else(|| str_of(p, "displayName"))
        .or_else(|| str_of(schedule, "principalId"))
        .unwrap_or("(unknown principal)")
        .to_owned()
}

async fn pim_used(ctx: &CheckContext) -> Evaluation {
    let id = PIM_USED.id;
    let max_permanent: usize = ctx.setting(id, "max_permanent", 2);
    let allow: Vec<String> = ctx.setting(id, "allow_permanent", vec![]);
    let privileged = |s: &&Value| {
        str_of(s, "roleDefinitionId")
            .and_then(privileged_role)
            .is_some()
    };
    let eligible: Vec<Value> = full_list(
        ctx,
        ELIGIBILITY_SCHEDULES.operation,
        json!({ "$expand": ["principal"] }),
    )
    .await?
    .into_iter()
    .filter(|s| privileged(&s))
    .collect();
    let schedules = full_list(
        ctx,
        ASSIGNMENT_SCHEDULES.operation,
        json!({ "$expand": ["principal"] }),
    )
    .await?;
    let mut permanent: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for s in schedules.iter().filter(privileged) {
        let activated = str_of(s, "assignmentType") == Some("Activated");
        let expires = s
            .pointer("/scheduleInfo/expiration/type")
            .and_then(Value::as_str)
            .is_some_and(|t| t != "noExpiration");
        if activated || expires {
            continue;
        }
        let role = role_name(str_of(s, "roleDefinitionId").unwrap_or_default()).to_owned();
        permanent
            .entry(principal_label(s))
            .or_default()
            .insert(role);
    }
    let counted: Vec<String> = permanent
        .keys()
        .filter(|p| !allow.iter().any(|a| a.eq_ignore_ascii_case(p)))
        .cloned()
        .collect();
    let eligible_principals: BTreeSet<String> = eligible.iter().map(principal_label).collect();
    let data = json!({
        "eligible_assignments": eligible.len(),
        "eligible_principals": eligible_principals.len(),
        "permanent_principals": permanent.len(),
        "permanent_counted": counted.len(),
        "max_permanent": max_permanent,
        "permanent": permanent,
    });
    let finding = if eligible.is_empty() {
        Finding::fail(format!(
            "No privileged role is assigned as eligible through PIM; {} {} permanent privileged access.",
            plural(permanent.len(), "principal", "principals"),
            if permanent.len() == 1 { "has" } else { "have" }
        ))
    } else if counted.len() > max_permanent {
        Finding::fail(format!(
            "{} {} permanent privileged access (allowance {max_permanent} for emergency accounts); {} eligible.",
            plural(counted.len(), "principal", "principals"),
            if counted.len() == 1 { "has" } else { "have" },
            plural(eligible.len(), "assignment is", "assignments are"),
        ))
    } else {
        Finding::pass(format!(
            "{} eligible through PIM; {} permanent (allowance {max_permanent}).",
            plural(
                eligible.len(),
                "privileged assignment is",
                "privileged assignments are"
            ),
            counted.len()
        ))
    };
    let affected = if counted.len() > max_permanent || eligible.is_empty() {
        counted
    } else {
        vec![]
    };
    Ok(finding.data(data).affected(affected))
}
