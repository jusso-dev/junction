//! `identity` pack: Entra ID sign-in and administrator controls.
use crate::check::{ApiRequirement, Check, CheckMeta, Evaluation, Finding, Requirements};
use crate::context::CheckContext;
use crate::model::{CheckKind, Level, Pack, Severity};
use serde_json::{Value, json};
use std::sync::Arc;

pub fn checks() -> Vec<Arc<dyn Check>> {
    vec![Arc::new(GlobalAdminCount)]
}

/// Role template id of Global Administrator (the same in every tenant).
pub const GLOBAL_ADMIN: &str = "62e90394-69f5-4237-9190-012177145e10";

const ROLE_ASSIGNMENTS: ApiRequirement = ApiRequirement {
    operation: "graph.role_management.directory.role_assignments.list",
    permissions: &["RoleManagement.Read.Directory"],
};

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
