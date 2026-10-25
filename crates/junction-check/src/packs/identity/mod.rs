//! `identity` pack: Entra ID sign-in and administrator controls.
//!
//! Checks share a few listings (role assignments, registration details, users,
//! Conditional Access policies); the context memoises them, so each is read once
//! per tenant run as long as every check passes the same input.
use crate::check::{ApiRequirement, Check, ManualCheck};
use crate::context::{CallFailure, CheckContext};
use crate::gateway::GatewayError;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

mod access;
mod admins;
mod ca;
mod mfa;

pub use access::{BASELINE, BREAK_GLASS, BREAK_GLASS_MONITORED, LEGACY_AUTH_BLOCKED};
pub use admins::{GLOBAL_ADMIN_COUNT, PIM_USED, SEPARATE_ADMIN_ACCOUNTS};
pub use mfa::{MFA_ADMINS, MFA_COVERAGE, PHISHING_RESISTANT_ADMINS};

pub fn checks() -> Vec<Arc<dyn Check>> {
    vec![
        Arc::new(mfa::MfaCoverage),
        Arc::new(mfa::MfaAdmins),
        Arc::new(mfa::PhishingResistantAdmins),
        Arc::new(access::LegacyAuthBlocked),
        Arc::new(access::Baseline),
        Arc::new(admins::GlobalAdminCount),
        Arc::new(admins::SeparateAdminAccounts),
        Arc::new(access::BreakGlass),
        Arc::new(ManualCheck(&BREAK_GLASS_MONITORED)),
        Arc::new(admins::PimUsed),
    ]
}

/// Role template id of Global Administrator (the same in every tenant).
pub const GLOBAL_ADMIN: &str = "62e90394-69f5-4237-9190-012177145e10";

/// Privileged directory roles (template id, name) the pack treats as admin.
pub const PRIVILEGED_ROLES: &[(&str, &str)] = &[
    (GLOBAL_ADMIN, "Global Administrator"),
    (
        "e8611ab8-c189-46e8-94e1-60213ab1f814",
        "Privileged Role Administrator",
    ),
    (
        "194ae4cb-b126-40b2-bd5b-6091b380977d",
        "Security Administrator",
    ),
    (
        "29232cdf-9323-42fd-ade2-1d097af3e4de",
        "Exchange Administrator",
    ),
    (
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
        "SharePoint Administrator",
    ),
    ("fe930be7-5e62-47db-91af-98c3a49a38b1", "User Administrator"),
    (
        "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
        "Conditional Access Administrator",
    ),
    (
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
        "Application Administrator",
    ),
    (
        "158c047a-c907-4556-b7ef-446551a6b5f7",
        "Cloud Application Administrator",
    ),
    (
        "c4e39bd9-1100-46d3-8c65-fb160da0071f",
        "Authentication Administrator",
    ),
    (
        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
        "Privileged Authentication Administrator",
    ),
    (
        "3a2c62db-5318-420d-8d74-23affee5d9d5",
        "Intune Administrator",
    ),
    (
        "b0f54661-2d74-4c50-afa3-1ec803f12efe",
        "Billing Administrator",
    ),
    (
        "729827e3-9c14-49f7-bb1b-9608f156bbb8",
        "Helpdesk Administrator",
    ),
];

/// The canonical (lower-case) template id when `id` is a privileged role.
pub fn privileged_role(id: &str) -> Option<&'static str> {
    PRIVILEGED_ROLES
        .iter()
        .find(|(r, _)| r.eq_ignore_ascii_case(id))
        .map(|(r, _)| *r)
}

pub fn role_name(id: &str) -> &str {
    PRIVILEGED_ROLES
        .iter()
        .find(|(r, _)| r.eq_ignore_ascii_case(id))
        .map_or(id, |(_, n)| n)
}

pub(crate) const ROLE_ASSIGNMENTS: ApiRequirement = ApiRequirement {
    operation: "graph.role_management.directory.role_assignments.list",
    permissions: &["RoleManagement.Read.Directory"],
};
pub(crate) const GROUP_MEMBERS: ApiRequirement = ApiRequirement {
    operation: "graph.groups.transitive_members.list",
    permissions: &["GroupMember.Read.All"],
};
pub(crate) const REGISTRATION: ApiRequirement = ApiRequirement {
    operation: "graph.reports.authentication_methods.user_registration_details.list",
    permissions: &["AuditLog.Read.All"],
};
pub(crate) const USERS: ApiRequirement = ApiRequirement {
    operation: "graph.users.list",
    permissions: &["User.Read.All"],
};
pub(crate) const SECURITY_DEFAULTS: ApiRequirement = ApiRequirement {
    operation: "graph.policies.identity_security_defaults_enforcement_policy.get",
    permissions: &["Policy.Read.All"],
};
pub(crate) const CA_POLICIES: ApiRequirement = ApiRequirement {
    operation: "graph.identity.conditional_access.policies.list",
    permissions: &["Policy.Read.All"],
};
pub(crate) const AUTH_STRENGTHS: ApiRequirement = ApiRequirement {
    operation: "graph.policies.authentication_strength_policies.list",
    permissions: &["Policy.Read.All"],
};

/// Every item of a listing, or a failure when the run's page limit cut it
/// short: a partial list must never decide a status.
pub(crate) async fn full_list(
    ctx: &CheckContext,
    operation: &str,
    parameters: Value,
) -> Result<Vec<Value>, CallFailure> {
    let listing = ctx
        .list(operation, json!({ "parameters": parameters }))
        .await?;
    if listing.truncated {
        return Err(CallFailure {
            operation: operation.to_owned(),
            error: GatewayError::Unavailable(
                "more results than the run's page limit allows; a partial list cannot decide this check"
                    .into(),
            ),
        });
    }
    Ok(listing.items)
}

pub(crate) fn str_of<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

/// A user holding at least one privileged role, directly or through a group.
#[derive(Debug, Clone)]
pub(crate) struct Admin {
    pub id: String,
    /// UPN, or display name or object id when the UPN is not returned.
    pub upn: String,
    /// Privileged role template ids held (active assignments).
    pub roles: BTreeSet<&'static str>,
}

impl Admin {
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r.eq_ignore_ascii_case(role))
    }
}

fn label(principal: &Value, fallback: &str) -> String {
    str_of(principal, "userPrincipalName")
        .or_else(|| str_of(principal, "displayName"))
        .unwrap_or(fallback)
        .to_owned()
}

fn is_user(object: &Value) -> bool {
    match str_of(object, "@odata.type") {
        Some(t) => t == "#microsoft.graph.user",
        None => object.get("userPrincipalName").is_some(),
    }
}

/// Users with an active privileged role assignment. Groups assigned a role are
/// expanded to their (transitive) user members.
pub(crate) async fn privileged_users(ctx: &CheckContext) -> Result<Vec<Admin>, CallFailure> {
    let assignments = full_list(
        ctx,
        ROLE_ASSIGNMENTS.operation,
        json!({ "$expand": ["principal"] }),
    )
    .await?;
    let mut admins: BTreeMap<String, Admin> = BTreeMap::new();
    let mut groups: BTreeMap<String, BTreeSet<&'static str>> = BTreeMap::new();
    for a in &assignments {
        let Some(role) = str_of(a, "roleDefinitionId").and_then(privileged_role) else {
            continue;
        };
        let principal = a.get("principal").unwrap_or(&Value::Null);
        let Some(id) = str_of(principal, "id").or_else(|| str_of(a, "principalId")) else {
            continue;
        };
        match str_of(principal, "@odata.type") {
            Some("#microsoft.graph.group") => {
                groups.entry(id.to_owned()).or_default().insert(role);
            }
            Some("#microsoft.graph.user") => {
                admins
                    .entry(id.to_owned())
                    .or_insert_with(|| Admin {
                        id: id.to_owned(),
                        upn: label(principal, id),
                        roles: BTreeSet::new(),
                    })
                    .roles
                    .insert(role);
            }
            // Service principals hold roles too, but have no MFA or mailbox.
            _ => {}
        }
    }
    for (group, roles) in groups {
        let members = full_list(
            ctx,
            GROUP_MEMBERS.operation,
            json!({ "group-id": group, "$select": ["id", "userPrincipalName", "displayName"] }),
        )
        .await?;
        for m in members.iter().filter(|m| is_user(m)) {
            let Some(id) = str_of(m, "id") else { continue };
            admins
                .entry(id.to_owned())
                .or_insert_with(|| Admin {
                    id: id.to_owned(),
                    upn: label(m, id),
                    roles: BTreeSet::new(),
                })
                .roles
                .extend(roles.iter().copied());
        }
    }
    let mut admins: Vec<Admin> = admins.into_values().collect();
    admins.sort_by(|a, b| a.upn.cmp(&b.upn));
    Ok(admins)
}

/// `userRegistrationDetails` keyed by user id (one shared, unfiltered listing).
pub(crate) async fn registration_details(
    ctx: &CheckContext,
) -> Result<BTreeMap<String, Value>, CallFailure> {
    Ok(full_list(ctx, REGISTRATION.operation, json!({}))
        .await?
        .into_iter()
        .filter_map(|d| Some((str_of(&d, "id")?.to_owned(), d)))
        .collect())
}

/// Enabled users with their licences (one shared listing).
pub(crate) async fn enabled_users(ctx: &CheckContext) -> Result<Vec<Value>, CallFailure> {
    full_list(
        ctx,
        USERS.operation,
        json!({
            "$filter": "accountEnabled eq true",
            "$select": ["id", "userPrincipalName", "userType", "assignedLicenses"],
            "$top": 999,
        }),
    )
    .await
}

pub(crate) async fn security_defaults_enabled(ctx: &CheckContext) -> Result<bool, CallFailure> {
    let policy = ctx.get(SECURITY_DEFAULTS.operation, json!({})).await?;
    Ok(policy.get("isEnabled").and_then(Value::as_bool) == Some(true))
}

pub(crate) async fn ca_policies(ctx: &CheckContext) -> Result<Vec<Value>, CallFailure> {
    full_list(ctx, CA_POLICIES.operation, json!({})).await
}

/// "1 user" / "2 users".
pub(crate) fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// A percentage rounded to one decimal place for evidence.
pub(crate) fn percent(part: usize, whole: usize) -> f64 {
    if whole == 0 {
        100.0
    } else {
        (part as f64 * 1000.0 / whole as f64).round() / 10.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privileged_roles_are_unique_and_lower_case() {
        let ids: BTreeSet<&str> = PRIVILEGED_ROLES.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids.len(), 14);
        assert!(ids.iter().all(|id| id.to_ascii_lowercase() == *id));
        assert_eq!(
            privileged_role("62E90394-69F5-4237-9190-012177145E10"),
            Some(GLOBAL_ADMIN)
        );
        assert_eq!(role_name("unknown-role"), "unknown-role");
    }

    #[test]
    fn percent_rounds_to_one_decimal() {
        assert_eq!(percent(2, 3), 66.7);
        assert_eq!(percent(0, 0), 100.0);
    }
}
