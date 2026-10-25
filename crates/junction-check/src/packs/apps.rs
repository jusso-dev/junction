//! `apps` pack: user consent, app registrations and enterprise applications.
//! Ported from M365-Secure `src/modules/identity/apps.rs`; the M365-Secure id each
//! check replaces is in `data/m365-secure-map.yaml`.
use crate::check::{ApiRequirement, Check, CheckMeta, Evaluation, Finding, Requirements};
use crate::context::{CallFailure, CheckContext};
use crate::model::{CheckKind, Level, Pack, Severity};
use junction_watch::clock::Instant;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

pub fn checks() -> Vec<Arc<dyn Check>> {
    vec![
        Arc::new(UserConsentRestricted),
        Arc::new(AdminConsentWorkflow),
        Arc::new(UsersCannotRegisterApps),
        Arc::new(AppManagementPolicy),
        Arc::new(CredentialExpiry),
        Arc::new(SecretLifetime),
        Arc::new(PrivilegedAppSecrets),
        Arc::new(HighPrivilegePermissions),
        Arc::new(SpPasswordCredentials),
        Arc::new(AssignmentRequired),
        Arc::new(MultiTenantApps),
    ]
}

/// Microsoft Graph and Exchange Online, whose application roles are resolved by name.
pub const GRAPH_APP_ID: &str = "00000003-0000-0000-c000-000000000000";
pub const EXCHANGE_APP_ID: &str = "00000002-0000-0ff1-ce00-000000000000";
/// Tenants that own Microsoft first-party applications.
const MICROSOFT_TENANTS: &[&str] = &[
    "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
    "72f988bf-86f1-41af-91ab-2d7cd011db47",
];
/// Permissions that read or control tenant-wide data or the directory itself.
pub const HIGH_IMPACT: &[&str] = &[
    "Mail.Read",
    "Mail.ReadWrite",
    "Mail.Send",
    "Files.ReadWrite.All",
    "Sites.FullControl.All",
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "full_access_as_app",
    "Exchange.ManageAsApp",
];

pub(crate) const AUTHZ: ApiRequirement = ApiRequirement {
    operation: "graph.policies.authorization_policy.get",
    permissions: &["Policy.Read.All"],
};
const CONSENT_REQUESTS: ApiRequirement = ApiRequirement {
    operation: "graph.policies.admin_consent_request_policy.get",
    permissions: &["Policy.Read.All"],
};
const APP_MANAGEMENT: ApiRequirement = ApiRequirement {
    operation: "graph.policies.default_app_management_policy.get",
    permissions: &["Policy.Read.All"],
};
const APPLICATIONS: ApiRequirement = ApiRequirement {
    operation: "graph.applications.list",
    permissions: &["Application.Read.All"],
};
const SERVICE_PRINCIPALS: ApiRequirement = ApiRequirement {
    operation: "graph.service_principals.list",
    permissions: &["Application.Read.All"],
};
const APP_ROLE_GRANTS: ApiRequirement = ApiRequirement {
    operation: "graph.service_principals.app_role_assigned_to.list",
    permissions: &["Application.Read.All"],
};
const DELEGATED_GRANTS: ApiRequirement = ApiRequirement {
    operation: "graph.oauth2permission_grants.list",
    permissions: &["DelegatedPermissionGrant.Read.All", "Directory.Read.All"],
};

const CONSENT_LINK: &str =
    "https://learn.microsoft.com/entra/identity/enterprise-apps/configure-user-consent";
const CREDENTIALS_LINK: &str =
    "https://learn.microsoft.com/entra/identity-platform/how-to-add-credentials";

/// Metadata for an automated check with no licence requirement.
#[allow(clippy::too_many_arguments)]
pub(crate) const fn meta(
    pack: Pack,
    id: &'static str,
    title: &'static str,
    severity: Severity,
    (effort, impact): (Level, Level),
    description: &'static str,
    apis: &'static [ApiRequirement],
    remediation: &'static str,
    links: &'static [&'static str],
    references: &'static [&'static str],
) -> CheckMeta {
    CheckMeta {
        id,
        title,
        pack,
        kind: CheckKind::Automated,
        severity,
        effort,
        impact,
        description,
        requires: Requirements {
            apis,
            licences: &[],
        },
        remediation,
        links,
        references,
        manual: None,
    }
}

// --- shared reads --------------------------------------------------------

pub fn is_high_impact(permission: &str) -> bool {
    HIGH_IMPACT
        .iter()
        .any(|p| p.eq_ignore_ascii_case(permission))
}

pub fn is_microsoft_owned(sp: &Value) -> bool {
    sp["appOwnerOrganizationId"]
        .as_str()
        .is_some_and(|o| MICROSOFT_TENANTS.iter().any(|t| t.eq_ignore_ascii_case(o)))
}

fn name(v: &Value) -> &str {
    v["displayName"].as_str().unwrap_or("Unknown")
}

fn sp_label(sp: &Value) -> String {
    format!(
        "{} ({})",
        name(sp),
        sp["appId"].as_str().unwrap_or_default()
    )
}

fn date(at: Instant) -> String {
    at.to_rfc3339()[..10].to_owned()
}

async fn service_principals(ctx: &CheckContext) -> Result<Vec<Value>, CallFailure> {
    ctx.list_with(
        SERVICE_PRINCIPALS.operation,
        json!({"$select": ["id", "displayName", "appId", "accountEnabled", "appRoleAssignmentRequired",
            "servicePrincipalType", "appOwnerOrganizationId", "passwordCredentials", "keyCredentials"]}),
    )
    .await
}

async fn applications(ctx: &CheckContext) -> Result<Vec<Value>, CallFailure> {
    ctx.list_with(
        APPLICATIONS.operation,
        json!({"$select": ["id", "displayName", "appId", "signInAudience", "passwordCredentials",
            "keyCredentials", "requiredResourceAccess"]}),
    )
    .await
}

/// Graph and Exchange Online resource service principals: their ids and
/// `appRoleId -> permission` names.
async fn resource_roles(
    ctx: &CheckContext,
) -> Result<(Vec<String>, BTreeMap<String, String>), CallFailure> {
    let mut ids = vec![];
    let mut names = BTreeMap::new();
    for app_id in [GRAPH_APP_ID, EXCHANGE_APP_ID] {
        let rows = ctx
            .list_with(
                SERVICE_PRINCIPALS.operation,
                json!({"$filter": format!("appId eq '{app_id}'"), "$select": ["id", "appId", "appRoles"]}),
            )
            .await?;
        for sp in rows {
            for role in sp["appRoles"].as_array().into_iter().flatten() {
                if let (Some(id), Some(value)) = (role["id"].as_str(), role["value"].as_str()) {
                    names.insert(id.to_lowercase(), value.to_owned());
                }
            }
            if let Some(id) = sp["id"].as_str() {
                ids.push(id.to_owned());
            }
        }
    }
    Ok((ids, names))
}

/// High-impact permissions per service principal id: application roles granted
/// on Graph and Exchange Online plus tenant-wide (AllPrincipals) delegated grants.
async fn high_impact_by_sp(
    ctx: &CheckContext,
) -> Result<BTreeMap<String, BTreeSet<String>>, CallFailure> {
    let (resources, names) = resource_roles(ctx).await?;
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for resource in resources {
        let grants = ctx
            .list_with(
                APP_ROLE_GRANTS.operation,
                json!({"servicePrincipal-id": resource}),
            )
            .await?;
        for g in grants {
            let (Some(sp), Some(role)) = (g["principalId"].as_str(), g["appRoleId"].as_str())
            else {
                continue;
            };
            if let Some(name) = names
                .get(&role.to_lowercase())
                .filter(|n| is_high_impact(n))
            {
                out.entry(sp.to_owned()).or_default().insert(name.clone());
            }
        }
    }
    for g in ctx.list_with(DELEGATED_GRANTS.operation, json!({})).await? {
        if g["consentType"].as_str() != Some("AllPrincipals") {
            continue;
        }
        let Some(client) = g["clientId"].as_str() else {
            continue;
        };
        for scope in g["scope"].as_str().unwrap_or("").split_whitespace() {
            if is_high_impact(scope) {
                out.entry(client.to_owned())
                    .or_default()
                    .insert(format!("{scope} (delegated, all users)"));
            }
        }
    }
    Ok(out)
}

// --- consent and app creation ---------------------------------------------

pub const USER_CONSENT_RESTRICTED: CheckMeta = meta(
    Pack::Apps,
    "apps.user_consent_restricted",
    "Users cannot consent to applications (or only to verified publishers for low-impact permissions)",
    Severity::Critical,
    (Level::Low, Level::High),
    "Reads the permission grant policies assigned to the default user role. Open user consent lets a phishing link turn into a tenant-wide OAuth grant to an attacker's application.",
    &[AUTHZ],
    "Entra admin center > Enterprise applications > Consent and permissions > User consent settings: choose 'Do not allow user consent', or 'Allow user consent for apps from verified publishers, for selected permissions'. Pair it with the admin consent workflow.",
    &[CONSENT_LINK],
    &["CIS M365 5.1.5.1"],
);

crate::check!(
    UserConsentRestricted,
    &USER_CONSENT_RESTRICTED,
    user_consent_restricted
);

/// Status for the user consent policies on the default user role (M365-Secure `evaluate_consent`).
pub fn consent_allowed(policies: &[&str]) -> Option<Vec<String>> {
    let for_self: Vec<String> = policies
        .iter()
        .filter(|p| p.starts_with("ManagePermissionGrantsForSelf."))
        .map(|p| (*p).to_owned())
        .collect();
    let low_only = for_self
        .iter()
        .all(|p| p.ends_with("microsoft-user-default-low"));
    (!low_only).then_some(for_self)
}

async fn user_consent_restricted(ctx: &CheckContext) -> Evaluation {
    let policy = ctx.get(AUTHZ.operation, json!({})).await?;
    let Some(assigned) = policy
        .pointer("/defaultUserRolePermissions/permissionGrantPoliciesAssigned")
        .and_then(Value::as_array)
    else {
        return Ok(Finding::unknown(
            "not_returned",
            "The authorization policy did not return permissionGrantPoliciesAssigned.",
        ));
    };
    let assigned: Vec<&str> = assigned.iter().filter_map(Value::as_str).collect();
    let data = json!({ "permission_grant_policies": assigned });
    let finding = match consent_allowed(&assigned) {
        None if assigned
            .iter()
            .any(|p| p.starts_with("ManagePermissionGrantsForSelf.")) =>
        {
            Finding::pass(
                "User consent is limited to verified publishers requesting low-impact permissions.",
            )
        }
        None => Finding::pass("User consent to applications is turned off."),
        Some(open) => Finding::fail(format!(
            "Users can consent to applications ({}).",
            open.join(", ")
        )),
    };
    Ok(finding.data(data))
}

pub const ADMIN_CONSENT_WORKFLOW: CheckMeta = meta(
    Pack::Apps,
    "apps.admin_consent_workflow",
    "The admin consent workflow is on with at least one reviewer",
    Severity::Medium,
    (Level::Low, Level::Medium),
    "Reads the admin consent request policy. With user consent off, the workflow gives users a reviewed path to request an app instead of a workaround.",
    &[CONSENT_REQUESTS],
    "Entra admin center > Enterprise applications > Admin consent settings: set 'Users can request admin consent to apps they are unable to consent to' to Yes, add reviewers and turn on notifications.",
    &[
        "https://learn.microsoft.com/entra/identity/enterprise-apps/configure-admin-consent-workflow",
    ],
    &["CIS M365 5.1.5.2"],
);

crate::check!(
    AdminConsentWorkflow,
    &ADMIN_CONSENT_WORKFLOW,
    admin_consent_workflow
);

async fn admin_consent_workflow(ctx: &CheckContext) -> Evaluation {
    let policy = ctx.get(CONSENT_REQUESTS.operation, json!({})).await?;
    let enabled = policy["isEnabled"].as_bool().unwrap_or(false);
    let reviewers = policy["reviewers"].as_array().map(Vec::len).unwrap_or(0);
    let finding = if enabled && reviewers > 0 {
        Finding::pass(format!(
            "The admin consent workflow is on with {reviewers} reviewer scope(s)."
        ))
    } else if enabled {
        Finding::warn("The admin consent workflow is on but has no reviewers.")
    } else {
        Finding::fail("The admin consent workflow is off.")
    };
    Ok(finding.data(json!({ "enabled": enabled, "reviewers": reviewers })))
}

pub const USERS_CANNOT_REGISTER_APPS: CheckMeta = meta(
    Pack::Apps,
    "apps.users_cannot_register_apps",
    "Non-admin users cannot register applications",
    Severity::Medium,
    (Level::Low, Level::Medium),
    "Reads defaultUserRolePermissions.allowedToCreateApps from the authorization policy. User-registered apps are owned by individuals and are a common persistence path.",
    &[AUTHZ],
    "Entra admin center > Identity > Users > User settings: set 'Users can register applications' to No, and grant the Application Developer role to the people who need it.",
    &["https://learn.microsoft.com/entra/identity/role-based-access-control/delegate-app-roles"],
    &["CIS M365 5.1.2.2"],
);

crate::check!(
    UsersCannotRegisterApps,
    &USERS_CANNOT_REGISTER_APPS,
    users_cannot_register_apps
);

async fn users_cannot_register_apps(ctx: &CheckContext) -> Evaluation {
    let policy = ctx.get(AUTHZ.operation, json!({})).await?;
    let allowed = policy
        .pointer("/defaultUserRolePermissions/allowedToCreateApps")
        .and_then(Value::as_bool);
    Ok(match allowed {
        Some(false) => Finding::pass("Only admins and Application Developers can register apps."),
        Some(true) => Finding::fail("Any user can register applications."),
        None => {
            return Ok(Finding::unknown(
                "not_returned",
                "The authorization policy did not return allowedToCreateApps.",
            ));
        }
    }
    .data(json!({ "allowed_to_create_apps": allowed })))
}

pub const APP_MANAGEMENT_POLICY: CheckMeta = meta(
    Pack::Apps,
    "apps.app_management_policy",
    "The tenant app management policy blocks or caps client secrets",
    Severity::Medium,
    (Level::Medium, Level::Medium),
    "Reads the default app management policy for an enabled password credential restriction (passwordAddition, passwordLifetime and similar).",
    &[APP_MANAGEMENT],
    "Set the tenant default app management policy (Entra admin center > App registrations > App management policies) to block new client secrets or cap their lifetime, after moving apps to certificates or federated credentials.",
    &["https://learn.microsoft.com/graph/api/resources/tenantappmanagementpolicy"],
    &["CIS M365 5.1.5.6"],
);

crate::check!(
    AppManagementPolicy,
    &APP_MANAGEMENT_POLICY,
    app_management_policy
);

async fn app_management_policy(ctx: &CheckContext) -> Evaluation {
    let policy = ctx.get(APP_MANAGEMENT.operation, json!({})).await?;
    let enabled = policy["isEnabled"].as_bool().unwrap_or(false);
    let restrictions: Vec<String> = policy
        .pointer("/applicationRestrictions/passwordCredentials")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|r| r["state"].as_str().is_none_or(|s| s == "enabled"))
        .filter_map(|r| r["restrictionType"].as_str())
        .filter(|t| t.starts_with("password") || t.starts_with("symmetricKey"))
        .map(str::to_owned)
        .collect();
    let finding = if enabled && !restrictions.is_empty() {
        Finding::pass(format!(
            "The app management policy restricts secrets ({}).",
            restrictions.join(", ")
        ))
    } else if enabled {
        Finding::warn("The app management policy is on but restricts no password credentials.")
    } else {
        Finding::fail("The tenant app management policy is off.")
    };
    Ok(finding.data(json!({ "enabled": enabled, "password_restrictions": restrictions })))
}

// --- app registrations ------------------------------------------------------

pub const CREDENTIAL_EXPIRY: CheckMeta = meta(
    Pack::Apps,
    "apps.credential_expiry",
    "No app registration has an expired or soon-expiring secret or certificate",
    Severity::Medium,
    (Level::Low, Level::Medium),
    "Reads passwordCredentials and keyCredentials end dates on app registrations. Expired credentials left in place hide which apps are live; ones about to expire cause outages and rushed, weaker fixes.",
    &[APPLICATIONS],
    "Remove expired secrets and certificates, rotate those expiring soon, and alert on credential expiry.",
    &[CREDENTIALS_LINK],
    &[],
);

crate::check!(CredentialExpiry, &CREDENTIAL_EXPIRY, credential_expiry);

async fn credential_expiry(ctx: &CheckContext) -> Evaluation {
    let warn_days: u64 = ctx.setting(CREDENTIAL_EXPIRY.id, "warn_days", 30);
    let now = ctx.now();
    let soon = now.plus(Duration::from_secs(warn_days * 86_400));
    let (mut expired, mut expiring) = (vec![], vec![]);
    for app in applications(ctx).await? {
        for (field, label) in [
            ("passwordCredentials", "secret"),
            ("keyCredentials", "certificate"),
        ] {
            for cred in app[field].as_array().into_iter().flatten() {
                let Some(end) = cred["endDateTime"]
                    .as_str()
                    .and_then(|s| Instant::parse(s).ok())
                else {
                    continue;
                };
                if end < now {
                    expired.push(format!("{} ({label} expired {})", name(&app), date(end)));
                } else if end < soon {
                    expiring.push(format!("{} ({label} expires {})", name(&app), date(end)));
                }
            }
        }
    }
    let data =
        json!({ "expired": expired.len(), "expiring": expiring.len(), "warn_days": warn_days });
    let finding = if !expired.is_empty() {
        Finding::fail(format!(
            "{} expired and {} soon-expiring app credentials.",
            expired.len(),
            expiring.len()
        ))
    } else if !expiring.is_empty() {
        Finding::warn(format!(
            "{} app credentials expire within {warn_days} days.",
            expiring.len()
        ))
    } else {
        Finding::pass("No expired or soon-expiring app credentials.")
    };
    Ok(finding
        .data(data)
        .affected(expired.into_iter().chain(expiring)))
}

pub const SECRET_LIFETIME: CheckMeta = meta(
    Pack::Apps,
    "apps.secret_lifetime",
    "App registration client secrets are valid for a year or less",
    Severity::Low,
    (Level::Low, Level::Medium),
    "Reads the start and end dates of current client secrets on app registrations. A long-lived secret that leaks stays useful to an attacker for years.",
    &[APPLICATIONS],
    "Replace long-lived client secrets with certificates or federated credentials; where a secret is unavoidable, issue it for 12 months or less and cap lifetimes with the app management policy.",
    &[CREDENTIALS_LINK],
    &[],
);

crate::check!(SecretLifetime, &SECRET_LIFETIME, secret_lifetime);

async fn secret_lifetime(ctx: &CheckContext) -> Evaluation {
    let max_days: u64 = ctx.setting(SECRET_LIFETIME.id, "max_days", 365);
    let now = ctx.now();
    let mut long_lived = vec![];
    let mut secrets = 0usize;
    for app in applications(ctx).await? {
        for cred in app["passwordCredentials"].as_array().into_iter().flatten() {
            let parse = |k: &str| cred[k].as_str().and_then(|s| Instant::parse(s).ok());
            let (Some(start), Some(end)) = (parse("startDateTime"), parse("endDateTime")) else {
                continue;
            };
            if end < now {
                continue; // expired: apps.credential_expiry reports it
            }
            secrets += 1;
            let days = end.since(start).as_secs() / 86_400;
            if days > max_days {
                long_lived.push(format!(
                    "{} (secret valid {days} days, to {})",
                    name(&app),
                    date(end)
                ));
            }
        }
    }
    let data =
        json!({ "current_secrets": secrets, "long_lived": long_lived.len(), "max_days": max_days });
    let finding = if long_lived.is_empty() {
        Finding::pass(format!(
            "{secrets} current client secrets, none valid for more than {max_days} days."
        ))
    } else {
        Finding::warn(format!(
            "{} of {secrets} current client secrets are valid for more than {max_days} days.",
            long_lived.len()
        ))
    };
    Ok(finding.data(data).affected(long_lived))
}

pub const PRIVILEGED_APP_SECRETS: CheckMeta = meta(
    Pack::Apps,
    "apps.privileged_app_secrets",
    "App registrations with high-impact application permissions do not use client secrets",
    Severity::High,
    (Level::Medium, Level::High),
    "Resolves the Microsoft Graph and Exchange Online application roles each app registration requests and flags those requesting high-impact roles (Mail.*, Files.ReadWrite.All, Directory.ReadWrite.All, RoleManagement.ReadWrite.Directory and similar) that carry a client secret.",
    &[APPLICATIONS, SERVICE_PRINCIPALS],
    "App registrations > app > Certificates & secrets: delete client secrets and use a certificate (kept in Key Vault), a managed identity or a federated credential instead.",
    &[CREDENTIALS_LINK],
    &["CIS M365 5.1.5.3", "CIS M365 5.1.5.4"],
);

crate::check!(
    PrivilegedAppSecrets,
    &PRIVILEGED_APP_SECRETS,
    privileged_app_secrets
);

/// High-impact application roles (type `Role`) an app registration requests.
pub fn requested_high_impact_roles(app: &Value, names: &BTreeMap<String, String>) -> Vec<String> {
    app["requiredResourceAccess"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|r| r["resourceAccess"].as_array().into_iter().flatten())
        .filter(|a| a["type"].as_str() == Some("Role"))
        .filter_map(|a| names.get(&a["id"].as_str()?.to_lowercase()))
        .filter(|n| is_high_impact(n))
        .cloned()
        .collect()
}

async fn privileged_app_secrets(ctx: &CheckContext) -> Evaluation {
    let (_, names) = resource_roles(ctx).await?;
    if names.is_empty() {
        return Ok(Finding::unknown(
            "roles_unresolved",
            "The Microsoft Graph application roles could not be resolved, so requested permissions cannot be named.",
        ));
    }
    let mut privileged = 0usize;
    let mut with_secret = vec![];
    for app in applications(ctx).await? {
        let roles = requested_high_impact_roles(&app, &names);
        if roles.is_empty() {
            continue;
        }
        privileged += 1;
        let secrets = app["passwordCredentials"]
            .as_array()
            .map(Vec::len)
            .unwrap_or(0);
        if secrets > 0 {
            with_secret.push(format!(
                "{} ({secrets} secret(s); {})",
                name(&app),
                roles.join(", ")
            ));
        }
    }
    let data = json!({ "privileged_apps": privileged, "with_secrets": with_secret.len() });
    Ok(Finding::pass_if(
        with_secret.is_empty(),
        format!("None of {privileged} privileged app registrations use a client secret."),
        format!(
            "{} of {privileged} privileged app registrations use a client secret.",
            with_secret.len()
        ),
    )
    .data(data)
    .affected(with_secret))
}

pub const MULTI_TENANT_APPS: CheckMeta = meta(
    Pack::Apps,
    "apps.multi_tenant_apps",
    "App registrations are single-tenant unless they need to be multi-tenant",
    Severity::Low,
    (Level::Medium, Level::Low),
    "Lists app registrations whose signInAudience lets other organisations (or personal Microsoft accounts) sign in. Multi-tenant apps widen who can obtain tokens for the app and are a known cross-tenant abuse path.",
    &[APPLICATIONS],
    "Review each multi-tenant app registration; set 'Supported account types' to 'Accounts in this organizational directory only' unless the app is deliberately offered to other tenants, and then make sure it validates the issuing tenant.",
    &["https://learn.microsoft.com/entra/identity-platform/supported-accounts-validation"],
    &[],
);

crate::check!(MultiTenantApps, &MULTI_TENANT_APPS, multi_tenant_apps);

async fn multi_tenant_apps(ctx: &CheckContext) -> Evaluation {
    let apps = applications(ctx).await?;
    let multi: Vec<String> = apps
        .iter()
        .filter(|a| {
            matches!(
                a["signInAudience"].as_str(),
                Some(
                    "AzureADMultipleOrgs"
                        | "AzureADandPersonalMicrosoftAccount"
                        | "PersonalMicrosoftAccount"
                )
            )
        })
        .map(|a| {
            format!(
                "{} ({})",
                name(a),
                a["signInAudience"].as_str().unwrap_or_default()
            )
        })
        .collect();
    let data = json!({ "app_registrations": apps.len(), "multi_tenant": multi.len() });
    let finding = if multi.is_empty() {
        Finding::pass(format!(
            "All {} app registrations are single-tenant.",
            apps.len()
        ))
    } else {
        Finding::warn(format!(
            "{} of {} app registrations accept other organisations or personal accounts.",
            multi.len(),
            apps.len()
        ))
    };
    Ok(finding.data(data).affected(multi))
}

// --- enterprise applications -------------------------------------------------

pub const HIGH_PRIVILEGE_PERMISSIONS: CheckMeta = meta(
    Pack::Apps,
    "apps.high_privilege_permissions",
    "Third-party applications hold no unreviewed high-impact permissions",
    Severity::High,
    (Level::Medium, Level::High),
    "Lists non-Microsoft service principals granted high-impact Microsoft Graph or Exchange Online application roles, or tenant-wide (all users) delegated grants of them. Each one can read mail or files, or change the directory, without a user present.",
    &[SERVICE_PRINCIPALS, APP_ROLE_GRANTS, DELEGATED_GRANTS],
    "Enterprise applications > app > Permissions: remove grants that are not justified, give each remaining one an owner and a business reason, and prefer resource-specific consent and Exchange RBAC for Applications over tenant-wide Mail.* permissions.",
    &["https://learn.microsoft.com/entra/identity/enterprise-apps/manage-application-permissions"],
    &[],
);

crate::check!(
    HighPrivilegePermissions,
    &HIGH_PRIVILEGE_PERMISSIONS,
    high_privilege_permissions
);

async fn high_privilege_permissions(ctx: &CheckContext) -> Evaluation {
    let by_sp = high_impact_by_sp(ctx).await?;
    let sps = service_principals(ctx).await?;
    let listed: Vec<String> = sps
        .iter()
        .filter(|s| !is_microsoft_owned(s))
        .filter_map(|s| {
            let perms = by_sp.get(s["id"].as_str()?)?;
            Some(format!(
                "{}: {}",
                sp_label(s),
                perms.iter().cloned().collect::<Vec<_>>().join(", ")
            ))
        })
        .collect();
    let data = json!({ "service_principals": sps.len(), "high_impact": listed.len() });
    let finding = if listed.is_empty() {
        Finding::pass("No third-party application holds high-impact permissions.")
    } else {
        Finding::warn(format!(
            "{} third-party applications hold high-impact permissions; confirm each is justified and owned.",
            listed.len()
        ))
    };
    Ok(finding.data(data).affected(listed))
}

pub const SP_PASSWORD_CREDENTIALS: CheckMeta = meta(
    Pack::Apps,
    "apps.sp_password_credentials",
    "Third-party service principals carry no client secrets of their own",
    Severity::Medium,
    (Level::Low, Level::Medium),
    "Lists non-Microsoft service principals with password credentials added directly to the enterprise application. These secrets do not appear on the app registration and are often missed in reviews.",
    &[SERVICE_PRINCIPALS],
    "Remove service-principal-level secrets (Remove-MgServicePrincipalPassword) and use certificates or federated credentials on the application object.",
    &[CREDENTIALS_LINK],
    &[],
);

crate::check!(
    SpPasswordCredentials,
    &SP_PASSWORD_CREDENTIALS,
    sp_password_credentials
);

async fn sp_password_credentials(ctx: &CheckContext) -> Evaluation {
    let sps = service_principals(ctx).await?;
    let with_secrets: Vec<String> = sps
        .iter()
        .filter(|s| !is_microsoft_owned(s))
        .filter_map(|s| {
            let n = s["passwordCredentials"].as_array().map(Vec::len)?;
            (n > 0).then(|| format!("{} ({n} secret(s))", sp_label(s)))
        })
        .collect();
    let data = json!({ "service_principals": sps.len(), "with_secrets": with_secrets.len() });
    let finding = if with_secrets.is_empty() {
        Finding::pass("No third-party service principal carries its own client secret.")
    } else {
        Finding::warn(format!(
            "{} third-party service principals carry client secrets.",
            with_secrets.len()
        ))
    };
    Ok(finding.data(data).affected(with_secrets))
}

pub const ASSIGNMENT_REQUIRED: CheckMeta = meta(
    Pack::Apps,
    "apps.assignment_required",
    "Third-party enterprise applications require user assignment",
    Severity::Low,
    (Level::Medium, Level::Medium),
    "Lists enabled non-Microsoft enterprise applications without 'Assignment required'. Without it, every user in the tenant can sign in to the app and the app can receive their data.",
    &[SERVICE_PRINCIPALS],
    "Enterprise applications > app > Properties: set 'Assignment required?' to Yes, then assign the users or groups that need the app.",
    &[
        "https://learn.microsoft.com/entra/identity/enterprise-apps/assign-user-or-group-access-portal",
    ],
    &[],
);

crate::check!(
    AssignmentRequired,
    &ASSIGNMENT_REQUIRED,
    assignment_required
);

async fn assignment_required(ctx: &CheckContext) -> Evaluation {
    let sps = service_principals(ctx).await?;
    let open: Vec<String> = sps
        .iter()
        .filter(|s| {
            s["accountEnabled"].as_bool().unwrap_or(true)
                && s["servicePrincipalType"].as_str() == Some("Application")
                && !is_microsoft_owned(s)
                && !s["appRoleAssignmentRequired"].as_bool().unwrap_or(false)
        })
        .map(sp_label)
        .collect();
    let data = json!({ "service_principals": sps.len(), "assignment_not_required": open.len() });
    let finding = if open.is_empty() {
        Finding::pass("Every enabled third-party enterprise application requires assignment.")
    } else {
        Finding::warn(format!(
            "{} third-party enterprise applications do not require assignment.",
            open.len()
        ))
    };
    Ok(finding.data(data).affected(open))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consent_policy_evaluation() {
        assert_eq!(consent_allowed(&[]), None);
        assert_eq!(
            consent_allowed(&["ManagePermissionGrantsForSelf.microsoft-user-default-low"]),
            None
        );
        assert!(
            consent_allowed(&["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"])
                .is_some()
        );
        assert_eq!(
            consent_allowed(&[
                "ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team"
            ]),
            None
        );
    }

    #[test]
    fn high_impact_roles_resolved_from_ids() {
        let mut names = BTreeMap::new();
        names.insert("aaa".to_owned(), "Mail.ReadWrite".to_owned());
        names.insert("bbb".to_owned(), "User.Read.All".to_owned());
        let app = json!({"requiredResourceAccess": [{
            "resourceAppId": GRAPH_APP_ID,
            "resourceAccess": [{"id": "AAA", "type": "Role"}, {"id": "bbb", "type": "Role"}, {"id": "aaa", "type": "Scope"}]
        }]});
        assert_eq!(
            requested_high_impact_roles(&app, &names),
            vec!["Mail.ReadWrite"]
        );
        assert!(is_high_impact("mail.readwrite"));
        assert!(is_microsoft_owned(
            &json!({"appOwnerOrganizationId": "f8cdef31-a31e-4b4a-93e4-5f571e91255a"})
        ));
    }
}
