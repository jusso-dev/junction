//! Tenant inventory of connected applications (`junction apps inventory`).
//!
//! One read-only pass over Microsoft Graph joins service principals, app
//! registrations, application permissions (app role assignments), delegated
//! consent grants, owners, guest principals, sign-in recency and workload
//! identity risk into one [`Inventory`]. Every call goes through the check
//! gateway, so the embedded catalogue and forced read-only policy apply.
//!
//! Core listings (service principals, applications, app role assignments and
//! delegated grants) are required: if one fails, there is no inventory.
//! Enrichment (owners, guests, sign-in activity, risk) is optional: a failure
//! is recorded as a [`Gap`] with the reason and the related fields stay empty,
//! so missing data is never read as "no owners" or "never signed in".
//!
//! Credential values are never read or copied: only type, key id, display name
//! and dates. `hint` (the first characters of a secret), `key` and
//! `customKeyIdentifier` are dropped.
use crate::check::{ApiRequirement, CheckMeta};
use crate::context::{CallFailure, CheckContext};
use crate::model::{Level, Pack, Reason, Severity};
use crate::packs::apps::is_microsoft_owned;
use futures_util::StreamExt;
use junction_watch::clock::Instant;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// Version of the [`Inventory`] JSON shape. Bump on breaking changes.
pub const SCHEMA_VERSION: u32 = 1;

/// Owner lookups and app role assignment listings run at most this many at once
/// (the gateway also limits concurrency per API host).
const FAN_OUT: usize = 8;

pub const SERVICE_PRINCIPALS: ApiRequirement = ApiRequirement {
    operation: "graph.service_principals.list",
    permissions: &["Application.Read.All"],
};
pub const APPLICATIONS: ApiRequirement = ApiRequirement {
    operation: "graph.applications.list",
    permissions: &["Application.Read.All"],
};
pub const APP_ROLE_ASSIGNMENTS: ApiRequirement = ApiRequirement {
    operation: "graph.service_principals.app_role_assigned_to.list",
    permissions: &["Application.Read.All"],
};
pub const DELEGATED_GRANTS: ApiRequirement = ApiRequirement {
    operation: "graph.oauth2permission_grants.list",
    permissions: &["DelegatedPermissionGrant.Read.All"],
};
pub const APPLICATION_OWNERS: ApiRequirement = ApiRequirement {
    operation: "graph.applications.owners.list",
    permissions: &["Application.Read.All"],
};
pub const SERVICE_PRINCIPAL_OWNERS: ApiRequirement = ApiRequirement {
    operation: "graph.service_principals.owners.list",
    permissions: &["Application.Read.All"],
};
pub const GUEST_USERS: ApiRequirement = ApiRequirement {
    operation: "graph.users.list",
    permissions: &["User.Read.All"],
};
pub const SIGN_IN_ACTIVITY: ApiRequirement = ApiRequirement {
    operation: "graph.reports.service_principal_sign_in_activities.list",
    permissions: &["AuditLog.Read.All"],
};
pub const RISKY_SERVICE_PRINCIPALS: ApiRequirement = ApiRequirement {
    operation: "graph.identity_protection.risky_service_principals.list",
    permissions: &["IdentityRiskyServicePrincipal.Read.All"],
};

/// Every read the inventory makes, least privileged permission first.
pub const READS: &[ApiRequirement] = &[
    SERVICE_PRINCIPALS,
    APPLICATIONS,
    APP_ROLE_ASSIGNMENTS,
    DELEGATED_GRANTS,
    APPLICATION_OWNERS,
    SERVICE_PRINCIPAL_OWNERS,
    GUEST_USERS,
    SIGN_IN_ACTIVITY,
    RISKY_SERVICE_PRINCIPALS,
];

/// Metadata used to name the permission to grant when a read is refused.
/// The inventory is not a scored check; this only feeds
/// [`crate::outcome::from_failure`].
pub const META: CheckMeta = crate::packs::apps::meta(
    Pack::Apps,
    "apps.inventory",
    "Connected-app inventory",
    Severity::Info,
    (Level::Low, Level::Low),
    "Inventory of enterprise applications, OAuth clients, permissions and consent grants.",
    READS,
    "",
    &[],
    &[],
);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Inventory {
    pub schema_version: u32,
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub captured_at: String,
    pub summary: Summary,
    /// Enrichment that could not be read, with the reason.
    #[serde(default)]
    pub gaps: Vec<Gap>,
    pub apps: Vec<App>,
    /// App registrations in this tenant with no service principal here.
    #[serde(default)]
    pub registrations_without_service_principal: Vec<Registration>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Summary {
    pub apps: usize,
    /// App registrations with no service principal in this tenant.
    #[serde(default)]
    pub registrations_without_service_principal: usize,
    pub home_tenant: usize,
    pub external: usize,
    pub microsoft: usize,
    pub with_application_permissions: usize,
    pub with_tenant_wide_delegated: usize,
    pub with_user_delegated: usize,
    /// Apps by their highest flag severity (`critical`, `high`, ...).
    #[serde(default)]
    pub flagged: BTreeMap<String, usize>,
}

/// Data the inventory could not read, so related fields and flags are absent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Gap {
    /// `owners`, `guests`, `sign_in_activity` or `service_principal_risk`.
    pub area: String,
    pub reason: Reason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerTenant {
    /// Registered in this tenant.
    Home,
    /// A Microsoft first-party application.
    Microsoft,
    /// Registered in another organisation (third-party or partner SaaS).
    External,
    /// No owning organisation reported (for example managed identities).
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Publisher {
    Microsoft,
    Verified { name: String },
    Unverified,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Credential {
    /// `application` (app registration) or `service_principal`.
    pub on: String,
    /// `secret` or `certificate`.
    pub kind: String,
    pub key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<String>,
    pub expired: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Owner {
    pub id: String,
    /// `user`, `service_principal` or `other`.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_principal_name: Option<String>,
    /// Whether the owner is a guest; `None` when Graph returned only an id stub
    /// and guest users could not be listed, so it is not known.
    pub guest: Option<bool>,
    /// `application` (app registration owner) or `service_principal`.
    pub of: String,
}

/// An application permission (app role) granted to the app.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AppPermission {
    pub resource_app_id: String,
    pub resource_name: String,
    /// Permission value, for example `Mail.Read`; the role id when unnamed.
    pub permission: String,
    pub assignment_id: String,
    pub resource_id: String,
    pub app_role_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted_at: Option<String>,
}

/// A delegated (OAuth2) permission grant made to the app.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DelegatedGrant {
    pub resource_app_id: String,
    pub resource_name: String,
    pub scopes: Vec<String>,
    /// `AllPrincipals` (admin consent for everyone) or `Principal` (one user).
    pub consent_type: String,
    pub grant_id: String,
    pub resource_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    /// Whether the consenting user is a guest; `None` when guests are unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_guest: Option<bool>,
}

/// Where a `last_sign_in` value comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignInData {
    /// The report lists a sign-in for this app.
    Recorded,
    /// The report was read and lists no sign-in for this app.
    NoneRecorded,
    /// The report could not be read (see the `sign_in_activity` gap).
    Unavailable,
}

/// An app registration in this tenant with no service principal here, so it
/// holds no permissions or grants in this tenant but its credentials and
/// owners still matter (for example a multi-tenant app offered to others).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registration {
    pub application_id: String,
    pub app_id: String,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_in_audience: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    pub credentials: Vec<Credential>,
    pub owners: Vec<Owner>,
    /// True when the owner lookup failed, so `owners` may be incomplete.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub owners_unread: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Risk {
    pub level: String,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct App {
    pub service_principal_id: String,
    pub app_id: String,
    pub display_name: String,
    pub service_principal_type: String,
    pub enabled: bool,
    pub owner_tenant: OwnerTenant,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_tenant_id: Option<String>,
    pub publisher: Publisher,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_in_audience: Option<String>,
    pub assignment_required: bool,
    /// Object id of the app registration when it lives in this tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    pub credentials: Vec<Credential>,
    /// The app registration has federated identity credentials (workload
    /// identity federation), so it can sign in without a secret or certificate.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub federated_credentials: bool,
    pub owners: Vec<Owner>,
    pub application_permissions: Vec<AppPermission>,
    pub delegated_grants: Vec<DelegatedGrant>,
    /// Owner lookups that failed for this app (`application` or
    /// `service_principal`). Owners from the other lookup are still listed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owners_unread: Vec<String>,
    /// Last sign-in in any role; always present, `null` when none is recorded
    /// or the report could not be read (see `sign_in_data`).
    #[serde(default)]
    pub last_sign_in: Option<String>,
    /// Whether `last_sign_in` is a reading, a reading of nothing, or missing.
    pub sign_in_data: SignInData,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<Risk>,
    #[serde(default)]
    pub flags: Vec<super::flags::Flag>,
}

impl App {
    /// Highest flag severity, if flagged.
    pub fn severity(&self) -> Option<Severity> {
        self.flags
            .iter()
            .map(|f| f.severity)
            .max_by_key(|s| s.rank())
    }
    pub fn is_microsoft(&self) -> bool {
        self.owner_tenant == OwnerTenant::Microsoft
    }
}

impl Inventory {
    pub fn gap(&self, area: &str) -> bool {
        self.gaps.iter().any(|g| g.area == area)
    }
    pub fn app(&self, id: &str) -> Option<&App> {
        self.apps.iter().find(|a| {
            a.service_principal_id.eq_ignore_ascii_case(id) || a.app_id.eq_ignore_ascii_case(id)
        })
    }
    /// Recompute [`Summary`] from the apps.
    pub fn summarise(&mut self) {
        let mut s = Summary {
            apps: self.apps.len(),
            registrations_without_service_principal: self
                .registrations_without_service_principal
                .len(),
            ..Summary::default()
        };
        for app in &self.apps {
            match app.owner_tenant {
                OwnerTenant::Home => s.home_tenant += 1,
                OwnerTenant::External => s.external += 1,
                OwnerTenant::Microsoft => s.microsoft += 1,
                OwnerTenant::Unknown => {}
            }
            s.with_application_permissions += usize::from(!app.application_permissions.is_empty());
            s.with_tenant_wide_delegated += usize::from(
                app.delegated_grants
                    .iter()
                    .any(|g| g.consent_type == "AllPrincipals"),
            );
            s.with_user_delegated += usize::from(
                app.delegated_grants
                    .iter()
                    .any(|g| g.consent_type == "Principal"),
            );
            if let Some(severity) = app.severity() {
                *s.flagged.entry(severity.as_str().to_owned()).or_default() += 1;
            }
        }
        self.summary = s;
    }
}

/// The inventory could not be built because a required listing failed.
#[derive(Debug, Clone)]
pub struct CollectError {
    pub reason: Reason,
}

impl std::fmt::Display for CollectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason.detail)
    }
}
impl std::error::Error for CollectError {}

fn reason(failure: &CallFailure) -> Reason {
    crate::outcome::from_failure(&META, failure).1
}

fn required(failure: CallFailure) -> CollectError {
    CollectError {
        reason: reason(&failure),
    }
}

fn s(v: &Value, key: &str) -> Option<String> {
    v[key].as_str().map(str::to_owned)
}

fn is_guest(user: &Value) -> bool {
    user["userType"]
        .as_str()
        .is_some_and(|t| t.eq_ignore_ascii_case("guest"))
        || user["userPrincipalName"]
            .as_str()
            .is_some_and(|u| u.to_ascii_uppercase().contains("#EXT#"))
}

/// Credentials without any secret material.
fn credentials(object: &Value, on: &str, now: Instant) -> Vec<Credential> {
    let mut out = vec![];
    for (field, kind) in [
        ("passwordCredentials", "secret"),
        ("keyCredentials", "certificate"),
    ] {
        for c in object[field].as_array().into_iter().flatten() {
            let end = s(c, "endDateTime");
            let expired = end
                .as_deref()
                .and_then(|e| Instant::parse(e).ok())
                .is_some_and(|e| e < now);
            out.push(Credential {
                on: on.to_owned(),
                kind: kind.to_owned(),
                key_id: s(c, "keyId").unwrap_or_default(),
                display_name: s(c, "displayName").filter(|n| !n.is_empty()),
                end,
                expired,
            });
        }
    }
    out
}

/// One owner. `guests` (lower-case ids of guest users, when they could be
/// listed) is authoritative; otherwise `userType` or an `#EXT#` UPN on the
/// object decides, and an id-only stub (Graph omits user properties without
/// `User.Read.All`) leaves guest status unknown.
fn owner(object: &Value, of: &str, guests: Option<&BTreeSet<String>>) -> Owner {
    let kind = match object["@odata.type"].as_str() {
        Some("#microsoft.graph.user") => "user",
        Some("#microsoft.graph.servicePrincipal") => "service_principal",
        None if object.get("userPrincipalName").is_some() => "user",
        _ => "other",
    };
    let id = s(object, "id").unwrap_or_default();
    let described = object.get("userType").is_some() || object.get("userPrincipalName").is_some();
    let guest = match (kind, guests) {
        ("user", Some(guests)) => Some(guests.contains(&id.to_lowercase()) || is_guest(object)),
        ("user", None) if described => Some(is_guest(object)),
        ("user", None) => None,
        _ => Some(false),
    };
    Owner {
        id,
        kind: kind.to_owned(),
        display_name: s(object, "displayName"),
        user_principal_name: s(object, "userPrincipalName"),
        guest,
        of: of.to_owned(),
    }
}

/// Run `calls` with bounded concurrency, keeping input order.
///
/// The indexed futures are built eagerly into boxed `Send` futures, so no
/// closure lives in the returned future's state: closures there defeat the
/// `Send` proof MCP and HTTP hosts need to spawn the inventory (see the same
/// note in [`crate::runner`]).
async fn fan_out<'a, T: Send + 'a>(
    calls: Vec<crate::gateway::BoxFut<'a, Result<T, CallFailure>>>,
) -> Vec<Result<T, CallFailure>> {
    let mut pending: Vec<crate::gateway::BoxFut<'a, (usize, Result<T, CallFailure>)>> = vec![];
    for (i, call) in calls.into_iter().enumerate() {
        pending.push(Box::pin(async move { (i, call.await) }));
    }
    let mut indexed: Vec<(usize, Result<T, CallFailure>)> = futures_util::stream::iter(pending)
        .buffer_unordered(FAN_OUT)
        .collect()
        .await;
    indexed.sort_by_key(|(i, _)| *i);
    indexed.into_iter().map(|(_, r)| r).collect()
}

struct Resource {
    app_id: String,
    name: String,
    roles: BTreeMap<String, String>,
}

/// Read the tenant and build the inventory (without flags; see
/// [`super::flags::apply`]).
pub async fn collect(ctx: &CheckContext) -> Result<Inventory, CollectError> {
    let now = ctx.now();
    let tenant = ctx.tenant_id().to_owned();
    let sps = ctx
        .list_with(
            SERVICE_PRINCIPALS.operation,
            json!({"$select": ["id", "appId", "displayName", "servicePrincipalType", "accountEnabled",
                "appOwnerOrganizationId", "verifiedPublisher", "appRoleAssignmentRequired",
                "passwordCredentials", "keyCredentials", "appRoles", "signInAudience"]}),
        )
        .await
        .map_err(required)?;
    let applications = ctx
        .list_with(
            APPLICATIONS.operation,
            json!({"$select": ["id", "appId", "displayName", "signInAudience", "createdDateTime",
                "passwordCredentials", "keyCredentials"],
                "$expand": ["federatedIdentityCredentials($select=id)"]}),
        )
        .await
        .map_err(required)?;
    let grants = ctx
        .list_with(DELEGATED_GRANTS.operation, json!({}))
        .await
        .map_err(required)?;

    // Resources: every service principal that defines application roles.
    let mut resources: BTreeMap<String, Resource> = BTreeMap::new();
    for sp in &sps {
        let Some(id) = sp["id"].as_str() else {
            continue;
        };
        // Only roles assignable to applications are application permissions;
        // user-only roles (gallery SSO apps) can have huge assignment lists
        // that are never app permissions, so their resources are not listed.
        let roles: BTreeMap<String, String> = sp["appRoles"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|r| {
                r["allowedMemberTypes"]
                    .as_array()
                    .is_some_and(|t| t.iter().any(|m| m.as_str() == Some("Application")))
                    && r["value"].as_str().is_some_and(|v| !v.is_empty())
            })
            .filter_map(|r| {
                Some((
                    r["id"].as_str()?.to_lowercase(),
                    r["value"].as_str()?.to_owned(),
                ))
            })
            .collect();
        resources.insert(
            id.to_lowercase(),
            Resource {
                app_id: s(sp, "appId").unwrap_or_default(),
                name: s(sp, "displayName").unwrap_or_else(|| "Unknown".into()),
                roles,
            },
        );
    }

    // Application permissions: assignments on each resource that defines app roles.
    let role_resources: Vec<String> = resources
        .iter()
        .filter(|(_, r)| !r.roles.is_empty())
        .map(|(id, _)| id.clone())
        .collect();
    let listings: Vec<Result<Vec<Value>, CallFailure>> = fan_out(
        role_resources
            .iter()
            .map(|id| {
                Box::pin(ctx.list_with(
                    APP_ROLE_ASSIGNMENTS.operation,
                    json!({"servicePrincipal-id": id}),
                )) as crate::gateway::BoxFut<'_, _>
            })
            .collect(),
    )
    .await;
    let mut permissions: BTreeMap<String, Vec<AppPermission>> = BTreeMap::new();
    for (resource_id, listing) in role_resources.iter().zip(listings) {
        let resource = &resources[resource_id];
        for a in listing.map_err(required)? {
            if a["principalType"].as_str() != Some("ServicePrincipal") {
                continue; // user and group assignments are not app permissions
            }
            let (Some(principal), Some(role)) =
                (a["principalId"].as_str(), a["appRoleId"].as_str())
            else {
                continue;
            };
            permissions
                .entry(principal.to_lowercase())
                .or_default()
                .push(AppPermission {
                    resource_app_id: resource.app_id.clone(),
                    resource_name: resource.name.clone(),
                    permission: resource
                        .roles
                        .get(&role.to_lowercase())
                        .cloned()
                        .unwrap_or_else(|| role.to_owned()),
                    assignment_id: s(&a, "id").unwrap_or_default(),
                    resource_id: resource_id.clone(),
                    app_role_id: role.to_lowercase(),
                    granted_at: s(&a, "createdDateTime"),
                });
        }
    }

    let mut gaps = vec![];

    // Guests, to mark per-user consents made by guests.
    let guests: Option<BTreeSet<String>> = match ctx
        .list_with(
            GUEST_USERS.operation,
            json!({"$filter": "userType eq 'Guest'", "$select": ["id", "userPrincipalName", "userType"]}),
        )
        .await
    {
        Ok(rows) => Some(
            rows.iter()
                .filter_map(|u| u["id"].as_str().map(str::to_lowercase))
                .collect(),
        ),
        Err(f) => {
            gaps.push(Gap {
                area: "guests".into(),
                reason: reason(&f),
            });
            None
        }
    };

    let mut delegated: BTreeMap<String, Vec<DelegatedGrant>> = BTreeMap::new();
    for g in &grants {
        let Some(client) = g["clientId"].as_str() else {
            continue;
        };
        let resource_id = s(g, "resourceId").unwrap_or_default().to_lowercase();
        let resource = resources.get(&resource_id);
        let principal_id = s(g, "principalId").filter(|p| !p.is_empty());
        let mut scopes: Vec<String> = g["scope"]
            .as_str()
            .unwrap_or("")
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        scopes.sort();
        scopes.dedup();
        delegated
            .entry(client.to_lowercase())
            .or_default()
            .push(DelegatedGrant {
                resource_app_id: resource.map(|r| r.app_id.clone()).unwrap_or_default(),
                resource_name: resource
                    .map(|r| r.name.clone())
                    .unwrap_or_else(|| "Unknown".into()),
                scopes,
                consent_type: s(g, "consentType").unwrap_or_default(),
                grant_id: s(g, "id").unwrap_or_default(),
                resource_id,
                principal_guest: match (&principal_id, &guests) {
                    (Some(p), Some(guests)) => Some(guests.contains(&p.to_lowercase())),
                    _ => None,
                },
                principal_id,
            });
    }

    // App registrations in this tenant, by app id.
    let registrations: BTreeMap<String, &Value> = applications
        .iter()
        .filter_map(|a| Some((a["appId"].as_str()?.to_lowercase(), a)))
        .collect();

    // Owners of every service principal (including Microsoft first-party ones,
    // which can still be given owners here) and of every app registration.
    // Targets are keyed by service principal id, or by `app:<object id>` for
    // registrations with no service principal in this tenant.
    let sp_app_ids: BTreeSet<String> = sps
        .iter()
        .filter_map(|sp| sp["appId"].as_str().map(str::to_lowercase))
        .collect();
    let mut owner_targets: Vec<(String, &'static str, String)> = vec![]; // (key, of, object id)
    for sp in &sps {
        let Some(id) = sp["id"].as_str() else {
            continue;
        };
        owner_targets.push((id.to_lowercase(), "service_principal", id.to_owned()));
        if let Some(app) = sp["appId"]
            .as_str()
            .and_then(|a| registrations.get(&a.to_lowercase()))
            && let Some(app_object) = app["id"].as_str()
        {
            owner_targets.push((id.to_lowercase(), "application", app_object.to_owned()));
        }
    }
    for (app_id, reg) in &registrations {
        if !sp_app_ids.contains(app_id)
            && let Some(object) = reg["id"].as_str()
        {
            owner_targets.push((
                format!("app:{}", object.to_lowercase()),
                "application",
                object.to_owned(),
            ));
        }
    }
    let owner_results: Vec<Result<Vec<Value>, CallFailure>> = fan_out(
        owner_targets
            .iter()
            .map(|(_, of, object)| {
                let (op, param) = if *of == "application" {
                    (APPLICATION_OWNERS.operation, "application-id")
                } else {
                    (SERVICE_PRINCIPAL_OWNERS.operation, "servicePrincipal-id")
                };
                Box::pin(ctx.list_with(op, json!({ param: object })))
                    as crate::gateway::BoxFut<'_, _>
            })
            .collect(),
    )
    .await;
    // Successful lookups are always kept; a failed one is recorded against
    // that app and source, so it never erases owners read elsewhere.
    let mut owners: BTreeMap<String, Vec<Owner>> = BTreeMap::new();
    let mut owners_unread: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut owner_gap = None;
    for ((key, of, _), result) in owner_targets.iter().zip(owner_results) {
        match result {
            Ok(rows) => owners
                .entry(key.clone())
                .or_default()
                .extend(rows.iter().map(|o| owner(o, of, guests.as_ref()))),
            Err(f) => {
                owners_unread
                    .entry(key.clone())
                    .or_default()
                    .push((*of).to_owned());
                owner_gap.get_or_insert_with(|| reason(&f));
            }
        }
    }
    if let Some(reason) = owner_gap {
        gaps.push(Gap {
            area: "owners".into(),
            reason,
        });
    }

    // Sign-in recency (Entra ID P1 or P2), by app id. `None` when unreadable.
    let sign_ins: Option<BTreeMap<String, String>> =
        match ctx.list_with(SIGN_IN_ACTIVITY.operation, json!({})).await {
            Ok(rows) => Some(
                rows.iter()
                    .filter_map(|r| {
                        let at = r
                            .pointer("/lastSignInActivity/lastSignInDateTime")
                            .and_then(Value::as_str)?;
                        Some((r["appId"].as_str()?.to_lowercase(), at.to_owned()))
                    })
                    .collect(),
            ),
            Err(f) => {
                gaps.push(Gap {
                    area: "sign_in_activity".into(),
                    reason: reason(&f),
                });
                None
            }
        };

    // Workload identity risk (Workload Identities Premium), keyed by the
    // service principal object id (`id`); Graph documents `appId` as optional.
    let risks: BTreeMap<String, Risk> = match ctx
        .list_with(RISKY_SERVICE_PRINCIPALS.operation, json!({}))
        .await
    {
        Ok(rows) => rows
            .iter()
            .filter_map(|r| {
                Some((
                    r["id"].as_str()?.to_lowercase(),
                    Risk {
                        level: s(r, "riskLevel").unwrap_or_default(),
                        state: s(r, "riskState").unwrap_or_default(),
                    },
                ))
            })
            .collect(),
        Err(f) => {
            gaps.push(Gap {
                area: "service_principal_risk".into(),
                reason: reason(&f),
            });
            BTreeMap::new()
        }
    };

    let mut apps = vec![];
    for sp in &sps {
        let Some(id) = sp["id"].as_str() else {
            continue;
        };
        let key = id.to_lowercase();
        let app_id = s(sp, "appId").unwrap_or_default();
        let owner_org = s(sp, "appOwnerOrganizationId");
        let owner_tenant = if is_microsoft_owned(sp) {
            OwnerTenant::Microsoft
        } else {
            match &owner_org {
                Some(o) if o.eq_ignore_ascii_case(&tenant) => OwnerTenant::Home,
                Some(_) => OwnerTenant::External,
                None => OwnerTenant::Unknown,
            }
        };
        let publisher = match (
            owner_tenant,
            sp["verifiedPublisher"]["displayName"].as_str(),
        ) {
            (OwnerTenant::Microsoft, _) => Publisher::Microsoft,
            (_, Some(name)) if !name.is_empty() => Publisher::Verified {
                name: name.to_owned(),
            },
            _ => Publisher::Unverified,
        };
        let registration = registrations.get(&app_id.to_lowercase()).copied();
        let mut creds = credentials(sp, "service_principal", now);
        if let Some(reg) = registration {
            creds.extend(credentials(reg, "application", now));
        }
        creds.sort();
        let mut app_permissions = permissions.remove(&key).unwrap_or_default();
        app_permissions.sort();
        let mut grants = delegated.remove(&key).unwrap_or_default();
        grants.sort();
        let mut app_owners = owners.remove(&key).unwrap_or_default();
        app_owners.sort();
        app_owners.dedup();
        let last_sign_in = sign_ins
            .as_ref()
            .and_then(|m| m.get(&app_id.to_lowercase()).cloned());
        let sign_in_data = match (&sign_ins, &last_sign_in) {
            (None, _) => SignInData::Unavailable,
            (Some(_), Some(_)) => SignInData::Recorded,
            (Some(_), None) => SignInData::NoneRecorded,
        };
        apps.push(App {
            service_principal_id: id.to_owned(),
            display_name: s(sp, "displayName").unwrap_or_else(|| "Unknown".into()),
            service_principal_type: s(sp, "servicePrincipalType").unwrap_or_default(),
            enabled: sp["accountEnabled"].as_bool().unwrap_or(true),
            owner_tenant,
            owner_tenant_id: owner_org,
            publisher,
            sign_in_audience: registration
                .and_then(|r| s(r, "signInAudience"))
                .or_else(|| s(sp, "signInAudience")),
            assignment_required: sp["appRoleAssignmentRequired"].as_bool().unwrap_or(false),
            application_id: registration.and_then(|r| s(r, "id")),
            created_at: registration.and_then(|r| s(r, "createdDateTime")),
            credentials: creds,
            federated_credentials: registration.is_some_and(|r| {
                r["federatedIdentityCredentials"]
                    .as_array()
                    .is_some_and(|f| !f.is_empty())
            }),
            owners: app_owners,
            owners_unread: owners_unread.remove(&key).unwrap_or_default(),
            application_permissions: app_permissions,
            delegated_grants: grants,
            last_sign_in,
            sign_in_data,
            risk: risks.get(&key).cloned(),
            flags: vec![],
            app_id,
        });
    }
    apps.sort_by(|a, b| {
        a.display_name
            .to_lowercase()
            .cmp(&b.display_name.to_lowercase())
            .then_with(|| a.service_principal_id.cmp(&b.service_principal_id))
    });
    let mut unmatched = vec![];
    for (app_id, reg) in &registrations {
        if sp_app_ids.contains(app_id) {
            continue;
        }
        let Some(object) = reg["id"].as_str() else {
            continue;
        };
        let key = format!("app:{}", object.to_lowercase());
        let mut reg_owners = owners.remove(&key).unwrap_or_default();
        reg_owners.sort();
        reg_owners.dedup();
        let mut creds = credentials(reg, "application", now);
        creds.sort();
        unmatched.push(Registration {
            application_id: object.to_owned(),
            app_id: s(reg, "appId").unwrap_or_default(),
            display_name: s(reg, "displayName").unwrap_or_else(|| "Unknown".into()),
            sign_in_audience: s(reg, "signInAudience"),
            created_at: s(reg, "createdDateTime"),
            credentials: creds,
            owners: reg_owners,
            owners_unread: owners_unread.contains_key(&key),
        });
    }
    unmatched.sort_by(|a, b| {
        a.display_name
            .to_lowercase()
            .cmp(&b.display_name.to_lowercase())
            .then_with(|| a.application_id.cmp(&b.application_id))
    });
    let mut inventory = Inventory {
        schema_version: SCHEMA_VERSION,
        tenant_id: tenant,
        label: ctx.label().map(str::to_owned),
        captured_at: now.to_rfc3339(),
        summary: Summary::default(),
        gaps,
        apps,
        registrations_without_service_principal: unmatched,
    };
    inventory.summarise();
    Ok(inventory)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_never_copy_secret_material() {
        let sp = json!({"passwordCredentials": [{"keyId": "k1", "hint": "abc", "secretText": "s",
            "displayName": "ci", "endDateTime": "2020-01-01T00:00:00Z"}],
            "keyCredentials": [{"keyId": "k2", "key": "MIIB", "customKeyIdentifier": "AB",
            "endDateTime": "2030-01-01T00:00:00Z"}]});
        let creds = credentials(
            &sp,
            "service_principal",
            Instant::parse("2026-01-01T00:00:00Z").unwrap(),
        );
        let text = serde_json::to_string(&creds).unwrap();
        for secret in ["abc", "MIIB", "\"AB\"", "secretText"] {
            assert!(!text.contains(secret), "{secret} leaked: {text}");
        }
        assert!(creds[0].expired && !creds[1].expired);
    }

    #[test]
    fn guests_detected_by_type_or_external_upn() {
        assert!(is_guest(&json!({"userType": "Guest"})));
        assert!(is_guest(
            &json!({"userPrincipalName": "a_fabrikam.example#EXT#@contoso.example"})
        ));
        assert!(!is_guest(
            &json!({"userType": "Member", "userPrincipalName": "a@contoso.example"})
        ));
    }
}
