//! What the watchdog reads, which permission each source needs, and why.
//!
//! Default application permissions are read-only. The optional Exchange runner's
//! effective access depends on its separately assigned, scoped Exchange roles.
use crate::upstream::Api;
use serde::Serialize;
use serde_json::{Value, json};

pub const GRAPH_APP_ID: &str = "00000003-0000-0000-c000-000000000000";
/// Office 365 Management APIs. Not published on Learn; confirm with
/// `GET /servicePrincipals(appId='c5393580-f805-4401-95e8-94b7a6ef2fc2')?$select=appRoles`.
pub const MANAGEMENT_APP_ID: &str = "c5393580-f805-4401-95e8-94b7a6ef2fc2";
pub const EXCHANGE_APP_ID: &str = "00000002-0000-0ff1-ce00-000000000000";

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Permission {
    pub name: &'static str,
    pub resource: &'static str,
    pub resource_app_id: &'static str,
    pub app_role_id: &'static str,
    pub optional: bool,
    pub why: &'static str,
    pub cannot: &'static str,
}

pub const PERMISSIONS: &[Permission] = &[
    Permission {
        name: "ActivityFeed.Read",
        resource: "Office 365 Management APIs",
        resource_app_id: MANAGEMENT_APP_ID,
        app_role_id: "594c1fb6-4f81-4475-ae41-0c394909246c",
        optional: false,
        why: "Reads the unified audit feed: mailbox rule and forwarding changes, mailbox permission changes, SharePoint and OneDrive sharing, downloads and deletions, and admin actions.",
        cannot: "Cannot read email, files or chat content, and cannot change any setting.",
    },
    Permission {
        name: "AuditLog.Read.All",
        resource: "Microsoft Graph",
        resource_app_id: GRAPH_APP_ID,
        app_role_id: "b0afded3-3588-46d8-8b3d-9842eff778da",
        optional: false,
        why: "Reads the Entra ID directory audit log (role assignments, app consents, credential changes). Sign-in logs are also read if the tenant has Entra ID P1 or P2.",
        cannot: "Cannot sign in as users, reset passwords or change the directory.",
    },
    Permission {
        name: "Organization.Read.All",
        resource: "Microsoft Graph",
        resource_app_id: GRAPH_APP_ID,
        app_role_id: "498476ce-e0fe-48b0-b801-37ba7e2685c6",
        optional: false,
        why: "Reads the organisation profile, verified domains (to tell internal from external addresses) and subscriptions (to explain coverage).",
        cannot: "Cannot change licences, domains or billing.",
    },
    Permission {
        name: "SharePointTenantSettings.Read.All",
        resource: "Microsoft Graph",
        resource_app_id: GRAPH_APP_ID,
        app_role_id: "83d4163d-a2d8-4d3b-9695-4ae3ca98f888",
        optional: false,
        why: "Reads tenant-wide SharePoint and OneDrive sharing settings to detect weakened external sharing.",
        cannot: "Cannot read sites or files, or change sharing settings.",
    },
    Permission {
        name: "Exchange.ManageAsApp",
        resource: "Office 365 Exchange Online",
        resource_app_id: EXCHANGE_APP_ID,
        app_role_id: "dc50a0fb-09a3-484d-be87-e023b12c6440",
        optional: true,
        why: "Only for the optional Exchange configuration runner (PowerShell). Combined with the View-Only Configuration and View-Only Recipients roles it reads forwarding, delegation and transport rules.",
        cannot: "With View-Only roles only, it cannot change mailboxes or rules and cannot read mail.",
    },
];

#[derive(Debug, Clone, Copy, Serialize)]
pub struct SourceSpec {
    pub id: &'static str,
    pub title: &'static str,
    #[serde(skip)]
    pub api: Api,
    pub permission: &'static str,
    pub licence_note: &'static str,
    pub docs_url: &'static str,
    /// Detection rule IDs this source can feed once it is collected.
    pub detections: &'static [&'static str],
    /// Whether this release actually collects the source. Only collected,
    /// usable sources count towards detection coverage; probe-only and
    /// enrichment sources never make a detection look runnable.
    pub collected: bool,
}

const MGMT_DOCS: &str = "https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference";
const AUDIT_LICENCE: &str = "Purview Audit (Standard): included in Microsoft 365 Business Basic, Standard and Premium and Office 365 E1/E3, nonprofit grant entitlements must be confirmed by actual probes. Auditing is OFF by default on Business plans and must be turned on. 180-day searchable retention; the API keeps content for 7 days.";

pub const CONTENT_TYPES: [&str; 4] = [
    "Audit.AzureActiveDirectory",
    "Audit.Exchange",
    "Audit.SharePoint",
    "Audit.General",
];

pub const SOURCES: &[SourceSpec] = &[
    SourceSpec {
        id: "o365:Audit.Exchange",
        title: "Exchange audit feed",
        api: Api::ManagementActivity,
        permission: "ActivityFeed.Read",
        licence_note: AUDIT_LICENCE,
        docs_url: MGMT_DOCS,
        detections: &[
            "M365-EXO-001",
            "M365-EXO-002",
            "M365-EXO-003",
            "M365-EXO-004",
            "M365-EXO-005",
            "M365-EXO-006",
        ],
        collected: true,
    },
    SourceSpec {
        id: "o365:Audit.SharePoint",
        title: "SharePoint and OneDrive audit feed",
        api: Api::ManagementActivity,
        permission: "ActivityFeed.Read",
        licence_note: AUDIT_LICENCE,
        docs_url: MGMT_DOCS,
        detections: &[
            "M365-SPO-001",
            "M365-SPO-002",
            "M365-SPO-003",
            "M365-SPO-004",
            "M365-SPO-005",
            "M365-SPO-006",
            "M365-SPO-007",
        ],
        collected: true,
    },
    SourceSpec {
        id: "o365:Audit.AzureActiveDirectory",
        title: "Entra ID audit feed (unified log)",
        api: Api::ManagementActivity,
        permission: "ActivityFeed.Read",
        licence_note: AUDIT_LICENCE,
        docs_url: MGMT_DOCS,
        detections: &[
            "M365-ID-001",
            "M365-ID-002",
            "M365-ID-003",
            "M365-ID-004",
            "M365-ID-005",
            "M365-ID-006",
        ],
        collected: true,
    },
    SourceSpec {
        id: "o365:Audit.General",
        title: "Other workloads audit feed",
        api: Api::ManagementActivity,
        permission: "ActivityFeed.Read",
        licence_note: AUDIT_LICENCE,
        docs_url: MGMT_DOCS,
        detections: &[],
        collected: true,
    },
    SourceSpec {
        id: "graph:directoryAudits",
        title: "Entra ID directory audit log (Graph)",
        api: Api::Graph,
        permission: "AuditLog.Read.All",
        licence_note: "Probe actual Graph directory-audit access. Entra directory retention is typically 7 days on Free and 30 days with P1/P2; API availability is not inferred from this retention.",
        docs_url: "https://learn.microsoft.com/en-us/graph/api/directoryaudit-list?view=graph-rest-1.0",
        detections: &[
            "M365-ID-001",
            "M365-ID-002",
            "M365-ID-003",
            "M365-ID-004",
            "M365-ID-005",
            "M365-ID-006",
        ],
        collected: true,
    },
    SourceSpec {
        id: "graph:signIns",
        title: "Entra ID sign-in log (Graph)",
        api: Api::Graph,
        permission: "AuditLog.Read.All",
        licence_note: "Requires Entra ID P1 or P2 for API access. Sign-ins visible in the admin portal on Free do NOT mean the API is available.",
        docs_url: "https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0",
        detections: &["M365-ID-007"],
        collected: true,
    },
    SourceSpec {
        id: "graph:organization",
        title: "Organisation profile and verified domains",
        api: Api::Graph,
        permission: "Organization.Read.All",
        licence_note: "All plans.",
        docs_url: "https://learn.microsoft.com/en-us/graph/api/organization-list?view=graph-rest-1.0",
        detections: &[],
        collected: false,
    },
    SourceSpec {
        id: "graph:subscribedSkus",
        title: "Subscriptions and service plans",
        api: Api::Graph,
        permission: "Organization.Read.All",
        licence_note: "All plans. Shown for context only; coverage is decided by live probes, never by plan names.",
        docs_url: "https://learn.microsoft.com/en-us/graph/api/subscribedsku-list?view=graph-rest-1.0",
        detections: &[],
        collected: false,
    },
    SourceSpec {
        id: "graph:sharepointSettings",
        title: "SharePoint tenant sharing settings",
        api: Api::Graph,
        permission: "SharePointTenantSettings.Read.All",
        licence_note: "All plans with SharePoint Online.",
        docs_url: "https://learn.microsoft.com/en-us/graph/api/sharepointsettings-get?view=graph-rest-1.0",
        detections: &["M365-SPO-006"],
        collected: true,
    },
];

pub fn source(id: &str) -> Option<&'static SourceSpec> {
    SOURCES.iter().find(|s| s.id == id)
}

/// `requiredResourceAccess` block for the app registration manifest.
pub fn required_resource_access(include_optional: bool) -> Value {
    let mut by_resource: Vec<(&str, Vec<Value>)> = vec![];
    for p in PERMISSIONS
        .iter()
        .filter(|p| include_optional || !p.optional)
    {
        let entry = json!({"id": p.app_role_id, "type": "Role"});
        match by_resource
            .iter_mut()
            .find(|(r, _)| *r == p.resource_app_id)
        {
            Some((_, list)) => list.push(entry),
            None => by_resource.push((p.resource_app_id, vec![entry])),
        }
    }
    Value::Array(
        by_resource
            .into_iter()
            .map(|(app, access)| json!({"resourceAppId": app, "resourceAccess": access}))
            .collect(),
    )
}

/// Tenant-wide admin consent link (v1 endpoint consents to every permission in
/// the app's manifest). The portal's "Grant admin consent" button is equivalent.
pub fn admin_consent_url(tenant_id: &str, client_id: &str, redirect_uri: &str) -> String {
    let mut url = url::Url::parse("https://login.microsoftonline.com/").expect("static URL");
    url.path_segments_mut()
        .expect("base URL")
        .push(tenant_id)
        .push("adminconsent");
    url.query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri);
    url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn manifest_requests_only_roles_and_no_write_permissions() {
        let rra = required_resource_access(false);
        let text = rra.to_string();
        assert!(
            !text.contains("dc50a0fb"),
            "optional Exchange role excluded by default"
        );
        for p in PERMISSIONS {
            assert!(!p.name.contains("Write") && !p.name.contains("FullControl"));
            assert!(!p.name.starts_with("Mail.") && !p.name.starts_with("Sites."));
        }
        assert!(rra.as_array().unwrap().iter().all(|r| {
            r["resourceAccess"]
                .as_array()
                .unwrap()
                .iter()
                .all(|a| a["type"] == "Role")
        }));
        assert!(
            required_resource_access(true)
                .to_string()
                .contains("dc50a0fb")
        );
    }
    #[test]
    fn every_source_permission_is_catalogued() {
        for s in SOURCES {
            assert!(
                PERMISSIONS.iter().any(|p| p.name == s.permission),
                "{}",
                s.id
            );
        }
        for ct in CONTENT_TYPES {
            assert!(source(&format!("o365:{ct}")).is_some());
        }
    }
    #[test]
    fn consent_url_is_encoded() {
        let url = admin_consent_url(
            "11111111-1111-4111-8111-111111111111",
            "abc",
            "http://localhost:8787/consent?x=1&y=2",
        );
        assert!(url.starts_with("https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/adminconsent?client_id=abc&redirect_uri=http%3A%2F%2Flocalhost"));
        assert!(!url.contains("&y=2"));
    }
}
