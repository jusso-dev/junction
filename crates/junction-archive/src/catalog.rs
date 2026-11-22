//! What the archive reads and writes, which permission each needs, and why.
//!
//! Tenant permissions are read-only application permissions. Storage roles are
//! split by job so the collector can only create objects, searchers can only
//! read, and only a separate hold administrator can place legal holds.
use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize)]
pub struct SourcePermission {
    pub source: &'static str,
    pub api: &'static str,
    pub endpoint: &'static str,
    pub permission: &'static str,
    pub resource: &'static str,
    pub default: bool,
    pub why: &'static str,
    pub licence_note: &'static str,
}

pub const SOURCES: &[SourcePermission] = &[
    SourcePermission {
        source: "o365:Audit.AzureActiveDirectory",
        api: "Office 365 Management Activity API",
        endpoint: "GET /api/v1.0/{tenant}/activity/feed/subscriptions/content, content blobs",
        permission: "ActivityFeed.Read",
        resource: "Office 365 Management APIs",
        default: true,
        why: "Entra ID events in the Unified Audit Log (user, group, role and application changes recorded by the audit pipeline).",
        licence_note: "Purview Audit (Standard). The feed subscription must be started (`junction watch subscribe`).",
    },
    SourcePermission {
        source: "o365:Audit.Exchange",
        api: "Office 365 Management Activity API",
        endpoint: "GET /api/v1.0/{tenant}/activity/feed/subscriptions/content, content blobs",
        permission: "ActivityFeed.Read",
        resource: "Office 365 Management APIs",
        default: true,
        why: "Exchange admin and mailbox audit records (forwarding, inbox rules, mailbox permissions, audit bypass).",
        licence_note: "Purview Audit (Standard).",
    },
    SourcePermission {
        source: "o365:Audit.SharePoint",
        api: "Office 365 Management Activity API",
        endpoint: "GET /api/v1.0/{tenant}/activity/feed/subscriptions/content, content blobs",
        permission: "ActivityFeed.Read",
        resource: "Office 365 Management APIs",
        default: true,
        why: "SharePoint and OneDrive file, sharing and site administration records.",
        licence_note: "Purview Audit (Standard).",
    },
    SourcePermission {
        source: "o365:Audit.General",
        api: "Office 365 Management Activity API",
        endpoint: "GET /api/v1.0/{tenant}/activity/feed/subscriptions/content, content blobs",
        permission: "ActivityFeed.Read",
        resource: "Office 365 Management APIs",
        default: true,
        why: "Every other workload that writes to the Unified Audit Log (Teams, Defender, Purview and others).",
        licence_note: "Purview Audit (Standard).",
    },
    SourcePermission {
        source: "graph:directoryAudits",
        api: "Microsoft Graph",
        endpoint: "GET /v1.0/auditLogs/directoryAudits",
        permission: "AuditLog.Read.All",
        resource: "Microsoft Graph",
        default: true,
        why: "Entra ID audit log: role assignments, app consents, credential and policy changes.",
        licence_note: "All Entra ID editions (7 days on Free, 30 days on P1 or P2).",
    },
    SourcePermission {
        source: "graph:signIns",
        api: "Microsoft Graph",
        endpoint: "GET /v1.0/auditLogs/signIns",
        permission: "AuditLog.Read.All",
        resource: "Microsoft Graph",
        default: true,
        why: "Entra ID interactive and federated sign-ins, with Conditional Access and risk fields.",
        licence_note: "Needs Entra ID P1 or P2. Skipped with requires_licence otherwise.",
    },
    SourcePermission {
        source: "graph:alerts_v2",
        api: "Microsoft Graph security API",
        endpoint: "GET /v1.0/security/alerts_v2",
        permission: "SecurityAlert.Read.All",
        resource: "Microsoft Graph",
        default: false,
        why: "Defender XDR alerts across Endpoint, Office 365, Identity, Cloud Apps and Entra ID Protection: what was detected, its severity, MITRE techniques and classification. Each update is archived as a new version.",
        licence_note: "Any Defender XDR workload. Opt-in.",
    },
    SourcePermission {
        source: "graph:incidents",
        api: "Microsoft Graph security API",
        endpoint: "GET /v1.0/security/incidents",
        permission: "SecurityIncident.Read.All",
        resource: "Microsoft Graph",
        default: false,
        why: "Defender XDR incidents: the correlated investigation record with classification, determination, assignment and resolution. Each update is archived as a new version.",
        licence_note: "Any Defender XDR workload. Opt-in.",
    },
];

#[derive(Debug, Clone, Copy, Serialize)]
pub struct StorageRole {
    pub identity: &'static str,
    pub backend: &'static str,
    pub grant: &'static str,
    pub can: &'static str,
    pub cannot: &'static str,
}

pub const STORAGE_ROLES: &[StorageRole] = &[
    StorageRole {
        identity: "collector",
        backend: "azure_blob",
        grant: "Custom role with Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read and .../blobs/add/action on the container (see examples/archive/archive-storage.bicep)",
        can: "Create new blobs and read them back.",
        cannot: "Overwrite, delete, change retention or set legal holds.",
    },
    StorageRole {
        identity: "searcher",
        backend: "azure_blob",
        grant: "Storage Blob Data Reader on the container",
        can: "List and read archived objects, for search and export.",
        cannot: "Write, delete or hold anything.",
    },
    StorageRole {
        identity: "hold administrator",
        backend: "azure_blob",
        grant: "Storage Blob Data Contributor on the container (needed for Set Blob Legal Hold)",
        can: "Set and clear legal holds, and create hold manifests.",
        cannot: "Delete or overwrite blobs while the container's immutability policy protects them.",
    },
    StorageRole {
        identity: "collector",
        backend: "r2",
        grant: "R2 API token with Object Read & Write, scoped to the one bucket",
        can: "Create new objects and read them back. Hold copies under holds/.",
        cannot: "Overwrite or delete objects covered by bucket lock rules, or change the rules (that needs Admin Read & Write).",
    },
    StorageRole {
        identity: "searcher",
        backend: "r2",
        grant: "R2 API token with Object Read only, scoped to the one bucket",
        can: "List and read archived objects.",
        cannot: "Write anything.",
    },
];

pub fn source(id: &str) -> Option<&'static SourcePermission> {
    SOURCES.iter().find(|s| s.source == id)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_configurable_source_is_catalogued() {
        for id in crate::config::ALL_SOURCES {
            let spec = source(id).expect(id);
            assert_eq!(
                spec.default,
                crate::config::DEFAULT_SOURCES.contains(&id),
                "{id}"
            );
        }
        assert_eq!(SOURCES.len(), crate::config::ALL_SOURCES.len());
    }
    #[test]
    fn tenant_permissions_are_read_only() {
        for s in SOURCES {
            assert!(s.permission.contains(".Read"), "{}", s.source);
            assert!(!s.permission.contains("Write"), "{}", s.source);
        }
    }
}
