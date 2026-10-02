//! Canonical product aliases for Microsoft 365 workloads served by Microsoft
//! Graph. Intune, Teams, SharePoint, OneDrive, Planner, Outlook, Entra ID,
//! Windows 365, Purview and parts of Defender have no separate public API:
//! their documented endpoints are Graph operations. Aliases give those
//! products stable names (`intune.devices.list`) that resolve to the Graph
//! operation (`graph.device_management.managed_devices.list`).
//!
//! Aliases never create operations or change metadata: resolution returns the
//! canonical Graph operation, so its ID, risk and policy rules apply unchanged.
//! A real operation with the requested ID always wins over an alias.

/// (alias prefix, canonical prefix). Longest matching prefix wins.
pub const ALIASES: &[(&str, &str)] = &[
    // Microsoft Intune
    ("intune.devices", "graph.device_management.managed_devices"),
    (
        "intune.compliance_policies",
        "graph.device_management.device_compliance_policies",
    ),
    (
        "intune.configurations",
        "graph.device_management.device_configurations",
    ),
    ("intune.apps", "graph.device_app_management.mobile_apps"),
    ("intune.app_management", "graph.device_app_management"),
    ("intune", "graph.device_management"),
    // Windows 365
    (
        "windows365.cloud_pcs",
        "graph.device_management.virtual_endpoint.cloud_p_cs",
    ),
    ("windows365", "graph.device_management.virtual_endpoint"),
    // Microsoft 365 workloads
    ("m365.teams", "graph.teams"),
    ("m365.chats", "graph.chats"),
    ("m365.sharepoint.sites", "graph.sites"),
    ("m365.sharepoint", "graph.sites"),
    ("m365.onedrive.drives", "graph.drives"),
    ("m365.onedrive", "graph.drives"),
    ("m365.planner", "graph.planner"),
    ("m365.outlook.messages", "graph.users.messages"),
    ("m365.outlook.mail_folders", "graph.users.mail_folders"),
    ("m365.outlook.events", "graph.users.events"),
    ("m365.outlook.calendar", "graph.users.calendar"),
    ("m365.exchange.messages", "graph.users.messages"),
    ("m365.exchange.mail_folders", "graph.users.mail_folders"),
    ("m365.service_health", "graph.admin.service_announcement"),
    ("m365.reports", "graph.reports"),
    ("m365.groups", "graph.groups"),
    ("m365.users", "graph.users"),
    // Microsoft Entra ID
    ("entra.users", "graph.users"),
    ("entra.groups", "graph.groups"),
    ("entra.applications", "graph.applications"),
    ("entra.service_principals", "graph.service_principals"),
    (
        "entra.conditional_access",
        "graph.identity.conditional_access",
    ),
    ("entra.directory_roles", "graph.directory_roles"),
    ("entra.roles", "graph.role_management"),
    ("entra.audit_logs", "graph.audit_logs"),
    ("entra.identity_protection", "graph.identity_protection"),
    ("entra.policies", "graph.policies"),
    // Microsoft Defender XDR, Defender for Identity and Defender for Office 365
    // capabilities exposed through the Graph security API.
    ("defender.incidents", "graph.security.incidents"),
    ("defender.alerts", "graph.security.alerts_v2"),
    (
        "defender.hunting.run_query",
        "graph.security.run_hunting_query",
    ),
    ("defender.identity", "graph.security.identities"),
    (
        "defender.threat_intelligence",
        "graph.security.threat_intelligence",
    ),
    (
        "defender.attack_simulation",
        "graph.security.attack_simulation",
    ),
    ("defender.secure_scores", "graph.security.secure_scores"),
    // Microsoft Purview
    ("purview.audit", "graph.security.audit_log"),
    ("purview.ediscovery", "graph.security.cases"),
    ("purview.labels", "graph.security.labels"),
    (
        "purview.subject_rights_requests",
        "graph.security.subject_rights_requests",
    ),
    (
        "purview.information_protection",
        "graph.information_protection",
    ),
];

/// Rewrite an alias ID to its canonical ID, or None when no alias applies.
pub fn canonical(id: &str) -> Option<String> {
    ALIASES
        .iter()
        .filter(|(alias, _)| {
            id == *alias
                || id
                    .strip_prefix(alias)
                    .is_some_and(|rest| rest.starts_with('.'))
        })
        .max_by_key(|(alias, _)| alias.len())
        .map(|(alias, target)| format!("{target}{}", &id[alias.len()..]))
}

#[cfg(test)]
mod tests {
    #[test]
    fn longest_prefix_wins_and_partial_segments_do_not_match() {
        assert_eq!(
            super::canonical("intune.devices.list").as_deref(),
            Some("graph.device_management.managed_devices.list")
        );
        assert_eq!(
            super::canonical("intune.roles.list").as_deref(),
            Some("graph.device_management.roles.list")
        );
        assert_eq!(
            super::canonical("defender.hunting.run_query").as_deref(),
            Some("graph.security.run_hunting_query")
        );
        assert!(super::canonical("intuneevil.devices.list").is_none());
        assert!(super::canonical("graph.users.list").is_none());
        let mut seen = std::collections::BTreeSet::new();
        for (alias, target) in super::ALIASES {
            assert!(seen.insert(*alias), "duplicate alias {alias}");
            assert!(target.starts_with("graph."));
            assert!(!alias.starts_with("graph"));
        }
    }
}
