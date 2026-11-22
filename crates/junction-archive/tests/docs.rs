//! The documentation names every permission, role and source the code uses.
use junction_archive::{catalog, config::ALL_SOURCES, forward::SELECTOR};

const GUIDE: &str = include_str!("../../../docs/ARCHIVE.md");
const SECURITY: &str = include_str!("../../../docs/ARCHIVE-SECURITY.md");
const CONTRACT: &str = include_str!("../../../docs/archive/BOWER-CONTRACT.md");
const README: &str = include_str!("../../../README.md");

#[test]
fn every_source_and_permission_is_documented() {
    for source in ALL_SOURCES {
        assert!(
            GUIDE.contains(&format!("`{source}`")),
            "docs/ARCHIVE.md is missing {source}"
        );
    }
    for spec in catalog::SOURCES {
        for doc in [GUIDE, SECURITY] {
            assert!(
                doc.contains(&format!("`{}`", spec.permission)),
                "{} missing from docs",
                spec.permission
            );
        }
    }
}

#[test]
fn every_storage_role_is_documented() {
    for role in [
        "blobs/read",
        "blobs/add/action",
        "Storage Blob Data Reader",
        "Storage Blob Data Contributor",
        "Object Read & Write",
        "Object Read",
    ] {
        assert!(
            SECURITY.contains(role),
            "docs/ARCHIVE-SECURITY.md is missing {role}"
        );
    }
    for role in catalog::STORAGE_ROLES {
        assert!(
            SECURITY.to_lowercase().contains(role.identity),
            "{} identity missing",
            role.identity
        );
    }
}

#[test]
fn every_forward_rule_is_in_the_contract() {
    for rule in SELECTOR {
        assert!(
            CONTRACT.contains(&format!("`{}`", rule.id)),
            "{} missing from the Bower contract",
            rule.id
        );
        let event_type = format!("m365_{}", rule.id.replace('-', "_"));
        assert!(
            CONTRACT.contains(&event_type),
            "{event_type} missing from the Bower contract"
        );
    }
}

#[test]
fn docs_follow_the_house_style() {
    for (name, doc) in [
        ("ARCHIVE.md", GUIDE),
        ("ARCHIVE-SECURITY.md", SECURITY),
        ("BOWER-CONTRACT.md", CONTRACT),
    ] {
        assert!(!doc.contains('\u{2014}'), "{name} contains an em dash");
    }
    assert!(
        README.contains("docs/ARCHIVE.md") && README.contains("docs/archive/BOWER-CONTRACT.md")
    );
}
