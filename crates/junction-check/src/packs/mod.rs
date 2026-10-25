//! Built-in check packs. Each pack module returns its checks; each tag file maps
//! check ids to framework tags (data, not code).
use crate::check::Check;
use std::sync::Arc;

pub mod apps;
pub mod azure;
pub mod backup;
pub mod collaboration;
pub mod email;
pub mod endpoint;
pub mod identity;
pub mod intune;
pub mod sentinel;

pub fn all() -> Vec<Arc<dyn Check>> {
    let mut all = vec![];
    all.extend(identity::checks());
    all.extend(endpoint::checks());
    all.extend(intune::checks());
    all.extend(email::checks());
    all.extend(backup::checks());
    all.extend(sentinel::checks());
    all.extend(apps::checks());
    all.extend(collaboration::checks());
    all.extend(azure::checks());
    all
}

pub const TAG_FILES: &[(&str, &str)] = &[
    ("identity", include_str!("../../data/tags/identity.yaml")),
    (
        "endpoint-coverage",
        include_str!("../../data/tags/endpoint-coverage.yaml"),
    ),
    (
        "endpoint-protection",
        include_str!("../../data/tags/endpoint-protection.yaml"),
    ),
    (
        "endpoint-asr",
        include_str!("../../data/tags/endpoint-asr.yaml"),
    ),
    ("intune", include_str!("../../data/tags/intune.yaml")),
    ("email", include_str!("../../data/tags/email.yaml")),
    ("backup", include_str!("../../data/tags/backup.yaml")),
    ("sentinel", include_str!("../../data/tags/sentinel.yaml")),
    ("apps", include_str!("../../data/tags/apps.yaml")),
    (
        "collaboration",
        include_str!("../../data/tags/collaboration.yaml"),
    ),
    ("azure", include_str!("../../data/tags/azure.yaml")),
];
