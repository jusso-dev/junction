//! Connected-app and OAuth governance for Entra ID and Microsoft 365
//! (`junction apps`).
//!
//! Answers "what is connected to this tenant?": every enterprise application,
//! service principal, OAuth client, application permission and delegated
//! consent grant, with owners, sign-in recency and documented risk flags.
//!
//! Everything here is read-only and runs through the check gateway
//! ([`crate::gateway`]), which forces Junction's read-only policy. See
//! `docs/APP-GOVERNANCE.md` and `docs/APP-GOVERNANCE-SECURITY.md`.
pub mod cli;
pub mod flags;
pub mod inventory;
pub mod report;

use crate::config::CheckConfig;
use crate::context::{CheckContext, ContextParts};
use crate::gateway::{Gateway, Governed};
use inventory::{CollectError, Inventory};
use junction_watch::backoff::Backoff;
use junction_watch::clock::Instant;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Build a flagged inventory for the tenant behind `gateway`.
pub async fn run(
    gateway: Arc<dyn Gateway>,
    label: Option<String>,
    config: Arc<CheckConfig>,
    now: Instant,
    per_host: usize,
) -> Result<Inventory, CollectError> {
    let governed: Arc<dyn Gateway> = Arc::new(Governed::new(gateway, per_host, Backoff::default()));
    let ctx = CheckContext::new(ContextParts {
        tenant_id: governed.tenant_id().to_owned(),
        label,
        gateway: governed,
        licences: None,
        config: config.clone(),
        attestations: BTreeMap::new(),
        dns: Arc::new(crate::dns::NoDns),
        now,
    });
    let mut inventory = inventory::collect(&ctx).await?;
    flags::apply(&mut inventory, flags::Settings::from_config(&config), now);
    Ok(inventory)
}
