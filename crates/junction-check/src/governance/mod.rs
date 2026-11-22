//! Connected-app and OAuth governance for Entra ID and Microsoft 365
//! (`junction apps`).
//!
//! Answers "what is connected to this tenant?": every enterprise application,
//! service principal, OAuth client, application permission and delegated
//! consent grant, with owners, sign-in recency and documented risk flags.
//!
//! Every read runs through the check gateway ([`crate::gateway`]), which
//! forces Junction's read-only policy. The one write path is [`apply`]: CLI
//! only, with per-item operator approval on the terminal. See
//! `docs/APP-GOVERNANCE.md` and `docs/APP-GOVERNANCE-SECURITY.md`.
pub mod apply;
pub mod baseline;
pub mod cli;
pub mod export;
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

/// Generated Markdown tables for `docs/APP-GOVERNANCE*.md` (kept in sync by
/// `junction check docs`, verified in CI).
pub mod docs {
    use super::{apply, flags, inventory};

    /// Read permissions, one row per permission, with the operations it covers.
    pub fn read_permissions() -> String {
        let mut rows: std::collections::BTreeMap<&str, Vec<&str>> = Default::default();
        for read in inventory::READS {
            rows.entry(read.permissions[0])
                .or_default()
                .push(read.operation);
        }
        let mut out = String::from(
            "| Permission | Type | Used for | Operations | If not granted |\n|---|---|---|---|---|\n",
        );
        for (permission, ops) in rows {
            let (used, missing) = match permission {
                "Application.Read.All" => (
                    "Service principals, app registrations, application permissions and owners",
                    "No inventory (service principals and registrations are required); owners recorded as not read",
                ),
                "DelegatedPermissionGrant.Read.All" => (
                    "Admin and per-user delegated consent grants",
                    "No inventory (grants are required)",
                ),
                "User.Read.All" => (
                    "Which users are guests (guest consent, and guest status of owners Graph returns as id-only stubs)",
                    "`guest_consented` not evaluated; owners returned as id-only stubs have unknown guest status, so `guest_owned` may be incomplete",
                ),
                "AuditLog.Read.All" => (
                    "Service principal sign-in activity (Entra ID P1 or P2)",
                    "`sign_in_data` is `unavailable`; `unused` and `privileged_no_recent_sign_in` not evaluated",
                ),
                "IdentityRiskyServicePrincipal.Read.All" => (
                    "Workload identity risk (Workload Identities Premium)",
                    "`risky_service_principal` not evaluated",
                ),
                _ => ("", ""),
            };
            out.push_str(&format!(
                "| `{permission}` | Microsoft Graph application | {used} | {} | {missing} |\n",
                ops.iter()
                    .map(|o| format!("`{o}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        out
    }

    /// Write permissions, only for `junction apps apply`.
    pub fn write_permissions() -> String {
        let registry = apply::registry().expect("apps write registry loads");
        let mut out = String::from(
            "| Operation | Method and path | Risk (after review) | Permission |\n|---|---|---|---|\n",
        );
        for (id, permission) in apply::WRITE_PERMISSIONS {
            let op = registry.resolve(id, None, false).expect("write operation");
            out.push_str(&format!(
                "| `{id}` | `{} {}` | {} | `{permission}` |\n",
                op.method,
                op.path,
                serde_json::to_value(&op.risk)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default()
            ));
        }
        out
    }

    /// Every flag with what it reads, why it matters and the fix.
    pub fn flags_table() -> String {
        let mut out = String::from(
            "| Flag | Severity | Reads | Why it matters | Suggested fix |\n|---|---|---|---|---|\n",
        );
        for f in flags::FLAGS {
            out.push_str(&format!(
                "| `{}` | {} | {} | {} | {} |\n",
                f.id,
                f.severity.as_str(),
                f.reads.replace('|', "\\|"),
                f.why.replace('|', "\\|"),
                f.fix.replace('|', "\\|")
            ));
        }
        out
    }
}
