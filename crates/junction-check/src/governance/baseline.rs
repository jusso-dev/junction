//! Approved baselines and drift (`junction apps baseline save`, `junction apps diff`).
//!
//! A baseline is a normalised snapshot of what an operator has reviewed and
//! accepted: per app, its identity, publisher, audience, enabled state, owners,
//! application permissions and delegated scopes. Volatile fields (sign-in
//! times, credential expiry, risk, flags) are left out, so drift reports
//! changes in what is connected and what it may do, not activity.
//!
//! Apps are keyed by service principal object id. An app deleted and
//! re-created under the same name shows as one removed and one added.
//! Permissions and scopes are keyed by the resource's app id, not its display
//! name, so renaming a resource is not drift and two resources with the same
//! name never collide. Owners are keyed by object id only: guest status
//! depends on whether User.Read.All was granted, so it is reported by the
//! `guest_owned` flag rather than as drift.
use super::inventory::{App, Inventory, OwnerTenant};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Version 2 keys permissions by resource app id and digests the whole file.
pub const BASELINE_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    pub baseline_version: u32,
    pub tenant_id: String,
    pub captured_at: String,
    /// SHA-256 of the canonical JSON of every other field (version, tenant,
    /// capture time and apps), so no part of the file can be edited unseen.
    pub digest: String,
    pub apps: BTreeMap<String, Snapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub app_id: String,
    pub display_name: String,
    pub enabled: bool,
    pub owner_tenant: OwnerTenant,
    pub publisher: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_in_audience: Option<String>,
    /// Owner object ids (lower case).
    pub owners: BTreeSet<String>,
    /// `resource-app-id/Permission` for application permissions.
    pub application_permissions: BTreeSet<String>,
    /// `resource-app-id/scope` for admin consent (all users).
    pub admin_delegated: BTreeSet<String>,
    /// `principal-id: resource-app-id/scope` for per-user consent.
    pub user_delegated: BTreeSet<String>,
    /// Resource app id to display name, for readable drift output only.
    #[serde(default)]
    pub resources: BTreeMap<String, String>,
}

fn publisher(app: &App) -> String {
    match &app.publisher {
        super::inventory::Publisher::Microsoft => "microsoft".into(),
        super::inventory::Publisher::Verified { name } => format!("verified:{name}"),
        super::inventory::Publisher::Unverified => "unverified".into(),
    }
}

impl Snapshot {
    pub fn of(app: &App) -> Self {
        let mut admin = BTreeSet::new();
        let mut user = BTreeSet::new();
        let mut resources = BTreeMap::new();
        let key = |app_id: &str, id: &str| {
            if app_id.is_empty() {
                id.to_lowercase()
            } else {
                app_id.to_lowercase()
            }
        };
        for g in &app.delegated_grants {
            let resource = key(&g.resource_app_id, &g.resource_id);
            resources.insert(resource.clone(), g.resource_name.clone());
            for scope in &g.scopes {
                let item = format!("{resource}/{scope}");
                if g.consent_type == "AllPrincipals" {
                    admin.insert(item);
                } else {
                    user.insert(format!(
                        "{}: {item}",
                        g.principal_id
                            .as_deref()
                            .unwrap_or("unknown")
                            .to_lowercase()
                    ));
                }
            }
        }
        Self {
            app_id: app.app_id.clone(),
            display_name: app.display_name.clone(),
            enabled: app.enabled,
            owner_tenant: app.owner_tenant,
            publisher: publisher(app),
            sign_in_audience: app.sign_in_audience.clone(),
            owners: app.owners.iter().map(|o| o.id.to_lowercase()).collect(),
            application_permissions: app
                .application_permissions
                .iter()
                .map(|p| {
                    let resource = key(&p.resource_app_id, &p.resource_id);
                    resources.insert(resource.clone(), p.resource_name.clone());
                    format!("{resource}/{}", p.permission)
                })
                .collect(),
            admin_delegated: admin,
            user_delegated: user,
            resources,
        }
    }
}

fn digest(
    version: u32,
    tenant: &str,
    captured_at: &str,
    apps: &BTreeMap<String, Snapshot>,
) -> String {
    use sha2::{Digest, Sha256};
    let canonical = serde_json::to_vec(&serde_json::json!({
        "baseline_version": version,
        "tenant_id": tenant.to_ascii_lowercase(),
        "captured_at": captured_at,
        "apps": apps,
    }))
    .expect("snapshots serialise");
    junction_watch::event::hex(&Sha256::digest(&canonical))
}

impl Baseline {
    /// Snapshot an inventory. Refused when owners could not be read, because a
    /// baseline without owners would report every owner as new later.
    pub fn from_inventory(inventory: &Inventory) -> Result<Self> {
        if inventory.gap("owners") {
            bail!(
                "owners could not be read, so this inventory cannot be a baseline; grant the missing permission and re-run"
            );
        }
        let apps: BTreeMap<String, Snapshot> = inventory
            .apps
            .iter()
            .map(|a| (a.service_principal_id.to_lowercase(), Snapshot::of(a)))
            .collect();
        Ok(Self {
            baseline_version: BASELINE_VERSION,
            tenant_id: inventory.tenant_id.clone(),
            captured_at: inventory.captured_at.clone(),
            digest: digest(
                BASELINE_VERSION,
                &inventory.tenant_id,
                &inventory.captured_at,
                &apps,
            ),
            apps,
        })
    }

    pub fn parse(text: &str) -> Result<Self> {
        if text.len() > 64 * 1024 * 1024 {
            bail!("the baseline is too large");
        }
        let baseline: Self =
            serde_json::from_str(text).map_err(|_| anyhow::anyhow!("invalid baseline file"))?;
        if baseline.baseline_version != BASELINE_VERSION {
            bail!("unsupported baseline version {}", baseline.baseline_version);
        }
        if baseline.digest
            != digest(
                baseline.baseline_version,
                &baseline.tenant_id,
                &baseline.captured_at,
                &baseline.apps,
            )
        {
            bail!("the baseline digest does not match its content; it was edited or corrupted");
        }
        Ok(baseline)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Changes {
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

impl Changes {
    fn of(before: &BTreeSet<String>, after: &BTreeSet<String>) -> Self {
        Self {
            added: after.difference(before).cloned().collect(),
            removed: before.difference(after).cloned().collect(),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Changed {
    pub service_principal_id: String,
    pub display_name: String,
    /// `field: before -> after` for scalar fields.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub properties: Vec<String>,
    #[serde(default, skip_serializing_if = "Changes::is_empty")]
    pub owners: Changes,
    #[serde(default, skip_serializing_if = "Changes::is_empty")]
    pub application_permissions: Changes,
    #[serde(default, skip_serializing_if = "Changes::is_empty")]
    pub admin_delegated: Changes,
    #[serde(default, skip_serializing_if = "Changes::is_empty")]
    pub user_delegated: Changes,
}

impl Changed {
    /// Did the app gain any access (new permission, scope or owner)?
    pub fn widened(&self) -> bool {
        !self.owners.added.is_empty()
            || !self.application_permissions.added.is_empty()
            || !self.admin_delegated.added.is_empty()
            || !self.user_delegated.added.is_empty()
            || self.properties.iter().any(|p| {
                p.starts_with("enabled: false")
                    || p.starts_with("app_id: ")
                    || p.starts_with("owner_tenant: ")
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRef {
    pub service_principal_id: String,
    pub app_id: String,
    pub display_name: String,
    pub owner_tenant: OwnerTenant,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub application_permissions: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub admin_delegated: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Drift {
    pub tenant_id: String,
    pub baseline_captured_at: String,
    pub baseline_digest: String,
    pub current_captured_at: String,
    pub added: Vec<AppRef>,
    pub removed: Vec<AppRef>,
    pub changed: Vec<Changed>,
}

impl Drift {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
    /// New apps or widened access since the baseline.
    pub fn widened(&self) -> bool {
        !self.added.is_empty() || self.changed.iter().any(Changed::widened)
    }
}

/// `resource-app-id/name` as `Resource display name/name` for output.
fn label(item: &str, names: &BTreeMap<String, String>) -> String {
    // Per-user items are `principal: resource/scope`.
    let (prefix, rest) = match item.split_once(": ") {
        Some((p, r)) => (format!("{p}: "), r),
        None => (String::new(), item),
    };
    match rest.split_once('/') {
        Some((resource, name)) => format!(
            "{prefix}{}/{name}",
            names.get(resource).map(String::as_str).unwrap_or(resource)
        ),
        None => item.to_owned(),
    }
}

fn labels(items: &BTreeSet<String>, names: &BTreeMap<String, String>) -> BTreeSet<String> {
    items.iter().map(|i| label(i, names)).collect()
}

fn labelled(changes: Changes, names: &BTreeMap<String, String>) -> Changes {
    Changes {
        added: changes.added.iter().map(|i| label(i, names)).collect(),
        removed: changes.removed.iter().map(|i| label(i, names)).collect(),
    }
}

fn app_ref(id: &str, s: &Snapshot) -> AppRef {
    AppRef {
        service_principal_id: id.to_owned(),
        app_id: s.app_id.clone(),
        display_name: s.display_name.clone(),
        owner_tenant: s.owner_tenant,
        application_permissions: labels(&s.application_permissions, &s.resources),
        admin_delegated: labels(&s.admin_delegated, &s.resources),
    }
}

/// Compare the current inventory with an approved baseline of the same tenant.
pub fn diff(baseline: &Baseline, current: &Inventory) -> Result<Drift> {
    if !baseline.tenant_id.eq_ignore_ascii_case(&current.tenant_id) {
        bail!(
            "the baseline is for tenant {}, not {}",
            baseline.tenant_id,
            current.tenant_id
        );
    }
    if current.gap("owners") {
        bail!("owners could not be read, so drift cannot be computed reliably");
    }
    let now = Baseline::from_inventory(current)?;
    let mut drift = Drift {
        tenant_id: current.tenant_id.clone(),
        baseline_captured_at: baseline.captured_at.clone(),
        baseline_digest: baseline.digest.clone(),
        current_captured_at: current.captured_at.clone(),
        added: vec![],
        removed: vec![],
        changed: vec![],
    };
    for (id, after) in &now.apps {
        let Some(before) = baseline.apps.get(id) else {
            drift.added.push(app_ref(id, after));
            continue;
        };
        let mut properties = vec![];
        let mut scalar = |name: &str, b: String, a: String| {
            if b != a {
                properties.push(format!("{name}: {b} -> {a}"));
            }
        };
        scalar(
            "display_name",
            before.display_name.clone(),
            after.display_name.clone(),
        );
        scalar(
            "enabled",
            before.enabled.to_string(),
            after.enabled.to_string(),
        );
        scalar(
            "publisher",
            before.publisher.clone(),
            after.publisher.clone(),
        );
        scalar(
            "sign_in_audience",
            before.sign_in_audience.clone().unwrap_or_default(),
            after.sign_in_audience.clone().unwrap_or_default(),
        );
        scalar(
            "app_id",
            before.app_id.to_lowercase(),
            after.app_id.to_lowercase(),
        );
        scalar(
            "owner_tenant",
            format!("{:?}", before.owner_tenant).to_lowercase(),
            format!("{:?}", after.owner_tenant).to_lowercase(),
        );
        // Names for output: current names first, then the baseline's.
        let mut names = before.resources.clone();
        names.extend(after.resources.clone());
        let changed = Changed {
            service_principal_id: id.clone(),
            display_name: after.display_name.clone(),
            properties,
            owners: Changes::of(&before.owners, &after.owners),
            application_permissions: labelled(
                Changes::of(
                    &before.application_permissions,
                    &after.application_permissions,
                ),
                &names,
            ),
            admin_delegated: labelled(
                Changes::of(&before.admin_delegated, &after.admin_delegated),
                &names,
            ),
            user_delegated: labelled(
                Changes::of(&before.user_delegated, &after.user_delegated),
                &names,
            ),
        };
        if !(changed.properties.is_empty()
            && changed.owners.is_empty()
            && changed.application_permissions.is_empty()
            && changed.admin_delegated.is_empty()
            && changed.user_delegated.is_empty())
        {
            drift.changed.push(changed);
        }
    }
    for (id, before) in &baseline.apps {
        if !now.apps.contains_key(id) {
            drift.removed.push(app_ref(id, before));
        }
    }
    let by_name = |a: &AppRef, b: &AppRef| {
        a.display_name
            .to_lowercase()
            .cmp(&b.display_name.to_lowercase())
    };
    drift.added.sort_by(by_name);
    drift.removed.sort_by(by_name);
    drift.changed.sort_by(|a, b| {
        a.display_name
            .to_lowercase()
            .cmp(&b.display_name.to_lowercase())
    });
    Ok(drift)
}

/// Drift as Markdown, for the evidence pack and `--format markdown`.
pub fn markdown(drift: &Drift) -> String {
    let esc = super::export::md_cell;
    let text = super::export::md_text;
    let id = super::export::md_id;
    let mut out = format!(
        "# Connected-app drift\n\nTenant `{}`. Baseline captured {} (digest `{}`), compared with the inventory captured {}.\n\n",
        id(&drift.tenant_id),
        text(&drift.baseline_captured_at),
        id(&drift.baseline_digest[..16.min(drift.baseline_digest.len())]),
        text(&drift.current_captured_at)
    );
    if drift.is_empty() {
        out.push_str("No changes since the baseline.\n");
        return out;
    }
    out.push_str(&format!(
        "{} added, {} removed, {} changed.\n\n",
        drift.added.len(),
        drift.removed.len(),
        drift.changed.len()
    ));
    for (title, apps) in [
        ("Added apps", &drift.added),
        ("Removed apps", &drift.removed),
    ] {
        if apps.is_empty() {
            continue;
        }
        out.push_str(&format!("## {title}\n\n| App | App id | Owner | Application permissions | Admin-consented scopes |\n|---|---|---|---|---|\n"));
        for a in apps {
            let join = |s: &BTreeSet<String>| {
                if s.is_empty() {
                    "none".to_owned()
                } else {
                    s.iter().cloned().collect::<Vec<_>>().join(", ")
                }
            };
            out.push_str(&format!(
                "| {} | `{}` | {:?} | {} | {} |\n",
                esc(&a.display_name),
                id(&a.app_id),
                a.owner_tenant,
                esc(&join(&a.application_permissions)),
                esc(&join(&a.admin_delegated))
            ));
        }
        out.push('\n');
    }
    if !drift.changed.is_empty() {
        out.push_str("## Changed apps\n\n");
        for c in &drift.changed {
            out.push_str(&format!("### {}\n\n", esc(&c.display_name)));
            for p in &c.properties {
                out.push_str(&format!("- {}\n", text(p)));
            }
            for (label, changes) in [
                ("owner", &c.owners),
                ("application permission", &c.application_permissions),
                ("admin-consented scope", &c.admin_delegated),
                ("user consent", &c.user_delegated),
            ] {
                for a in &changes.added {
                    out.push_str(&format!("- added {label}: {}\n", text(a)));
                }
                for r in &changes.removed {
                    out.push_str(&format!("- removed {label}: {}\n", text(r)));
                }
            }
            out.push('\n');
        }
    }
    out
}
