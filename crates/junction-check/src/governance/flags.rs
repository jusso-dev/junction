//! Risk flags for inventoried apps (`junction apps`).
//!
//! Each flag is justified from Graph data alone and documented in [`FLAGS`]
//! (what it reads, why it matters and how to fix it). Flags never fire on
//! missing data: when sign-in activity, guests or risk could not be read (an
//! inventory [`super::inventory::Gap`]), or one app's owner lookup failed
//! (`owners_unread`), the flags that would need that data are not evaluated.
//! Positive evidence that was read (a guest owner) is still reported.
use super::inventory::{App, Inventory, OwnerTenant, Publisher, SignInData};
use crate::config::CheckConfig;
use crate::model::Severity;
use junction_watch::clock::Instant;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::Duration;

const TIERS: &str = include_str!("../../data/graph-permission-tiers.yaml");

/// Settings section: `[packs.governance]` in the check configuration file.
pub const SETTINGS: &str = "governance";
pub const DEFAULT_UNUSED_DAYS: u64 = 90;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Critical,
    High,
    Medium,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TierEntry {
    pub permission: String,
    pub reason: String,
    /// Narrower alternative when held as an application permission.
    #[serde(default)]
    pub narrower: Option<String>,
    /// Narrower alternative when held as a tenant-wide delegated grant, where
    /// application-only advice (Exchange RBAC for Applications, Sites.Selected)
    /// does not apply. `None` means no narrower delegated scope is advised.
    #[serde(default)]
    pub narrower_delegated: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tiers {
    pub critical: Vec<TierEntry>,
    pub high: Vec<TierEntry>,
    pub medium: Vec<TierEntry>,
}

impl Tiers {
    pub fn embedded() -> &'static Tiers {
        static TIERS_DATA: OnceLock<Tiers> = OnceLock::new();
        TIERS_DATA.get_or_init(|| serde_saphyr::from_str(TIERS).expect("permission tiers parse"))
    }
    pub fn entries(&self) -> impl Iterator<Item = (Tier, &TierEntry)> {
        self.critical
            .iter()
            .map(|e| (Tier::Critical, e))
            .chain(self.high.iter().map(|e| (Tier::High, e)))
            .chain(self.medium.iter().map(|e| (Tier::Medium, e)))
    }
    pub fn lookup(&self, permission: &str) -> Option<(Tier, &TierEntry)> {
        self.entries()
            .find(|(_, e)| e.permission.eq_ignore_ascii_case(permission))
    }
}

/// One flag on one app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flag {
    pub id: String,
    pub severity: Severity,
    pub summary: String,
    /// The permissions, owners, credentials or dates that triggered it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
}

/// Documentation for a flag (`junction apps flags`, docs/APP-GOVERNANCE.md).
#[derive(Debug, Clone, Copy, Serialize)]
pub struct FlagDoc {
    pub id: &'static str,
    pub severity: Severity,
    pub title: &'static str,
    pub reads: &'static str,
    pub why: &'static str,
    pub fix: &'static str,
}

pub const FLAGS: &[FlagDoc] = &[
    FlagDoc {
        id: "critical_permission",
        severity: Severity::Critical,
        title: "Holds a critical permission",
        reads: "Application permissions (app role assignments) and tenant-wide delegated grants, classified with data/graph-permission-tiers.yaml.",
        why: "Critical permissions let the app take over the directory or roles, or read and change every mailbox, file or site, without a user present.",
        fix: "Remove the permission, or replace it with the narrower alternative shown, then confirm an owner and a business reason for anything that stays.",
    },
    FlagDoc {
        id: "high_permission",
        severity: Severity::High,
        title: "Holds a high-impact permission",
        reads: "Application permissions and tenant-wide delegated grants in the high tier.",
        why: "High-impact permissions read every mailbox, file or chat, or change a broad class of objects.",
        fix: "Confirm the app needs it, scope it where the API allows (Exchange RBAC for Applications, Sites.Selected), or remove it.",
    },
    FlagDoc {
        id: "overbroad_scope",
        severity: Severity::Medium,
        title: "Uses a broad permission where a narrower one exists",
        reads: "Each held permission against the `narrower` alternative recorded in the tier file.",
        why: "A tenant-wide permission where a selected or read-only variant would do widens the damage if the app or its credential is compromised.",
        fix: "Move the app to the narrower permission shown, then remove the broad one.",
    },
    FlagDoc {
        id: "tenant_wide_delegated",
        severity: Severity::High,
        title: "Admin consent for all users to high-impact delegated scopes",
        reads: "Delegated grants with consentType AllPrincipals and a high or critical scope.",
        why: "Admin consent lets the app act as any user who signs in to it, up to that user's own rights, without each user agreeing.",
        fix: "Revoke the tenant-wide grant and require user assignment, or replace it with per-user consent for the people who need the app.",
    },
    FlagDoc {
        id: "privileged_no_recent_sign_in",
        severity: Severity::High,
        title: "Privileged app with no recent sign-in",
        reads: "Service principal sign-in activity (Entra ID P1 or P2) for apps holding high or critical permissions.",
        why: "A privileged app nobody uses is pure risk: its credentials and grants stay valid for an attacker while nobody notices activity.",
        fix: "Confirm with the owner whether it is still needed; if not, disable the service principal, then remove its grants.",
    },
    FlagDoc {
        id: "unused",
        severity: Severity::Low,
        title: "No sign-in within the unused period",
        reads: "Service principal sign-in activity for enabled, non-Microsoft apps older than the unused period.",
        why: "Unused apps accumulate grants and credentials that nobody reviews.",
        fix: "Disable apps that are no longer needed and remove their grants; delete them once the owner confirms.",
    },
    FlagDoc {
        id: "unverified_publisher_external",
        severity: Severity::High,
        title: "External app from an unverified publisher holds high-impact permissions",
        reads: "Owning organisation, verifiedPublisher and held permissions.",
        why: "Consent phishing uses unverified multi-tenant apps; high-impact permissions on one is a strong signal.",
        fix: "Confirm the vendor and the business need; if unknown, revoke its grants and disable it.",
    },
    FlagDoc {
        id: "guest_owned",
        severity: Severity::Medium,
        title: "Owned by a guest user",
        reads: "Owners of the app registration and the service principal, and whether each is a guest.",
        why: "An owner can add credentials and act as the app. Guests are outside the organisation's joiner and leaver process.",
        fix: "Replace guest owners with members of the organisation.",
    },
    FlagDoc {
        id: "guest_consented",
        severity: Severity::Medium,
        title: "Delegated consent granted by a guest user",
        reads: "Per-user delegated grants and whether the consenting user is a guest.",
        why: "Guests consenting apps in the tenant bypass internal review and can expose tenant data to an outside app.",
        fix: "Review and revoke the guest's consent, and restrict user consent for guests.",
    },
    FlagDoc {
        id: "ownerless",
        severity: Severity::Low,
        title: "App registration with no owner",
        reads: "Owners of app registrations in this tenant.",
        why: "Nobody is accountable for its credentials, permissions or retirement.",
        fix: "Assign at least two owners who are members of the organisation.",
    },
    FlagDoc {
        id: "credential_on_service_principal",
        severity: Severity::Medium,
        title: "Client secret added directly to the service principal",
        reads: "passwordCredentials on the service principal (not the app registration).",
        why: "These secrets do not appear on the app registration and are often missed in reviews; it is a known persistence technique.",
        fix: "Remove the secret from the service principal and use a certificate or federated credential on the app registration.",
    },
    FlagDoc {
        id: "expired_credentials_only",
        severity: Severity::Low,
        title: "Enabled with permissions but every credential has expired",
        reads: "Credential end dates on the app registration and service principal of apps in this tenant.",
        why: "The app is probably dead, but its grants stay live and a new credential brings them straight back.",
        fix: "Confirm with the owner and disable or remove the app, or rotate the credential if it is still needed.",
    },
    FlagDoc {
        id: "risky_service_principal",
        severity: Severity::High,
        title: "Identity Protection reports the workload identity at risk",
        reads: "Risky service principals (Workload Identities Premium).",
        why: "Microsoft has seen suspicious sign-ins or leaked credentials for the app.",
        fix: "Investigate the risk detections, rotate credentials, and disable the service principal if compromise is confirmed.",
    },
];

pub fn doc(id: &str) -> Option<&'static FlagDoc> {
    FLAGS.iter().find(|f| f.id == id)
}

fn flag(id: &str, summary: String, evidence: Vec<String>) -> Flag {
    let doc = doc(id).expect("documented flag");
    Flag {
        id: id.to_owned(),
        severity: doc.severity,
        summary,
        evidence,
    }
}

/// Thresholds from `[packs.governance]`.
#[derive(Debug, Clone, Copy)]
pub struct Settings {
    pub unused_days: u64,
}

impl Settings {
    pub fn from_config(config: &CheckConfig) -> Self {
        Self {
            unused_days: config
                .pack_setting(SETTINGS, "unused_days")
                .unwrap_or(DEFAULT_UNUSED_DAYS)
                .max(1),
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            unused_days: DEFAULT_UNUSED_DAYS,
        }
    }
}

/// Permissions the app holds tenant wide (application permissions and
/// AllPrincipals delegated scopes), as `(permission, label)`.
fn tenant_wide(app: &App) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = app
        .application_permissions
        .iter()
        .map(|p| {
            (
                p.permission.clone(),
                format!("{} ({}, application)", p.permission, p.resource_name),
            )
        })
        .collect();
    for g in app
        .delegated_grants
        .iter()
        .filter(|g| g.consent_type == "AllPrincipals")
    {
        for scope in &g.scopes {
            out.push((
                scope.clone(),
                format!("{scope} ({}, delegated for all users)", g.resource_name),
            ));
        }
    }
    out.sort();
    out.dedup();
    out
}

fn tiered(app: &App, tier: Tier) -> Vec<String> {
    let tiers = Tiers::embedded();
    tenant_wide(app)
        .into_iter()
        .filter(|(p, _)| tiers.lookup(p).is_some_and(|(t, _)| t == tier))
        .map(|(_, label)| label)
        .collect()
}

fn privileged(app: &App) -> bool {
    !tiered(app, Tier::Critical).is_empty() || !tiered(app, Tier::High).is_empty()
}

fn date(value: &str) -> &str {
    value.get(..10).unwrap_or(value)
}

/// Flags for one app.
pub fn evaluate(app: &App, inventory: &Inventory, settings: Settings, now: Instant) -> Vec<Flag> {
    let tiers = Tiers::embedded();
    let mut flags = vec![];
    let critical = tiered(app, Tier::Critical);
    if !critical.is_empty() {
        flags.push(flag(
            "critical_permission",
            format!("Holds {} critical permission(s).", critical.len()),
            critical,
        ));
    }
    let high = tiered(app, Tier::High);
    if !high.is_empty() {
        flags.push(flag(
            "high_permission",
            format!("Holds {} high-impact permission(s).", high.len()),
            high,
        ));
    }
    let overbroad: Vec<String> = tenant_wide(app)
        .into_iter()
        .filter_map(|(p, label)| {
            let (_, entry) = tiers.lookup(&p)?;
            let advice = if label.ends_with(", application)") {
                entry.narrower.as_ref()
            } else {
                entry.narrower_delegated.as_ref()
            }?;
            Some(format!("{label}: use {advice}"))
        })
        .collect();
    if !overbroad.is_empty() {
        flags.push(flag(
            "overbroad_scope",
            format!(
                "{} permission(s) have a narrower alternative.",
                overbroad.len()
            ),
            overbroad,
        ));
    }
    let admin_consented: Vec<String> = app
        .delegated_grants
        .iter()
        .filter(|g| g.consent_type == "AllPrincipals")
        .flat_map(|g| {
            g.scopes
                .iter()
                .filter(|s| {
                    tiers
                        .lookup(s)
                        .is_some_and(|(t, _)| matches!(t, Tier::Critical | Tier::High))
                })
                .map(move |s| format!("{s} ({})", g.resource_name))
        })
        .collect();
    if !admin_consented.is_empty() {
        flags.push(flag(
            "tenant_wide_delegated",
            format!(
                "Admin consent for all users to {} high-impact delegated scope(s).",
                admin_consented.len()
            ),
            admin_consented,
        ));
    }

    // Sign-in recency, only when the report was read.
    if app.sign_in_data != SignInData::Unavailable && app.enabled {
        let cutoff = now.minus(Duration::from_secs(settings.unused_days * 86_400));
        let last = app
            .last_sign_in
            .as_deref()
            .and_then(|s| Instant::parse(s).ok());
        let stale = last.is_none_or(|l| l < cutoff);
        // An app must be known to be older than the period to be called
        // unused. Its age is known from the local registration's creation date,
        // the earliest application permission grant, or a recorded (old)
        // sign-in. External apps with none of these have an unknown age and
        // are never flagged here.
        let known_since = app
            .created_at
            .iter()
            .chain(
                app.application_permissions
                    .iter()
                    .filter_map(|p| p.granted_at.as_ref()),
            )
            .chain(app.last_sign_in.iter())
            .filter_map(|d| Instant::parse(d).ok())
            .min();
        let old_enough = known_since.is_some_and(|c| c < cutoff);
        if stale && old_enough {
            let seen = match &app.last_sign_in {
                Some(at) => format!("last sign-in {}", date(at)),
                None => "no sign-in recorded".to_owned(),
            };
            if privileged(app) {
                flags.push(flag(
                    "privileged_no_recent_sign_in",
                    format!(
                        "Holds high-impact permissions with {seen} (more than {} days).",
                        settings.unused_days
                    ),
                    vec![seen.clone()],
                ));
            } else if !app.is_microsoft() {
                flags.push(flag(
                    "unused",
                    format!(
                        "Enabled with {seen} (more than {} days).",
                        settings.unused_days
                    ),
                    vec![seen],
                ));
            }
        }
    }

    if app.owner_tenant == OwnerTenant::External
        && app.publisher == Publisher::Unverified
        && privileged(app)
    {
        let mut evidence = critical_and_high(app);
        evidence.insert(
            0,
            format!(
                "owner tenant {}",
                app.owner_tenant_id.as_deref().unwrap_or("unknown")
            ),
        );
        flags.push(flag(
            "unverified_publisher_external",
            "External app from an unverified publisher holds high-impact permissions.".into(),
            evidence,
        ));
    }

    {
        // Guest owners that were read are evidence even if another owner
        // lookup for this app failed.
        let guests: Vec<String> = app
            .owners
            .iter()
            .filter(|o| o.guest == Some(true))
            .map(|o| {
                format!(
                    "{} (owner of the {})",
                    o.user_principal_name
                        .as_deref()
                        .or(o.display_name.as_deref())
                        .unwrap_or(&o.id),
                    o.of.replace('_', " ")
                )
            })
            .collect();
        if !guests.is_empty() {
            flags.push(flag(
                "guest_owned",
                format!("{} guest owner(s).", guests.len()),
                guests,
            ));
        }
        // Ownerless only when this app's registration-owner lookup succeeded.
        if app.owner_tenant == OwnerTenant::Home
            && app.application_id.is_some()
            && !app.owners_unread.iter().any(|o| o == "application")
            && !app.owners.iter().any(|o| o.of == "application")
        {
            flags.push(flag(
                "ownerless",
                "The app registration has no owner.".into(),
                vec![],
            ));
        }
    }

    if !inventory.gap("guests") {
        let consents: Vec<String> = app
            .delegated_grants
            .iter()
            .filter(|g| g.consent_type == "Principal" && g.principal_guest == Some(true))
            .map(|g| {
                format!(
                    "user {} consented {} ({})",
                    g.principal_id.as_deref().unwrap_or("unknown"),
                    g.scopes.join(" "),
                    g.resource_name
                )
            })
            .collect();
        if !consents.is_empty() {
            flags.push(flag(
                "guest_consented",
                format!("{} delegated grant(s) consented by guests.", consents.len()),
                consents,
            ));
        }
    }

    if !app.is_microsoft() {
        let sp_secrets: Vec<String> = app
            .credentials
            .iter()
            .filter(|c| c.on == "service_principal" && c.kind == "secret" && !c.expired)
            .map(|c| {
                format!(
                    "secret {}{}",
                    c.display_name.as_deref().unwrap_or(&c.key_id),
                    c.end
                        .as_deref()
                        .map(|e| format!(" (expires {})", date(e)))
                        .unwrap_or_default()
                )
            })
            .collect();
        if !sp_secrets.is_empty() {
            flags.push(flag(
                "credential_on_service_principal",
                format!(
                    "{} client secret(s) on the service principal.",
                    sp_secrets.len()
                ),
                sp_secrets,
            ));
        }
    }

    // Skip apps that still sign in: they authenticate some other way (for
    // example federated identity credentials or a managed identity), so the
    // expired secrets are leftovers, not a sign the app is dead.
    let recently_active = app.sign_in_data == SignInData::Recorded
        && app
            .last_sign_in
            .as_deref()
            .and_then(|s| Instant::parse(s).ok())
            .is_some_and(|l| l >= now.minus(Duration::from_secs(settings.unused_days * 86_400)));
    if app.owner_tenant == OwnerTenant::Home
        && app.enabled
        && !app.federated_credentials
        && !recently_active
        && !app.credentials.is_empty()
        && app.credentials.iter().all(|c| c.expired)
        && (!app.application_permissions.is_empty() || !app.delegated_grants.is_empty())
    {
        flags.push(flag(
            "expired_credentials_only",
            format!(
                "All {} credential(s) have expired but the app keeps its grants.",
                app.credentials.len()
            ),
            vec![],
        ));
    }

    if let Some(risk) = &app.risk
        && !matches!(
            risk.state.as_str(),
            "remediated" | "dismissed" | "confirmedSafe" | "none" | ""
        )
        && !matches!(risk.level.as_str(), "none" | "hidden" | "")
    {
        let mut f = flag(
            "risky_service_principal",
            format!("Identity Protection risk {} ({}).", risk.level, risk.state),
            vec![],
        );
        if risk.state == "confirmedCompromised" {
            f.severity = Severity::Critical;
        }
        flags.push(f);
    }

    flags.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then_with(|| a.id.cmp(&b.id))
    });
    flags
}

fn critical_and_high(app: &App) -> Vec<String> {
    let mut out = tiered(app, Tier::Critical);
    out.extend(tiered(app, Tier::High));
    out
}

/// Evaluate every app's flags in place and refresh the summary.
pub fn apply(inventory: &mut Inventory, settings: Settings, now: Instant) {
    let flags: Vec<Vec<Flag>> = inventory
        .apps
        .iter()
        .map(|app| evaluate(app, inventory, settings, now))
        .collect();
    for (app, flags) in inventory.apps.iter_mut().zip(flags) {
        app.flags = flags;
    }
    inventory.summarise();
}

/// Counts of each flag id across the inventory.
pub fn counts(inventory: &Inventory) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for app in &inventory.apps {
        for f in &app.flags {
            *out.entry(f.id.clone()).or_default() += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_tier_entry_has_a_reason_and_no_duplicates() {
        let mut seen = BTreeSet::new();
        for (_, entry) in Tiers::embedded().entries() {
            assert!(!entry.reason.trim().is_empty(), "{}", entry.permission);
            assert!(
                seen.insert(entry.permission.to_ascii_lowercase()),
                "duplicate {}",
                entry.permission
            );
        }
        assert!(seen.contains("mail.readwrite"));
    }

    #[test]
    fn every_flag_is_documented_once() {
        let ids: BTreeSet<_> = FLAGS.iter().map(|f| f.id).collect();
        assert_eq!(ids.len(), FLAGS.len());
        for f in FLAGS {
            assert!(!f.reads.is_empty() && !f.why.is_empty() && !f.fix.is_empty());
        }
    }

    #[test]
    fn lookup_is_case_insensitive_and_unlisted_is_unclassified() {
        let tiers = Tiers::embedded();
        assert_eq!(tiers.lookup("mail.read").unwrap().0, Tier::High);
        assert!(tiers.lookup("User.Read").is_none());
    }
}
