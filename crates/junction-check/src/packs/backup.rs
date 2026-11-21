//! `backup` pack: what the APIs show about Microsoft 365 Backup, Azure Backup and
//! third-party backup apps, plus attested checks for what no API can show
//! (offline copies, restore tests, backup administrator separation).
use crate::check::{
    ApiRequirement, Check, CheckMeta, Evaluation, Finding, ManualCheck, ManualSpec, Requirements,
};
use crate::context::{CallFailure, CheckContext};
use crate::gateway::GatewayError;
use crate::model::{CheckKind, Level, Pack, Severity};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::{Arc, OnceLock};

pub fn checks() -> Vec<Arc<dyn Check>> {
    vec![
        Arc::new(M365Backup),
        Arc::new(AzureVaults),
        Arc::new(ThirdPartyApp),
        Arc::new(ManualCheck(&OFFLINE_COPY)),
        Arc::new(ManualCheck(&RESTORE_TESTED)),
        Arc::new(ManualCheck(&ADMIN_SEPARATION)),
    ]
}

const BACKUP_READ: &[&str] = &["BackupRestore-Configuration.Read.All"];
const BACKUP_ROOT: ApiRequirement = ApiRequirement {
    operation: "graph.solutions.backup_restore.get",
    permissions: BACKUP_READ,
};
const EXCHANGE_POLICIES: ApiRequirement = ApiRequirement {
    operation: "graph.solutions.backup_restore.exchange_protection_policies.list",
    permissions: BACKUP_READ,
};
const SHAREPOINT_POLICIES: ApiRequirement = ApiRequirement {
    operation: "graph.solutions.backup_restore.share_point_protection_policies.list",
    permissions: BACKUP_READ,
};
const ONEDRIVE_POLICIES: ApiRequirement = ApiRequirement {
    operation: "graph.solutions.backup_restore.one_drive_for_business_protection_policies.list",
    permissions: BACKUP_READ,
};
const RESOURCE_GRAPH: ApiRequirement = ApiRequirement {
    operation: "azure.resource_graph.resources.post",
    permissions: &["Reader", "Backup Reader"],
};
const SERVICE_PRINCIPALS: ApiRequirement = ApiRequirement {
    operation: "graph.service_principals.list",
    permissions: &["Application.Read.All"],
};

const ATTESTED: &str = "backup.offline_copy, backup.restore_tested and backup.admin_separation";

// ---------------------------------------------------------------------------
// backup.m365_backup

pub const M365_BACKUP: CheckMeta = CheckMeta {
    id: "backup.m365_backup",
    title: "Microsoft 365 Backup protects Exchange, OneDrive and SharePoint",
    pack: Pack::Backup,
    kind: CheckKind::Automated,
    severity: Severity::High,
    effort: Level::Medium,
    impact: Level::High,
    description: "Reads the Microsoft 365 Backup service status and the Exchange, OneDrive and SharePoint protection policies. Backups held outside the recycle bins and version history give a recovery path an attacker with admin rights cannot simply purge. Microsoft 365 Backup is billed pay-as-you-go through Azure, so there is no licence to detect: when the service is not enabled the check is not applicable and the attested backup checks cover other products.",
    requires: Requirements {
        apis: &[
            BACKUP_ROOT,
            EXCHANGE_POLICIES,
            SHAREPOINT_POLICIES,
            ONEDRIVE_POLICIES,
        ],
        licences: &[],
    },
    remediation: "In the Microsoft 365 admin center (Settings > Microsoft 365 Backup) create active protection policies for Exchange mailboxes, OneDrive accounts and SharePoint sites, with inclusion rules that pick up new ones. If the service is locked, fix the Azure billing profile it is linked to. If another backup product is used, answer the attested backup checks instead.",
    links: &[
        "https://learn.microsoft.com/microsoft-365/backup/backup-overview",
        "https://learn.microsoft.com/graph/api/resources/backuprestoreroot",
    ],
    references: &["M365-Secure BCK-M365-001"],
    manual: None,
};

crate::check!(M365Backup, &M365_BACKUP, m365_backup);

/// Is this failure the documented "service not enabled" answer rather than a refusal?
fn not_enabled(failure: &CallFailure) -> bool {
    let GatewayError::Call(error) = &failure.error else {
        return false;
    };
    let text = format!(
        "{} {}",
        error.code.as_deref().unwrap_or_default(),
        error.message.as_deref().unwrap_or_default()
    )
    .to_ascii_lowercase();
    error.status == Some(404)
        || (matches!(error.status, Some(400 | 403))
            && (text.contains("not enabled") || text.contains("notenabled")))
}

async fn m365_backup(ctx: &CheckContext) -> Evaluation {
    let root = match ctx.get(BACKUP_ROOT.operation, json!({})).await {
        Ok(root) => root,
        Err(failure) if not_enabled(&failure) => {
            return Ok(Finding::not_applicable(
                "service_not_enabled",
                format!(
                    "Microsoft 365 Backup is not enabled for this tenant. If another product backs up Microsoft 365, answer {ATTESTED}."
                ),
            ));
        }
        Err(failure) => return Err(failure),
    };
    let status = str_at(&root, "/serviceStatus/status");
    match status.as_str() {
        "disabled" => {
            return Ok(Finding::not_applicable(
                "service_not_enabled",
                format!("Microsoft 365 Backup is not enabled for this tenant. If another product backs up Microsoft 365, answer {ATTESTED}."),
            )
            .data(json!({ "service_status": status })));
        }
        "protectionChangeLocked" | "restoreLocked" => {
            let reason = str_at(&root, "/serviceStatus/disableReason");
            return Ok(Finding::fail(format!(
                "Microsoft 365 Backup is {status}{}: protection policies are deactivated until the billing profile or service app is fixed.",
                if reason.is_empty() || reason == "none" { String::new() } else { format!(" ({reason})") }
            ))
            .data(json!({ "service_status": status, "disable_reason": reason })));
        }
        "enabled" => {}
        "" => {
            return Ok(Finding::unknown(
                "missing_data",
                "The Microsoft 365 Backup service status was not in the response.",
            ));
        }
        other => {
            return Ok(Finding::unknown(
                "unrecognised_value",
                format!("Unrecognised Microsoft 365 Backup service status '{other}'."),
            ));
        }
    }
    let (exchange, sharepoint, onedrive) = tokio::join!(
        ctx.list_with(EXCHANGE_POLICIES.operation, json!({})),
        ctx.list_with(SHAREPOINT_POLICIES.operation, json!({})),
        ctx.list_with(ONEDRIVE_POLICIES.operation, json!({})),
    );
    let workloads = [
        ("Exchange", exchange?),
        ("OneDrive", onedrive?),
        ("SharePoint", sharepoint?),
    ];
    let mut active = vec![];
    let mut missing = vec![];
    let mut data = serde_json::Map::new();
    data.insert("service_status".into(), json!(status));
    for (name, policies) in &workloads {
        let states: Vec<String> = policies.iter().map(|p| str_at(p, "/status")).collect();
        let on = states
            .iter()
            .filter(|s| matches!(s.as_str(), "active" | "activeWithErrors"))
            .count();
        data.insert(
            name.to_ascii_lowercase(),
            json!({ "policies": policies.len(), "active": on }),
        );
        if on > 0 {
            active.push(*name);
        } else {
            missing.push(*name);
        }
    }
    let finding = if missing.is_empty() {
        Finding::pass(
            "Active Microsoft 365 Backup protection policies cover Exchange, OneDrive and SharePoint.",
        )
    } else if active.is_empty() {
        Finding::fail(format!(
            "Microsoft 365 Backup is enabled but no workload has an active protection policy. If another product backs up Microsoft 365, answer {ATTESTED}."
        ))
    } else {
        Finding::warn(format!(
            "Active Microsoft 365 Backup policies for {}; none for {}.",
            active.join(", "),
            missing.join(", ")
        ))
    };
    Ok(finding.data(Value::Object(data)).affected(missing))
}

// ---------------------------------------------------------------------------
// backup.azure_vaults

pub const AZURE_VAULTS: CheckMeta = CheckMeta {
    id: "backup.azure_vaults",
    title: "Azure Backup vaults are immutable, soft-delete protected and cover critical VMs",
    pack: Pack::Backup,
    kind: CheckKind::Automated,
    severity: Severity::High,
    effort: Level::Medium,
    impact: Level::High,
    description: "Uses Azure Resource Graph to read Recovery Services and Backup vaults (soft delete and immutability state) and the Azure Backup protected items, and matches them against virtual machines tagged as critical (tag `criticality` = `critical` by default). Ransomware operators delete recovery points before encrypting; always-on soft delete and locked immutability stop a compromised subscription owner from doing that. Only subscriptions the identity can read are seen.",
    requires: Requirements {
        apis: &[RESOURCE_GRAPH],
        licences: &[],
    },
    remediation: "On each vault open Properties > Security settings: set soft delete to Always-on, enable immutability and lock it, and consider multi-user authorisation with a Resource Guard in a separate subscription. Configure backup for every critical virtual machine, and enforce both with Azure Policy. Settings: `[checks.\"backup.azure_vaults\"]` `critical_tag`, `critical_value`, `require_locked` (default true).",
    links: &[
        "https://learn.microsoft.com/azure/backup/backup-azure-immutable-vault-concept",
        "https://learn.microsoft.com/azure/backup/secure-by-default",
        "https://learn.microsoft.com/azure/backup/query-backups-using-azure-resource-graph",
    ],
    references: &["M365-Secure AZ-BACKUP-001"],
    manual: None,
};

crate::check!(AzureVaults, &AZURE_VAULTS, azure_vaults);

pub const VAULTS_QUERY: &str = "resources | where type in~ ('microsoft.recoveryservices/vaults', 'microsoft.dataprotection/backupvaults') | project id, name, type = tolower(type), properties";
pub const VM_COUNT_QUERY: &str =
    "resources | where type =~ 'microsoft.compute/virtualmachines' | summarize vms = count()";
pub const PROTECTED_VMS_QUERY: &str = "recoveryservicesresources | where type =~ 'microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems' | where tostring(properties.backupManagementType) =~ 'AzureIaasVM' | project sourceId = tolower(tostring(properties.sourceResourceId)), state = tostring(properties.protectionState)";

/// Resource Graph query for VMs whose tag `tag` equals `value` (case-insensitive).
pub fn critical_vms_query(tag: &str, value: &str) -> String {
    format!(
        "resources | where type =~ 'microsoft.compute/virtualmachines' | where tostring(tags[{}]) =~ {} | project id = tolower(id), name",
        kql_string(tag),
        kql_string(value)
    )
}

/// A KQL string literal.
fn kql_string(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

/// Pages Resource Graph follows before giving up (1,000 rows each).
const RESOURCE_GRAPH_PAGES: usize = 20;

/// Run a Resource Graph query and return its rows, following `$skipToken`.
async fn resource_graph(
    ctx: &CheckContext,
    query: &str,
) -> Result<(Vec<Value>, bool), CallFailure> {
    let mut rows = vec![];
    let mut token: Option<String> = None;
    for _ in 0..RESOURCE_GRAPH_PAGES {
        let mut options = json!({ "resultFormat": "objectArray", "$top": 1000 });
        if let Some(t) = &token {
            options["$skipToken"] = json!(t);
        }
        let body = ctx
            .get(
                RESOURCE_GRAPH.operation,
                json!({ "body": { "query": query, "options": options } }),
            )
            .await?;
        rows.extend(
            body.get("data")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
        );
        token = body
            .get("$skipToken")
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty())
            .map(str::to_owned);
        if token.is_none() {
            return Ok((rows, false));
        }
    }
    Ok((rows, true))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Setting {
    Off,
    Unknown,
    On,
    Strong,
}

fn soft_delete(vault: &Value) -> (Setting, String) {
    let settings = vault.pointer("/properties/securitySettings/softDeleteSettings");
    let state = settings
        .and_then(|s| s.get("softDeleteState").or_else(|| s.get("state")))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let level = match state.to_ascii_lowercase().as_str() {
        "alwayson" => Setting::Strong,
        "enabled" | "on" => Setting::On,
        "disabled" | "off" => Setting::Off,
        _ => Setting::Unknown,
    };
    (
        level,
        if state.is_empty() { "unknown" } else { state }.to_owned(),
    )
}

fn immutability(vault: &Value) -> (Setting, String) {
    let state = vault
        .pointer("/properties/securitySettings/immutabilitySettings/state")
        .and_then(Value::as_str)
        .unwrap_or("Disabled");
    let level = match state.to_ascii_lowercase().as_str() {
        "locked" => Setting::Strong,
        "unlocked" => Setting::On,
        "disabled" => Setting::Off,
        _ => Setting::Unknown,
    };
    (level, state.to_owned())
}

async fn azure_vaults(ctx: &CheckContext) -> Evaluation {
    let id = AZURE_VAULTS.id;
    let tag: String = ctx.setting(id, "critical_tag", "criticality".to_owned());
    let value: String = ctx.setting(id, "critical_value", "critical".to_owned());
    let require_locked: bool = ctx.setting(id, "require_locked", true);
    let critical_query = critical_vms_query(&tag, &value);
    let (vaults, vm_count, critical) = tokio::join!(
        resource_graph(ctx, VAULTS_QUERY),
        resource_graph(ctx, VM_COUNT_QUERY),
        resource_graph(ctx, &critical_query),
    );
    let (vaults, vaults_truncated) = vaults?;
    let vm_count = vm_count?
        .0
        .first()
        .and_then(|r| r.get("vms"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let (critical, critical_truncated) = critical?;
    if vaults_truncated || critical_truncated {
        return Ok(Finding::unknown(
            "truncated",
            "Resource Graph returned more rows than the check reads; narrow the scope and re-run.",
        ));
    }
    if vaults.is_empty() && vm_count == 0 {
        return Ok(Finding::not_applicable(
            "no_azure_workloads",
            format!(
                "No Recovery Services or Backup vaults and no virtual machines in the subscriptions this identity can read. If backups run elsewhere, answer {ATTESTED}."
            ),
        ));
    }

    // Vault posture.
    let mut gaps = vec![];
    let mut vault_rows = vec![];
    let mut off = 0;
    for vault in &vaults {
        let name = str_at(vault, "/name");
        let (sd, sd_state) = soft_delete(vault);
        let (im, im_state) = immutability(vault);
        let level = sd.min(im);
        let ok = if require_locked {
            level == Setting::Strong
        } else {
            level >= Setting::On
        };
        if !ok {
            gaps.push(name.clone());
        }
        if level == Setting::Off {
            off += 1;
        }
        vault_rows.push(json!({
            "name": name,
            "kind": if str_at(vault, "/type").contains("dataprotection") { "backup_vault" } else { "recovery_services_vault" },
            "soft_delete": sd_state,
            "immutability": im_state,
        }));
    }

    // Critical VM coverage.
    let mut uncovered = vec![];
    if !critical.is_empty() {
        let (protected, truncated) = resource_graph(ctx, PROTECTED_VMS_QUERY).await?;
        if truncated {
            return Ok(Finding::unknown(
                "truncated",
                "Resource Graph returned more protected items than the check reads; narrow the scope and re-run.",
            ));
        }
        let covered: std::collections::BTreeSet<String> = protected
            .iter()
            .filter(|p| !str_at(p, "/state").eq_ignore_ascii_case("ProtectionStopped"))
            .map(|p| str_at(p, "/sourceId"))
            .collect();
        uncovered = critical
            .iter()
            .filter(|vm| !covered.contains(&str_at(vm, "/id").to_ascii_lowercase()))
            .map(|vm| str_at(vm, "/name"))
            .collect();
    }

    let data = json!({
        "vaults": vault_rows,
        "virtual_machines": vm_count,
        "critical_vms": critical.len(),
        "critical_vms_unprotected": uncovered.len(),
        "critical_tag": format!("{tag}={value}"),
        "require_locked": require_locked,
    });
    let coverage = if critical.is_empty() {
        format!(" No virtual machines are tagged {tag}={value}, so coverage was not assessed.")
    } else if uncovered.is_empty() {
        format!(
            " Critical virtual machines protected: {} of {}.",
            critical.len(),
            critical.len()
        )
    } else {
        String::new()
    };
    let finding = if vaults.is_empty() {
        if uncovered.is_empty() {
            Finding::warn(format!(
                "{} but no Recovery Services or Backup vault.{coverage} If another product backs them up, answer {ATTESTED}.",
                plural(vm_count as usize, "virtual machine")
            ))
        } else {
            Finding::fail(format!(
                "No Recovery Services or Backup vault; critical virtual machines without Azure Backup: {}.",
                uncovered.len()
            ))
        }
    } else if !uncovered.is_empty() || off > 0 {
        let mut parts = vec![];
        if off > 0 {
            parts.push(format!(
                "vaults with soft delete or immutability turned off: {off} of {}",
                vaults.len()
            ));
        }
        if !uncovered.is_empty() {
            parts.push(format!(
                "critical virtual machines without Azure Backup: {} of {}",
                uncovered.len(),
                critical.len()
            ));
        }
        let text = parts.join("; ");
        Finding::fail(format!("{}{}.", text[..1].to_uppercase(), &text[1..]))
    } else if !gaps.is_empty() {
        Finding::warn(format!(
            "Vaults without both always-on soft delete and locked immutability: {} of {}.{coverage}",
            gaps.len(),
            vaults.len()
        ))
    } else {
        Finding::pass(format!(
            "{} with {}.{coverage}",
            plural(vaults.len(), "vault"),
            if require_locked {
                "always-on soft delete and locked immutability"
            } else {
                "soft delete and immutability enabled"
            }
        ))
    };
    Ok(finding
        .data(data)
        .affected(gaps.into_iter().chain(uncovered)))
}

// ---------------------------------------------------------------------------
// backup.third_party_app

pub const THIRD_PARTY_APP: CheckMeta = CheckMeta {
    id: "backup.third_party_app",
    title: "A third-party Microsoft 365 backup app has consent",
    pack: Pack::Backup,
    kind: CheckKind::Automated,
    severity: Severity::Info,
    effort: Level::Low,
    impact: Level::Low,
    description: "Lists enterprise applications and matches them against known Microsoft 365 backup products (`data/backup-vendors.yaml`: published application ids, then product and publisher names). A match is a signal that a backup product has been granted access, not proof that backups run or cover everything. When no known product is found, an attestation for this check is used if one exists.",
    requires: Requirements {
        apis: &[SERVICE_PRINCIPALS],
        licences: &[],
    },
    remediation: "If no backup product protects Microsoft 365, enable Microsoft 365 Backup or a third-party backup service. If you use a product this check does not recognise, attest this check (`junction check attest backup.third_party_app`) and answer the other attested backup checks.",
    links: &["https://learn.microsoft.com/microsoft-365/backup/backup-overview"],
    references: &[],
    manual: None,
};

crate::check!(ThirdPartyApp, &THIRD_PARTY_APP, third_party_app);

/// Known backup products, from `data/backup-vendors.yaml`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupVendors {
    pub apps: Vec<VendorApp>,
    pub patterns: Vec<VendorPattern>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VendorApp {
    pub app_id: String,
    pub vendor: String,
    pub product: String,
    pub source: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VendorPattern {
    pub vendor: String,
    pub product: String,
    #[serde(default)]
    pub display_name: Vec<String>,
    #[serde(default)]
    pub publisher: Vec<String>,
    #[serde(default)]
    pub source: Option<String>,
}

pub fn backup_vendors() -> &'static BackupVendors {
    static DATA: OnceLock<BackupVendors> = OnceLock::new();
    DATA.get_or_init(|| {
        serde_saphyr::from_str(include_str!("../../data/backup-vendors.yaml"))
            .expect("data/backup-vendors.yaml is valid")
    })
}

impl BackupVendors {
    /// The vendor and product a service principal belongs to, if known.
    pub fn match_app(&self, sp: &Value) -> Option<(&str, &str)> {
        let app_id = str_at(sp, "/appId");
        if let Some(app) = self
            .apps
            .iter()
            .find(|a| a.app_id.eq_ignore_ascii_case(&app_id))
        {
            return Some((&app.vendor, &app.product));
        }
        let name = str_at(sp, "/displayName").to_ascii_lowercase();
        let publishers = [
            str_at(sp, "/publisherName").to_ascii_lowercase(),
            str_at(sp, "/verifiedPublisher/displayName").to_ascii_lowercase(),
        ];
        self.patterns
            .iter()
            .find(|p| {
                p.display_name.iter().any(|n| name.contains(n.as_str()))
                    || p.publisher
                        .iter()
                        .any(|n| publishers.iter().any(|v| v.contains(n.as_str())))
            })
            .map(|p| (p.vendor.as_str(), p.product.as_str()))
    }
}

async fn third_party_app(ctx: &CheckContext) -> Evaluation {
    let listing = ctx
        .list(
            SERVICE_PRINCIPALS.operation,
            json!({ "parameters": {
                "$select": ["id", "appId", "displayName", "publisherName", "verifiedPublisher", "accountEnabled"],
                "$top": 999,
            }}),
        )
        .await?;
    let vendors = backup_vendors();
    let mut found = vec![];
    let mut products = std::collections::BTreeSet::new();
    let mut disabled = 0;
    for sp in &listing.items {
        if let Some((vendor, product)) = vendors.match_app(sp) {
            if sp.get("accountEnabled").and_then(Value::as_bool) == Some(false) {
                disabled += 1;
                continue;
            }
            found.push(str_at(sp, "/displayName"));
            products.insert(format!("{vendor}: {product}"));
        }
    }
    let data = json!({
        "service_principals": listing.items.len(),
        "matches": found.len(),
        "disabled_matches": disabled,
        "products": products,
    });
    if !found.is_empty() {
        return Ok(Finding::pass(format!(
            "Backup app with consent: {}.",
            products.iter().cloned().collect::<Vec<_>>().join("; ")
        ))
        .data(data)
        .affected(found));
    }
    if let Some(attestation) = ctx.attestation(THIRD_PARTY_APP.id) {
        return Ok(Finding::from_attestation(attestation).data(data));
    }
    if listing.truncated {
        return Ok(Finding::unknown(
            "truncated",
            "The enterprise application listing was cut short before a backup app was found.",
        )
        .data(data));
    }
    Ok(Finding::warn(
        "No enterprise application matches a known Microsoft 365 backup product. If you use another product, attest this check instead.",
    )
    .data(data))
}

// ---------------------------------------------------------------------------
// Attested checks

pub const OFFLINE_COPY: CheckMeta = CheckMeta {
    severity: Severity::High,
    impact: Level::High,
    effort: Level::Medium,
    links: &[
        "https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/essential-eight-maturity-model",
    ],
    ..CheckMeta::manual(
        "backup.offline_copy",
        "An offline or immutable copy of backups exists",
        Pack::Backup,
        ManualSpec {
            question: "Is at least one copy of your important data, software and settings held offline, or in storage that cannot be changed or deleted during its retention period (immutable), separate from production credentials?",
            guidance: "Answer yes only if the copy survives a compromised Global Administrator or subscription owner: offline media, an immutable vault with locked immutability, or a backup provider whose deletion needs a separate identity. Record where the copy is and its retention in the note. Answer partial if only some systems have such a copy.",
            why_manual: "Offline media and third-party storage are not visible to Microsoft APIs.",
        },
    )
};

pub const RESTORE_TESTED: CheckMeta = CheckMeta {
    severity: Severity::High,
    impact: Level::High,
    effort: Level::Medium,
    links: &[
        "https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/essential-eight-maturity-model",
    ],
    ..CheckMeta::manual(
        "backup.restore_tested",
        "A test restore was done in the last six months",
        Pack::Backup,
        ManualSpec {
            question: "Was a restore of data, applications and settings from backup tested, to a common point in time, within the last six months?",
            guidance: "Record the date of the last test restore (DD-MM-YYYY) and what was restored in the note. Answer no if the last test is older than six months, and partial if only some systems were tested. Re-attest after each test; set the attestation expiry to six months so a stale answer becomes unknown.",
            why_manual: "Restore exercises are not recorded in any Microsoft API.",
        },
    )
};

pub const ADMIN_SEPARATION: CheckMeta = CheckMeta {
    severity: Severity::Medium,
    impact: Level::High,
    effort: Level::Medium,
    links: &[
        "https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/essential-eight-maturity-model",
    ],
    ..CheckMeta::manual(
        "backup.admin_separation",
        "Backup administrator accounts are separate from production administrators",
        Pack::Backup,
        ManualSpec {
            question: "Are backups administered by dedicated accounts that are not used for production administration, and can production administrators not modify or delete backups?",
            guidance: "Answer yes if backup administrator accounts are separate identities (ideally in a separate tenant, subscription or the backup provider's own directory), protected by phishing-resistant MFA, and production Global Administrators or subscription owners cannot delete backups. Name the accounts or groups in the note.",
            why_manual: "Backup product roles and third-party consoles are outside Microsoft APIs, and separation is an organisational control.",
        },
    )
};

/// `1 vault`, `2 vaults`.
fn plural(count: usize, noun: &str) -> String {
    format!("{count} {noun}{}", if count == 1 { "" } else { "s" })
}

/// A string at a JSON pointer, or empty.
fn str_at(value: &Value, pointer: &str) -> String {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_data_is_valid() {
        let data = backup_vendors();
        assert!(!data.apps.is_empty());
        for app in &data.apps {
            assert_eq!(app.app_id.len(), 36, "{}", app.app_id);
            assert!(app.source.starts_with("https://"), "{}", app.vendor);
        }
        for p in &data.patterns {
            assert!(
                !p.display_name.is_empty() || !p.publisher.is_empty(),
                "{}",
                p.vendor
            );
            assert!(
                p.display_name
                    .iter()
                    .chain(&p.publisher)
                    .all(|n| *n == n.to_ascii_lowercase())
            );
        }
    }

    #[test]
    fn matches_by_app_id_then_name_or_publisher() {
        let data = backup_vendors();
        let sp = json!({"appId": "4D69A8E1-9C38-4B33-B76F-9D59B5AE051B", "displayName": "x"});
        assert_eq!(data.match_app(&sp).unwrap().0, "AvePoint");
        let sp = json!({"appId": "1", "displayName": "Veeam Backup for Microsoft 365"});
        assert_eq!(data.match_app(&sp).unwrap().0, "Veeam");
        let sp = json!({"appId": "1", "displayName": "Tool", "verifiedPublisher": {"displayName": "Keepit A/S"}});
        assert_eq!(data.match_app(&sp).unwrap().0, "Keepit");
        let sp =
            json!({"appId": "1", "displayName": "AvePoint Policies", "publisherName": "AvePoint"});
        assert!(data.match_app(&sp).is_none());
    }

    #[test]
    fn kql_literals_are_escaped() {
        assert_eq!(kql_string("it's"), r"'it\'s'");
        assert!(
            critical_vms_query("criticality", "critical")
                .contains("tags['criticality']) =~ 'critical'")
        );
    }

    #[test]
    fn vault_settings_are_read_from_both_vault_types() {
        let rsv = json!({"properties": {"securitySettings": {
            "softDeleteSettings": {"softDeleteState": "AlwaysON"},
            "immutabilitySettings": {"state": "Locked"}}}});
        assert_eq!(soft_delete(&rsv).0, Setting::Strong);
        assert_eq!(immutability(&rsv).0, Setting::Strong);
        let bv =
            json!({"properties": {"securitySettings": {"softDeleteSettings": {"state": "On"}}}});
        assert_eq!(soft_delete(&bv).0, Setting::On);
        assert_eq!(immutability(&bv).0, Setting::Off);
        assert_eq!(soft_delete(&json!({})).0, Setting::Unknown);
    }
}
