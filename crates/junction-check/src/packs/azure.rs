//! `azure` pack: Defender for Cloud plans, Key Vault protection and public network
//! exposure of storage and PaaS data services. Ported from M365-Secure
//! `src/modules/azure/{defender,keyvault,workloads}.rs`.
//!
//! Subscriptions come from `[packs.azure] subscriptions = [...]` or, when not set,
//! every subscription Resource Graph can see.
use crate::check::{ApiRequirement, Check, CheckMeta, Evaluation, Finding, Requirements};
use crate::context::{CallFailure, CheckContext};
use crate::model::{Level, Pack, Severity};
use crate::packs::apps::meta;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub fn checks() -> Vec<Arc<dyn Check>> {
    vec![
        Arc::new(DefenderPlans),
        Arc::new(KeyVaultProtection),
        Arc::new(PublicNetworkExposure),
    ]
}

const RESOURCE_GRAPH: ApiRequirement = ApiRequirement {
    operation: "azure.resource_graph.resources.post",
    permissions: &["Reader"],
};
const PRICINGS: ApiRequirement = ApiRequirement {
    operation: "defender.cloud.pricings.list",
    permissions: &["Security Reader", "Reader"],
};

/// Resource Graph pages read before a query is cut short.
const MAX_PAGES: usize = 20;

pub const SUBSCRIPTIONS_KQL: &str = "resourcecontainers | where type =~ 'microsoft.resources/subscriptions' | project subscriptionId, name, state = tostring(properties.state)";
pub const INVENTORY_KQL: &str = "resources | where type in~ ('microsoft.compute/virtualmachines', 'microsoft.hybridcompute/machines', 'microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.keyvault/vaults', 'microsoft.containerservice/managedclusters', 'microsoft.containerregistry/registries') | summarize n = count() by subscriptionId, type = tolower(type)";
pub const VAULTS_KQL: &str = "resources | where type =~ 'microsoft.keyvault/vaults' | project id, name, subscriptionId, enableRbacAuthorization = properties.enableRbacAuthorization, enablePurgeProtection = properties.enablePurgeProtection, enableSoftDelete = properties.enableSoftDelete, publicNetworkAccess = tostring(properties.publicNetworkAccess), defaultAction = tostring(properties.networkAcls.defaultAction)";
pub const STORAGE_KQL: &str = "resources | where type =~ 'microsoft.storage/storageaccounts' | project id, name, subscriptionId, allowSharedKeyAccess = properties.allowSharedKeyAccess, allowBlobPublicAccess = properties.allowBlobPublicAccess, publicNetworkAccess = tostring(properties.publicNetworkAccess), defaultAction = tostring(properties.networkAcls.defaultAction)";
pub const DATA_SERVICES_KQL: &str = "resources | where type in~ ('microsoft.sql/servers', 'microsoft.documentdb/databaseaccounts', 'microsoft.dbforpostgresql/flexibleservers', 'microsoft.dbforpostgresql/servers', 'microsoft.dbformysql/flexibleservers', 'microsoft.dbformysql/servers', 'microsoft.dbformariadb/servers', 'microsoft.synapse/workspaces', 'microsoft.cache/redis') | project id, name, type, publicNetworkAccess = iff(isnotempty(tostring(properties.publicNetworkAccess)), tostring(properties.publicNetworkAccess), tostring(properties.network.publicNetworkAccess))";

fn configured_subscriptions(ctx: &CheckContext) -> Vec<String> {
    ctx.pack_setting(Pack::Azure.as_str(), "subscriptions", Vec::new())
}

/// Rows of a Resource Graph query over the configured (or all readable) subscriptions.
pub async fn resource_graph(ctx: &CheckContext, query: &str) -> Result<Vec<Value>, CallFailure> {
    let subscriptions = configured_subscriptions(ctx);
    let mut rows = vec![];
    let mut skip: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let mut options = json!({ "resultFormat": "objectArray", "$top": 1000 });
        if let Some(token) = &skip {
            options["$skipToken"] = Value::String(token.clone());
        }
        let mut body = json!({ "query": query, "options": options });
        if !subscriptions.is_empty() {
            body["subscriptions"] = json!(subscriptions);
        }
        let page = ctx
            .get(RESOURCE_GRAPH.operation, json!({ "body": body }))
            .await?;
        rows.extend(page["data"].as_array().into_iter().flatten().cloned());
        skip = page["$skipToken"].as_str().map(str::to_owned);
        if skip.is_none() {
            break;
        }
    }
    Ok(rows)
}

fn str_at<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or("")
}

fn eq_ci(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn no_resources(what: &str) -> Finding {
    Finding::not_applicable(
        "no_resources",
        format!("No {what} in the readable subscriptions."),
    )
}

// --- Defender for Cloud plans ---------------------------------------------------

pub const DEFENDER_PLANS: CheckMeta = CheckMeta {
    requires: Requirements {
        apis: &[RESOURCE_GRAPH, PRICINGS],
        licences: &[],
    },
    ..meta(
        Pack::Azure,
        "azure.defender_plans",
        "Defender for Cloud plans are on wherever matching resources exist",
        Severity::High,
        (Level::Low, Level::High),
        "Reads each subscription's Defender for Cloud pricing tiers and its resource inventory. A plan is relevant when the subscription holds that resource type (Servers, Storage, SQL, Key Vault, Containers); Resource Manager is relevant to every subscription.",
        &[RESOURCE_GRAPH, PRICINGS],
        "Turn on the relevant Defender plans (Defender for Cloud > Environment settings), starting with Resource Manager, Servers, Storage, SQL and Key Vault on production subscriptions, and enforce them with Azure Policy at management-group scope.",
        &["https://learn.microsoft.com/azure/defender-for-cloud/connect-azure-subscription"],
        &[],
    )
};

crate::check!(DefenderPlans, &DEFENDER_PLANS, defender_plans);

/// Defender plan that protects a resource type.
fn plan_for_type(resource_type: &str) -> Option<&'static str> {
    Some(match resource_type.to_ascii_lowercase().as_str() {
        "microsoft.compute/virtualmachines" | "microsoft.hybridcompute/machines" => {
            "VirtualMachines"
        }
        "microsoft.storage/storageaccounts" => "StorageAccounts",
        "microsoft.sql/servers" => "SqlServers",
        "microsoft.keyvault/vaults" => "KeyVaults",
        "microsoft.containerservice/managedclusters" | "microsoft.containerregistry/registries" => {
            "Containers"
        }
        _ => return None,
    })
}

async fn subscriptions(ctx: &CheckContext) -> Result<Vec<(String, String)>, CallFailure> {
    let configured = configured_subscriptions(ctx);
    if !configured.is_empty() {
        return Ok(configured.into_iter().map(|s| (s.clone(), s)).collect());
    }
    let mut subs: Vec<(String, String)> = resource_graph(ctx, SUBSCRIPTIONS_KQL)
        .await?
        .iter()
        .filter(|r| !str_at(r, "subscriptionId").is_empty())
        .map(|r| {
            (
                str_at(r, "subscriptionId").to_owned(),
                str_at(r, "name").to_owned(),
            )
        })
        .collect();
    subs.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));
    Ok(subs)
}

async fn defender_plans(ctx: &CheckContext) -> Evaluation {
    let subs = subscriptions(ctx).await?;
    if subs.is_empty() {
        return Ok(Finding::not_applicable(
            "no_subscriptions",
            "No Azure subscriptions are readable. Grant Reader at the root management group to assess Azure.",
        ));
    }
    let mut relevant: BTreeMap<&str, BTreeSet<&'static str>> = subs
        .iter()
        .map(|(id, _)| (id.as_str(), BTreeSet::from(["Arm"])))
        .collect();
    let inventory = resource_graph(ctx, INVENTORY_KQL).await?;
    for row in &inventory {
        if row["n"].as_i64().unwrap_or(0) <= 0 {
            continue;
        }
        if let (Some(set), Some(plan)) = (
            relevant.get_mut(str_at(row, "subscriptionId")),
            plan_for_type(str_at(row, "type")),
        ) {
            set.insert(plan);
        }
    }
    let mut gaps = vec![];
    let mut per_subscription = vec![];
    let (mut any_standard, mut all_standard) = (false, true);
    for (id, label) in &subs {
        let pricings = ctx
            .get(
                PRICINGS.operation,
                json!({ "parameters": { "scopeId": format!("subscriptions/{id}") } }),
            )
            .await?;
        let on: BTreeSet<String> = pricings["value"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|p| {
                eq_ci(
                    p["properties"]["pricingTier"].as_str().unwrap_or(""),
                    "Standard",
                )
            })
            .filter_map(|p| p["name"].as_str().map(str::to_ascii_lowercase))
            .collect();
        let (standard, missing): (Vec<&str>, Vec<&str>) = relevant[id.as_str()]
            .iter()
            .partition(|p| on.contains(&p.to_ascii_lowercase()));
        any_standard |= !standard.is_empty();
        all_standard &= missing.is_empty();
        if !missing.is_empty() {
            gaps.push(format!("{label}: {}", missing.join("/")));
        }
        per_subscription
            .push(json!({ "subscription": label, "standard": standard, "missing": missing }));
    }
    let data = json!({ "subscriptions": per_subscription });
    let finding = if all_standard {
        Finding::pass(format!(
            "Every relevant Defender plan is on across {} subscription(s).",
            subs.len()
        ))
    } else {
        let summary = format!(
            "{} of {} subscription(s) have relevant Defender plans off.",
            gaps.len(),
            subs.len()
        );
        if any_standard {
            Finding::warn(summary)
        } else {
            Finding::fail(summary)
        }
    };
    Ok(finding.data(data).affected(gaps))
}

// --- Key Vault -----------------------------------------------------------------

pub const KEY_VAULT_PROTECTION: CheckMeta = meta(
    Pack::Azure,
    "azure.key_vault_protection",
    "Key vaults use Azure RBAC, purge protection and restricted networking",
    Severity::High,
    (Level::Medium, Level::High),
    "Reads every key vault's permission model, purge protection, soft delete and network settings. Access policies are coarse and hard to audit; without purge protection a deleted vault or key is gone for good.",
    &[RESOURCE_GRAPH],
    "Move vaults to the Azure RBAC permission model, turn on purge protection, restrict networking with private endpoints or a firewall that denies by default, and enforce with the built-in Key Vault Azure Policy definitions.",
    &["https://learn.microsoft.com/azure/key-vault/general/security-features"],
    &[],
);

crate::check!(
    KeyVaultProtection,
    &KEY_VAULT_PROTECTION,
    key_vault_protection
);

async fn key_vault_protection(ctx: &CheckContext) -> Evaluation {
    let vaults = resource_graph(ctx, VAULTS_KQL).await?;
    if vaults.is_empty() {
        return Ok(no_resources("key vaults"));
    }
    let (mut access_policies, mut no_purge, mut soft_delete_off, mut public) =
        (vec![], vec![], vec![], vec![]);
    for v in &vaults {
        let name = str_at(v, "name").to_owned();
        if v["enableRbacAuthorization"].as_bool() != Some(true) {
            access_policies.push(name.clone());
        }
        if v["enablePurgeProtection"].as_bool() != Some(true) {
            no_purge.push(name.clone());
        }
        // Soft delete is on by default; only an explicit false is a gap (reported, not failed).
        if v["enableSoftDelete"].as_bool() == Some(false) {
            soft_delete_off.push(name.clone());
        }
        if !(eq_ci(str_at(v, "publicNetworkAccess"), "Disabled")
            || eq_ci(str_at(v, "defaultAction"), "Deny"))
        {
            public.push(name);
        }
    }
    let compliant = access_policies.is_empty() && no_purge.is_empty() && public.is_empty();
    let data = json!({
        "vaults": vaults.len(),
        "access_policy_model": access_policies,
        "no_purge_protection": no_purge,
        "public_network": public,
        "soft_delete_off": soft_delete_off,
    });
    let affected: Vec<String> = [&access_policies, &no_purge, &public, &soft_delete_off]
        .into_iter()
        .flatten()
        .cloned()
        .collect();
    Ok(Finding::pass_if(
        compliant,
        format!(
            "All {} key vault(s) use Azure RBAC, have purge protection and restrict network access.",
            vaults.len()
        ),
        format!(
            "Of {} key vault(s): {} use access policies, {} lack purge protection, {} are open to public networks.",
            vaults.len(),
            access_policies.len(),
            no_purge.len(),
            public.len()
        ),
    )
    .data(data)
    .affected(affected))
}

// --- public exposure --------------------------------------------------------------

pub const PUBLIC_NETWORK_EXPOSURE: CheckMeta = meta(
    Pack::Azure,
    "azure.public_network_exposure",
    "Storage and PaaS data services are closed to anonymous and public network access",
    Severity::High,
    (Level::Medium, Level::High),
    "Reads storage accounts (anonymous blob access, public network access, firewall default) and SQL, Cosmos DB, PostgreSQL, MySQL, MariaDB, Synapse and Redis (public network access). Public endpoints are the usual route for data theft from cloud storage.",
    &[RESOURCE_GRAPH],
    "Disable anonymous blob access, set the storage firewall default to Deny with private endpoints or selected networks, disable public network access on database and cache services behind private endpoints, and enforce both with Azure Policy deny effects.",
    &["https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent"],
    &[],
);

crate::check!(
    PublicNetworkExposure,
    &PUBLIC_NETWORK_EXPOSURE,
    public_network_exposure
);

async fn public_network_exposure(ctx: &CheckContext) -> Evaluation {
    let storage = resource_graph(ctx, STORAGE_KQL).await?;
    let services = resource_graph(ctx, DATA_SERVICES_KQL).await?;
    if storage.is_empty() && services.is_empty() {
        return Ok(no_resources("storage accounts or PaaS data services"));
    }
    let enabled = |v: &Value| {
        let pna = str_at(v, "publicNetworkAccess");
        pna.is_empty() || eq_ci(pna, "Enabled")
    };
    // Unset anonymous blob access means the pre-2023 default (allowed).
    let blob_public: Vec<String> = storage
        .iter()
        .filter(|s| s["allowBlobPublicAccess"].as_bool() != Some(false))
        .map(|s| str_at(s, "name").to_owned())
        .collect();
    let storage_open: Vec<String> = storage
        .iter()
        .filter(|s| enabled(s) && !eq_ci(str_at(s, "defaultAction"), "Deny"))
        .map(|s| str_at(s, "name").to_owned())
        .collect();
    let services_public: Vec<String> = services
        .iter()
        .filter(|d| enabled(d))
        .map(|d| {
            format!(
                "{} ({})",
                str_at(d, "name"),
                str_at(d, "type").rsplit('/').next().unwrap_or("")
            )
        })
        .collect();
    let compliant = blob_public.is_empty() && storage_open.is_empty() && services_public.is_empty();
    let data = json!({
        "storage_accounts": storage.len(),
        "blob_public_access_allowed": blob_public,
        "storage_network_open": storage_open,
        "data_services": services.len(),
        "data_services_public": services_public,
    });
    let affected: Vec<String> = [&blob_public, &storage_open, &services_public]
        .into_iter()
        .flatten()
        .cloned()
        .collect();
    Ok(Finding::pass_if(
        compliant,
        format!(
            "All {} storage account(s) and {} data service(s) are closed to anonymous and public network access.",
            storage.len(),
            services.len()
        ),
        format!(
            "{} storage account(s) allow anonymous blob access, {} accept traffic from all networks, {} data service(s) have public network access.",
            blob_public.len(),
            storage_open.len(),
            services_public.len()
        ),
    )
    .data(data)
    .affected(affected))
}
