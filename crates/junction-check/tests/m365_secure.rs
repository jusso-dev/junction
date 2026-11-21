//! The M365-Secure schema 1.1 export carries every field crownguard's importer
//! (`src/imports/m365Secure.ts`, mapping `content/imports/m365-secure.yaml`) reads.
use junction_check::model::{
    LicenceSnapshot, RunReport, SCHEMA_VERSION, TenantReport, TenantStatus, Tool,
};
use junction_check::registry::CheckRegistry;
use junction_check::report::m365_secure::{mapping, render};
use junction_check::score;
use junction_check::testkit::run_case;
use serde_json::{Value, json};
use std::collections::BTreeMap;

const STATUSES: &[&str] = &[
    "pass",
    "fail",
    "warning",
    "review",
    "info",
    "unknown",
    "notlicensed",
];

async fn report() -> RunReport {
    let mut results = vec![];
    for (id, pack, case) in [
        ("apps.user_consent_restricted", "apps", "consent_open"),
        (
            "apps.admin_consent_workflow",
            "apps",
            "workflow_no_reviewers",
        ),
        ("apps.secret_lifetime", "apps", "lifetime_long"),
        ("apps.credential_expiry", "apps", "expiry_forbidden"),
        (
            "collaboration.sharepoint_external_sharing",
            "collaboration",
            "sharing_unlicensed",
        ),
        (
            "collaboration.guest_access_restricted",
            "collaboration",
            "guest_access_pass",
        ),
        ("azure.key_vault_protection", "azure", "vaults_none"),
        (
            "identity.global_admin_count",
            "identity",
            "global_admins_pass",
        ),
    ] {
        results.push(run_case(id, pack, case).await);
    }
    let tenant = TenantReport {
        tenant_id: "00000000-0000-4000-8000-000000000001".into(),
        label: Some("contoso.example".into()),
        status: TenantStatus::Partial,
        error: None,
        licences: Some(LicenceSnapshot {
            features: vec!["entra_id_p1".into()],
            skus: vec!["SPB".into()],
        }),
        score: score::score(&results),
        packs: score::pack_scores(&results),
        quick_wins: vec![],
        results,
        diff: None,
    };
    RunReport {
        schema_version: SCHEMA_VERSION.into(),
        run_id: "run-1".into(),
        tool: Tool {
            name: "junction".into(),
            version: "0.0.0".into(),
        },
        started_at: "2026-10-25T00:00:00.000Z".into(),
        finished_at: "2026-10-25T00:00:12.000Z".into(),
        selection: json!({}),
        tenants: vec![tenant],
    }
}

fn findings(doc: &Value) -> BTreeMap<String, Value> {
    doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| (f["check_id"].as_str().unwrap().to_owned(), f.clone()))
        .collect()
}

#[tokio::test]
async fn export_has_what_crownguard_reads() {
    let doc = render(&report().await);
    assert_eq!(doc["schema_version"], "1.1");
    // scanSchema: summary.timestamp, summary.tenant.{display_name, primary_domain, license_skus[].sku_part_number}
    let summary = &doc["summary"];
    assert!(summary["timestamp"].is_string());
    assert_eq!(summary["tenant"]["display_name"], "contoso.example");
    assert_eq!(summary["tenant"]["primary_domain"], "contoso.example");
    assert_eq!(
        summary["tenant"]["license_skus"][0]["sku_part_number"],
        "SPB"
    );
    // detect(): the text contains "summary", "findings" and license_skus.
    let text = serde_json::to_string_pretty(&doc).unwrap();
    for needle in ["\"summary\"", "\"findings\"", "license_skus"] {
        assert!(text.contains(needle), "{needle}");
    }
    // findings[]: check_id, status (enum), setting, current_value, expected_value.
    let all = doc["findings"].as_array().unwrap();
    assert!(!all.is_empty() && all.len() <= 5000);
    for f in all {
        assert!(f["check_id"].is_string());
        assert!(STATUSES.contains(&f["status"].as_str().unwrap()), "{f}");
        for key in ["setting", "current_value", "expected_value"] {
            assert!(f[key].is_string(), "{key} in {f}");
        }
    }
}

#[tokio::test]
async fn results_map_back_to_m365_secure_ids_and_statuses() {
    let doc = render(&report().await);
    let f = findings(&doc);
    // One Junction check can answer several M365-Secure ids.
    assert_eq!(f["ENTRA-CONSENT-001"]["status"], "fail");
    assert_eq!(f["ENTRA-CONSENT-003"]["status"], "fail");
    assert_eq!(f["ENTRA-CONSENT-002"]["status"], "warning");
    assert_eq!(f["ENTRA-APPREG-002"]["status"], "unknown");
    assert_eq!(f["SPO-SHARING-001"]["status"], "notlicensed");
    assert_eq!(f["ENTRA-GUEST-001"]["status"], "pass");
    assert_eq!(f["AZ-KV-001"]["status"], "info");
    assert_eq!(f["ENTRA-ADMIN-001"]["status"], "pass");
    assert_eq!(
        f["ENTRA-ADMIN-001"]["details"]["junction_check_id"],
        "identity.global_admin_count"
    );
    // apps.secret_lifetime has no M365-Secure id, so it is skipped.
    assert!(
        f.values()
            .all(|x| x["details"]["junction_check_id"] != "apps.secret_lifetime")
    );
    assert_eq!(doc["summary"]["total_checks"], f.len());
    assert_eq!(doc["summary"]["status_counts"]["Fail"], 2);
    assert_eq!(doc["summary"]["status_counts"]["Not Licensed"], 1);
}

#[tokio::test]
async fn several_tenants_give_one_document_each() {
    let mut report = report().await;
    let mut second = report.tenants[0].clone();
    second.label = None;
    report.tenants.push(second);
    let docs = render(&report);
    let docs = docs.as_array().expect("array for several tenants");
    assert_eq!(docs.len(), 2);
    assert_eq!(
        docs[1]["summary"]["tenant"]["primary_domain"],
        "00000000-0000-4000-8000-000000000001"
    );
}

/// The exporter map and the migration table in docs/migration/m365-secure.md agree.
#[test]
fn map_matches_the_migration_table() {
    let doc = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/migration/m365-secure.md"),
    )
    .unwrap();
    let mut rows: BTreeMap<String, (String, String)> = BTreeMap::new();
    for line in doc.lines().filter(|l| l.starts_with("| `")) {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        let id = cells[1].trim_matches('`').to_owned();
        let junction = cells[4].split('`').nth(1).unwrap_or_default().to_owned();
        assert!(
            rows.insert(id.clone(), (cells[3].to_owned(), junction))
                .is_none(),
            "{id} listed twice"
        );
    }
    assert_eq!(
        rows.len(),
        306,
        "every M365-Secure check id is accounted for"
    );
    let mut mapped = 0;
    for (junction, ids) in mapping() {
        for id in ids {
            let (disposition, row_junction) = rows.get(id).unwrap_or_else(|| panic!("{id}"));
            assert!(matches!(disposition.as_str(), "new" | "merged"), "{id}");
            assert_eq!(row_junction, junction, "{id}");
            mapped += 1;
        }
    }
    let in_table = rows
        .values()
        .filter(|(d, _)| d == "new" || d == "merged")
        .count();
    assert_eq!(mapped, in_table);
    // Every ported check is mapped, except Junction-only checks.
    let registry = CheckRegistry::builtin();
    for check in registry.all() {
        let id = check.id();
        let ported = ["apps.", "collaboration.", "azure."]
            .iter()
            .any(|p| id.starts_with(p));
        if ported && id != "apps.secret_lifetime" {
            assert!(
                mapping().contains_key(id),
                "{id} has no M365-Secure mapping"
            );
        }
        if let Some((d, _)) = mapping().get(id).and_then(|ids| rows.get(&ids[0])) {
            assert_eq!(d, if ported { "new" } else { "merged" }, "{id}");
        }
    }
}
