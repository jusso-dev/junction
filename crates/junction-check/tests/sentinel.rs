use junction_check::model::{CheckResult, Status};
use junction_check::testkit::{assert_snapshot, assert_status, run_case};

const PACK: &str = "sentinel";
const ALL: [&str; 8] = [
    "sentinel.workspace",
    "sentinel.connectors",
    "sentinel.rules_enabled",
    "sentinel.incidents_stale",
    "sentinel.ingestion_cost",
    "sentinel.retention",
    "sentinel.health_auditing",
    "sentinel.automation",
];

async fn outcomes(id: &str, cases: &[(&str, Status)]) {
    for (case, status) in cases {
        let result = run_case(id, PACK, case).await;
        assert_status(&result, *status);
        assert_snapshot(&result, PACK, case);
    }
}

fn missing_permissions(result: &CheckResult) -> Vec<String> {
    let reason = result.reason.as_ref().expect("reason");
    assert_eq!(reason.code, "missing_permission", "{}", result.id);
    reason.missing_permissions.clone()
}

#[tokio::test]
async fn resource_graph_refused_names_reader_for_every_check() {
    for id in ALL {
        let result = run_case(id, PACK, "rg_forbidden").await;
        assert_status(&result, Status::Unknown);
        assert_eq!(missing_permissions(&result), ["Reader"]);
    }
}

#[tokio::test]
async fn onboarding_refused_names_sentinel_reader() {
    for id in ALL {
        let result = run_case(id, PACK, "onboarding_forbidden").await;
        assert_status(&result, Status::Unknown);
        assert_eq!(missing_permissions(&result), ["Microsoft Sentinel Reader"]);
    }
}

#[tokio::test]
async fn without_sentinel_only_the_workspace_check_applies() {
    for case in ["no_sentinel", "no_workspaces"] {
        for id in ALL {
            let result = run_case(id, PACK, case).await;
            if id == "sentinel.workspace" {
                assert_status(&result, Status::Fail);
            } else {
                assert_status(&result, Status::NotApplicable);
                assert_eq!(result.reason.unwrap().code, "no_sentinel_workspace");
            }
        }
    }
}

#[tokio::test]
async fn workspace_outcomes() {
    outcomes(
        "sentinel.workspace",
        &[
            ("workspace_pass", Status::Pass),
            ("workspace_paged", Status::Pass),
            ("workspace_configured", Status::Pass),
            ("workspace_invalid_config", Status::Unknown),
            ("no_sentinel", Status::Fail),
            ("no_workspaces", Status::Fail),
            ("no_subscriptions", Status::Unknown),
        ],
    )
    .await;
}

#[tokio::test]
async fn resource_graph_pages_are_followed() {
    let result = run_case("sentinel.workspace", PACK, "workspace_paged").await;
    let names: Vec<&str> = result.evidence.data["workspaces"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["workspace"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["law-apps-01", "law-sentinel-01"]);
    assert_eq!(result.evidence.data["sentinel_workspaces"], 1);
}

#[tokio::test]
async fn connectors_outcomes() {
    outcomes(
        "sentinel.connectors",
        &[
            ("connectors_pass", Status::Pass),
            ("connectors_missing", Status::Fail),
            ("connectors_forbidden", Status::Unknown),
            ("connectors_query_forbidden", Status::Unknown),
        ],
    )
    .await;
    let result = run_case("sentinel.connectors", PACK, "connectors_missing").await;
    assert_eq!(
        result.affected.items,
        [
            "Azure Activity",
            "Entra ID audit logs",
            "Microsoft Defender XDR"
        ]
    );
    assert!(result.evidence.summary.contains("free to ingest"));
    let result = run_case("sentinel.connectors", PACK, "connectors_query_forbidden").await;
    assert_eq!(missing_permissions(&result), ["Log Analytics Reader"]);
    let result = run_case("sentinel.connectors", PACK, "connectors_forbidden").await;
    assert_eq!(missing_permissions(&result), ["Microsoft Sentinel Reader"]);
}

#[tokio::test]
async fn rules_outcomes() {
    outcomes(
        "sentinel.rules_enabled",
        &[
            ("rules_pass", Status::Pass),
            ("rules_low", Status::Warn),
            ("rules_none", Status::Fail),
            ("rules_failing", Status::Warn),
            ("rules_forbidden", Status::Unknown),
        ],
    )
    .await;
}

#[tokio::test]
async fn rules_are_counted_across_pages() {
    let result = run_case("sentinel.rules_enabled", PACK, "rules_pass").await;
    let data = &result.evidence.data;
    assert_eq!(data["enabled_scheduled"], 6);
    assert_eq!(data["enabled_nrt"], 3);
    assert_eq!(data["fusion_enabled"], true);
    assert_eq!(data["enabled_total"], 10);
    assert_eq!(data["disabled"], 1);
}

#[tokio::test]
async fn incidents_outcomes() {
    outcomes(
        "sentinel.incidents_stale",
        &[
            ("incidents_pass", Status::Pass),
            ("incidents_stale_high", Status::Fail),
            ("incidents_stale_low", Status::Warn),
            ("incidents_forbidden", Status::Unknown),
        ],
    )
    .await;
    let result = run_case("sentinel.incidents_stale", PACK, "incidents_stale_high").await;
    assert_eq!(result.evidence.data["open"], 4);
    assert_eq!(result.evidence.data["stale"], 3);
}

#[tokio::test]
async fn ingestion_cost_outcomes() {
    outcomes(
        "sentinel.ingestion_cost",
        &[
            ("cost_suggest", Status::Warn),
            ("cost_pass", Status::Pass),
            ("cost_price_override", Status::Warn),
            ("cost_forbidden", Status::Unknown),
        ],
    )
    .await;
}

#[tokio::test]
async fn ingestion_cost_states_its_price_assumption() {
    let result = run_case("sentinel.ingestion_cost", PACK, "cost_pass").await;
    let price = &result.evidence.data["price"];
    assert_eq!(price["price_data_as_of"], "2026-10-25");
    assert!(result.evidence.summary.contains("as of 2026-10-25"));
    let result = run_case("sentinel.ingestion_cost", PACK, "cost_price_override").await;
    assert_eq!(result.evidence.data["price"]["price_per_gb"], 5.0);
    assert_eq!(result.evidence.data["currency"], "USD");
    assert_eq!(result.evidence.data["estimated_monthly"], 62.5);
    let result = run_case("sentinel.ingestion_cost", PACK, "cost_suggest").await;
    assert_eq!(result.affected.total, 1);
    assert!(result.affected.items[0].starts_with("law-sentinel-01/CommonSecurityLog"));
}

#[tokio::test]
async fn retention_outcomes() {
    outcomes(
        "sentinel.retention",
        &[
            ("retention_pass", Status::Pass),
            ("retention_short", Status::Fail),
            ("retention_forbidden", Status::Unknown),
        ],
    )
    .await;
    let result = run_case("sentinel.retention", PACK, "retention_short").await;
    assert_eq!(result.affected.total, 3);
}

#[tokio::test]
async fn health_auditing_outcomes() {
    outcomes(
        "sentinel.health_auditing",
        &[
            ("health_pass", Status::Pass),
            ("health_missing", Status::Fail),
            ("health_audit_quiet", Status::Warn),
            ("health_forbidden", Status::Unknown),
        ],
    )
    .await;
}

#[tokio::test]
async fn automation_outcomes() {
    outcomes(
        "sentinel.automation",
        &[
            ("automation_pass", Status::Pass),
            ("automation_warn", Status::Warn),
            ("automation_forbidden", Status::Unknown),
        ],
    )
    .await;
}

#[tokio::test]
async fn configured_workspaces_scope_the_resource_graph_query() {
    use junction_check::testkit::{case_context, fixtures_root};
    let dir = fixtures_root().join(PACK).join("workspace_configured");
    let (ctx, gateway) = case_context(&dir).unwrap();
    junction_check::packs::sentinel::workspaces::discover(&ctx)
        .await
        .unwrap();
    let call = gateway
        .calls()
        .into_iter()
        .find(|c| c.operation == "azure.resource_graph.resources.post")
        .unwrap();
    let body = &call.input["body"];
    assert_eq!(
        body["subscriptions"],
        serde_json::json!(["00000000-0000-4000-8000-0000000000a1"])
    );
    assert!(
        body["query"]
            .as_str()
            .unwrap()
            .contains("| where tolower(id) in ('/subscriptions/00000000-0000-4000-8000-0000000000a1/resourcegroups/rg-security/providers/microsoft.operationalinsights/workspaces/law-sentinel-01')")
    );
}
