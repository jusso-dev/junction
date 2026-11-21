use junction_check::config::CheckConfig;
use junction_check::context::{CheckContext, ContextParts};
use junction_check::gateway::Governed;
use junction_check::model::Status;
use junction_check::packs::endpoint::protection::scid_table;
use junction_check::registry::CheckRegistry;
use junction_check::testkit::{
    FixtureGateway, TENANT, assert_snapshot, assert_status, fixtures_root, run_case,
};
use junction_watch::backoff::Backoff;
use junction_watch::clock::Instant;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

const PACK: &str = "endpoint";

async fn expect(id: &str, cases: &[(&str, Status)]) {
    for (case, status) in cases {
        let result = run_case(id, PACK, case).await;
        assert_status(&result, *status);
        // One snapshot per check in a shared case: `<case>/<check>/expected.snap`.
        let snap = format!("{case}/{}", id.trim_start_matches("endpoint."));
        std::fs::create_dir_all(fixtures_root().join(PACK).join(&snap)).expect("snapshot dir");
        assert_snapshot(&result, PACK, &snap);
    }
}

#[tokio::test]
async fn tamper_protection_outcomes() {
    expect(
        "endpoint.tamper_protection",
        &[
            ("protection_tvm_pass", Status::Pass),
            ("protection_tvm_fail", Status::Fail),
            ("protection_tvm_paged", Status::Fail),
            ("protection_tvm_empty", Status::Unknown),
            ("protection_tvm_forbidden", Status::Unknown),
            ("protection_unlicensed", Status::NotApplicable),
        ],
    )
    .await;
}

#[tokio::test]
async fn cloud_protection_outcomes() {
    expect(
        "endpoint.cloud_protection",
        &[
            ("protection_tvm_pass", Status::Pass),
            ("protection_tvm_fail", Status::Fail),
            ("protection_tvm_paged", Status::Pass),
            ("protection_tvm_forbidden", Status::Unknown),
            ("protection_unlicensed", Status::NotApplicable),
        ],
    )
    .await;
}

#[tokio::test]
async fn realtime_protection_outcomes() {
    expect(
        "endpoint.realtime_protection",
        &[
            ("protection_tvm_pass", Status::Pass),
            ("protection_tvm_fail", Status::Fail),
            ("protection_tvm_paged", Status::Pass),
            ("protection_tvm_forbidden", Status::Unknown),
            ("protection_unlicensed", Status::NotApplicable),
        ],
    )
    .await;
}

#[tokio::test]
async fn network_protection_outcomes() {
    expect(
        "endpoint.network_protection",
        &[
            ("protection_tvm_pass", Status::Pass),
            ("protection_network_audit", Status::Warn),
            // Compliant assessment but no events: audit and block look alike.
            ("protection_network_quiet", Status::Warn),
            ("protection_tvm_fail", Status::Fail),
            ("protection_tvm_forbidden", Status::Unknown),
            ("protection_unlicensed", Status::NotApplicable),
        ],
    )
    .await;
}

#[tokio::test]
async fn edr_block_mode_outcomes() {
    expect(
        "endpoint.edr_block_mode",
        &[
            ("protection_av_pass", Status::Pass),
            ("protection_av_edr_block", Status::Pass),
            ("protection_av_fail", Status::Fail),
            ("protection_av_empty", Status::Unknown),
            ("protection_hunt_forbidden", Status::Unknown),
            ("protection_unlicensed", Status::NotApplicable),
        ],
    )
    .await;
}

#[tokio::test]
async fn av_mode_outcomes() {
    expect(
        "endpoint.av_mode",
        &[
            ("protection_av_pass", Status::Pass),
            ("protection_av_edr_block", Status::Warn),
            ("protection_av_fail", Status::Warn),
            ("protection_av_third_party", Status::Pass),
            ("protection_av_no_third_party", Status::Fail),
            ("protection_av_empty", Status::Unknown),
            ("protection_hunt_forbidden", Status::Unknown),
            ("protection_unlicensed", Status::NotApplicable),
        ],
    )
    .await;
}

#[tokio::test]
async fn av_definition_age_outcomes() {
    expect(
        "endpoint.av_definition_age",
        &[
            ("protection_av_pass", Status::Pass),
            ("protection_av_fail", Status::Fail),
            ("protection_av_third_party", Status::Pass),
            ("protection_av_empty", Status::Unknown),
            ("protection_hunt_forbidden", Status::Unknown),
            ("protection_unlicensed", Status::NotApplicable),
        ],
    )
    .await;
}

#[tokio::test]
async fn air_level_is_attested() {
    expect(
        "endpoint.air_level",
        &[
            ("protection_air_attested", Status::Pass),
            ("protection_av_pass", Status::Unknown),
            ("protection_unlicensed", Status::NotApplicable),
        ],
    )
    .await;
    let unanswered = run_case("endpoint.air_level", PACK, "protection_av_pass").await;
    assert_eq!(unanswered.reason.expect("reason").code, "not_attested");
}

#[tokio::test]
async fn refusals_name_the_permission_to_grant() {
    let tvm = run_case(
        "endpoint.tamper_protection",
        PACK,
        "protection_tvm_forbidden",
    )
    .await;
    let reason = tvm.reason.expect("reason");
    assert_eq!(reason.code, "missing_permission");
    assert_eq!(reason.missing_permissions, ["Vulnerability.Read.All"]);

    let hunt = run_case("endpoint.av_mode", PACK, "protection_hunt_forbidden").await;
    let reason = hunt.reason.expect("reason");
    assert_eq!(reason.code, "missing_permission");
    assert_eq!(reason.missing_permissions, ["ThreatHunting.Read.All"]);
}

#[tokio::test]
async fn paging_reads_every_page() {
    let result = run_case("endpoint.tamper_protection", PACK, "protection_tvm_paged").await;
    assert_eq!(result.evidence.data["devices_assessed"], 4);
    assert_eq!(result.evidence.data["percent_compliant"], 75);
    assert_eq!(result.affected.items, ["pc-03.contoso.example"]);
}

/// A throttled hunting call (429 with Retry-After) is retried by the governed
/// gateway the runner uses, and the check still decides.
#[tokio::test]
async fn throttled_hunting_is_retried() {
    let dir = fixtures_root().join(PACK).join("protection_hunt_throttled");
    let fixtures = Arc::new(FixtureGateway::load(TENANT, &dir).expect("fixtures"));
    let ctx = CheckContext::new(ContextParts {
        tenant_id: TENANT.into(),
        label: None,
        gateway: Arc::new(Governed::new(fixtures.clone(), 2, Backoff::IMMEDIATE)),
        licences: None,
        config: Arc::new(CheckConfig::default()),
        attestations: BTreeMap::new(),
        dns: Arc::new(junction_check::dns::NoDns),
        now: Instant::parse("2026-10-25T00:00:00Z").expect("time"),
    });
    let registry = CheckRegistry::builtin();
    let check = registry.get("endpoint.av_mode").expect("registered");
    let result =
        junction_check::runner::evaluate(registry, check.as_ref(), &ctx, Duration::from_secs(30))
            .await;
    assert_status(&result, Status::Pass);
    assert_snapshot(&result, PACK, "protection_hunt_throttled");
    assert_eq!(fixtures.calls().len(), 2, "one 429, then the answer");
}

#[test]
fn scid_table_is_complete() {
    let table = scid_table();
    for setting in [
        "tamper_protection",
        "realtime_protection",
        "cloud_protection",
        "network_protection",
    ] {
        let s = &table.settings[setting];
        assert!(
            !s.ids.is_empty() && s.source.starts_with("https://"),
            "{setting}"
        );
        assert!(s.ids.iter().all(|e| e.id.starts_with("scid-")), "{setting}");
    }
    assert_eq!(table.settings["tamper_protection"].ids[0].id, "scid-2003");
}

#[test]
fn checks_are_registered_with_tags() {
    let registry = CheckRegistry::builtin();
    for check in junction_check::packs::endpoint::protection::checks() {
        assert!(registry.get(check.id()).is_some(), "{}", check.id());
        assert!(!registry.tags(check.id()).is_empty(), "{}", check.id());
    }
}
