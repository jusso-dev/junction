use junction_check::model::Status;
use junction_check::testkit::{assert_snapshot, assert_status, run_case};

const PACK: &str = "endpoint";
const ONBOARDING: &str = "endpoint.onboarding_coverage";
const STALE: &str = "endpoint.stale_sensors";
const OS: &str = "endpoint.unsupported_os";
const LINUX_MACOS: &str = "endpoint.linux_macos_health";
const SERVERS: &str = "endpoint.servers_covered";
const ALL: [&str; 5] = [ONBOARDING, STALE, OS, LINUX_MACOS, SERVERS];

async fn outcomes(id: &str, cases: &[(&str, Status)]) {
    for &(case, status) in cases {
        let result = run_case(id, PACK, case).await;
        assert_status(&result, status);
        assert_snapshot(&result, PACK, case);
    }
}

#[tokio::test]
async fn onboarding_coverage_outcomes() {
    outcomes(
        ONBOARDING,
        &[
            ("coverage_onboarding_pass", Status::Pass),
            ("coverage_onboarding_fail", Status::Fail),
            ("coverage_onboarding_mobile", Status::Warn),
            ("coverage_onboarding_paged", Status::Pass),
        ],
    )
    .await;
}

#[tokio::test]
async fn stale_sensors_outcomes() {
    outcomes(
        STALE,
        &[
            ("coverage_stale_pass", Status::Pass),
            ("coverage_stale_fail", Status::Fail),
            ("coverage_stale_warn", Status::Warn),
        ],
    )
    .await;
}

#[tokio::test]
async fn unsupported_os_outcomes() {
    outcomes(
        OS,
        &[
            ("coverage_os_pass", Status::Pass),
            ("coverage_os_fail", Status::Fail),
            ("coverage_os_warn", Status::Warn),
            ("coverage_os_linux_only", Status::NotApplicable),
        ],
    )
    .await;
}

#[tokio::test]
async fn linux_macos_health_outcomes() {
    outcomes(
        LINUX_MACOS,
        &[
            ("coverage_linux_macos_pass", Status::Pass),
            ("coverage_linux_macos_warn", Status::Warn),
            ("coverage_linux_macos_none", Status::NotApplicable),
        ],
    )
    .await;
}

#[tokio::test]
async fn servers_covered_outcomes() {
    outcomes(
        SERVERS,
        &[
            ("coverage_servers_pass", Status::Pass),
            ("coverage_servers_warn", Status::Warn),
            ("coverage_servers_arm_forbidden", Status::Unknown),
            ("coverage_servers_no_azure", Status::NotApplicable),
            ("coverage_servers_no_subscriptions", Status::Unknown),
        ],
    )
    .await;
}

#[tokio::test]
async fn every_check_names_machine_read_all_when_refused() {
    for id in ALL {
        let result = run_case(id, PACK, "coverage_forbidden").await;
        assert_status(&result, Status::Unknown);
        let reason = result.reason.expect("reason");
        assert_eq!(reason.code, "missing_permission", "{id}");
        assert_eq!(reason.missing_permissions, ["Machine.Read.All"], "{id}");
    }
    let result = run_case(ONBOARDING, PACK, "coverage_forbidden").await;
    assert_snapshot(&result, PACK, "coverage_forbidden");
}

#[tokio::test]
async fn every_check_is_not_applicable_without_defender_for_endpoint() {
    for id in ALL {
        let result = run_case(id, PACK, "coverage_unlicensed").await;
        assert_status(&result, Status::NotApplicable);
        assert_eq!(result.reason.expect("reason").code, "licence_required");
    }
    let result = run_case(ONBOARDING, PACK, "coverage_unlicensed").await;
    assert_snapshot(&result, PACK, "coverage_unlicensed");
}

#[tokio::test]
async fn refused_arm_access_names_reader() {
    let result = run_case(SERVERS, PACK, "coverage_servers_arm_forbidden").await;
    let reason = result.reason.expect("reason");
    assert_eq!(reason.code, "missing_permission");
    assert_eq!(reason.missing_permissions, ["Reader"]);
}

#[tokio::test]
async fn onboarding_evidence_groups_by_platform_and_matching() {
    let result = run_case(ONBOARDING, PACK, "coverage_onboarding_fail").await;
    let data = &result.evidence.data;
    assert_eq!(data["by_platform"]["Windows"]["missing"], 2);
    assert_eq!(data["by_platform"]["iOS"]["missing"], 1);
    assert_eq!(data["by_platform"]["macOS"]["onboarded"], 1);
    assert_eq!(data["discovered_not_onboarded"], 1);
    // The renamed device matches on its Entra device id, Linux on its name.
    assert_eq!(data["matched_by"]["device_id"], 4);
    assert_eq!(data["matched_by"]["name"], 1);
    assert_eq!(
        result.affected.items,
        ["IPHONE-001", "WS-004", "WS-005"].map(String::from)
    );
}

#[tokio::test]
async fn paging_reads_every_page() {
    let result = run_case(ONBOARDING, PACK, "coverage_onboarding_paged").await;
    assert_eq!(result.evidence.data["devices"], 5);
    assert_eq!(result.evidence.data["onboarded"], 5);
    let result = run_case(SERVERS, PACK, "coverage_servers_warn").await;
    assert_eq!(result.evidence.data["azure_vms"], 3);
    assert_eq!(
        result.affected.items,
        ["arc-002", "vm-db-01"].map(String::from)
    );
}
