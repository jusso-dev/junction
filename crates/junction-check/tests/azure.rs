//! Golden tests for the `azure` pack. Expected statuses are what M365-Secure's
//! `src/modules/azure/{defender,keyvault,workloads}.rs` produce for the same
//! input; M365-Secure's Info for "nothing to check" is `not_applicable` here.
use junction_check::model::Status::{self, *};
use junction_check::testkit::{assert_snapshot, assert_status, run_case};

const PACK: &str = "azure";

async fn golden(id: &str, cases: &[(&str, Status)]) {
    for (case, status) in cases {
        let result = run_case(id, PACK, case).await;
        assert_status(&result, *status);
        assert_snapshot(&result, PACK, case);
        if case.ends_with("_forbidden") {
            let reason = result.reason.expect("reason");
            assert_eq!(reason.code, "missing_permission", "{case}");
        }
    }
}

#[tokio::test]
async fn defender_plans() {
    // AZ-DEFENDER-001: Pass, Warning (some Standard), Fail (none Standard), Unknown,
    // no subscriptions (M365-Secure emits AZ-ACCESS-001 Warning instead), paging.
    golden(
        "azure.defender_plans",
        &[
            ("defender_pass", Pass),
            ("defender_partial", Warn),
            ("defender_free", Fail),
            ("defender_forbidden", Unknown),
            ("defender_no_subscriptions", NotApplicable),
            ("defender_paged", Warn),
        ],
    )
    .await;
}

#[tokio::test]
async fn key_vaults() {
    // AZ-KV-001: Pass, Fail, Info (no vaults), Unknown.
    golden(
        "azure.key_vault_protection",
        &[
            ("vaults_pass", Pass),
            ("vaults_fail", Fail),
            ("vaults_none", NotApplicable),
            ("vaults_forbidden", Unknown),
        ],
    )
    .await;
}

#[tokio::test]
async fn public_exposure() {
    // AZ-PUBLIC-001: Pass, Fail, Info (nothing to check), Unknown.
    golden(
        "azure.public_network_exposure",
        &[
            ("exposure_pass", Pass),
            ("exposure_fail", Fail),
            ("exposure_none", NotApplicable),
            ("exposure_forbidden", Unknown),
        ],
    )
    .await;
}

#[tokio::test]
async fn paged_subscriptions_are_all_assessed() {
    let result = run_case("azure.defender_plans", PACK, "defender_paged").await;
    assert_eq!(
        result.evidence.data["subscriptions"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(result.affected.items, ["Development: StorageAccounts"]);
}
