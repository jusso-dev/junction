use junction_check::model::{CheckResult, Status};
use junction_check::testkit::{assert_snapshot, assert_status, run_case};

async fn outcomes(id: &str, cases: &[(&str, Status)]) {
    for (case, status) in cases {
        let result = run_case(id, "identity", case).await;
        assert_status(&result, *status);
        assert_snapshot(&result, "identity", case);
    }
}

fn missing_permissions(result: &CheckResult) -> Vec<String> {
    let reason = result.reason.as_ref().expect("reason");
    assert_eq!(reason.code, "missing_permission", "{}", reason.detail);
    reason.missing_permissions.clone()
}

#[tokio::test]
async fn global_admin_count_outcomes() {
    outcomes(
        "identity.global_admin_count",
        &[
            ("global_admins_pass", Status::Pass),
            ("global_admins_too_many", Status::Fail),
            ("global_admins_single", Status::Fail),
            ("global_admins_group", Status::Warn),
            ("global_admins_forbidden", Status::Unknown),
            ("global_admins_paged", Status::Fail),
        ],
    )
    .await;
}

#[tokio::test]
async fn forbidden_names_the_permission_to_grant() {
    let result = run_case(
        "identity.global_admin_count",
        "identity",
        "global_admins_forbidden",
    )
    .await;
    assert_eq!(
        missing_permissions(&result),
        ["RoleManagement.Read.Directory"]
    );
}

#[tokio::test]
async fn paging_counts_every_page() {
    let result = run_case(
        "identity.global_admin_count",
        "identity",
        "global_admins_paged",
    )
    .await;
    assert_eq!(result.evidence.data["global_admins"], 5);
    assert_eq!(result.affected.total, 5);
}

#[tokio::test]
async fn mfa_coverage_outcomes() {
    outcomes(
        "identity.mfa_coverage",
        &[
            ("mfa_coverage_pass", Status::Pass),
            ("mfa_coverage_fail", Status::Fail),
            ("mfa_coverage_threshold", Status::Pass),
            ("mfa_coverage_admin_below", Status::Fail),
            ("mfa_coverage_paged", Status::Fail),
            ("mfa_coverage_forbidden", Status::Unknown),
            ("mfa_coverage_unlicensed", Status::NotApplicable),
        ],
    )
    .await;
}

#[tokio::test]
async fn mfa_coverage_reads_every_page_and_lists_every_upn() {
    let result = run_case("identity.mfa_coverage", "identity", "mfa_coverage_paged").await;
    let data = &result.evidence.data;
    assert_eq!(data["users"], 5);
    assert_eq!(data["users_mfa_capable"], 4);
    assert_eq!(
        data["not_capable"],
        serde_json::json!(["user5@contoso.example"])
    );
    let missing = run_case("identity.mfa_coverage", "identity", "mfa_coverage_fail").await;
    assert_eq!(missing.evidence.data["not_in_report"], 1);
    let forbidden = run_case(
        "identity.mfa_coverage",
        "identity",
        "mfa_coverage_forbidden",
    )
    .await;
    assert_eq!(missing_permissions(&forbidden), ["AuditLog.Read.All"]);
}

#[tokio::test]
async fn mfa_admins_outcomes() {
    outcomes(
        "identity.mfa_admins",
        &[
            ("mfa_admins_pass", Status::Pass),
            ("mfa_admins_fail", Status::Fail),
            ("mfa_admins_no_p1", Status::Fail),
            ("mfa_admins_forbidden", Status::Unknown),
            ("mfa_admins_paged", Status::Fail),
        ],
    )
    .await;
}

#[tokio::test]
async fn mfa_admins_expands_groups_and_skips_service_principals() {
    let result = run_case("identity.mfa_admins", "identity", "mfa_admins_pass").await;
    // admin1, admin2 directly; admin3 through the Security Admins group.
    assert_eq!(result.evidence.data["admins"], 3);
    let fallback = run_case("identity.mfa_admins", "identity", "mfa_admins_no_p1").await;
    assert_eq!(fallback.evidence.data["source"], "authentication_methods");
    assert_eq!(fallback.affected.items, ["admin2@contoso.example"]);
}

#[tokio::test]
async fn phishing_resistant_admins_outcomes() {
    outcomes(
        "identity.phishing_resistant_admins",
        &[
            ("phishing_resistant_pass", Status::Pass),
            ("phishing_resistant_fail", Status::Fail),
            ("phishing_resistant_report_only", Status::Warn),
            ("phishing_resistant_forbidden", Status::Unknown),
            ("phishing_resistant_unlicensed", Status::NotApplicable),
        ],
    )
    .await;
}

#[tokio::test]
async fn legacy_auth_blocked_outcomes() {
    outcomes(
        "identity.legacy_auth_blocked",
        &[
            ("legacy_auth_security_defaults", Status::Pass),
            ("legacy_auth_pass", Status::Pass),
            ("legacy_auth_report_only", Status::Warn),
            ("legacy_auth_partial", Status::Warn),
            ("legacy_auth_fail", Status::Fail),
            ("legacy_auth_no_p1", Status::Fail),
            ("legacy_auth_forbidden", Status::Unknown),
        ],
    )
    .await;
}

#[tokio::test]
async fn baseline_outcomes() {
    outcomes(
        "identity.baseline",
        &[
            ("baseline_security_defaults", Status::Pass),
            ("baseline_no_p1", Status::Fail),
            ("baseline_pass", Status::Pass),
            ("baseline_p2_missing_risk", Status::Fail),
            ("baseline_report_only", Status::Warn),
            ("baseline_forbidden", Status::Unknown),
        ],
    )
    .await;
}

#[tokio::test]
async fn separate_admin_accounts_outcomes() {
    outcomes(
        "identity.separate_admin_accounts",
        &[
            ("separate_admins_pass", Status::Pass),
            ("separate_admins_warn", Status::Warn),
            ("separate_admins_forbidden", Status::Unknown),
        ],
    )
    .await;
}

#[tokio::test]
async fn break_glass_outcomes() {
    outcomes(
        "identity.break_glass",
        &[
            ("break_glass_pass", Status::Pass),
            ("break_glass_fail", Status::Fail),
            ("break_glass_configured", Status::Fail),
            ("break_glass_no_policies", Status::NotApplicable),
            ("break_glass_unlicensed", Status::NotApplicable),
            ("break_glass_forbidden", Status::Unknown),
        ],
    )
    .await;
}

#[tokio::test]
async fn break_glass_monitored_is_attested() {
    outcomes(
        "identity.break_glass_monitored",
        &[
            ("break_glass_monitored_yes", Status::Pass),
            ("break_glass_monitored_no", Status::Fail),
            ("break_glass_monitored_unanswered", Status::Unknown),
        ],
    )
    .await;
}

#[tokio::test]
async fn pim_used_outcomes() {
    outcomes(
        "identity.pim_used",
        &[
            ("pim_used_pass", Status::Pass),
            ("pim_used_permanent", Status::Fail),
            ("pim_used_allowed", Status::Pass),
            ("pim_used_no_eligible", Status::Fail),
            ("pim_used_forbidden", Status::Unknown),
            ("pim_used_unlicensed", Status::NotApplicable),
        ],
    )
    .await;
}
