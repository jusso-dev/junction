use junction_check::model::Status;
use junction_check::testkit::{assert_snapshot, assert_status, run_case};

const PACK: &str = "backup";

async fn outcomes(id: &str, cases: &[(&str, Status)]) {
    for (case, status) in cases {
        let result = run_case(id, PACK, case).await;
        assert_status(&result, *status);
        assert_snapshot(&result, PACK, case);
    }
}

#[tokio::test]
async fn m365_backup_outcomes() {
    outcomes(
        "backup.m365_backup",
        &[
            ("m365_pass", Status::Pass),
            ("m365_partial", Status::Warn),
            ("m365_no_policies", Status::Fail),
            ("m365_locked", Status::Fail),
            ("m365_disabled", Status::NotApplicable),
            ("m365_not_enabled_error", Status::NotApplicable),
            ("m365_forbidden", Status::Unknown),
        ],
    )
    .await;
}

#[tokio::test]
async fn azure_vaults_outcomes() {
    outcomes(
        "backup.azure_vaults",
        &[
            ("vaults_pass", Status::Pass),
            ("vaults_unlocked", Status::Warn),
            ("vaults_fail", Status::Fail),
            ("vaults_custom_tag", Status::Pass),
            ("vaults_none", Status::NotApplicable),
            ("vaults_forbidden", Status::Unknown),
        ],
    )
    .await;
}

#[tokio::test]
async fn third_party_app_outcomes() {
    outcomes(
        "backup.third_party_app",
        &[
            ("apps_app_id", Status::Pass),
            ("apps_paged", Status::Pass),
            ("apps_none", Status::Warn),
            ("apps_none_attested", Status::Pass),
            ("apps_forbidden", Status::Unknown),
        ],
    )
    .await;
}

#[tokio::test]
async fn attested_checks_use_the_answer() {
    for (id, case, status) in [
        ("backup.offline_copy", "offline_copy_yes", Status::Pass),
        ("backup.restore_tested", "restore_tested_no", Status::Fail),
        (
            "backup.admin_separation",
            "admin_separation_partial",
            Status::Warn,
        ),
        ("backup.offline_copy", "not_attested", Status::Unknown),
    ] {
        let result = run_case(id, PACK, case).await;
        assert_status(&result, status);
        assert_snapshot(&result, PACK, case);
    }
    let result = run_case("backup.restore_tested", PACK, "restore_tested_no").await;
    assert!(result.attested.is_some());
    let result = run_case("backup.restore_tested", PACK, "not_attested").await;
    assert_eq!(result.reason.expect("reason").code, "not_attested");
}

#[tokio::test]
async fn forbidden_names_the_role_or_permission_to_grant() {
    for (id, case, permissions) in [
        (
            "backup.m365_backup",
            "m365_forbidden",
            &["BackupRestore-Configuration.Read.All"][..],
        ),
        (
            "backup.azure_vaults",
            "vaults_forbidden",
            &["Reader", "Backup Reader"],
        ),
        (
            "backup.third_party_app",
            "apps_forbidden",
            &["Application.Read.All"],
        ),
    ] {
        let reason = run_case(id, PACK, case).await.reason.expect("reason");
        assert_eq!(reason.code, "missing_permission", "{id}");
        assert_eq!(reason.missing_permissions, permissions, "{id}");
    }
}

#[tokio::test]
async fn evidence_counts_pages_and_coverage() {
    let apps = run_case("backup.third_party_app", PACK, "apps_paged").await;
    assert_eq!(apps.evidence.data["service_principals"], 4);
    assert_eq!(apps.evidence.data["disabled_matches"], 1);
    assert_eq!(apps.affected.items, ["Veeam Backup for Microsoft 365"]);

    let vaults = run_case("backup.azure_vaults", PACK, "vaults_pass").await;
    assert_eq!(vaults.evidence.data["vaults"].as_array().unwrap().len(), 2);

    let fail = run_case("backup.azure_vaults", PACK, "vaults_fail").await;
    assert_eq!(fail.affected.items, ["rsv-contoso-2", "vm-db-01"]);
}
