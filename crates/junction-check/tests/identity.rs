use junction_check::model::Status;
use junction_check::testkit::{assert_snapshot, assert_status, run_case};

const ID: &str = "identity.global_admin_count";

#[tokio::test]
async fn global_admin_count_outcomes() {
    for (case, status) in [
        ("global_admins_pass", Status::Pass),
        ("global_admins_too_many", Status::Fail),
        ("global_admins_single", Status::Fail),
        ("global_admins_group", Status::Warn),
        ("global_admins_forbidden", Status::Unknown),
        ("global_admins_paged", Status::Fail),
    ] {
        let result = run_case(ID, "identity", case).await;
        assert_status(&result, status);
        assert_snapshot(&result, "identity", case);
    }
}

#[tokio::test]
async fn forbidden_names_the_permission_to_grant() {
    let result = run_case(ID, "identity", "global_admins_forbidden").await;
    let reason = result.reason.expect("reason");
    assert_eq!(reason.code, "missing_permission");
    assert_eq!(
        reason.missing_permissions,
        ["RoleManagement.Read.Directory"]
    );
}

#[tokio::test]
async fn paging_counts_every_page() {
    let result = run_case(ID, "identity", "global_admins_paged").await;
    assert_eq!(result.evidence.data["global_admins"], 5);
    assert_eq!(result.affected.total, 5);
}
