//! Golden tests for the `apps` pack. Each case's expected status is what
//! M365-Secure's logic (`src/modules/identity/apps.rs`) produces for the same
//! synthetic input; the M365-Secure id is noted per case. Cases marked
//! "Junction only" have no automated M365-Secure equivalent.
use junction_check::model::Status::{self, *};
use junction_check::testkit::{assert_snapshot, assert_status, run_case};

const PACK: &str = "apps";

async fn golden(cases: &[(&str, &str, Status)]) {
    for (id, case, status) in cases {
        let result = run_case(id, PACK, case).await;
        assert_status(&result, *status);
        assert_snapshot(&result, PACK, case);
        if *status == Unknown && case.ends_with("_forbidden") {
            let reason = result.reason.expect("reason");
            assert_eq!(reason.code, "missing_permission", "{case}");
            assert!(!reason.missing_permissions.is_empty(), "{case}");
        }
    }
}

#[tokio::test]
async fn consent_and_registration() {
    golden(&[
        // ENTRA-CONSENT-001 (and ENTRA-CONSENT-003): Pass, Pass, Fail, Unknown.
        ("apps.user_consent_restricted", "consent_off", Pass),
        ("apps.user_consent_restricted", "consent_low", Pass),
        ("apps.user_consent_restricted", "consent_open", Fail),
        ("apps.user_consent_restricted", "consent_forbidden", Unknown),
        // ENTRA-APPS-001: Pass, Fail, Unknown.
        ("apps.users_cannot_register_apps", "register_blocked", Pass),
        ("apps.users_cannot_register_apps", "register_open", Fail),
        (
            "apps.users_cannot_register_apps",
            "register_forbidden",
            Unknown,
        ),
        // ENTRA-CONSENT-002: Pass, Warning, Fail, Unknown.
        ("apps.admin_consent_workflow", "workflow_pass", Pass),
        ("apps.admin_consent_workflow", "workflow_no_reviewers", Warn),
        ("apps.admin_consent_workflow", "workflow_off", Fail),
        ("apps.admin_consent_workflow", "workflow_forbidden", Unknown),
        // ENTRA-APPREG-006: Pass, Warning, Fail, Unknown.
        ("apps.app_management_policy", "app_policy_pass", Pass),
        (
            "apps.app_management_policy",
            "app_policy_no_restriction",
            Warn,
        ),
        ("apps.app_management_policy", "app_policy_off", Fail),
        (
            "apps.app_management_policy",
            "app_policy_forbidden",
            Unknown,
        ),
    ])
    .await;
}

#[tokio::test]
async fn app_registrations() {
    golden(&[
        // ENTRA-APPREG-002 (and ENTRA-ENTAPP-013): Pass, Warning, Fail, Unknown, Fail across pages.
        ("apps.credential_expiry", "expiry_pass", Pass),
        ("apps.credential_expiry", "expiry_soon", Warn),
        ("apps.credential_expiry", "expiry_expired", Fail),
        ("apps.credential_expiry", "expiry_forbidden", Unknown),
        ("apps.credential_expiry", "expiry_paged", Fail),
        // Junction only (long-lived secrets).
        ("apps.secret_lifetime", "lifetime_pass", Pass),
        ("apps.secret_lifetime", "lifetime_long", Warn),
        ("apps.secret_lifetime", "lifetime_forbidden", Unknown),
        // ENTRA-APPREG-005: Pass, Fail, Unknown (appRoles unresolved), Unknown.
        ("apps.privileged_app_secrets", "privileged_pass", Pass),
        ("apps.privileged_app_secrets", "privileged_secret", Fail),
        (
            "apps.privileged_app_secrets",
            "privileged_unresolved",
            Unknown,
        ),
        (
            "apps.privileged_app_secrets",
            "privileged_forbidden",
            Unknown,
        ),
        // ENTRA-ENTAPP-021 (registry-only in M365-Secure; Junction logic).
        ("apps.multi_tenant_apps", "multitenant_pass", Pass),
        ("apps.multi_tenant_apps", "multitenant_warn", Warn),
        ("apps.multi_tenant_apps", "multitenant_forbidden", Unknown),
        ("apps.multi_tenant_apps", "multitenant_paged", Warn),
    ])
    .await;
}

#[tokio::test]
async fn enterprise_applications() {
    golden(&[
        // ENTRA-ENTAPP-004: Pass (Microsoft-owned and per-user grants ignored), Warning, Unknown, Warning across pages.
        ("apps.high_privilege_permissions", "high_priv_pass", Pass),
        ("apps.high_privilege_permissions", "high_priv_warn", Warn),
        (
            "apps.high_privilege_permissions",
            "high_priv_forbidden",
            Unknown,
        ),
        ("apps.high_privilege_permissions", "high_priv_paged", Warn),
        // ENTRA-ENTAPP-005: Pass (Microsoft-owned secret ignored), Warning, Unknown, Warning across pages.
        ("apps.sp_password_credentials", "sp_secrets_pass", Pass),
        ("apps.sp_password_credentials", "sp_secrets_warn", Warn),
        (
            "apps.sp_password_credentials",
            "sp_secrets_forbidden",
            Unknown,
        ),
        ("apps.sp_password_credentials", "sp_secrets_paged", Warn),
        // ENTRA-ENTAPP-003: Pass (disabled and managed identities ignored), Warning, Unknown.
        ("apps.assignment_required", "assignment_pass", Pass),
        ("apps.assignment_required", "assignment_warn", Warn),
        ("apps.assignment_required", "assignment_forbidden", Unknown),
    ])
    .await;
}

#[tokio::test]
async fn evidence_names_apps_and_permissions() {
    let result = run_case("apps.high_privilege_permissions", PACK, "high_priv_warn").await;
    assert_eq!(result.affected.total, 2);
    assert!(
        result.affected.items[0].contains("Directory.ReadWrite.All"),
        "{:?}",
        result.affected.items
    );
    let result = run_case("apps.credential_expiry", PACK, "expiry_paged").await;
    assert_eq!(result.evidence.data["expired"], 1);
}
