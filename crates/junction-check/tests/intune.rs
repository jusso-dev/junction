use junction_check::model::Status;
use junction_check::registry::CheckRegistry;
use junction_check::testkit::{
    assert_snapshot, assert_status, case_context, fixtures_root, run_case,
};
use std::time::Duration;

const PACK: &str = "intune";

async fn outcomes(id: &str, cases: &[(&str, Status)]) {
    for (case, status) in cases {
        let result = run_case(id, PACK, case).await;
        assert_status(&result, *status);
        assert_snapshot(&result, PACK, case);
    }
}

#[tokio::test]
async fn update_rings_outcomes() {
    outcomes(
        "intune.update_rings",
        &[
            ("update_rings_pass", Status::Pass),
            ("update_rings_fail", Status::Fail),
            ("update_rings_profiles_only", Status::Warn),
            ("update_rings_forbidden", Status::Unknown),
            ("update_rings_unlicensed", Status::NotApplicable),
            ("update_rings_paged", Status::Pass),
        ],
    )
    .await;
}

#[tokio::test]
async fn patch_age_outcomes() {
    outcomes(
        "intune.patch_age",
        &[
            ("patch_age_pass", Status::Pass),
            ("patch_age_fail", Status::Fail),
            ("patch_age_forbidden", Status::Unknown),
            ("patch_age_tvm_forbidden", Status::Unknown),
            ("patch_age_unlicensed", Status::NotApplicable),
            ("patch_age_paged", Status::Pass),
        ],
    )
    .await;
}

#[tokio::test]
async fn patch_age_reads_builds_and_tvm() {
    let result = run_case("intune.patch_age", PACK, "patch_age_fail").await;
    let data = &result.evidence.data;
    assert_eq!(data["behind"], 1);
    assert_eq!(data["behind_devices"][0]["device"], "WIN-03");
    assert_eq!(data["behind_devices"][0]["missing_update"], "KB5121003");
    // Chrome CVE from 2026-09-01 is past the two-week application timeframe;
    // the Windows CVE from 2026-10-14 and 7-Zip from 2026-10-01 are within theirs.
    assert_eq!(data["tvm"]["overdue"], 1);
    assert_eq!(data["tvm"]["overdue_by_device"]["WIN-01"], 1);
    // Stale devices are left out rather than reported as unpatched.
    let pass = run_case("intune.patch_age", PACK, "patch_age_pass").await;
    assert_eq!(pass.evidence.data["stale_left_out"], 1);
    assert_eq!(pass.evidence.data["tvm"]["status"], "not licensed");
}

#[tokio::test]
async fn browser_updates_outcomes() {
    outcomes(
        "intune.browser_updates",
        &[
            ("browser_updates_pass", Status::Pass),
            ("browser_updates_fail", Status::Fail),
            ("browser_updates_forbidden", Status::Unknown),
            ("browser_updates_unlicensed", Status::NotApplicable),
            ("browser_updates_paged", Status::Fail),
        ],
    )
    .await;
}

#[tokio::test]
async fn laps_outcomes() {
    outcomes(
        "intune.laps",
        &[
            ("laps_pass", Status::Pass),
            ("laps_fail", Status::Fail),
            ("laps_missing_backups", Status::Fail),
            ("laps_forbidden", Status::Unknown),
            ("laps_unlicensed", Status::NotApplicable),
            ("laps_paged", Status::Pass),
        ],
    )
    .await;
}

#[tokio::test]
async fn bitlocker_escrow_outcomes() {
    outcomes(
        "intune.bitlocker_escrow",
        &[
            ("bitlocker_pass", Status::Pass),
            ("bitlocker_fail", Status::Fail),
            ("bitlocker_forbidden", Status::Unknown),
            ("bitlocker_unlicensed", Status::NotApplicable),
            ("bitlocker_paged", Status::Pass),
        ],
    )
    .await;
}

#[tokio::test]
async fn local_admin_outcomes() {
    // Device registration is an Entra ID setting, so a tenant without Intune is
    // still assessed (without the Intune group membership policies).
    outcomes(
        "intune.local_admin",
        &[
            ("local_admin_pass", Status::Pass),
            ("local_admin_fail", Status::Fail),
            ("local_admin_selected", Status::Warn),
            ("local_admin_forbidden", Status::Unknown),
            ("local_admin_no_intune", Status::Fail),
            ("local_admin_paged", Status::Pass),
        ],
    )
    .await;
}

#[tokio::test]
async fn office_macros_outcomes() {
    outcomes(
        "intune.office_macros",
        &[
            ("office_macros_pass", Status::Pass),
            ("office_macros_fail", Status::Fail),
            ("office_macros_none", Status::Fail),
            ("office_macros_notify", Status::Warn),
            ("office_macros_forbidden", Status::Unknown),
            ("office_macros_unlicensed", Status::NotApplicable),
            ("office_macros_paged", Status::Pass),
        ],
    )
    .await;
}

#[tokio::test]
async fn compliance_policy_outcomes() {
    outcomes(
        "intune.compliance_policy",
        &[
            ("compliance_policy_pass", Status::Pass),
            ("compliance_policy_fail", Status::Fail),
            ("compliance_policy_report_only", Status::Warn),
            ("compliance_policy_forbidden", Status::Unknown),
            ("compliance_policy_unlicensed", Status::NotApplicable),
            ("compliance_policy_paged", Status::Pass),
        ],
    )
    .await;
}

#[tokio::test]
async fn missing_intune_points_at_attestation() {
    let result = run_case("intune.laps", PACK, "laps_unlicensed").await;
    let reason = result.reason.expect("reason");
    assert_eq!(reason.code, "licence_required");
    assert!(reason.detail.contains("junction check attest intune.laps"));
}

#[tokio::test]
async fn forbidden_names_the_permission_to_grant() {
    for (id, case, permission) in [
        (
            "intune.laps",
            "laps_forbidden",
            "DeviceLocalCredential.ReadBasic.All",
        ),
        (
            "intune.bitlocker_escrow",
            "bitlocker_forbidden",
            "BitlockerKey.ReadBasic.All",
        ),
        (
            "intune.patch_age",
            "patch_age_tvm_forbidden",
            "Vulnerability.Read.All",
        ),
    ] {
        let reason = run_case(id, PACK, case).await.reason.expect("reason");
        assert_eq!(reason.code, "missing_permission", "{case}");
        assert_eq!(reason.missing_permissions, [permission], "{case}");
    }
}

/// Values planted in fixtures that must never reach a result.
const SECRETS: &[&str] = &[
    "Rml4dHVyZUxhcHNTZWNyZXQ=",
    "111111-222222-333333-444444-555555-666666-777777-888888",
];

/// No intune check ever asks for a LAPS password or BitLocker key, in any
/// fixture case, and planted secret values never appear in a result.
#[tokio::test]
async fn laps_passwords_and_bitlocker_keys_are_never_requested() {
    let registry = CheckRegistry::builtin();
    let checks: Vec<_> = registry
        .all()
        .iter()
        .filter(|c| c.id().starts_with("intune."))
        .cloned()
        .collect();
    assert_eq!(checks.len(), 8);
    let mut cases: Vec<_> = std::fs::read_dir(fixtures_root().join(PACK))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    cases.sort();
    let mut planted = 0;
    for dir in &cases {
        let text: String = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
            .collect();
        planted += SECRETS.iter().filter(|s| text.contains(*s)).count();
        for check in &checks {
            let (ctx, gateway) = case_context(dir).unwrap();
            let result = junction_check::runner::evaluate(
                registry,
                check.as_ref(),
                &ctx,
                Duration::from_secs(30),
            )
            .await;
            for call in gateway.calls() {
                assert!(
                    !call.operation.contains("device_local_credentials.get")
                        && !call.operation.contains("recovery_keys.get"),
                    "{}: {} called {}",
                    dir.display(),
                    check.id(),
                    call.operation
                );
                if let Some(select) = call.input.pointer("/parameters/$select") {
                    let select = select.to_string().to_ascii_lowercase();
                    assert!(
                        !select.contains("credentials") && !select.contains("\"key\""),
                        "{}: {} selected {select}",
                        dir.display(),
                        check.id()
                    );
                }
            }
            let json = serde_json::to_string(&result).unwrap();
            for secret in SECRETS {
                assert!(
                    !json.contains(secret),
                    "{}: {} leaked a secret",
                    dir.display(),
                    check.id()
                );
            }
        }
    }
    assert!(
        planted >= 2,
        "fixtures must plant a LAPS password and a BitLocker key"
    );
}
