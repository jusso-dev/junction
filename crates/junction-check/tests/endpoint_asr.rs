use junction_check::model::Status;
use junction_check::testkit::{assert_snapshot, assert_status, run_case};

const PACK: &str = "endpoint";
const RULE_STATE: &str = "endpoint.asr_rule_state";
const QUICK_WINS: &str = "endpoint.asr_quick_wins";
const AUDIT_NOISE: &str = "endpoint.asr_audit_noise";

/// Rule state and quick wins share fixtures; each snapshot is per check.
async fn check(id: &str, case: &str, status: Status) -> junction_check::model::CheckResult {
    let result = run_case(id, PACK, case).await;
    assert_status(&result, status);
    let snap = format!("{case}/{}", id.trim_start_matches("endpoint."));
    if std::env::var_os("UPDATE_SNAPSHOTS").is_some() {
        std::fs::create_dir_all(
            junction_check::testkit::fixtures_root()
                .join(PACK)
                .join(&snap),
        )
        .unwrap();
    }
    assert_snapshot(&result, PACK, &snap);
    result
}

#[tokio::test]
async fn rule_state_outcomes() {
    for (case, status) in [
        ("asr_intune_block", Status::Pass),
        ("asr_intune_paged", Status::Pass),
        ("asr_intune_audit", Status::Fail),
        ("asr_intune_states", Status::Warn),
        ("asr_intune_quick_win_gaps", Status::Warn),
        ("asr_gpo_devices", Status::Warn),
        ("asr_gpo_block", Status::Warn),
        ("asr_gpo_unobserved", Status::Warn),
        ("asr_not_configured", Status::Fail),
        ("asr_intune_only_empty", Status::Unknown),
        ("asr_forbidden", Status::Unknown),
        ("asr_hunting_forbidden", Status::Unknown),
        ("asr_unlicensed", Status::NotApplicable),
    ] {
        check(RULE_STATE, case, status).await;
    }
}

#[tokio::test]
async fn quick_wins_outcomes() {
    for (case, status) in [
        ("asr_intune_block", Status::Pass),
        ("asr_intune_paged", Status::Pass),
        ("asr_gpo_block", Status::Pass),
        ("asr_intune_audit", Status::Fail),
        ("asr_intune_quick_win_gaps", Status::Fail),
        ("asr_gpo_devices", Status::Fail),
        ("asr_not_configured", Status::Fail),
        ("asr_intune_states", Status::Warn),
        ("asr_gpo_unobserved", Status::Unknown),
        ("asr_intune_only_empty", Status::Unknown),
        ("asr_forbidden", Status::Unknown),
        ("asr_hunting_forbidden", Status::Unknown),
        ("asr_unlicensed", Status::NotApplicable),
    ] {
        check(QUICK_WINS, case, status).await;
    }
}

#[tokio::test]
async fn audit_noise_outcomes() {
    for (case, status) in [
        ("asr_noise_none", Status::Pass),
        ("asr_noise_rules", Status::Warn),
        ("asr_noise_forbidden", Status::Unknown),
        ("asr_noise_unlicensed", Status::NotApplicable),
    ] {
        check(AUDIT_NOISE, case, status).await;
    }
}

#[tokio::test]
async fn intune_states_count_assigned_policies_per_rule() {
    let result = run_case(RULE_STATE, PACK, "asr_intune_states").await;
    let data = &result.evidence.data;
    assert_eq!(data["source"], "intune");
    assert_eq!(data["unassigned_policies"], 1);
    assert_eq!(
        data["policies"],
        serde_json::json!(["ASR - Standard", "ASR - Pilot", "Legacy ASR template"])
    );
    let state = |guid: &str| {
        let rule = data["rules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["guid"] == guid)
            .unwrap();
        (
            rule["state"].as_str().unwrap().to_owned(),
            rule["policies"].clone(),
        )
    };
    // Office child processes: block in one policy, audit in the pilot.
    let (s, counts) = state("d4f940ab-401b-4efc-aadc-ad5f3c50688a");
    assert_eq!(
        (s.as_str(), counts),
        ("mixed", serde_json::json!({"audit": 1, "block": 1}))
    );
    for (guid, expected) in [
        ("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "block"),
        ("3b576869-a4ec-4529-8536-b80a7769e899", "audit"),
        ("7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", "warn"),
        ("5beb7efe-fd9a-4556-801d-275e5ffc04cc", "off"),
        ("b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "not_configured"),
    ] {
        assert_eq!(state(guid).0, expected, "{guid}");
    }
}

#[tokio::test]
async fn paging_reads_every_policy_page() {
    let result = run_case(RULE_STATE, PACK, "asr_intune_paged").await;
    assert_eq!(
        result.evidence.data["policies"],
        serde_json::json!(["ASR - All Windows devices"])
    );
    assert_eq!(result.affected.total, 0);
}

#[tokio::test]
async fn gpo_devices_name_the_rule_still_in_audit() {
    let result = run_case(QUICK_WINS, PACK, "asr_gpo_devices").await;
    assert_eq!(result.evidence.data["source"], "device_events");
    assert_eq!(
        result.affected.items,
        ["Block Win32 API calls from Office macros (mixed)"]
    );
}

#[tokio::test]
async fn forbidden_names_the_permission_to_grant() {
    let result = run_case(QUICK_WINS, PACK, "asr_forbidden").await;
    let reason = result.reason.expect("reason");
    assert_eq!(reason.code, "missing_permission");
    assert_eq!(
        reason.missing_permissions,
        ["DeviceManagementConfiguration.Read.All"]
    );
    let result = run_case(AUDIT_NOISE, PACK, "asr_noise_forbidden").await;
    let reason = result.reason.expect("reason");
    assert_eq!(reason.code, "missing_permission");
    assert_eq!(reason.missing_permissions, ["ThreatHunting.Read.All"]);
}

#[tokio::test]
async fn ignored_rules_are_not_expected_in_block() {
    // The fixtures run with no configuration; the warn in asr_intune_quick_win_gaps lists
    // exactly the rules that are not in block.
    let result = run_case(RULE_STATE, PACK, "asr_intune_quick_win_gaps").await;
    assert_eq!(
        result.affected.items,
        [
            "Block JavaScript or VBScript from launching downloaded executable content",
            "Block Win32 API calls from Office macros"
        ]
    );
}
