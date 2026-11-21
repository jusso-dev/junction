use junction_check::model::Status;
use junction_check::testkit::{assert_snapshot, assert_status, run_case};

const PACK: &str = "email";
const DNS_CHECKS: [&str; 3] = ["email.spf", "email.dkim", "email.dmarc"];
const MANUAL: [&str; 4] = [
    "email.preset_policies",
    "email.external_sender_tag",
    "email.auto_forward_blocked",
    "email.mailbox_audit",
];

async fn outcomes(id: &str, cases: &[(&str, Status)]) {
    for (case, status) in cases {
        let result = run_case(id, PACK, case).await;
        assert_status(&result, *status);
        assert_snapshot(&result, PACK, case);
    }
}

#[tokio::test]
async fn spf_outcomes() {
    outcomes(
        "email.spf",
        &[
            ("spf_pass", Status::Pass),
            ("spf_fail", Status::Fail),
            ("spf_too_many_lookups", Status::Fail),
            ("spf_parked_warn", Status::Warn),
            ("spf_dns_failure", Status::Unknown),
            ("spf_paged", Status::Fail),
            ("spf_no_custom_domains", Status::NotApplicable),
        ],
    )
    .await;
}

#[tokio::test]
async fn dkim_outcomes() {
    outcomes(
        "email.dkim",
        &[
            ("dkim_pass", Status::Pass),
            ("dkim_fail", Status::Fail),
            ("dkim_dns_failure", Status::Unknown),
            ("dkim_no_exchange_domains", Status::NotApplicable),
        ],
    )
    .await;
}

#[tokio::test]
async fn dmarc_outcomes() {
    outcomes(
        "email.dmarc",
        &[
            ("dmarc_pass", Status::Pass),
            ("dmarc_none", Status::Warn),
            ("dmarc_fail", Status::Fail),
            ("dmarc_dns_failure", Status::Unknown),
        ],
    )
    .await;
}

#[tokio::test]
async fn spf_counts_nested_lookups_and_follows_redirects() {
    let result = run_case("email.spf", PACK, "spf_too_many_lookups").await;
    let detail = result.evidence.data["domains"][0]["detail"]
        .as_str()
        .unwrap();
    assert!(detail.contains("needs at least 13 DNS lookups"), "{detail}");

    let result = run_case("email.spf", PACK, "spf_pass").await;
    let domains = result.evidence.data["domains"].as_array().unwrap();
    let names: Vec<&str> = domains
        .iter()
        .map(|d| d["domain"].as_str().unwrap())
        .collect();
    // The initial, unverified and onmicrosoft domains are not assessed.
    assert_eq!(
        names,
        ["contoso.example", "fabrikam.example", "parked.example.org"]
    );
    assert_eq!(domains[1]["detail"], "ends ~all, 3 of 10 DNS lookups");
    assert_eq!(domains[2]["role"], "parked");
}

#[tokio::test]
async fn dns_failures_are_unknown_and_name_the_domain() {
    for (id, case) in [
        ("email.spf", "spf_dns_failure"),
        ("email.dkim", "dkim_dns_failure"),
        ("email.dmarc", "dmarc_dns_failure"),
    ] {
        let result = run_case(id, PACK, case).await;
        let reason = result.reason.expect("reason");
        assert_eq!(reason.code, "dns_lookup_failed", "{id}");
        assert!(reason.detail.contains("fabrikam.example"), "{id}");
        assert_eq!(result.affected.total, 1, "{id}");
    }
}

#[tokio::test]
async fn paging_reads_every_domain() {
    let result = run_case("email.spf", PACK, "spf_paged").await;
    assert_eq!(result.evidence.data["assessed"], 2);
    assert!(result.evidence.summary.contains("fabrikam.example"));
}

#[tokio::test]
async fn forbidden_names_the_permission_to_grant() {
    for id in DNS_CHECKS {
        let result = run_case(id, PACK, "forbidden").await;
        assert_status(&result, Status::Unknown);
        let reason = result.reason.expect("reason");
        assert_eq!(reason.code, "missing_permission");
        assert_eq!(reason.missing_permissions, ["Domain.Read.All"]);
    }
}

#[tokio::test]
async fn without_exchange_online_every_check_is_not_applicable() {
    for id in DNS_CHECKS.iter().chain(&MANUAL) {
        let result = run_case(id, PACK, "no_licence").await;
        assert_status(&result, Status::NotApplicable);
        assert_eq!(result.reason.expect("reason").code, "licence_required");
    }
}

#[tokio::test]
async fn manual_checks_use_attestations() {
    for (id, status) in
        MANUAL
            .into_iter()
            .zip([Status::Pass, Status::Pass, Status::Fail, Status::Warn])
    {
        let result = run_case(id, PACK, "manual_attested").await;
        assert_status(&result, status);
        assert!(result.attested.is_some(), "{id}");

        let result = run_case(id, PACK, "manual_unanswered").await;
        assert_status(&result, Status::Unknown);
        let reason = result.reason.expect("reason");
        assert_eq!(reason.code, "not_attested");
        assert!(reason.detail.contains(id), "{id}");
    }
}
