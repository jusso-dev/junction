//! Golden tests for the `collaboration` pack. Expected statuses are what
//! M365-Secure produces for the same input: SharePoint checks follow
//! `src/modules/collaboration/sharepoint.rs` with only Graph `sharepointSettings`
//! answering (its CSOM call is not in Junction's catalogue), guest checks follow
//! `src/modules/identity/settings.rs`.
use junction_check::model::Status::{self, *};
use junction_check::testkit::{assert_snapshot, assert_status, run_case};

const PACK: &str = "collaboration";

async fn golden(id: &str, cases: &[(&str, Status)]) {
    for (case, status) in cases {
        let result = run_case(id, PACK, case).await;
        assert_status(&result, *status);
        assert_snapshot(&result, PACK, case);
        let code = result.reason.as_ref().map(|r| r.code.as_str());
        if case.ends_with("_forbidden") {
            assert_eq!(code, Some("missing_permission"), "{case}");
        }
        if case.ends_with("_unlicensed") {
            assert_eq!(code, Some("licence_required"), "{case}");
        }
    }
}

#[tokio::test]
async fn sharepoint_sharing() {
    // SPO-SHARING-001: Pass, Pass, Fail (Graph has no Anyone-link expiry), Unknown, Not Licensed.
    golden(
        "collaboration.sharepoint_external_sharing",
        &[
            ("sharing_pass", Pass),
            ("sharing_internal", Pass),
            ("sharing_anyone", Fail),
            ("sharing_forbidden", Unknown),
            ("sharing_unlicensed", NotApplicable),
        ],
    )
    .await;
    // SPO-SHARING-002: Pass, Pass (sharing off), Fail.
    golden(
        "collaboration.external_resharing_blocked",
        &[
            ("reshare_pass", Pass),
            ("reshare_off", Pass),
            ("reshare_fail", Fail),
            ("reshare_forbidden", Unknown),
            ("reshare_unlicensed", NotApplicable),
        ],
    )
    .await;
    // SPO-SHARING-003: Pass (allow list), Warning (block list), Fail (none).
    golden(
        "collaboration.sharing_domain_restriction",
        &[
            ("domains_pass", Pass),
            ("domains_blocklist", Warn),
            ("domains_none", Fail),
            ("domains_forbidden", Unknown),
            ("domains_unlicensed", NotApplicable),
        ],
    )
    .await;
}

#[tokio::test]
async fn sharepoint_access() {
    // SPO-AUTH-001: Pass, Fail.
    golden(
        "collaboration.sharepoint_legacy_auth_blocked",
        &[
            ("legacy_pass", Pass),
            ("legacy_fail", Fail),
            ("legacy_forbidden", Unknown),
            ("legacy_unlicensed", NotApplicable),
        ],
    )
    .await;
    // SPO-SYNC-001: Pass, Fail.
    golden(
        "collaboration.unmanaged_sync_restricted",
        &[
            ("sync_pass", Pass),
            ("sync_fail", Fail),
            ("sync_forbidden", Unknown),
            ("sync_unlicensed", NotApplicable),
        ],
    )
    .await;
    // SPO-SESSION-001: Pass (3 hours), Warning (8 hours), Fail (off).
    golden(
        "collaboration.idle_session_signout",
        &[
            ("idle_pass", Pass),
            ("idle_long", Warn),
            ("idle_off", Fail),
            ("idle_forbidden", Unknown),
            ("idle_unlicensed", NotApplicable),
        ],
    )
    .await;
}

#[tokio::test]
async fn guests_and_groups() {
    // ENTRA-GUEST-001: Pass (restricted), Warning (limited), Fail (member).
    golden(
        "collaboration.guest_access_restricted",
        &[
            ("guest_access_pass", Pass),
            ("guest_access_limited", Warn),
            ("guest_access_member", Fail),
            ("guest_access_forbidden", Unknown),
        ],
    )
    .await;
    // ENTRA-GUEST-002: Pass, Pass (none), Warning (all members), Fail (everyone).
    golden(
        "collaboration.guest_invites_restricted",
        &[
            ("guest_invites_pass", Pass),
            ("guest_invites_none", Pass),
            ("guest_invites_members", Warn),
            ("guest_invites_everyone", Fail),
            ("guest_invites_forbidden", Unknown),
        ],
    )
    .await;
    // ENTRA-GUEST-003: Pass, Fail.
    golden(
        "collaboration.email_verified_join_blocked",
        &[
            ("email_join_pass", Pass),
            ("email_join_fail", Fail),
            ("email_join_forbidden", Unknown),
        ],
    )
    .await;
    // ENTRA-GROUP-001 (registry-only in M365-Secure; Junction logic): security
    // groups open is a fail, Microsoft 365 group creation open is a warning.
    golden(
        "collaboration.group_creation_restricted",
        &[
            ("groups_pass", Pass),
            ("groups_m365_open", Warn),
            ("groups_security_open", Fail),
            ("groups_forbidden", Unknown),
            ("groups_settings_forbidden", Unknown),
        ],
    )
    .await;
}
