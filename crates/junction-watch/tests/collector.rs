mod common;
use common::*;
use junction_watch::{
    activity::{CollectOptions, RunStatus, collect},
    backoff::Backoff,
    capability::{CapabilityState, Reason},
    clock::Instant,
    store::Store,
    upstream::Api,
};
use serde_json::json;
use std::time::Duration;

const CT: &str = "Audit.Exchange";

fn opts() -> CollectOptions {
    CollectOptions {
        backoff: Backoff::IMMEDIATE,
        ..Default::default()
    }
}

fn now() -> Instant {
    Instant::parse("2026-10-25T06:00:00Z").unwrap()
}

#[tokio::test]
async fn collects_paginated_content_and_dedupes_on_rerun() {
    let store = Store::in_memory(TENANT).unwrap();
    let m = Mock::new();
    let next = format!(
        "https://manage.office.com/api/v1.0/{TENANT}/activity/feed/subscriptions/content?contentType=Audit.Exchange&nextPage=2"
    );
    m.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/content",
        Some("nextPage=2"),
        vec![ok(json!([content("b2", "2026-10-25T05:00:00.000Z")]))],
    );
    m.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/content",
        None,
        vec![
            page(json!([content("b1", "2026-10-25T04:00:00.000Z")]), &next),
            ok(json!([])),
        ],
    );
    m.route(
        Api::ManagementActivity,
        "GET",
        "/audit/b1",
        None,
        vec![ok(json!([
            exchange_record("r1", "2026-10-25T03:58:00", "New-InboxRule"),
            exchange_record("r2", "2026-10-25T03:59:00", "Set-Mailbox"),
            json!({"Operation": "no id, dropped"})
        ]))],
    );
    // b2 repeats r2: Microsoft documents duplicate delivery.
    m.route(
        Api::ManagementActivity,
        "GET",
        "/audit/b2",
        None,
        vec![ok(json!([
            exchange_record("r2", "2026-10-25T03:59:00", "Set-Mailbox"),
            exchange_record("r3", "2026-10-25T04:30:00", "Add-MailboxPermission")
        ]))],
    );

    let out = collect(&m, &store, CT, now(), &opts()).await.unwrap();
    assert_eq!(
        out.status,
        RunStatus::OkWithWarnings,
        "the record without an Id is surfaced: {out:?}"
    );
    assert_eq!(out.blobs, 2);
    assert_eq!(out.events_new, 3);
    assert_eq!(out.events_duplicate, 1);
    assert_eq!(out.unparseable_records, 1);
    assert!(out.max_delay_seconds.is_some());
    assert_eq!(store.event_count().unwrap(), 3);
    assert!(
        store.checkpoint("o365:Audit.Exchange").unwrap().unwrap()
            >= now().minus(Duration::from_secs(60))
    );
    let cap = store.capability("o365:Audit.Exchange").unwrap().unwrap();
    assert_eq!(cap.state, CapabilityState::Available);
    // Every listing and blob request carries the publisher identifier.
    assert!(m.calls.lock().unwrap().iter().all(|(_, _, u)| {
        u.query()
            .unwrap_or_default()
            .contains("PublisherIdentifier=")
    }));

    // Second run: overlap re-lists b1/b2 but they are not fetched again.
    let blob_calls = m.calls_to("/audit/");
    let out = collect(
        &m,
        &store,
        CT,
        now().plus(Duration::from_secs(900)),
        &opts(),
    )
    .await
    .unwrap();
    assert_eq!(out.status, RunStatus::Ok);
    assert_eq!(out.blobs, 0);
    assert_eq!(m.calls_to("/audit/"), blob_calls);
}

#[tokio::test]
async fn first_run_backfills_seven_days_in_24_hour_windows() {
    let store = Store::in_memory(TENANT).unwrap();
    let m = Mock::new();
    m.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/content",
        None,
        vec![ok(json!([]))],
    );
    let out = collect(&m, &store, CT, now(), &opts()).await.unwrap();
    assert_eq!(out.status, RunStatus::Ok);
    let listings = m.calls_to("/subscriptions/content");
    assert_eq!(
        listings, 7,
        "7 days less a margin fits in 7 windows of under 24 hours"
    );
    for (_, _, url) in m.calls.lock().unwrap().iter() {
        let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        let start = Instant::parse(&q["startTime"]).unwrap();
        let end = Instant::parse(&q["endTime"]).unwrap();
        assert!(end.since(start) <= Duration::from_secs(24 * 3600));
        assert!(now().since(start) <= Duration::from_secs(7 * 86_400));
    }
}

#[tokio::test]
async fn transient_failures_are_retried() {
    let store = Store::in_memory(TENANT).unwrap();
    let m = Mock::new();
    m.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/content",
        None,
        vec![
            err(429, ""),
            err(403, "AF429"),
            err(503, ""),
            ok(json!([content("b1", "2026-10-25T04:00:00.000Z")])),
            ok(json!([])),
        ],
    );
    m.route(
        Api::ManagementActivity,
        "GET",
        "/audit/b1",
        None,
        vec![ok(json!([exchange_record(
            "r1",
            "2026-10-25T03:58:00",
            "New-InboxRule"
        )]))],
    );
    let out = collect(&m, &store, CT, now(), &opts()).await.unwrap();
    assert_eq!(out.status, RunStatus::Ok, "{out:?}");
    assert_eq!(out.events_new, 1);
}

#[tokio::test]
async fn persistent_server_errors_fail_without_advancing_or_downgrading() {
    let store = Store::in_memory(TENANT).unwrap();
    let m = Mock::new();
    m.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/content",
        None,
        vec![err(500, "AF50000")],
    );
    let out = collect(&m, &store, CT, now(), &opts()).await.unwrap();
    assert_eq!(out.status, RunStatus::Failed);
    assert!(store.checkpoint("o365:Audit.Exchange").unwrap().is_none());
    assert!(
        store.capability("o365:Audit.Exchange").unwrap().is_none(),
        "transient failure does not settle a capability"
    );
    assert_eq!(store.recent_runs(1).unwrap()[0].status, "failed");
}

#[tokio::test]
async fn expired_credentials_fail_but_keep_polling() {
    let store = Store::in_memory(TENANT).unwrap();
    let m = Mock::new();
    m.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/content",
        None,
        vec![credential_failure()],
    );
    let out = collect(&m, &store, CT, now(), &opts()).await.unwrap();
    assert_eq!(out.status, RunStatus::Failed);
    let out = collect(&m, &store, CT, now(), &opts()).await.unwrap();
    assert_eq!(
        out.status,
        RunStatus::Failed,
        "credential problems are not settled; fixing the cert resumes collection"
    );
    assert_eq!(m.calls_to("/subscriptions/content"), 2);
}

#[tokio::test]
async fn permission_and_subscription_failures_stop_polling_until_retested() {
    for (code, status, reason) in [
        ("AF10001", 401, Reason::MissingPermission),
        ("AF20022", 400, Reason::SubscriptionNotStarted),
        ("AF20023", 400, Reason::SubscriptionDisabled),
    ] {
        let store = Store::in_memory(TENANT).unwrap();
        let m = Mock::new();
        m.route(
            Api::ManagementActivity,
            "GET",
            "/subscriptions/content",
            None,
            vec![err(status, code)],
        );
        let out = collect(&m, &store, CT, now(), &opts()).await.unwrap();
        assert_eq!(out.status, RunStatus::Failed);
        let cap = store.capability("o365:Audit.Exchange").unwrap().unwrap();
        assert_eq!(cap.reason, reason, "{code}");
        assert_eq!(cap.error_code.as_deref(), Some(code));
        let calls = m.total_calls();
        let out = collect(&m, &store, CT, now(), &opts()).await.unwrap();
        assert_eq!(out.status, RunStatus::Skipped);
        assert_eq!(
            m.total_calls(),
            calls,
            "known-unavailable source is not polled"
        );
    }
}

#[tokio::test]
async fn expired_blobs_become_gaps_not_retries() {
    let store = Store::in_memory(TENANT).unwrap();
    let m = Mock::new();
    m.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/content",
        None,
        vec![
            ok(json!([content("old", "2026-10-25T04:00:00.000Z")])),
            ok(json!([])),
        ],
    );
    m.route(
        Api::ManagementActivity,
        "GET",
        "/audit/old",
        None,
        vec![err(400, "AF20051")],
    );
    let out = collect(&m, &store, CT, now(), &opts()).await.unwrap();
    assert_eq!(out.status, RunStatus::OkWithWarnings);
    assert_eq!(out.quarantined_blobs, 1);
    assert_eq!(store.gaps().unwrap().len(), 1);
    assert!(store.content_processed("old").unwrap());
}

#[tokio::test]
async fn offline_longer_than_content_window_records_a_gap() {
    let store = Store::in_memory(TENANT).unwrap();
    store
        .advance_checkpoint(
            "o365:Audit.Exchange",
            now().minus(Duration::from_secs(10 * 86_400)),
        )
        .unwrap();
    let m = Mock::new();
    m.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/content",
        None,
        vec![ok(json!([]))],
    );
    collect(&m, &store, CT, now(), &opts()).await.unwrap();
    let gaps = store.gaps().unwrap();
    assert_eq!(gaps.len(), 1);
    assert!(gaps[0].reason.contains("7-day"));
}

#[tokio::test]
async fn delayed_content_inside_overlap_is_collected() {
    let store = Store::in_memory(TENANT).unwrap();
    let m = Mock::new();
    m.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/content",
        None,
        vec![ok(json!([]))],
    );
    collect(&m, &store, CT, now(), &opts()).await.unwrap();
    // A blob listed late, with contentCreated 30 minutes before the watermark.
    let m2 = Mock::new();
    m2.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/content",
        None,
        vec![ok(json!([content("late", "2026-10-25T05:30:00.000Z")]))],
    );
    m2.route(
        Api::ManagementActivity,
        "GET",
        "/audit/late",
        None,
        vec![ok(json!([exchange_record(
            "late1",
            "2026-10-25T05:00:00",
            "New-InboxRule"
        )]))],
    );
    let out = collect(
        &m2,
        &store,
        CT,
        now().plus(Duration::from_secs(900)),
        &opts(),
    )
    .await
    .unwrap();
    assert_eq!(out.events_new, 1);
}

#[tokio::test]
async fn blob_uris_off_origin_or_off_tenant_are_ignored() {
    let store = Store::in_memory(TENANT).unwrap();
    let m = Mock::new();
    let mut evil_host = content("x1", "2026-10-25T04:00:00.000Z");
    evil_host["contentUri"] = json!("https://evil.example/api/v1.0/x/activity/feed/audit/x1");
    let mut other_tenant = content("x2", "2026-10-25T04:00:00.000Z");
    other_tenant["contentUri"] = json!(
        "https://manage.office.com/api/v1.0/99999999-9999-4999-8999-999999999999/activity/feed/audit/x2"
    );
    let mut other_path = content("x3", "2026-10-25T04:00:00.000Z");
    other_path["contentUri"] = json!(format!(
        "https://manage.office.com/api/v1.0/{TENANT}/activity/feed/subscriptions/stop"
    ));
    m.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/content",
        None,
        vec![
            ok(json!([evil_host, other_tenant, other_path])),
            ok(json!([])),
        ],
    );
    let out = collect(&m, &store, CT, now(), &opts()).await.unwrap();
    assert_eq!(out.status, RunStatus::OkWithWarnings);
    assert_eq!(out.blobs, 0);
    assert_eq!(out.rejected_entries, 3);
    let run = &store.recent_runs(1).unwrap()[0];
    assert_eq!(
        (run.status.as_str(), run.rejected_entries),
        ("ok_with_warnings", 3),
        "rejections are durable"
    );
    assert_eq!(
        store.gaps().unwrap().len(),
        1,
        "one summary gap per run, not one per entry"
    );
    assert!(
        m.calls
            .lock()
            .unwrap()
            .iter()
            .all(|(_, _, u)| u.host_str() == Some("manage.office.com")
                && u.path().contains("/subscriptions/content"))
    );
}

#[tokio::test]
async fn non_terminating_pagination_fails_safely() {
    let store = Store::in_memory(TENANT).unwrap();
    let m = Mock::new();
    let same = format!(
        "https://manage.office.com/api/v1.0/{TENANT}/activity/feed/subscriptions/content?nextPage=loop"
    );
    m.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/content",
        None,
        vec![page(json!([]), &same)],
    );
    let out = collect(&m, &store, CT, now(), &opts()).await.unwrap();
    assert_eq!(out.status, RunStatus::Failed);
    assert!(out.error.unwrap().contains("malformed"));
}

#[tokio::test]
async fn run_budget_yields_partial_and_resumes() {
    let store = Store::in_memory(TENANT).unwrap();
    let m = Mock::new();
    m.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/content",
        None,
        vec![ok(json!([
            content("p1", "2026-10-25T04:00:00.000Z"),
            content("p2", "2026-10-25T04:10:00.000Z")
        ]))],
    );
    m.route(
        Api::ManagementActivity,
        "GET",
        "/audit/p1",
        None,
        vec![ok(json!([exchange_record(
            "a",
            "2026-10-25T03:00:00",
            "Set-Mailbox"
        )]))],
    );
    m.route(
        Api::ManagementActivity,
        "GET",
        "/audit/p2",
        None,
        vec![ok(json!([exchange_record(
            "b",
            "2026-10-25T03:00:00",
            "Set-Mailbox"
        )]))],
    );
    let budget = CollectOptions {
        max_blobs_per_run: 1,
        ..opts()
    };
    let out = collect(&m, &store, CT, now(), &budget).await.unwrap();
    assert_eq!(out.status, RunStatus::Partial);
    assert_eq!(out.blobs, 1);
    let out = collect(&m, &store, CT, now(), &budget).await.unwrap();
    assert_eq!(out.blobs, 1);
    assert_eq!(store.event_count().unwrap(), 2);
}

#[tokio::test]
async fn interrupted_runs_are_closed_on_next_start() {
    let store = Store::in_memory(TENANT).unwrap();
    store.start_run("o365:Audit.Exchange").unwrap();
    assert_eq!(store.close_abandoned_runs().unwrap(), 1);
}

// ---- council review regressions ----

fn listing_with(m: &Mock, items: serde_json::Value) {
    m.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/content",
        None,
        vec![ok(items), ok(json!([]))],
    );
}

#[tokio::test]
async fn poison_blob_is_quarantined_without_switching_the_feed_off() {
    for (label, blob) in [
        ("404 without code", err(404, "")),
        ("malformed body", ok(json!({"not": "an array"}))),
        ("null body", ok(serde_json::Value::Null)),
    ] {
        let store = Store::in_memory(TENANT).unwrap();
        let m = Mock::new();
        listing_with(
            &m,
            json!([
                content("bad", "2026-10-25T04:00:00.000Z"),
                content("good", "2026-10-25T04:10:00.000Z")
            ]),
        );
        m.route(
            Api::ManagementActivity,
            "GET",
            "/audit/bad",
            None,
            vec![blob],
        );
        m.route(
            Api::ManagementActivity,
            "GET",
            "/audit/good",
            None,
            vec![ok(json!([exchange_record(
                "g1",
                "2026-10-25T04:00:00",
                "Set-Mailbox"
            )]))],
        );
        let out = collect(&m, &store, CT, now(), &opts()).await.unwrap();
        assert_eq!(out.status, RunStatus::OkWithWarnings, "{label}: {out:?}");
        assert_eq!((out.quarantined_blobs, out.events_new), (1, 1), "{label}");
        assert!(store.content_processed("bad").unwrap(), "{label}");
        let cap = store.capability("o365:Audit.Exchange").unwrap().unwrap();
        assert_eq!(
            cap.state,
            CapabilityState::Available,
            "{label}: feed stays on"
        );
        assert!(
            store.checkpoint("o365:Audit.Exchange").unwrap().is_some(),
            "{label}: watermark advances"
        );
    }
}

#[tokio::test]
async fn transiently_failing_blob_is_quarantined_after_three_runs() {
    let store = Store::in_memory(TENANT).unwrap();
    let m = Mock::new();
    m.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/content",
        None,
        vec![ok(json!([content("flaky", "2026-10-25T04:00:00.000Z")]))],
    );
    m.route(
        Api::ManagementActivity,
        "GET",
        "/audit/flaky",
        None,
        vec![err(503, "")],
    );
    for run in 1..=2 {
        let out = collect(&m, &store, CT, now(), &opts()).await.unwrap();
        assert_eq!(out.status, RunStatus::Failed, "run {run} retries later");
        assert!(!store.content_processed("flaky").unwrap());
        assert!(
            store.capability("o365:Audit.Exchange").unwrap().is_none(),
            "blob failures never set feed state"
        );
    }
    let out = collect(&m, &store, CT, now(), &opts()).await.unwrap();
    assert_eq!(out.quarantined_blobs, 1);
    assert!(store.content_processed("flaky").unwrap());
    assert!(
        store.meta("blob_failures:flaky").unwrap().is_none(),
        "counter cleared"
    );
}

#[tokio::test]
async fn permission_failure_on_a_blob_skips_nothing() {
    let store = Store::in_memory(TENANT).unwrap();
    let m = Mock::new();
    listing_with(&m, json!([content("b", "2026-10-25T04:00:00.000Z")]));
    m.route(
        Api::ManagementActivity,
        "GET",
        "/audit/b",
        None,
        vec![err(403, "")],
    );
    let out = collect(&m, &store, CT, now(), &opts()).await.unwrap();
    assert_eq!(out.status, RunStatus::Failed);
    assert!(
        !store.content_processed("b").unwrap(),
        "access problems never drop content"
    );
    assert!(
        store.meta("blob_failures:b").unwrap().is_none(),
        "not counted towards quarantine"
    );
}

#[tokio::test]
async fn non_array_listing_fails_without_advancing() {
    let store = Store::in_memory(TENANT).unwrap();
    let m = Mock::new();
    m.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/content",
        None,
        vec![ok(json!({"value": []}))],
    );
    let out = collect(&m, &store, CT, now(), &opts()).await.unwrap();
    assert_eq!(out.status, RunStatus::Failed);
    assert!(store.checkpoint("o365:Audit.Exchange").unwrap().is_none());
}

#[tokio::test]
async fn next_page_off_the_listing_endpoint_fails_without_advancing() {
    let store = Store::in_memory(TENANT).unwrap();
    let m = Mock::new();
    let off_path =
        format!("https://manage.office.com/api/v1.0/{TENANT}/activity/feed/subscriptions/list");
    m.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/content",
        None,
        vec![page(json!([]), &off_path)],
    );
    let out = collect(&m, &store, CT, now(), &opts()).await.unwrap();
    assert_eq!(out.status, RunStatus::Failed);
    assert!(store.checkpoint("o365:Audit.Exchange").unwrap().is_none());
    assert_eq!(m.calls_to("/subscriptions/list"), 0, "link not followed");
}

#[tokio::test]
async fn records_from_another_organisation_are_rejected() {
    let store = Store::in_memory(TENANT).unwrap();
    let m = Mock::new();
    listing_with(&m, json!([content("b", "2026-10-25T04:00:00.000Z")]));
    let mut foreign = exchange_record("f1", "2026-10-25T04:00:00", "New-InboxRule");
    foreign["OrganizationId"] = json!("99999999-9999-4999-8999-999999999999");
    m.route(
        Api::ManagementActivity,
        "GET",
        "/audit/b",
        None,
        vec![ok(json!([
            foreign,
            exchange_record("ok1", "2026-10-25T04:00:00", "Set-Mailbox")
        ]))],
    );
    let out = collect(&m, &store, CT, now(), &opts()).await.unwrap();
    assert_eq!((out.events_new, out.unparseable_records), (1, 1));
    assert_eq!(store.event_count().unwrap(), 1);
}

#[tokio::test]
async fn offline_gap_is_recorded_once_across_catch_up_runs() {
    let store = Store::in_memory(TENANT).unwrap();
    store
        .advance_checkpoint(
            "o365:Audit.Exchange",
            now().minus(Duration::from_secs(10 * 86_400)),
        )
        .unwrap();
    let m = Mock::new();
    // Listing keeps failing (catch-up not finished), across two runs an hour apart.
    m.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/content",
        None,
        vec![err(503, "")],
    );
    collect(&m, &store, CT, now(), &opts()).await.unwrap();
    collect(
        &m,
        &store,
        CT,
        now().plus(Duration::from_secs(3600)),
        &opts(),
    )
    .await
    .unwrap();
    let gaps = store.gaps().unwrap();
    assert_eq!(
        gaps.len(),
        1,
        "the hour lost while catch-up kept failing extends the same gap"
    );
    let lost = Instant::parse(&gaps[0].gap_end)
        .unwrap()
        .since(Instant::parse(&gaps[0].gap_start).unwrap());
    assert!(
        lost >= Duration::from_secs(3 * 86_400),
        "gap covers the whole offline span"
    );
}

#[tokio::test]
async fn one_feed_failing_does_not_stop_the_others_and_starved_feeds_go_first() {
    use junction_watch::activity::collect_all;
    let store = Store::in_memory(TENANT).unwrap();
    let m = Mock::new();
    m.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/content",
        Some("contentType=Audit.Exchange"),
        vec![err(500, "")],
    );
    m.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/content",
        None,
        vec![ok(json!([]))],
    );
    let feeds = vec!["Audit.Exchange".to_string(), "Audit.SharePoint".to_string()];
    let out = collect_all(&m, &store, &feeds, &opts()).await;
    assert_eq!(out.len(), 2);
    let status = |ct: &str| out.iter().find(|o| o.content_type == ct).unwrap().status;
    assert_eq!(status("Audit.Exchange"), RunStatus::Failed);
    assert_eq!(status("Audit.SharePoint"), RunStatus::Ok);
    assert!(
        store
            .recent_runs(10)
            .unwrap()
            .iter()
            .all(|r| r.status != "running"),
        "every run row is closed"
    );
    // Next pass: Exchange has never succeeded, so it runs first.
    let out = collect_all(&m, &store, &feeds, &opts()).await;
    assert_eq!(out[0].content_type, "Audit.Exchange");
}
