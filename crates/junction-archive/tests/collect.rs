//! Collector fixtures: resumable windows, replay safety, rejection and
//! throttling, against the scripted Microsoft API double from junction-watch.
//! All records are synthetic.
#[path = "../../junction-watch/tests/common/mod.rs"]
mod common;

use common::{Mock, TENANT, blob_uri, content, exchange_record, ok, page};
use junction_archive::{
    checkpoint::Checkpoint,
    collect::{CollectOptions, Status, collect_graph, collect_management, graph_spec},
    manifest::Manifest,
    record::decode,
    store::{LocalStore, ObjectStore},
};
use junction_watch::{backoff::Backoff, clock::Instant, upstream::Api};
use serde_json::{Value, json};

fn options() -> CollectOptions {
    CollectOptions {
        backoff: Backoff::IMMEDIATE,
        ..CollectOptions::default()
    }
}

/// AF429 with a Retry-After longer than the in-process backoff cap, so the run
/// stops and leaves the rest for the next run.
fn throttled() -> Result<junction_watch::upstream::Reply, junction_watch::upstream::CallError> {
    let mut e = junction_watch::upstream::CallError::http(403, Some("AF429"), None);
    e.retry_after = Some(std::time::Duration::from_secs(600));
    Err(e)
}

fn now() -> Instant {
    Instant::parse("2026-11-22T00:00:00Z").unwrap()
}

async fn records_in(store: &LocalStore, prefix: &str) -> Vec<Value> {
    let mut out = vec![];
    for key in store.list(prefix).await.unwrap() {
        if key.ends_with(".ndjson.gz") {
            let bytes = store.get(&key).await.unwrap().unwrap();
            for r in decode(&key, &bytes).unwrap().records {
                out.push(serde_json::to_value(r).unwrap());
            }
        }
    }
    out
}

async fn manifests(store: &LocalStore, source_slug: &str) -> Vec<Manifest> {
    let prefix = format!("v1/tenant={TENANT}/manifests/source={source_slug}/");
    let mut out = vec![];
    for key in store.list(&prefix).await.unwrap() {
        out.push(Manifest::decode(&key, &store.get(&key).await.unwrap().unwrap()).unwrap());
    }
    out
}

#[tokio::test]
async fn management_feed_is_archived_once_across_runs() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalStore::new(&dir.path().join("store")).unwrap();
    let mut cp = Checkpoint::open(&dir.path().join("state"), TENANT).unwrap();
    let up = Mock::new();
    up.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/content",
        None,
        vec![ok(json!([content("blob-1", "2026-11-21T10:00:00.000Z")]))],
    )
    .route(
        Api::ManagementActivity,
        "GET",
        "/activity/feed/audit/blob-1",
        None,
        vec![ok(json!([
            exchange_record("rec-1", "2026-11-21T09:58:00Z", "Set-Mailbox"),
            exchange_record("rec-2", "2026-11-21T09:59:00Z", "New-InboxRule"),
            // Another organisation's record is never stored.
            {"Id": "foreign", "CreationTime": "2026-11-21T09:59:00Z", "Operation": "X",
             "OrganizationId": "22222222-2222-4222-8222-222222222222"},
        ]))],
    );
    let first = collect_management(
        &up,
        &store,
        &mut cp,
        "Audit.Exchange",
        "run-1",
        now(),
        &options(),
    )
    .await
    .unwrap();
    assert_eq!(first.status, Status::OkWithWarnings, "{first:?}");
    assert_eq!(first.records_stored, 2);
    assert_eq!(first.rejected_records, 1);
    assert_eq!(up.calls_to("/activity/feed/audit/blob-1"), 1);
    let stored = records_in(
        &store,
        &format!("v1/tenant={TENANT}/source=o365-Audit.Exchange/"),
    )
    .await;
    assert_eq!(stored.len(), 2);
    assert!(stored.iter().all(|r| r["raw"]["Id"] != "foreign"));
    assert!(cp.get("o365:Audit.Exchange").unwrap().watermark().is_some());

    // The second run re-lists the overlap and sees the same blob: it is skipped.
    let second = collect_management(
        &up,
        &store,
        &mut cp,
        "Audit.Exchange",
        "run-2",
        now(),
        &options(),
    )
    .await
    .unwrap();
    assert_eq!(second.records_stored, 0);
    assert_eq!(
        up.calls_to("/activity/feed/audit/blob-1"),
        1,
        "archived blob is not fetched again"
    );
    let chain = manifests(&store, "o365-Audit.Exchange").await;
    assert!(chain.iter().all(|m| m.tenant_id == TENANT));
    assert!(
        chain.iter().any(|m| m.previous_manifest_sha256.is_some()),
        "manifests are chained"
    );
}

#[tokio::test]
async fn interrupted_run_resumes_and_replay_adds_no_objects() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalStore::new(&dir.path().join("store")).unwrap();
    let state = dir.path().join("state");
    let up = Mock::new();
    up.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/content",
        None,
        vec![ok(json!([
            content("blob-a", "2026-11-21T10:00:00.000Z"),
            content("blob-b", "2026-11-21T10:05:00.000Z"),
        ]))],
    )
    .route(
        Api::ManagementActivity,
        "GET",
        "/activity/feed/audit/blob-a",
        None,
        vec![ok(json!([exchange_record(
            "a1",
            "2026-11-21T09:50:00Z",
            "Set-Mailbox"
        )]))],
    )
    // blob-b is throttled: the run stops, keeping blob-a.
    .route(
        Api::ManagementActivity,
        "GET",
        "/activity/feed/audit/blob-b",
        None,
        vec![
            throttled(),
            ok(json!([exchange_record(
                "b1",
                "2026-11-21T09:51:00Z",
                "Set-Mailbox"
            )])),
        ],
    );
    {
        let mut cp = Checkpoint::open(&state, TENANT).unwrap();
        let out = collect_management(
            &up,
            &store,
            &mut cp,
            "Audit.Exchange",
            "run-1",
            now(),
            &options(),
        )
        .await
        .unwrap();
        assert_eq!(out.status, Status::Failed);
        assert_eq!(
            out.records_stored, 1,
            "blob-a is stored before the run stops"
        );
        assert!(
            cp.get("o365:Audit.Exchange").unwrap().watermark().is_none(),
            "window not complete"
        );
    }
    let objects_after_first = store.list("v1/").await.unwrap().len();
    // Restart from the saved checkpoint once Retry-After has passed: blob-a is
    // remembered, blob-b is fetched.
    let mut cp = Checkpoint::open(&state, TENANT).unwrap();
    assert!(
        cp.get("o365:Audit.Exchange")
            .unwrap()
            .retry_after()
            .is_some(),
        "Retry-After is honoured"
    );
    cp.source("o365:Audit.Exchange").retry_after = None;
    let out = collect_management(
        &up,
        &store,
        &mut cp,
        "Audit.Exchange",
        "run-2",
        now(),
        &options(),
    )
    .await
    .unwrap();
    assert_eq!(out.status, Status::Ok, "{out:?}");
    assert_eq!(up.calls_to("/activity/feed/audit/blob-a"), 1);
    let ids: Vec<String> = records_in(
        &store,
        &format!("v1/tenant={TENANT}/source=o365-Audit.Exchange/"),
    )
    .await
    .iter()
    .map(|r| r["sourceEventId"].as_str().unwrap().to_owned())
    .collect();
    assert_eq!(ids.len(), 2, "no gap and no duplicate: {ids:?}");
    assert!(store.list("v1/").await.unwrap().len() > objects_after_first);
}

#[tokio::test]
async fn offline_longer_than_the_content_window_is_a_recorded_gap() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalStore::new(&dir.path().join("store")).unwrap();
    let mut cp = Checkpoint::open(&dir.path().join("state"), TENANT).unwrap();
    cp.source("o365:Audit.General")
        .set_watermark(Instant::parse("2026-11-01T00:00:00Z").unwrap());
    let up = Mock::new();
    up.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/content",
        None,
        vec![ok(json!([]))],
    );
    collect_management(
        &up,
        &store,
        &mut cp,
        "Audit.General",
        "run-1",
        now(),
        &options(),
    )
    .await
    .unwrap();
    let gaps: Vec<String> = manifests(&store, "o365-Audit.General")
        .await
        .into_iter()
        .flat_map(|m| m.gaps)
        .map(|g| g.reason)
        .collect();
    assert!(gaps.iter().any(|g| g.contains("7-day")), "{gaps:?}");
}

#[tokio::test]
async fn graph_pages_dedupe_the_overlap_and_refuse_foreign_records() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalStore::new(&dir.path().join("store")).unwrap();
    let mut cp = Checkpoint::open(&dir.path().join("state"), TENANT).unwrap();
    let audit = |id: &str, at: &str| {
        json!({"id": id, "activityDateTime": at, "activityDisplayName": "Add member to role",
               "category": "RoleManagement", "result": "success",
               "initiatedBy": {"user": {"id": "u1", "userPrincipalName": "admin@example.test"}}})
    };
    let up = Mock::new();
    up.route(
        Api::Graph,
        "GET",
        "/v1.0/auditLogs/directoryAudits",
        Some("skiptoken"),
        vec![ok(json!({"value": [audit("d2", "2026-11-15T10:30:00Z")]}))],
    )
    .route(
        Api::Graph,
        "GET",
        "/v1.0/auditLogs/directoryAudits",
        None,
        vec![page(
            json!({
                "value": [
                    audit("d1", "2026-11-15T10:00:00Z"),
                    {"id": "x", "activityDateTime": "2026-11-15T10:00:00Z", "activityDisplayName": "Y",
                     "tenantId": "22222222-2222-4222-8222-222222222222"},
                ],
                "@odata.nextLink": "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$skiptoken=p2"
            }),
            "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$skiptoken=p2",
        )],
    );
    let spec = graph_spec("graph:directoryAudits").unwrap();
    let first = collect_graph(&up, &store, &mut cp, spec, "run-1", now(), &options())
        .await
        .unwrap();
    // Mock pages repeat their last response for every later window, so each
    // window lists d1, d2 and the foreign record again. Only the window that
    // contains their timestamps accepts them; others reject them as out of window.
    assert_eq!(first.records_stored, 2, "{first:?}");
    assert!(first.rejected_records >= 1);
    let stored = records_in(
        &store,
        &format!("v1/tenant={TENANT}/source=graph-directoryAudits/"),
    )
    .await;
    assert_eq!(stored.len(), 2);
}

#[tokio::test]
async fn sign_ins_without_a_premium_licence_are_skipped_until_retest() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalStore::new(&dir.path().join("store")).unwrap();
    let mut cp = Checkpoint::open(&dir.path().join("state"), TENANT).unwrap();
    let up = Mock::new();
    up.route(
        Api::Graph,
        "GET",
        "/v1.0/auditLogs/signIns",
        None,
        vec![common::err_msg(
            403,
            Some("Authentication_RequestFromNonPremiumTenantOrB2CTenant"),
            "Tenant doesn't have premium license",
        )],
    );
    let spec = graph_spec("graph:signIns").unwrap();
    let out = collect_graph(&up, &store, &mut cp, spec, "run-1", now(), &options())
        .await
        .unwrap();
    assert_eq!(out.status, Status::Failed);
    let state = cp.get("graph:signIns").unwrap();
    assert!(
        state
            .unavailable
            .as_deref()
            .unwrap()
            .starts_with("requires_licence"),
        "{state:?}"
    );
    let calls = up.total_calls();
    let again = collect_graph(&up, &store, &mut cp, spec, "run-2", now(), &options())
        .await
        .unwrap();
    assert_eq!(again.status, Status::Skipped);
    assert_eq!(
        up.total_calls(),
        calls,
        "no call while the licence re-test delay runs"
    );
}

#[tokio::test]
async fn unsafe_graph_continuation_is_refused_without_moving_the_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalStore::new(&dir.path().join("store")).unwrap();
    let mut cp = Checkpoint::open(&dir.path().join("state"), TENANT).unwrap();
    let up = Mock::new();
    up.route(
        Api::Graph,
        "GET",
        "/v1.0/auditLogs/directoryAudits",
        None,
        vec![ok(json!({"value": [], "@odata.nextLink": "https://attacker.example/v1.0/auditLogs/directoryAudits"}))],
    );
    let spec = graph_spec("graph:directoryAudits").unwrap();
    let out = collect_graph(&up, &store, &mut cp, spec, "run-1", now(), &options())
        .await
        .unwrap();
    assert_eq!(out.status, Status::Failed);
    assert!(
        cp.get("graph:directoryAudits")
            .unwrap()
            .watermark()
            .is_none()
    );
    assert!(
        !up.calls
            .lock()
            .unwrap()
            .iter()
            .any(|(_, _, u)| u.host_str() == Some("attacker.example"))
    );
    let _ = blob_uri("unused");
}
