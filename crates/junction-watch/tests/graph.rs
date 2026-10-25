mod common;
use common::*;
use junction_watch::{
    backoff::Backoff,
    capability::{CapabilityState, Reason},
    clock::Instant,
    graph,
    store::{CapabilityRecord, Store},
    upstream::Api,
};
use serde_json::json;
fn ready(store: &Store, source: &str) {
    store
        .put_capability(&CapabilityRecord {
            source: source.into(),
            state: CapabilityState::Available,
            reason: Reason::Ok,
            http_status: Some(200),
            error_code: None,
            detail: None,
            required_permission: "AuditLog.Read.All".into(),
            licence_note: "probe".into(),
            docs_url: "https://learn.microsoft.com".into(),
            checked_at: Instant::now().to_rfc3339(),
        })
        .unwrap();
    store
        .advance_checkpoint(source, Instant::parse("2026-10-24T23:30:00Z").unwrap())
        .unwrap();
}
fn record() -> serde_json::Value {
    json!({"id":"one","activityDateTime":"2026-10-25T00:00:00Z","activityDisplayName":"Add member to role","result":"success","initiatedBy":{"user":{"userPrincipalName":"admin@club.example"}},"targetResources":[]})
}
#[tokio::test]
async fn graph_paging_retries_dedup_and_checkpoint() {
    let s = Store::in_memory(TENANT).unwrap();
    ready(&s, graph::SOURCES[0]);
    let m = Mock::new();
    m.route(Api::Graph,"GET","directoryAudits",None,vec![err(429,"TooManyRequests"),ok(json!({"value":[record()],"@odata.nextLink":"https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$skiptoken=x"})),ok(json!({"value":[record()]}))]);
    let now = Instant::parse("2026-10-25T01:00:00Z").unwrap();
    let out = graph::collect(&m, &s, graph::SOURCES[0], now, Backoff::IMMEDIATE)
        .await
        .unwrap();
    assert_eq!(out["status"], "ok");
    assert_eq!(s.event_count().unwrap(), 1);
    assert_eq!(s.checkpoint(graph::SOURCES[0]).unwrap(), Some(now));
    assert_eq!(m.total_calls(), 3);
}
#[tokio::test]
async fn incomplete_pages_and_bad_links_preserve_checkpoint() {
    for response in [
        err(401, "InvalidAuthenticationToken"),
        err(403, "Authorization_RequestDenied"),
        err(503, "Unavailable"),
        ok(json!({"value":[record()],"@odata.nextLink":"https://evil.example/steal"})),
        ok(json!({"value":"broken"})),
    ] {
        let s = Store::in_memory(TENANT).unwrap();
        ready(&s, graph::SOURCES[0]);
        let before = s.checkpoint(graph::SOURCES[0]).unwrap();
        let m = Mock::new();
        m.route(Api::Graph, "GET", "directoryAudits", None, vec![response]);
        let out = graph::collect(
            &m,
            &s,
            graph::SOURCES[0],
            Instant::parse("2026-10-25T01:00:00Z").unwrap(),
            Backoff::IMMEDIATE,
        )
        .await
        .unwrap();
        assert_eq!(out["status"], "failed");
        assert_eq!(s.checkpoint(graph::SOURCES[0]).unwrap(), before);
        assert!(
            m.calls
                .lock()
                .unwrap()
                .iter()
                .all(|(_, _, u)| u.host_str() == Some("graph.microsoft.com"))
        );
    }
}
#[tokio::test]
async fn unprobed_signins_are_not_requested() {
    let s = Store::in_memory(TENANT).unwrap();
    let m = Mock::new();
    assert_eq!(
        graph::collect(
            &m,
            &s,
            graph::SOURCES[1],
            Instant::now(),
            Backoff::IMMEDIATE
        )
        .await
        .unwrap()["status"],
        "skipped"
    );
    assert_eq!(m.total_calls(), 0);
}

#[tokio::test]
async fn long_retry_after_is_persisted_instead_of_shortened() {
    use std::time::Duration;
    let s = Store::in_memory(TENANT).unwrap();
    ready(&s, graph::SOURCES[0]);
    let m = Mock::new();
    let mut e = junction_watch::upstream::CallError::http(429, Some("TooManyRequests"), None);
    e.retry_after = Some(Duration::from_secs(3600));
    m.route(Api::Graph, "GET", "directoryAudits", None, vec![Err(e)]);
    let now = Instant::parse("2026-10-25T01:00:00Z").unwrap();
    assert_eq!(
        graph::collect(&m, &s, graph::SOURCES[0], now, Backoff::IMMEDIATE)
            .await
            .unwrap()["status"],
        "failed"
    );
    assert_eq!(
        graph::collect(
            &m,
            &s,
            graph::SOURCES[0],
            now.plus(Duration::from_secs(30)),
            Backoff::IMMEDIATE
        )
        .await
        .unwrap()["status"],
        "skipped"
    );
    assert_eq!(m.total_calls(), 1);
}

#[tokio::test]
async fn malformed_records_are_visible_without_blocking_later_pages() {
    let s = Store::in_memory(TENANT).unwrap();
    ready(&s, graph::SOURCES[0]);
    let m = Mock::new();
    let mut bad = record();
    bad.as_object_mut().unwrap().remove("activityDisplayName");
    m.route(Api::Graph,"GET","directoryAudits",None,vec![
        ok(json!({"value":[bad],"@odata.nextLink":"https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$skiptoken=next"})),
        ok(json!({"value":[record()]}))]);
    let now = Instant::parse("2026-10-25T01:00:00Z").unwrap();
    let result = graph::collect(&m, &s, graph::SOURCES[0], now, Backoff::IMMEDIATE)
        .await
        .unwrap();
    assert_eq!(result["status"], "ok_with_warnings");
    assert_eq!(result["rejected_records"], 1);
    assert_eq!(s.event_count().unwrap(), 1);
    assert_eq!(s.checkpoint(graph::SOURCES[0]).unwrap(), Some(now));
    assert_eq!(s.gaps().unwrap().len(), 1);
}
#[tokio::test]
async fn overlap_collects_signins_published_more_than_one_hour_late() {
    let s = Store::in_memory(TENANT).unwrap();
    ready(&s, graph::SOURCES[1]);
    let m = Mock::new();
    m.route(Api::Graph,"GET","signIns",None,vec![ok(json!({"value":[{"id":"late","createdDateTime":"2026-10-24T20:00:00Z","status":{"errorCode":0}}]}))]);
    let now = Instant::parse("2026-10-25T01:00:00Z").unwrap();
    let result = graph::collect(&m, &s, graph::SOURCES[1], now, Backoff::IMMEDIATE)
        .await
        .unwrap();
    assert_eq!(result["status"], "ok");
    assert_eq!(s.event_count().unwrap(), 1);
    let calls = m.calls.lock().unwrap();
    assert!(
        calls[0]
            .2
            .query_pairs()
            .any(|(k, v)| k == "$filter" && v.contains("2026-10-24T17:30:00.000Z"))
    );
}
