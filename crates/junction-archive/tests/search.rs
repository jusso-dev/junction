//! Search fixtures over a local store holding synthetic records.
use junction_archive::{
    cli::{FilterArgs, SearchArgs, run_search},
    record::{ArchiveRecord, encode},
    search::{Query, search},
    store::{BoxFut, HoldOutcome, LocalStore, ObjectStore, PutOutcome},
};
use junction_watch::{clock::Instant, event::from_management_record};
use serde_json::json;
use std::sync::Mutex;

const T: &str = "11111111-1111-4111-8111-111111111111";

fn rec(id: &str, at: &str, op: &str, user: &str, ip: &str, ingested: &str) -> ArchiveRecord {
    let raw = json!({"Id": id, "CreationTime": at, "Operation": op, "UserId": user,
                     "ClientIP": ip, "Workload": "Exchange", "ResultStatus": "Succeeded"});
    let e = from_management_record(T, "Audit.Exchange", &raw, Instant::parse(ingested).unwrap())
        .unwrap();
    ArchiveRecord::from_event(&e, &raw, None)
}

async fn put_all(store: &dyn ObjectStore, records: Vec<ArchiveRecord>) {
    for o in encode(T, records).unwrap() {
        store
            .put_new(&o.key, o.bytes, "application/gzip")
            .await
            .unwrap();
    }
}

/// Records which keys were listed and read, to prove partition pruning.
struct Spy {
    inner: LocalStore,
    listed: Mutex<Vec<String>>,
    read: Mutex<Vec<String>>,
}
impl ObjectStore for Spy {
    fn describe(&self) -> String {
        self.inner.describe()
    }
    fn put_new<'a>(
        &'a self,
        k: &'a str,
        b: Vec<u8>,
        c: &'a str,
    ) -> BoxFut<'a, anyhow::Result<PutOutcome>> {
        self.inner.put_new(k, b, c)
    }
    fn get<'a>(&'a self, k: &'a str) -> BoxFut<'a, anyhow::Result<Option<Vec<u8>>>> {
        self.read.lock().unwrap().push(k.to_owned());
        self.inner.get(k)
    }
    fn list<'a>(&'a self, p: &'a str) -> BoxFut<'a, anyhow::Result<Vec<String>>> {
        self.listed.lock().unwrap().push(p.to_owned());
        self.inner.list(p)
    }
    fn hold<'a>(&'a self, k: &'a str, h: &'a str) -> BoxFut<'a, anyhow::Result<HoldOutcome>> {
        self.inner.hold(k, h)
    }
    fn release<'a>(&'a self, k: &'a str) -> BoxFut<'a, anyhow::Result<()>> {
        self.inner.release(k)
    }
    fn delete_probe<'a>(
        &'a self,
        k: &'a str,
    ) -> BoxFut<'a, anyhow::Result<junction_archive::store::DeleteProbe>> {
        self.inner.delete_probe(k)
    }
    fn retention_until<'a>(&'a self, k: &'a str) -> BoxFut<'a, anyhow::Result<Option<String>>> {
        self.inner.retention_until(k)
    }
}

fn range(from: &str, to: &str) -> Query {
    Query {
        from: from.into(),
        to: to.into(),
        ..Query::default()
    }
}

#[tokio::test]
async fn only_overlapping_partitions_are_read_and_duplicates_count_once() {
    let dir = tempfile::tempdir().unwrap();
    let store = Spy {
        inner: LocalStore::new(dir.path()).unwrap(),
        listed: Mutex::default(),
        read: Mutex::default(),
    };
    put_all(
        &store,
        vec![
            rec(
                "a",
                "2026-11-01T10:15:00Z",
                "Set-Mailbox",
                "Person@Example.Test",
                "203.0.113.5",
                "2026-11-01T11:00:00Z",
            ),
            rec(
                "b",
                "2026-11-03T10:15:00Z",
                "New-InboxRule",
                "other@example.test",
                "203.0.113.6",
                "2026-11-03T11:00:00Z",
            ),
        ],
    )
    .await;
    // The same record "a" delivered again later (overlapping windows or blobs).
    put_all(
        &store,
        vec![rec(
            "a",
            "2026-11-01T10:15:00Z",
            "Set-Mailbox",
            "Person@Example.Test",
            "203.0.113.5",
            "2026-11-01T12:00:00Z",
        )],
    )
    .await;
    let mut q = range("2026-11-01T00:00:00Z", "2026-11-02T00:00:00Z");
    q.sources = vec!["o365:Audit.Exchange".into()];
    let r = search(&store, T, &q, 100).await.unwrap();
    assert_eq!(r.records.len(), 1);
    assert_eq!(r.duplicates_removed, 1);
    assert_eq!(
        r.records[0].ingested_at, "2026-11-01T12:00:00.000Z",
        "latest ingest wins"
    );
    let listed = store.listed.lock().unwrap().clone();
    assert_eq!(
        listed,
        [format!(
            "v1/tenant={T}/source=o365-Audit.Exchange/date=2026-11-01/"
        )]
    );
    assert!(
        store
            .read
            .lock()
            .unwrap()
            .iter()
            .all(|k| k.contains("date=2026-11-01"))
    );
}

#[tokio::test]
async fn filters_and_default_output_is_redacted() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalStore::new(dir.path()).unwrap();
    put_all(
        &store,
        vec![
            rec(
                "a",
                "2026-11-01T10:15:00Z",
                "Set-Mailbox",
                "Person@Example.Test",
                "203.0.113.5",
                "2026-11-01T11:00:00Z",
            ),
            rec(
                "b",
                "2026-11-01T10:20:00Z",
                "New-InboxRule",
                "other@example.test",
                "198.51.100.9",
                "2026-11-01T11:00:00Z",
            ),
        ],
    )
    .await;
    let filter = FilterArgs {
        from: "2026-11-01T00:00:00Z".into(),
        to: "2026-11-02T00:00:00Z".into(),
        sources: vec![],
        operation: None,
        actor: Some("PERSON@example.test".into()),
        ip: None,
        contains: None,
    };
    let args = SearchArgs {
        filter: filter.clone(),
        limit: 10,
        full: false,
        yes: false,
    };
    let out = run_search(&store, T, &args).await.unwrap();
    assert_eq!(out["count"], 1);
    let text = out["records"].to_string();
    for personal in ["person@example.test", "Person@Example.Test", "203.0.113.5"] {
        assert!(
            !text.contains(personal),
            "{personal} leaked in default output: {text}"
        );
    }
    assert!(
        out["records"][0].get("raw").is_none(),
        "raw records are never in the default view"
    );
    assert_eq!(out["records"][0]["ip"], "203.0.113.0/24");
    assert!(
        out["records"][0]["actor"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    assert_eq!(out["redacted"], true);
    let query = out["query"].to_string();
    assert!(
        !query.to_lowercase().contains("person@example.test"),
        "the query must not undo the pseudonyms: {query}"
    );
    assert!(
        out["query"]["actor"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );

    let full = run_search(
        &store,
        T,
        &SearchArgs {
            filter,
            limit: 10,
            full: true,
            yes: true,
        },
    )
    .await
    .unwrap();
    assert!(full["records"].to_string().contains("person@example.test"));

    let mut contains = range("2026-11-01T00:00:00Z", "2026-11-02T00:00:00Z");
    contains.contains = Some("inboxrule".into());
    assert_eq!(
        search(&store, T, &contains, 10)
            .await
            .unwrap()
            .records
            .len(),
        1
    );
    // A forwarded event's raw hash finds the archived record.
    let hash = search(
        &store,
        T,
        &range("2026-11-01T00:00:00Z", "2026-11-02T00:00:00Z"),
        10,
    )
    .await
    .unwrap()
    .records[0]
        .raw_sha256
        .clone();
    let mut by_hash = range("2026-11-01T00:00:00Z", "2026-11-02T00:00:00Z");
    by_hash.contains = Some(hash);
    assert_eq!(
        search(&store, T, &by_hash, 10).await.unwrap().records.len(),
        1
    );
    let mut ip = range("2026-11-01T00:00:00Z", "2026-11-02T00:00:00Z");
    ip.ip = Some("198.51.100.9".into());
    assert_eq!(
        search(&store, T, &ip, 10).await.unwrap().records[0].source_event_id,
        "b"
    );
}

#[tokio::test]
async fn corrupt_and_tampered_objects_are_reported_not_dropped_silently() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalStore::new(dir.path()).unwrap();
    put_all(
        &store,
        vec![rec(
            "a",
            "2026-11-01T10:15:00Z",
            "Set-Mailbox",
            "a@example.test",
            "203.0.113.5",
            "2026-11-01T11:00:00Z",
        )],
    )
    .await;
    let prefix = format!("v1/tenant={T}/source=o365-Audit.Exchange/date=2026-11-01/hour=10/");
    store
        .put_new(
            &format!("{prefix}{}.ndjson.gz", "0".repeat(64)),
            b"not gzip".to_vec(),
            "x",
        )
        .await
        .unwrap();
    let real = encode(
        T,
        vec![rec(
            "z",
            "2026-11-01T10:30:00Z",
            "X",
            "z@example.test",
            "203.0.113.9",
            "2026-11-01T11:00:00Z",
        )],
    )
    .unwrap();
    store
        .put_new(
            &format!("{prefix}{}.ndjson.gz", "f".repeat(64)),
            real[0].bytes.clone(),
            "x",
        )
        .await
        .unwrap();
    let r = search(
        &store,
        T,
        &range("2026-11-01T00:00:00Z", "2026-11-02T00:00:00Z"),
        10,
    )
    .await
    .unwrap();
    assert_eq!(r.records.len(), 1, "the intact object is still read");
    assert_eq!(r.problems.len(), 2, "{:?}", r.problems);
    assert!(
        r.problems
            .iter()
            .any(|p| p.problem.contains("does not match its hash"))
    );
}

#[tokio::test]
async fn limit_truncates() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalStore::new(dir.path()).unwrap();
    let records = (0..5)
        .map(|i| {
            rec(
                &format!("r{i}"),
                &format!("2026-11-01T10:0{i}:00Z"),
                "X",
                "a@example.test",
                "203.0.113.5",
                "2026-11-01T11:00:00Z",
            )
        })
        .collect();
    put_all(&store, records).await;
    let r = search(
        &store,
        T,
        &range("2026-11-01T00:00:00Z", "2026-11-02T00:00:00Z"),
        3,
    )
    .await
    .unwrap();
    assert_eq!(r.records.len(), 3);
    assert!(r.truncated);
}
