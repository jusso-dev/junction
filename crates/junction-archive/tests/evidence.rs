//! Legal hold and evidence bundle fixtures over a local store. Synthetic data.
use junction_archive::{
    evidence::{create_hold, export, list_holds, release_hold, result_set_sha256, verify},
    manifest::{Gap, Manifest},
    record::{ArchiveRecord, encode},
    search::Query,
    store::{BoxFut, HoldOutcome, LocalStore, ObjectStore, PutOutcome},
};
use junction_watch::{clock::Instant, event::from_management_record};
use serde_json::{Value, json};

const T: &str = "11111111-1111-4111-8111-111111111111";

fn rec(id: &str, at: &str, op: &str) -> ArchiveRecord {
    let raw = json!({"Id": id, "CreationTime": at, "Operation": op, "UserId": "person@example.test",
                     "ClientIP": "203.0.113.5", "Workload": "Exchange"});
    let e = from_management_record(
        T,
        "Audit.Exchange",
        &raw,
        Instant::parse("2026-11-02T00:00:00Z").unwrap(),
    )
    .unwrap();
    ArchiveRecord::from_event(&e, &raw, None)
}

async fn seed(store: &dyn ObjectStore) -> Vec<ArchiveRecord> {
    let records = vec![
        rec("a", "2026-11-01T10:15:00Z", "Set-Mailbox"),
        rec("b", "2026-11-01T11:15:00Z", "New-InboxRule"),
        rec("c", "2026-11-01T12:15:00Z", "Set-Mailbox"),
    ];
    for o in encode(T, records.clone()).unwrap() {
        store
            .put_new(&o.key, o.bytes, "application/gzip")
            .await
            .unwrap();
    }
    records
}

fn day() -> Query {
    Query {
        from: "2026-11-01T00:00:00Z".into(),
        to: "2026-11-02T00:00:00Z".into(),
        sources: vec!["o365:Audit.Exchange".into()],
        ..Query::default()
    }
}

fn now() -> Instant {
    Instant::parse("2026-11-22T00:00:00Z").unwrap()
}

#[test]
fn result_set_hash_is_order_independent() {
    let a = rec("a", "2026-11-01T10:15:00Z", "X");
    let b = rec("b", "2026-11-01T10:16:00Z", "Y");
    assert_eq!(
        result_set_sha256(&[a.clone(), b.clone()]),
        result_set_sha256(&[b.clone(), a.clone()])
    );
    assert_ne!(
        result_set_sha256(std::slice::from_ref(&a)),
        result_set_sha256(&[a, b])
    );
}

#[tokio::test]
async fn export_verifies_and_detects_tampering() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalStore::new(&dir.path().join("store")).unwrap();
    let records = seed(&store).await;
    // A gap inside the range must appear in the bundle.
    let t = Instant::parse("2026-11-01T13:00:00Z").unwrap();
    let m = Manifest::new(
        T,
        "o365:Audit.Exchange",
        "run-1",
        t,
        t,
        true,
        vec![],
        vec![Gap::new(
            t,
            t.plus(std::time::Duration::from_secs(600)),
            "blob quarantined",
        )],
        None,
    );
    let (key, bytes, _) = m.encode().unwrap();
    store
        .put_new(&key, bytes, "application/json")
        .await
        .unwrap();

    let out = dir.path().join("bundle");
    let e = export(
        &store,
        T,
        &day(),
        false,
        "IRAP assessment 2026",
        &out,
        now(),
    )
    .await
    .unwrap();
    assert_eq!(e.manifest["recordCount"], 3);
    assert_eq!(e.manifest["resultSetSha256"], result_set_sha256(&records));
    assert_eq!(e.manifest["redacted"], true);
    let gaps = e.manifest["gaps"].as_array().unwrap();
    assert!(
        gaps.iter()
            .any(|g| g["kind"] == "recorded" && g["reason"] == "blob quarantined"),
        "{gaps:?}"
    );
    // No complete window manifest covers the day in this fixture, so the
    // whole range is also reported as uncovered.
    assert!(
        gaps.iter().any(|g| g["kind"] == "uncovered"
            && g["from"] == "2026-11-01T00:00:00.000Z"
            && g["to"] == "2026-11-02T00:00:00.000Z"),
        "{gaps:?}"
    );
    let text = std::fs::read_to_string(out.join("records.ndjson")).unwrap();
    assert!(!text.contains("person@example.test") && !text.contains("203.0.113.5"));
    assert!(verify(&out).unwrap().is_empty());

    // Redacted and full bundles of the same query share the result-set hash.
    let full = dir.path().join("full");
    let f = export(&store, T, &day(), true, "incident", &full, now())
        .await
        .unwrap();
    assert_eq!(f.manifest["resultSetSha256"], e.manifest["resultSetSha256"]);
    assert!(
        std::fs::read_to_string(full.join("records.ndjson"))
            .unwrap()
            .contains("person@example.test")
    );

    // One changed byte fails verification.
    let path = out.join("records.ndjson");
    let mut bytes = std::fs::read(&path).unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(false);
    std::fs::set_permissions(&path, perms).unwrap();
    let i = bytes.iter().position(|b| *b == b'S').unwrap();
    bytes[i] = b'T';
    std::fs::write(&path, bytes).unwrap();
    let problems = verify(&out).unwrap();
    assert!(
        problems.iter().any(|p| p.contains("SHA-256")),
        "{problems:?}"
    );

    // Exports are create-only: an existing directory is refused.
    assert!(
        export(&store, T, &day(), false, "again", &out, now())
            .await
            .is_err()
    );
    // Every export leaves an audit entry in the store.
    assert_eq!(
        store
            .list(&format!("v1/tenant={T}/audit/"))
            .await
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn hold_copies_matching_objects_and_release_is_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalStore::new(&dir.path().join("store")).unwrap();
    seed(&store).await;
    let mut q = day();
    q.operation = Some("set-mailbox".into());
    let m = create_hold(&store, T, "case-1", "Matter 2026-17", &q, now())
        .await
        .unwrap();
    assert_eq!(m.records.len(), 2);
    assert_eq!(
        m.objects.len(),
        2,
        "only objects holding a matching record are held"
    );
    assert!(
        m.objects
            .iter()
            .all(|o| o.held_key.starts_with("holds/case-1/v1/"))
    );
    for o in &m.objects {
        assert_eq!(
            store.get(&o.held_key).await.unwrap(),
            store.get(&o.key).await.unwrap()
        );
    }
    assert!(
        create_hold(&store, T, "case-1", "again", &q, now())
            .await
            .is_err(),
        "hold ids are unique"
    );
    assert!(
        create_hold(&store, T, "case-2", "  ", &q, now())
            .await
            .is_err(),
        "a reason is required"
    );

    let holds = list_holds(&store, T).await.unwrap();
    assert_eq!(holds.len(), 1);
    assert_eq!(holds[0]["state"], "active");
    release_hold(&store, T, "case-1", "matter closed", now())
        .await
        .unwrap();
    let holds: Vec<Value> = list_holds(&store, T).await.unwrap();
    assert_eq!(holds[0]["state"], "released");
    assert!(
        release_hold(&store, T, "case-1", "twice", now())
            .await
            .is_err()
    );
    // Release never deletes the held copies.
    for o in &m.objects {
        assert!(store.get(&o.held_key).await.unwrap().is_some());
    }
}

/// A store whose holds always fail, to prove hold creation fails closed.
struct NoHolds(LocalStore);
impl ObjectStore for NoHolds {
    fn describe(&self) -> String {
        "no-holds".into()
    }
    fn put_new<'a>(
        &'a self,
        k: &'a str,
        b: Vec<u8>,
        c: &'a str,
    ) -> BoxFut<'a, anyhow::Result<PutOutcome>> {
        self.0.put_new(k, b, c)
    }
    fn get<'a>(&'a self, k: &'a str) -> BoxFut<'a, anyhow::Result<Option<Vec<u8>>>> {
        self.0.get(k)
    }
    fn list<'a>(&'a self, p: &'a str) -> BoxFut<'a, anyhow::Result<Vec<String>>> {
        self.0.list(p)
    }
    fn hold<'a>(&'a self, _: &'a str, _: &'a str) -> BoxFut<'a, anyhow::Result<HoldOutcome>> {
        Box::pin(async {
            anyhow::bail!("legal hold failed: HTTP 403 AuthorizationPermissionMismatch")
        })
    }
    fn release<'a>(&'a self, k: &'a str) -> BoxFut<'a, anyhow::Result<()>> {
        self.0.release(k)
    }
    fn delete_probe<'a>(
        &'a self,
        k: &'a str,
    ) -> BoxFut<'a, anyhow::Result<junction_archive::store::DeleteProbe>> {
        self.0.delete_probe(k)
    }
    fn retention_until<'a>(&'a self, k: &'a str) -> BoxFut<'a, anyhow::Result<Option<String>>> {
        self.0.retention_until(k)
    }
}

#[tokio::test]
async fn hold_fails_closed_and_names_the_objects() {
    let dir = tempfile::tempdir().unwrap();
    let store = NoHolds(LocalStore::new(dir.path()).unwrap());
    seed(&store).await;
    let error = create_hold(&store, T, "case-9", "reason", &day(), now())
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("3 of 3 object(s) could not be held"),
        "{error}"
    );
    assert!(error.contains("AuthorizationPermissionMismatch"));
    let holds = list_holds(&store, T).await.unwrap();
    assert_eq!(
        holds[0]["state"], "incomplete",
        "the failed attempt is still recorded"
    );
}

#[tokio::test]
async fn offline_gap_filed_after_the_range_still_reaches_the_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalStore::new(&dir.path().join("store")).unwrap();
    // The collector was offline from 1 to 15 November; the resumed window's
    // manifest is filed on 15 November, after the exported range.
    let resumed = Instant::parse("2026-11-15T00:00:00Z").unwrap();
    let m = Manifest::new(
        T,
        "o365:Audit.Exchange",
        "run-9",
        resumed,
        resumed.plus(std::time::Duration::from_secs(86_400)),
        true,
        vec![],
        vec![Gap::new(
            Instant::parse("2026-11-01T00:00:00Z").unwrap(),
            resumed,
            "collector was offline",
        )],
        None,
    );
    let (key, bytes, _) = m.encode().unwrap();
    store
        .put_new(&key, bytes, "application/json")
        .await
        .unwrap();
    let q = Query {
        from: "2026-11-03T00:00:00Z".into(),
        to: "2026-11-04T00:00:00Z".into(),
        sources: vec!["o365:Audit.Exchange".into()],
        ..Query::default()
    };
    let e = export(
        &store,
        T,
        &q,
        false,
        "incident",
        &dir.path().join("b"),
        now(),
    )
    .await
    .unwrap();
    let gaps = e.manifest["gaps"].as_array().unwrap();
    // Within eight days after the range the recorded gap itself is found; in
    // every case the period is reported as uncovered, so a bundle never shows
    // an outage as complete.
    assert!(
        gaps.iter().any(|g| g["kind"] == "uncovered"
            && g["from"] == "2026-11-03T00:00:00.000Z"
            && g["to"] == "2026-11-04T00:00:00.000Z"),
        "{gaps:?}"
    );
    let q = Query {
        from: "2026-11-10T00:00:00Z".into(),
        to: "2026-11-11T00:00:00Z".into(),
        sources: vec!["o365:Audit.Exchange".into()],
        ..Query::default()
    };
    let e = export(
        &store,
        T,
        &q,
        false,
        "incident",
        &dir.path().join("c"),
        now(),
    )
    .await
    .unwrap();
    let gaps = e.manifest["gaps"].as_array().unwrap();
    assert!(
        gaps.iter().any(|g| g["reason"] == "collector was offline"),
        "{gaps:?}"
    );
}

#[tokio::test]
async fn complete_windows_leave_no_uncovered_gap_and_redacted_query_hides_the_actor() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalStore::new(&dir.path().join("store")).unwrap();
    seed(&store).await;
    let start = Instant::parse("2026-11-01T00:00:00Z").unwrap();
    let m = Manifest::new(
        T,
        "o365:Audit.Exchange",
        "run-1",
        start,
        start.plus(std::time::Duration::from_secs(86_400)),
        true,
        vec![],
        vec![],
        None,
    );
    let (key, bytes, _) = m.encode().unwrap();
    store
        .put_new(&key, bytes, "application/json")
        .await
        .unwrap();
    let mut q = day();
    q.actor = Some("person@example.test".into());
    let out = dir.path().join("b");
    let e = export(&store, T, &q, false, "IRAP", &out, now())
        .await
        .unwrap();
    assert!(
        e.manifest["gaps"].as_array().unwrap().is_empty(),
        "{}",
        e.manifest["gaps"]
    );
    let manifest = std::fs::read_to_string(out.join("manifest.json")).unwrap();
    assert!(!manifest.contains("person@example.test"), "{manifest}");
    assert!(verify(&out).unwrap().is_empty());
}

#[tokio::test]
async fn verify_detects_an_edited_query_and_repeated_records() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalStore::new(&dir.path().join("store")).unwrap();
    seed(&store).await;
    let out = dir.path().join("b");
    export(&store, T, &day(), true, "incident", &out, now())
        .await
        .unwrap();
    let path = out.join("manifest.json");
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(false);
    std::fs::set_permissions(&path, perms).unwrap();
    let mut m: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    m["query"]["to"] = json!("2026-11-30T00:00:00Z");
    std::fs::write(&path, serde_json::to_vec(&m).unwrap()).unwrap();
    let problems = verify(&out).unwrap();
    assert!(
        problems.iter().any(|p| p.contains("querySha256")),
        "{problems:?}"
    );
}

/// A read-only store: every put is refused, as for the searcher identity.
struct ReadOnly(LocalStore);
impl ObjectStore for ReadOnly {
    fn describe(&self) -> String {
        "read-only".into()
    }
    fn put_new<'a>(
        &'a self,
        _: &'a str,
        _: Vec<u8>,
        _: &'a str,
    ) -> BoxFut<'a, anyhow::Result<PutOutcome>> {
        Box::pin(async {
            anyhow::bail!("archive write failed: HTTP 403 AuthorizationPermissionMismatch")
        })
    }
    fn get<'a>(&'a self, k: &'a str) -> BoxFut<'a, anyhow::Result<Option<Vec<u8>>>> {
        self.0.get(k)
    }
    fn list<'a>(&'a self, p: &'a str) -> BoxFut<'a, anyhow::Result<Vec<String>>> {
        self.0.list(p)
    }
    fn hold<'a>(&'a self, k: &'a str, h: &'a str) -> BoxFut<'a, anyhow::Result<HoldOutcome>> {
        self.0.hold(k, h)
    }
    fn release<'a>(&'a self, k: &'a str) -> BoxFut<'a, anyhow::Result<()>> {
        self.0.release(k)
    }
    fn delete_probe<'a>(
        &'a self,
        k: &'a str,
    ) -> BoxFut<'a, anyhow::Result<junction_archive::store::DeleteProbe>> {
        self.0.delete_probe(k)
    }
    fn retention_until<'a>(&'a self, k: &'a str) -> BoxFut<'a, anyhow::Result<Option<String>>> {
        self.0.retention_until(k)
    }
}

#[tokio::test]
async fn export_works_for_a_read_only_searcher() {
    let dir = tempfile::tempdir().unwrap();
    let local = LocalStore::new(&dir.path().join("store")).unwrap();
    seed(&local).await;
    let store = ReadOnly(local);
    let out = dir.path().join("b");
    let e = export(&store, T, &day(), false, "IRAP", &out, now())
        .await
        .unwrap();
    assert!(!e.audit_written);
    assert!(e.audit_error.unwrap().contains("403"));
    assert!(verify(&out).unwrap().is_empty());
}

#[tokio::test]
async fn release_keeps_flags_another_hold_needs_and_refuses_on_an_unreadable_hold() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalStore::new(&dir.path().join("store")).unwrap();
    seed(&store).await;
    create_hold(&store, T, "case-a", "a", &day(), now())
        .await
        .unwrap();
    create_hold(&store, T, "case-b", "b", &day(), now())
        .await
        .unwrap();
    // Corrupt case-b's manifest: case-a's release must refuse rather than guess.
    let prefix = format!("v1/tenant={T}/holds/case-b/");
    let bad = format!("{prefix}20261122T000000000Z-create-{}.json", "0".repeat(64));
    store
        .put_new(&bad, b"{}".to_vec(), "application/json")
        .await
        .unwrap();
    let error = release_hold(&store, T, "case-a", "closed", now())
        .await
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("release refused"),
        "{error:#}"
    );
}
