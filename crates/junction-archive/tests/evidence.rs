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
    assert_eq!(e.manifest["gaps"].as_array().unwrap().len(), 1);
    assert_eq!(e.manifest["gaps"][0]["reason"], "blob quarantined");
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
    fn delete_refused<'a>(&'a self, k: &'a str) -> BoxFut<'a, anyhow::Result<bool>> {
        self.0.delete_refused(k)
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
