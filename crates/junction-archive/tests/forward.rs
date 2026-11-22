//! Forward fixtures: only selected events leave, each once per destination,
//! and Bower envelopes validate against the vendored 1.0.0 schema.
use junction_archive::{
    checkpoint::Checkpoint,
    forward::{BowerSender, Destination, bower_event, forward, select},
    record::{ArchiveRecord, encode},
    search::Query,
    store::{BoxFut, LocalStore, ObjectStore, Retry},
};
use junction_check::gateway::{BoxFut as CheckFut, CallError};
use junction_watch::{backoff::Backoff, clock::Instant};
use serde_json::{Value, json};
use std::{collections::VecDeque, sync::Mutex};

const T: &str = "11111111-1111-4111-8111-111111111111";
const SCHEMA: &str = include_str!("../data/bower-security-event-1.0.0.schema.json");

fn audit(id: &str, op: &str, result: &str) -> ArchiveRecord {
    let raw = json!({"id": id, "activityDateTime": "2026-11-01T10:00:00Z", "activityDisplayName": op,
                     "result": result, "correlationId": "c-1",
                     "initiatedBy": {"user": {"userPrincipalName": "admin@example.test"}},
                     "targetResources": [{"id": "t-1", "type": "User"}]});
    let e = junction_watch::graph::normalise(
        T,
        "graph:directoryAudits",
        &raw,
        Instant::parse("2026-11-02T00:00:00Z").unwrap(),
    )
    .unwrap();
    ArchiveRecord::from_event(&e, &raw, None)
}

async fn seed(store: &dyn ObjectStore) {
    let records = vec![
        audit("1", "Add member to role", "success"),
        audit("2", "Consent to application", "success"),
        audit("3", "Update user", "success"),
        audit("4", "Add member to role", "failure"),
    ];
    for o in encode(T, records).unwrap() {
        store
            .put_new(&o.key, o.bytes, "application/gzip")
            .await
            .unwrap();
    }
}

fn day() -> Query {
    Query {
        from: "2026-11-01T00:00:00Z".into(),
        to: "2026-11-02T00:00:00Z".into(),
        ..Query::default()
    }
}

struct FakeBower {
    statuses: Mutex<VecDeque<u16>>,
    sent: Mutex<Vec<Value>>,
}
impl FakeBower {
    fn new(statuses: &[u16]) -> Self {
        Self {
            statuses: Mutex::new(statuses.iter().copied().collect()),
            sent: Mutex::default(),
        }
    }
}
impl BowerSender for FakeBower {
    fn post<'a>(&'a self, event: &'a Value) -> BoxFut<'a, anyhow::Result<u16>> {
        Box::pin(async move {
            self.sent.lock().unwrap().push(event.clone());
            Ok(self.statuses.lock().unwrap().pop_front().unwrap_or(202))
        })
    }
}

#[test]
fn bower_envelopes_validate_against_the_published_schema() {
    let schema: Value = serde_json::from_str(SCHEMA).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    for record in [
        audit("1", "Add member to role", "success"),
        audit("2", "Consent to application", "success"),
    ] {
        let rule = select(&record, &[]).unwrap();
        let event = bower_event(&record, rule, "production");
        let errors: Vec<String> = validator
            .iter_errors(&event)
            .map(|e| e.to_string())
            .collect();
        assert!(errors.is_empty(), "{errors:?}\n{event:#}");
    }
}

#[tokio::test]
async fn only_selected_events_are_forwarded_once_with_backpressure_retried() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalStore::new(&dir.path().join("store")).unwrap();
    seed(&store).await;
    let mut cp = Checkpoint::open(&dir.path().join("state"), T).unwrap();
    let bower = FakeBower::new(&[503, 202, 200]);
    let summary = forward(
        &store,
        &mut cp,
        "bower-test",
        &day(),
        &[],
        Destination::Bower {
            sender: &bower,
            environment: "production",
        },
        Retry::IMMEDIATE,
        Backoff::IMMEDIATE,
    )
    .await
    .unwrap();
    assert_eq!(summary.scanned, 4);
    assert_eq!(
        summary.selected, 2,
        "an ordinary update and a failed role grant stay in the archive"
    );
    assert_eq!(summary.sent, 2);
    assert_eq!(bower.sent.lock().unwrap().len(), 3, "one 503 was retried");
    let text = serde_json::to_string(&*bower.sent.lock().unwrap()).unwrap();
    assert!(
        !text.contains("admin@example.test"),
        "identifiers are pseudonymised"
    );

    // A second pass sends nothing: the cursor remembers both.
    let again = FakeBower::new(&[]);
    let mut cp = Checkpoint::open(&dir.path().join("state"), T).unwrap();
    let summary = forward(
        &store,
        &mut cp,
        "bower-test",
        &day(),
        &[],
        Destination::Bower {
            sender: &again,
            environment: "production",
        },
        Retry::IMMEDIATE,
        Backoff::IMMEDIATE,
    )
    .await
    .unwrap();
    assert_eq!(summary.already_forwarded, 2);
    assert!(again.sent.lock().unwrap().is_empty());
}

#[tokio::test]
async fn bower_scope_refusal_stops_and_keeps_progress() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalStore::new(&dir.path().join("store")).unwrap();
    seed(&store).await;
    let mut cp = Checkpoint::open(&dir.path().join("state"), T).unwrap();
    let bower = FakeBower::new(&[202, 403]);
    let error = forward(
        &store,
        &mut cp,
        "bower-test",
        &day(),
        &[],
        Destination::Bower {
            sender: &bower,
            environment: "production",
        },
        Retry::IMMEDIATE,
        Backoff::IMMEDIATE,
    )
    .await
    .unwrap_err();
    assert!(format!("{error:#}").contains("producer scope"), "{error:#}");
    let cp = Checkpoint::open(&dir.path().join("state"), T).unwrap();
    assert_eq!(
        cp.get("forward:bower-test").unwrap().recent_records.len(),
        1,
        "the delivered event is remembered"
    );
}

struct CaptureSentinel(Mutex<Vec<Value>>);
impl junction_check::push::Sender for CaptureSentinel {
    fn send<'a>(&'a self, input: Value) -> CheckFut<'a, Result<(), CallError>> {
        Box::pin(async move {
            self.0.lock().unwrap().push(input);
            Ok(())
        })
    }
}

#[tokio::test]
async fn sentinel_rows_are_redacted_summaries_narrowed_by_only() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalStore::new(&dir.path().join("store")).unwrap();
    seed(&store).await;
    let mut cp = Checkpoint::open(&dir.path().join("state"), T).unwrap();
    let target = junction_check::push::PushTarget::parse(
        "https://dce.example.ingest.monitor.azure.com/",
        "dcr-0123456789abcdef0123456789abcdef",
        "Custom-JunctionArchive_CL",
    )
    .unwrap();
    let sender = CaptureSentinel(Mutex::default());
    let summary = forward(
        &store,
        &mut cp,
        "sentinel-test",
        &day(),
        &["app-consent-granted".into()],
        Destination::Sentinel {
            target: &target,
            sender: &sender,
        },
        Retry::IMMEDIATE,
        Backoff::IMMEDIATE,
    )
    .await
    .unwrap();
    assert_eq!(summary.sent, 1);
    let inputs = sender.0.lock().unwrap().clone();
    assert_eq!(inputs.len(), 1);
    let rows = inputs[0]["body"].as_array().unwrap();
    assert_eq!(rows[0]["Rule"], "app-consent-granted");
    assert_eq!(
        inputs[0]["parameters"]["stream"],
        "Custom-JunctionArchive_CL"
    );
    let text = inputs[0].to_string();
    assert!(
        !text.contains("admin@example.test") && !text.contains("\"raw\""),
        "{text}"
    );
    assert!(
        forward(
            &store,
            &mut cp,
            "sentinel-test",
            &day(),
            &["all".into()],
            Destination::Sentinel {
                target: &target,
                sender: &sender
            },
            Retry::IMMEDIATE,
            Backoff::IMMEDIATE
        )
        .await
        .is_err(),
        "the selector cannot be widened"
    );
}
