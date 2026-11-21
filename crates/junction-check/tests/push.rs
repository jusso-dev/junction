use junction_auth::{AccessToken, AuthFlow, Secret, TokenMetadata, TokenRequest};
use junction_check::gateway::{BoxFut, CallError, FailureKind, LiveTarget, TokenProvider};
use junction_check::model::RunReport;
use junction_check::push::{self, PushTarget, Sender};
use junction_core::OperationRisk;
use junction_core::cloud::MicrosoftCloud;
use junction_policy::{AgentMode, Policy};
use junction_watch::backoff::Backoff;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

const DCE: &str = "https://junction-dce-a1b2.australiaeast-1.ingest.monitor.example";
const DCR: &str = "dcr-0123456789abcdef0123456789abcdef";
const TENANT_A: &str = "00000000-0000-4000-8000-00000000000a";
const TENANT_B: &str = "00000000-0000-4000-8000-00000000000b";
const WORKSPACE_TENANT: &str = "00000000-0000-4000-8000-0000000000ff";
const COLUMNS: [&str; 13] = [
    "TimeGenerated",
    "RunId",
    "EntraTenantId",
    "TenantLabel",
    "CheckId",
    "Pack",
    "Status",
    "Severity",
    "Score",
    "PackScore",
    "Tags",
    "Summary",
    "Attested",
];

fn target() -> PushTarget {
    PushTarget::parse(DCE, DCR, push::DEFAULT_STREAM).unwrap()
}

fn score(score: Option<f64>) -> Value {
    json!({"score": score, "counted": 2, "excluded": 0,
        "statuses": {"pass": 1, "fail": 1, "warn": 0, "unknown": 0, "not_applicable": 0}})
}

fn result(id: &str, status: &str, severity: &str, summary: &str, attested: bool) -> Value {
    let mut value = json!({
        "id": id,
        "title": "Synthetic check",
        "pack": "identity",
        "kind": "automated",
        "status": status,
        "severity": severity,
        "effort": "low",
        "impact": "high",
        "evidence": {"summary": summary, "data": {"secretish": "raw-evidence-value", "count": 3}},
        "affected": {"total": 1, "items": ["admin@contoso.example"]},
        "remediation": {"text": "Do the thing.", "links": []},
        "references": [],
        "tags": {
            "essential_eight": [{"strategy": "mfa", "levels": [1, 2]}],
            "ism": ["ISM-1504"],
            "mitre": ["T1078"]
        }
    });
    if attested {
        value["attested"] = json!({"answer": "yes", "note": "n", "author": "ops@contoso.example",
            "attested_at": "2026-10-01T00:00:00Z", "expires_at": "2027-10-01T00:00:00Z"});
    }
    value
}

fn report(results: Vec<Value>) -> RunReport {
    serde_json::from_value(json!({
        "schema_version": "1.0",
        "run_id": "20261025t010203-0011223344556677",
        "tool": {"name": "junction", "version": "0.0.0"},
        "started_at": "2026-10-25T01:02:03Z",
        "finished_at": "2026-10-25T01:04:05Z",
        "selection": {},
        "tenants": [
            {
                "tenant_id": TENANT_A,
                "label": "Contoso",
                "status": "complete",
                "score": score(Some(62.5)),
                "packs": [{"pack": "identity", "score": 50.0, "counted": 2, "excluded": 0,
                    "statuses": {"pass": 1, "fail": 1, "warn": 0, "unknown": 0, "not_applicable": 0}}],
                "quick_wins": [],
                "results": results
            },
            {
                "tenant_id": TENANT_B,
                "status": "failed",
                "error": {"code": "auth_failed", "detail": "credential refused"},
                "score": score(None),
                "packs": [],
                "quick_wins": [],
                "results": []
            }
        ]
    }))
    .unwrap()
}

fn sample() -> RunReport {
    report(vec![
        result(
            "identity.global_admin_count",
            "fail",
            "high",
            "Seven global admins.",
            false,
        ),
        result("identity.break_glass", "pass", "medium", "Attested.", true),
    ])
}

#[test]
fn embedded_operation_is_the_only_one_and_is_a_write() {
    let registry = push::registry().unwrap();
    assert_eq!(registry.all().count(), 1);
    let op = registry.resolve(push::OPERATION, None, false).unwrap();
    assert_eq!(op.method, "POST");
    assert_eq!(op.path, "/dataCollectionRules/{ruleId}/streams/{stream}");
    assert_eq!(op.api_version.as_deref(), Some("2023-01-01"));
    assert_eq!(op.risk, OperationRisk::Write);
    let template = op.endpoint_template.as_ref().unwrap();
    assert_eq!(template.template, "{endpoint}");
    assert!(template.variables["endpoint"].default.is_none());
    assert!(op.source.id.ends_with(
        "specification/monitor/data-plane/Ingestion/stable/2023-01-01/DataCollectionRules.json"
    ));
    // The endpoint has no default: without an operator binding it cannot resolve.
    assert!(template.resolve(&Default::default()).is_err());
}

#[test]
fn target_is_validated_without_echoing_values() {
    let t = target();
    assert_eq!(t.dcr_immutable_id, DCR);
    assert_eq!(t.endpoint().unwrap(), DCE);
    let upper = PushTarget::parse(
        DCE,
        &DCR.to_ascii_uppercase().replace("DCR-", "dcr-"),
        "Custom-X",
    )
    .unwrap();
    assert_eq!(upper.dcr_immutable_id, DCR);
    for (dce, dcr, stream) in [
        ("http://dce.example", DCR, "Custom-X"),
        ("https://user:hunter2@dce.example", DCR, "Custom-X"),
        ("https://dce.example/?sig=hunter2", DCR, "Custom-X"),
        ("https://dce.example/#hunter2", DCR, "Custom-X"),
        ("https://dce.example/hunter2", DCR, "Custom-X"),
        ("not a url hunter2", DCR, "Custom-X"),
        (DCE, "dcr-hunter2", "Custom-X"),
        (DCE, "0123456789abcdef0123456789abcdef", "Custom-X"),
        (DCE, "dcr-0123456789abcdef0123456789abcdeg", "Custom-X"),
        (DCE, DCR, "JunctionCheck_CL"),
        (DCE, DCR, "Custom-"),
        (DCE, DCR, "Custom-a/../hunter2"),
        (DCE, DCR, "Custom-a?x=hunter2"),
    ] {
        let error = PushTarget::parse(dce, dcr, stream).unwrap_err().to_string();
        assert!(!error.contains("hunter2"), "{error}");
    }
    let long = format!("Custom-{}", "a".repeat(121));
    assert!(PushTarget::parse(DCE, DCR, &long).is_ok());
    assert!(PushTarget::parse(DCE, DCR, &format!("{long}a")).is_err());
}

#[test]
fn rows_carry_only_the_documented_columns() {
    let rows = push::rows(&sample());
    assert_eq!(rows.len(), 3);
    let expected: BTreeSet<&str> = COLUMNS.into_iter().collect();
    for row in &rows {
        let keys: BTreeSet<&str> = row
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, expected);
        let text = row.to_string();
        assert!(!text.contains("raw-evidence-value"), "evidence data leaked");
        assert!(
            !text.contains("admin@contoso.example"),
            "affected list leaked"
        );
        assert!(!text.contains("Do the thing"), "remediation leaked");
    }
    let failed = &rows[2];
    assert_eq!(failed["CheckId"], "_tenant");
    assert_eq!(failed["Status"], "failed");
    assert_eq!(failed["Summary"], "auth_failed");
    assert_eq!(failed["EntraTenantId"], TENANT_B);
    let fail = &rows[0];
    assert_eq!(
        fail,
        &json!({
            "TimeGenerated": "2026-10-25T01:04:05Z",
            "RunId": "20261025t010203-0011223344556677",
            "EntraTenantId": TENANT_A,
            "TenantLabel": "Contoso",
            "CheckId": "identity.global_admin_count",
            "Pack": "identity",
            "Status": "fail",
            "Severity": "high",
            "Score": 62.5,
            "PackScore": 50.0,
            "Tags": ["e8:mfa:ml1", "e8:mfa:ml2", "ism:ISM-1504", "mitre:T1078"],
            "Summary": "Seven global admins.",
            "Attested": false
        })
    );
    assert_eq!(rows[1]["Attested"], true);
    assert_eq!(failed["Pack"], Value::Null);
    assert_eq!(failed["Score"], Value::Null);
}

#[test]
fn long_summaries_are_truncated() {
    let long = "é".repeat(5000);
    let rows = push::rows(&report(vec![result(
        "identity.x",
        "fail",
        "low",
        &long,
        false,
    )]));
    let summary = rows[0]["Summary"].as_str().unwrap();
    assert_eq!(summary.chars().count(), push::SUMMARY_CHARS);
    assert!(summary.ends_with('…'));
}

fn many(n: usize) -> RunReport {
    report(
        (0..n)
            .map(|i| {
                result(
                    &format!("identity.synthetic_{i}"),
                    "fail",
                    "medium",
                    &"x".repeat(1000),
                    false,
                )
            })
            .collect(),
    )
}

#[test]
fn batches_stay_within_the_byte_limit_and_keep_every_row() {
    let rows = push::rows(&many(2000));
    let total = rows.len();
    let ids: Vec<Value> = rows.iter().map(|r| r["CheckId"].clone()).collect();
    let batches = push::batches(rows, push::MAX_BATCH_BYTES);
    assert!(batches.len() >= 3, "{} batches", batches.len());
    for batch in &batches {
        let bytes = serde_json::to_vec(batch).unwrap().len();
        assert!(bytes <= push::MAX_BATCH_BYTES, "{bytes}");
        assert!(bytes < 1_000_000);
    }
    let flat: Vec<Value> = batches
        .into_iter()
        .flatten()
        .map(|r| r["CheckId"].clone())
        .collect();
    assert_eq!(flat.len(), total);
    assert_eq!(flat, ids, "order preserved");
    assert!(push::batches(vec![], push::MAX_BATCH_BYTES).is_empty());
}

#[test]
fn oversized_rows_are_truncated_not_dropped() {
    let rows = push::rows(&many(3));
    let batches = push::batches(rows.clone(), 600);
    assert_eq!(batches.iter().map(Vec::len).sum::<usize>(), rows.len());
    for batch in &batches {
        assert!(serde_json::to_vec(batch).unwrap().len() <= 600);
    }
    let shrunk = &batches[0][0];
    assert_eq!(shrunk["CheckId"], "identity.synthetic_0");
    assert_eq!(shrunk["Status"], "fail");
    assert!(shrunk["Summary"].as_str().unwrap().len() < 1000);
    // A limit too small for even the fixed columns still sends every row alone.
    let tiny = push::batches(rows.clone(), 10);
    assert_eq!(tiny.len(), rows.len());
}

fn safe_write() -> Policy {
    Policy {
        agent: junction_policy::Agent {
            mode: AgentMode::SafeWrite,
        },
        ..Policy::default()
    }
}

#[test]
fn policy_rule_needs_opt_in_and_an_allowing_policy_or_approval() {
    let read_only = Policy::default();
    assert!(!push::policy_allows(&read_only));
    assert!(push::policy_allows(&safe_write()));
    let full = Policy::parse("[agent]\nmode = 'full'").unwrap();
    assert!(push::policy_allows(&full));
    let denied =
        Policy::parse("[agent]\nmode = 'safe-write'\n[deny]\noperations = ['azure.monitor.*']")
            .unwrap();
    assert!(!push::policy_allows(&denied));
    let other_tenants =
        Policy::parse("[agent]\nmode = 'safe-write'\n[allow]\ntenants = ['contoso.example']")
            .unwrap();
    assert!(push::policy_allows(&other_tenants));

    let off = push::effective_policy(false, &safe_write(), true)
        .unwrap_err()
        .to_string();
    assert!(off.contains("--push-sentinel"), "{off}");
    let refused = push::effective_policy(true, &read_only, false)
        .unwrap_err()
        .to_string();
    assert!(
        refused.contains("safe-write") && refused.contains("approve"),
        "{refused}"
    );
    assert!(refused.contains("docs/APPROVALS.md"), "{refused}");
    let approved = push::effective_policy(true, &read_only, true).unwrap();
    assert_eq!(approved.agent.mode, AgentMode::SafeWrite);
    assert!(push::effective_policy(true, &safe_write(), false).is_ok());
    let deny = push::effective_policy(true, &denied, true)
        .unwrap_err()
        .to_string();
    assert!(deny.contains("deny.operations"), "{deny}");
}

#[test]
fn fixture_request_matches_the_logs_ingestion_contract() {
    let rows = push::rows(&sample());
    let request =
        push::prepare_request(&target(), rows.clone(), WORKSPACE_TENANT, &safe_write()).unwrap();
    assert_eq!(request.method, "POST");
    assert_eq!(request.url.origin(), url::Url::parse(DCE).unwrap().origin());
    assert_eq!(
        request.url.path(),
        format!("/dataCollectionRules/{DCR}/streams/Custom-JunctionCheck_CL")
    );
    // The runtime percent-encodes every query name and value (as for ARM calls);
    // it decodes to exactly api-version=2023-01-01.
    assert_eq!(request.url.query(), Some("api%2Dversion=2023%2D01%2D01"));
    let pairs: Vec<(String, String)> = request.url.query_pairs().into_owned().collect();
    assert_eq!(pairs, [("api-version".to_owned(), "2023-01-01".to_owned())]);
    assert_eq!(request.body, Some(Value::Array(rows)));
    // The runtime declares Content-Type only for non-plain JSON media types; for
    // application/json the transport sets it when serialising the body
    // (reqwest `json`), together with the bearer and client-request-id headers.
    assert!(request.headers.get("content-type").is_none());
    assert!(request.headers.is_empty());

    // The default read-only policy refuses the write before anything is planned.
    let denied = push::prepare_request(&target(), vec![], WORKSPACE_TENANT, &Policy::default());
    assert_eq!(denied.err().unwrap().to_string(), "policy_rejected");
    // A body that is not an array of objects fails schema validation.
    let mut input = push::input(&target(), vec![]);
    input["body"] = json!({"not": "an array"});
    assert!(
        junction_runtime::prepare(
            &push::operation(),
            &input,
            WORKSPACE_TENANT,
            DCE,
            &safe_write()
        )
        .is_err()
    );
}

struct Scripted {
    replies: Mutex<Vec<Result<(), CallError>>>,
    sent: Mutex<Vec<Value>>,
}

impl Scripted {
    fn new(mut replies: Vec<Result<(), CallError>>) -> Self {
        replies.reverse();
        Self {
            replies: Mutex::new(replies),
            sent: Mutex::new(vec![]),
        }
    }
    fn sent(&self) -> Vec<Value> {
        self.sent.lock().unwrap().clone()
    }
}

impl Sender for Scripted {
    fn send<'a>(&'a self, input: Value) -> BoxFut<'a, Result<(), CallError>> {
        self.sent.lock().unwrap().push(input);
        let reply = self.replies.lock().unwrap().pop().unwrap_or(Ok(()));
        Box::pin(async move { reply })
    }
}

fn throttled(after: Option<Duration>) -> CallError {
    let mut error = CallError::http(429, None, None);
    error.retry_after = after;
    error
}

#[tokio::test]
async fn throttling_is_retried_then_succeeds() {
    let sender = Scripted::new(vec![Err(throttled(None)), Ok(())]);
    let summary = push::push(&target(), &sample(), &sender, Backoff::IMMEDIATE)
        .await
        .unwrap();
    assert_eq!(summary.rows, 3);
    assert_eq!(summary.batches, 1);
    assert_eq!(summary.run_id, "20261025t010203-0011223344556677");
    let sent = sender.sent();
    assert_eq!(sent.len(), 2, "429 then 204");
    assert_eq!(sent[0], sent[1], "the same batch is resent");
    assert_eq!(sent[0]["parameters"]["ruleId"], DCR);
    assert_eq!(sent[0]["parameters"]["stream"], "Custom-JunctionCheck_CL");
    assert_eq!(sent[0]["parameters"]["api-version"], "2023-01-01");
    assert_eq!(sent[0]["body"], Value::Array(push::rows(&sample())));
}

#[tokio::test]
async fn retry_after_is_honoured() {
    let backoff = Backoff {
        attempts: 5,
        base: Duration::ZERO,
        cap: Duration::from_secs(5),
    };
    let sender = Scripted::new(vec![
        Err(throttled(Some(Duration::from_millis(60)))),
        Err(CallError::http(503, None, None)),
        Ok(()),
    ]);
    let started = std::time::Instant::now();
    push::push(&target(), &sample(), &sender, backoff)
        .await
        .unwrap();
    assert!(started.elapsed() >= Duration::from_millis(60));
    assert_eq!(sender.sent().len(), 3);

    // A server delay longer than the in-process budget stops with an explanation.
    let sender = Scripted::new(vec![Err(throttled(Some(Duration::from_secs(600))))]);
    let error = push::push(&target(), &sample(), &sender, backoff)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("600 seconds"), "{error}");
    assert_eq!(sender.sent().len(), 1);
}

#[tokio::test]
async fn forbidden_stops_and_names_the_role() {
    let sender = Scripted::new(vec![Err(CallError::http(403, Some("Forbidden"), None))]);
    let error = push::push(&target(), &sample(), &sender, Backoff::IMMEDIATE)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("Monitoring Metrics Publisher on the DCR"),
        "{error}"
    );
    assert_eq!(sender.sent().len(), 1, "403 is not retried");

    let sender = Scripted::new(vec![Err(CallError::http(404, None, None))]);
    let error = push::push(&target(), &sample(), &sender, Backoff::IMMEDIATE)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("--dcr"), "{error}");
    assert_eq!(sender.sent().len(), 1);
}

#[tokio::test]
async fn large_runs_are_sent_in_batches_and_failures_report_progress() {
    let report = many(2000);
    let sender = Scripted::new(vec![]);
    let summary = push::push(&target(), &report, &sender, Backoff::IMMEDIATE)
        .await
        .unwrap();
    let sent = sender.sent();
    assert_eq!(sent.len(), summary.batches);
    assert!(summary.batches >= 3);
    let rows: usize = sent
        .iter()
        .map(|s| s["body"].as_array().unwrap().len())
        .sum();
    assert_eq!(rows, summary.rows);
    assert_eq!(rows, 2001);
    for input in &sent {
        assert!(serde_json::to_vec(&input["body"]).unwrap().len() <= push::MAX_BATCH_BYTES);
    }

    let sender = Scripted::new(vec![
        Ok(()),
        Err(CallError::http(400, Some("InvalidStream"), None)),
    ]);
    let error = push::push(&target(), &report, &sender, Backoff::IMMEDIATE)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("batch 2 of"), "{error}");
    assert!(error.contains("already ingested"), "{error}");
    assert_eq!(sender.sent().len(), 2);
}

#[tokio::test]
async fn empty_reports_send_nothing() {
    let mut report = sample();
    report.tenants.clear();
    let sender = Scripted::new(vec![]);
    let summary = push::push(&target(), &report, &sender, Backoff::IMMEDIATE)
        .await
        .unwrap();
    assert_eq!((summary.rows, summary.batches), (0, 0));
    assert!(sender.sent().is_empty());
}

/// Issues synthetic tokens and records every request, without any network.
struct Tokens {
    audience: &'static str,
    expires_in: Duration,
    requests: Mutex<Vec<TokenRequest>>,
}

impl Tokens {
    fn new(audience: &'static str, expires_in: Duration) -> Arc<Self> {
        Arc::new(Self {
            audience,
            expires_in,
            requests: Mutex::new(vec![]),
        })
    }
    fn requests(&self) -> Vec<TokenRequest> {
        self.requests.lock().unwrap().clone()
    }
}

impl TokenProvider for Tokens {
    fn token<'a>(&'a self, request: TokenRequest) -> BoxFut<'a, Result<AccessToken, CallError>> {
        let token = AccessToken::new(
            Secret::new("synthetic-token".into()).unwrap(),
            TokenMetadata {
                tenant: request.tenant.clone(),
                audience: self.audience.into(),
                expires_at: SystemTime::now() + self.expires_in,
                scopes: vec![],
                roles: vec![],
                account: None,
            },
        );
        self.requests.lock().unwrap().push(request);
        Box::pin(async move { Ok(token) })
    }
}

fn live() -> LiveTarget {
    LiveTarget {
        tenant_id: WORKSPACE_TENANT.into(),
        endpoints: MicrosoftCloud::Public.endpoints().unwrap(),
        credential_profile: "synthetic".into(),
        flow: AuthFlow::ClientCredentials,
    }
}

#[tokio::test]
async fn executor_sender_is_governed_before_any_network() {
    let fresh = Tokens::new(push::AUDIENCE, Duration::from_secs(3600));
    assert!(
        push::ExecutorSender::new(&target(), live(), fresh.clone(), Policy::default()).is_err(),
        "read-only policy is refused"
    );

    // The executor applies the tenant allow-list to the workspace tenant before
    // any token is requested.
    let restricted = Policy::parse(&format!(
        "[agent]\nmode = 'safe-write'\n[allow]\ntenants = ['{TENANT_A}']"
    ))
    .unwrap();
    let sender = push::ExecutorSender::new(&target(), live(), fresh.clone(), restricted).unwrap();
    let error = sender
        .send(push::input(&target(), vec![]))
        .await
        .unwrap_err();
    assert!(
        error
            .message
            .clone()
            .unwrap_or_default()
            .contains("policy denied")
    );
    assert!(!error.is_transient());
    assert!(fresh.requests().is_empty());

    // Credential checks run before transport: an expired token never leaves the
    // machine. The token is requested for the Logs Ingestion audience.
    let expired = Tokens::new(push::AUDIENCE, Duration::ZERO);
    let sender =
        push::ExecutorSender::new(&target(), live(), expired.clone(), safe_write()).unwrap();
    let error = sender
        .send(push::input(&target(), vec![]))
        .await
        .unwrap_err();
    assert_eq!(error.kind, FailureKind::Credential);
    let requests = expired.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].audience, "https://monitor.azure.com");
    assert_eq!(requests[0].tenant, WORKSPACE_TENANT);
    assert_eq!(requests[0].credential_profile, "synthetic");

    // A token issued for another audience is rejected the same way.
    let graph = Tokens::new("https://graph.microsoft.com", Duration::from_secs(3600));
    let sender = push::ExecutorSender::new(&target(), live(), graph, safe_write()).unwrap();
    let error = sender
        .send(push::input(&target(), vec![]))
        .await
        .unwrap_err();
    assert_eq!(error.kind, FailureKind::Credential);

    // Invalid input is refused before a token is requested and is not retried.
    let sender = push::ExecutorSender::new(&target(), live(), fresh.clone(), safe_write()).unwrap();
    let mut input = push::input(&target(), vec![]);
    input["body"] = json!("not an array");
    let error = sender.send(input).await.unwrap_err();
    assert!(!error.is_transient());
    assert!(fresh.requests().is_empty());
}

fn sentinel_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/sentinel")
}

#[test]
fn sentinel_examples_parse_and_match_the_row_columns() {
    let dir = sentinel_dir();
    let workbook: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("workbook.json")).unwrap()).unwrap();
    assert_eq!(workbook["version"], "Notebook/1.0");
    let text = workbook.to_string();
    for needle in ["JunctionCheck_CL", "Score", "EntraTenantId", "Status"] {
        assert!(text.contains(needle), "workbook lacks {needle}");
    }
    for rule in ["score-drop.json", "new-critical-fail.json"] {
        let template: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join("analytic-rules").join(rule)).unwrap(),
        )
        .unwrap();
        let resource = &template["resources"][0];
        assert_eq!(resource["kind"], "Scheduled", "{rule}");
        let query = resource["properties"]["query"].as_str().unwrap();
        assert!(query.contains("JunctionCheck_CL"), "{rule}");
    }
    let bicep = std::fs::read_to_string(dir.join("junction-check-table.bicep")).unwrap();
    for column in COLUMNS {
        assert!(
            bicep.contains(&format!("name: '{column}'")),
            "bicep lacks {column}"
        );
    }
    assert!(bicep.contains(push::DEFAULT_STREAM));
    let readme = std::fs::read_to_string(dir.join("README.md")).unwrap();
    assert!(readme.contains("Monitoring Metrics Publisher"));
    assert!(readme.contains(push::AUDIENCE));
}
