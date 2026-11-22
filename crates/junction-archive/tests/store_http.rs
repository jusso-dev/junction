//! Azure Blob and R2 backends against a scripted HTTP double. No network.
use junction_archive::store::{
    AzureBlobStore, BoxFut, Http, HttpReply, HttpRequest, ObjectStore, PutOutcome, R2Credentials,
    R2Store, Retry, StaticToken,
};
use junction_watch::clock::Instant;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};
use zeroize::Zeroizing;

#[derive(Default)]
struct Script {
    replies: Mutex<VecDeque<HttpReply>>,
    seen: Mutex<Vec<HttpRequest>>,
}

impl Script {
    fn new(replies: Vec<HttpReply>) -> Arc<Self> {
        Arc::new(Self {
            replies: Mutex::new(replies.into()),
            seen: Mutex::default(),
        })
    }
    fn seen(&self) -> Vec<HttpRequest> {
        self.seen.lock().unwrap().clone()
    }
}

impl Http for Script {
    fn send(&self, request: HttpRequest) -> BoxFut<'_, anyhow::Result<HttpReply>> {
        Box::pin(async move {
            self.seen.lock().unwrap().push(request);
            self.replies
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("unscripted request"))
        })
    }
}

fn reply(status: u16, headers: &[(&str, &str)], body: &str) -> HttpReply {
    HttpReply {
        status,
        headers: headers
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
        body: body.as_bytes().to_vec(),
    }
}

fn header<'a>(r: &'a HttpRequest, name: &str) -> Option<&'a str> {
    r.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn azure(script: Arc<Script>) -> AzureBlobStore {
    AzureBlobStore::new(
        "https://acct.blob.core.windows.net/",
        "junction-archive",
        script,
        Arc::new(StaticToken("synthetic-token".into())),
        Retry::IMMEDIATE,
    )
    .unwrap()
}

const KEY: &str = "v1/tenant=t/source=graph-signIns/date=2026-10-31/hour=10/ab.ndjson.gz";

#[tokio::test]
async fn azure_put_is_create_only() {
    let script = Script::new(vec![
        reply(201, &[], ""),
        reply(409, &[("x-ms-error-code", "BlobAlreadyExists")], ""),
        reply(412, &[("x-ms-error-code", "ConditionNotMet")], ""),
        reply(
            403,
            &[("x-ms-error-code", "AuthorizationPermissionMismatch")],
            "secret detail",
        ),
    ]);
    let store = azure(script.clone());
    assert_eq!(
        store
            .put_new(KEY, b"x".to_vec(), "application/gzip")
            .await
            .unwrap(),
        PutOutcome::Created
    );
    assert_eq!(
        store
            .put_new(KEY, b"x".to_vec(), "application/gzip")
            .await
            .unwrap(),
        PutOutcome::AlreadyExists
    );
    assert_eq!(
        store
            .put_new(KEY, b"x".to_vec(), "application/gzip")
            .await
            .unwrap(),
        PutOutcome::AlreadyExists
    );
    let error = store
        .put_new(KEY, b"x".to_vec(), "application/gzip")
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        error,
        "archive write failed: HTTP 403 AuthorizationPermissionMismatch"
    );
    let seen = script.seen();
    let put = &seen[0];
    assert_eq!(put.method, "PUT");
    assert_eq!(
        put.url.as_str(),
        format!("https://acct.blob.core.windows.net/junction-archive/{KEY}")
    );
    assert_eq!(header(put, "if-none-match"), Some("*"));
    assert_eq!(header(put, "x-ms-blob-type"), Some("BlockBlob"));
    assert_eq!(header(put, "authorization"), Some("Bearer synthetic-token"));
    assert!(header(put, "x-ms-version").is_some_and(|v| v.as_bytes() >= b"2020-06-12".as_slice()));
}

#[tokio::test]
async fn azure_retries_throttling_and_pages_listings() {
    let page1 = r#"<?xml version="1.0" encoding="utf-8"?><EnumerationResults><Blobs><Blob><Name>v1/a</Name></Blob><Blob><Name>../evil</Name></Blob></Blobs><NextMarker>m2</NextMarker></EnumerationResults>"#;
    let page2 = r#"<EnumerationResults><Blobs><Blob><Name>v1/b</Name></Blob></Blobs><NextMarker/></EnumerationResults>"#;
    let script = Script::new(vec![
        reply(503, &[("retry-after", "0")], ""),
        reply(200, &[], page1),
        reply(200, &[], page2),
    ]);
    let store = azure(script.clone());
    assert_eq!(store.list("v1/").await.unwrap(), ["v1/a", "v1/b"]);
    let seen = script.seen();
    assert_eq!(seen.len(), 3, "the 503 was retried");
    let query = |r: &HttpRequest, k: &str| {
        r.url
            .query_pairs()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.into_owned())
    };
    assert_eq!(query(&seen[1], "comp").as_deref(), Some("list"));
    assert_eq!(query(&seen[1], "prefix").as_deref(), Some("v1/"));
    assert_eq!(query(&seen[2], "marker").as_deref(), Some("m2"));
}

#[tokio::test]
async fn azure_listing_that_repeats_its_marker_fails() {
    let page = r#"<EnumerationResults><Blobs/><NextMarker>same</NextMarker></EnumerationResults>"#;
    let script = Script::new(vec![reply(200, &[], page), reply(200, &[], page)]);
    assert!(azure(script).list("v1/").await.is_err());
}

#[tokio::test]
async fn azure_legal_hold_and_retention() {
    let script = Script::new(vec![
        reply(200, &[("x-ms-legal-hold", "true")], ""),
        reply(200, &[], ""),
        reply(
            200,
            &[(
                "x-ms-immutability-policy-until-date",
                "Sun, 31 Oct 2027 10:00:00 GMT",
            )],
            "",
        ),
        reply(200, &[("x-ms-legal-hold", "false")], ""),
    ]);
    let store = azure(script.clone());
    let held = store.hold(KEY, "case-1").await.unwrap();
    assert_eq!(held.method, "legal_hold_flag");
    assert_eq!(held.held_key, KEY);
    store.release(KEY).await.unwrap();
    assert_eq!(
        store.retention_until(KEY).await.unwrap().as_deref(),
        Some("Sun, 31 Oct 2027 10:00:00 GMT")
    );
    let seen = script.seen();
    assert_eq!(seen[0].url.query(), Some("comp=legalhold"));
    assert_eq!(header(&seen[0], "x-ms-legal-hold"), Some("true"));
    assert_eq!(header(&seen[1], "x-ms-legal-hold"), Some("false"));
    assert_eq!(seen[2].method, "HEAD");
    // A hold the service did not confirm is an error, never a silent success.
    assert!(store.hold(KEY, "case-1").await.is_err());
}

fn r2(script: Arc<Script>) -> R2Store {
    R2Store::new(
        "0123456789abcdef0123456789abcdef",
        "default",
        "junction-archive",
        R2Credentials {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: Zeroizing::new("synthetic-secret".into()),
        },
        script,
        Retry::IMMEDIATE,
    )
    .unwrap()
    .with_clock(|| Instant::parse("2026-11-22T00:00:00Z").unwrap())
}

#[tokio::test]
async fn r2_put_is_signed_and_create_only() {
    let locked = "<Error><Code>ObjectLockedByBucketPolicy</Code></Error>";
    let script = Script::new(vec![
        reply(200, &[], ""),
        reply(412, &[], "<Error><Code>PreconditionFailed</Code></Error>"),
        reply(409, &[], locked),
        reply(409, &[], "<Error><Code>Other</Code></Error>"),
    ]);
    let store = r2(script.clone());
    assert_eq!(
        store
            .put_new(KEY, b"x".to_vec(), "application/gzip")
            .await
            .unwrap(),
        PutOutcome::Created
    );
    assert_eq!(
        store
            .put_new(KEY, b"x".to_vec(), "application/gzip")
            .await
            .unwrap(),
        PutOutcome::AlreadyExists
    );
    assert_eq!(
        store
            .put_new(KEY, b"x".to_vec(), "application/gzip")
            .await
            .unwrap(),
        PutOutcome::AlreadyExists
    );
    assert!(
        store
            .put_new(KEY, b"x".to_vec(), "application/gzip")
            .await
            .is_err()
    );
    let put = &script.seen()[0];
    assert_eq!(
        put.url.as_str(),
        format!(
            "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com/junction-archive/{KEY}"
        )
    );
    assert_eq!(header(put, "if-none-match"), Some("*"));
    assert_eq!(header(put, "x-amz-date"), Some("20261122T000000Z"));
    let auth = header(put, "authorization").unwrap();
    assert!(auth.starts_with(
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261122/auto/s3/aws4_request, SignedHeaders="
    ));
    assert!(
        auth.contains("if-none-match"),
        "the create-only condition is signed"
    );
    assert!(!auth.contains("synthetic-secret"));
}

#[tokio::test]
async fn r2_lists_with_continuation_and_holds_by_copy() {
    let page1 = "<ListBucketResult><Contents><Key>v1/a</Key></Contents><IsTruncated>true</IsTruncated><NextContinuationToken>t2</NextContinuationToken></ListBucketResult>";
    let page2 = "<ListBucketResult><Contents><Key>v1/b</Key></Contents><IsTruncated>false</IsTruncated></ListBucketResult>";
    let script = Script::new(vec![
        reply(200, &[], page1),
        reply(200, &[], page2),
        reply(200, &[], "gzip-bytes"),
        reply(200, &[], ""),
    ]);
    let store = r2(script.clone());
    assert_eq!(store.list("v1/").await.unwrap(), ["v1/a", "v1/b"]);
    let held = store.hold("v1/a", "case-7").await.unwrap();
    assert_eq!(held.method, "copied_to_hold_prefix");
    assert_eq!(held.held_key, "holds/case-7/v1/a");
    let seen = script.seen();
    assert!(
        seen[1]
            .url
            .query()
            .unwrap()
            .contains("continuation-token=t2")
    );
    assert_eq!(seen[3].method, "PUT");
    assert!(
        seen[3]
            .url
            .path()
            .ends_with("/junction-archive/holds/case-7/v1/a")
    );
    assert_eq!(seen[3].body, b"gzip-bytes");
}

#[test]
fn r2_inputs_are_validated() {
    let creds = || R2Credentials {
        access_key_id: "a".into(),
        secret_access_key: Zeroizing::new("b".into()),
    };
    let http: Arc<Script> = Script::new(vec![]);
    assert!(
        R2Store::new(
            "short",
            "default",
            "bucket",
            creds(),
            http.clone(),
            Retry::IMMEDIATE
        )
        .is_err()
    );
    assert!(
        R2Store::new(
            "0123456789abcdef0123456789abcdef",
            "mars",
            "bucket",
            creds(),
            http.clone(),
            Retry::IMMEDIATE
        )
        .is_err()
    );
    assert!(
        R2Store::new(
            "0123456789abcdef0123456789abcdef",
            "eu",
            "Bad_Bucket",
            creds(),
            http,
            Retry::IMMEDIATE
        )
        .is_err()
    );
}
