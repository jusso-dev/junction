use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use junction_server::{HttpHost, HttpResponse, ServerConfig};
use serde_json::{Value, json};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tower::ServiceExt;

const TOKEN: &str = "synthetic-junction-server-token-123456789";
struct Host {
    calls: AtomicUsize,
}
impl HttpHost for Host {
    fn handle<'a>(
        &'a self,
        _: &'a str,
        target: &'a str,
        _: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = HttpResponse> + Send + 'a>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            HttpResponse {
                status: 200,
                body: if target == "/oversize" {
                    json!({"private_response":"private-marker".repeat(1_400_000)})
                } else {
                    json!({"status":"ok"})
                },
            }
        })
    }
}
fn config(address: &str, external: bool, token: &str) -> anyhow::Result<ServerConfig> {
    ServerConfig::new(
        address.parse().unwrap(),
        external,
        junction_auth::Secret::new(token.into())?,
    )
}
#[test]
fn external_binding_and_token_validation_are_explicit() {
    assert!(config("127.0.0.1:8080", false, TOKEN).is_ok());
    assert!(config("[::1]:8080", false, TOKEN).is_ok());
    assert!(config("0.0.0.0:8080", false, TOKEN).is_err());
    assert!(config("0.0.0.0:8080", true, TOKEN).is_ok());
    for token in [
        "short",
        "private token contains spaces here",
        &"x".repeat(257),
    ] {
        assert!(config("127.0.0.1:8080", false, token).is_err());
    }
}
#[tokio::test]
async fn authentication_origin_and_body_guards_precede_host_dispatch() {
    let host = Arc::new(Host {
        calls: AtomicUsize::new(0),
    });
    let app = junction_server::router(
        host.clone(),
        config("127.0.0.1:8080", false, TOKEN).unwrap(),
    );
    for (authorization, origin, expected) in [
        (None, None, 401),
        (Some("Bearer private-invalid-credential"), None, 401),
        (Some(TOKEN), None, 401),
        (
            Some("Bearer synthetic-junction-server-token-123456789"),
            Some("https://private-origin.invalid"),
            403,
        ),
    ] {
        let mut request = Request::builder().uri("/health");
        if let Some(value) = authorization {
            request = request.header("authorization", value);
        }
        if let Some(value) = origin {
            request = request.header("origin", value);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), expected);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        assert!(!String::from_utf8_lossy(&body).contains("private"));
    }
    let duplicate = Request::builder()
        .uri("/health")
        .header("authorization", format!("Bearer {TOKEN}"))
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.clone().oneshot(duplicate).await.unwrap().status(), 401);
    let wrong_type = Request::builder()
        .method("POST")
        .uri("/v1/batch")
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(Body::from("{}"))
        .unwrap();
    assert_eq!(app.clone().oneshot(wrong_type).await.unwrap().status(), 415);
    let huge = Request::builder()
        .method("POST")
        .uri("/v1/batch")
        .header("authorization", format!("Bearer {TOKEN}"))
        .header("content-type", "application/json")
        .body(Body::from(vec![b'x'; 16 * 1024 * 1024 + 1]))
        .unwrap();
    assert_eq!(app.clone().oneshot(huge).await.unwrap().status(), 413);
    assert_eq!(host.calls.load(Ordering::SeqCst), 0);
    let lowercase = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .header("authorization", format!("bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(lowercase.status(), 200);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert_eq!(host.calls.load(Ordering::SeqCst), 2);
}
#[tokio::test(start_paused = true)]
async fn stalled_bodies_time_out_without_dispatching() {
    let host = Arc::new(Host {
        calls: AtomicUsize::new(0),
    });
    let app = junction_server::router(
        host.clone(),
        config("127.0.0.1:8080", false, TOKEN).unwrap(),
    );
    let body = Body::from_stream(futures_util::stream::once(std::future::pending::<
        Result<axum::body::Bytes, std::io::Error>,
    >()));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/batch")
                .header("authorization", format!("Bearer {TOKEN}"))
                .header("content-type", "application/json")
                .body(body)
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 408);
    assert_eq!(host.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn request_admission_is_bounded_and_released_when_tasks_end() {
    struct PendingHost;
    impl HttpHost for PendingHost {
        fn handle<'a>(
            &'a self,
            _: &'a str,
            _: &'a str,
            _: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = HttpResponse> + Send + 'a>> {
            Box::pin(std::future::pending())
        }
    }
    let app = junction_server::router(
        Arc::new(PendingHost),
        config("127.0.0.1:8080", false, TOKEN).unwrap(),
    );
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let app = app.clone();
        tasks.push(tokio::spawn(async move {
            app.oneshot(
                Request::builder()
                    .uri("/health")
                    .header("authorization", format!("Bearer {TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
        }));
        tokio::task::yield_now().await;
    }
    let rejected = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), 429);
    for task in tasks {
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }
    // A freed admission slot reaches the pending host again rather than returning 429.
    let admitted = app.oneshot(
        Request::builder()
            .uri("/health")
            .header("authorization", format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .unwrap(),
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), admitted)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn oversized_responses_are_replaced_before_any_payload_is_sent() {
    let host = Arc::new(Host {
        calls: AtomicUsize::new(0),
    });
    let app = junction_server::router(host, config("127.0.0.1:8080", false, TOKEN).unwrap());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/oversize")
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 413);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["status"], "response_too_large");
    assert_eq!(value["execution_may_have_completed"], true);
    assert!(!String::from_utf8_lossy(&body).contains("private-marker"));
}
