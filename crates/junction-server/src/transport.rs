use crate::HttpResponse;
use anyhow::{Result, bail};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{StatusCode, header},
    response::Response,
};
use junction_auth::Secret;
use serde_json::json;
use std::{future::Future, io::Write, net::SocketAddr, pin::Pin, sync::Arc, time::Duration};
use subtle::ConstantTimeEq;

pub const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Only fixed messages may cross the CLI error-reporting boundary.
#[derive(Debug)]
pub enum ServerError {
    TokenMissing,
    TokenInvalid,
    ExternalBindDisabled,
    BindFailed,
    ListenerFailed,
}
impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TokenMissing => {
                "configured server token environment variable is missing or invalid"
            }
            Self::TokenInvalid => {
                "server token must contain 32 to 256 ASCII letters, digits, or -_.~ characters"
            }
            Self::ExternalBindDisabled => "external listening requires --allow-external",
            Self::BindFailed => "could not bind Junction HTTP listener",
            Self::ListenerFailed => "Junction HTTP listener failed",
        })
    }
}
impl std::error::Error for ServerError {}

pub trait HttpHost: Send + Sync + 'static {
    fn handle<'a>(
        &'a self,
        method: &'a str,
        target: &'a str,
        body: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = HttpResponse> + Send + 'a>>;
}

/// Listener configuration deliberately has no Debug/Serialize implementation.
pub struct ServerConfig {
    listen: SocketAddr,
    token: Secret,
}
impl ServerConfig {
    pub fn new(listen: SocketAddr, allow_external: bool, token: Secret) -> Result<Self> {
        if !listen.ip().is_loopback() && !allow_external {
            bail!(ServerError::ExternalBindDisabled);
        }
        let value = token.expose();
        if !(32..=256).contains(&value.len())
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.~".contains(&b))
        {
            bail!(ServerError::TokenInvalid);
        }
        Ok(Self { listen, token })
    }
}
struct AppState {
    host: Arc<dyn HttpHost>,
    config: ServerConfig,
    bodies: tokio::sync::Semaphore,
}
pub fn router(host: Arc<dyn HttpHost>, config: ServerConfig) -> Router {
    Router::new()
        .fallback(request)
        .with_state(Arc::new(AppState {
            host,
            config,
            bodies: tokio::sync::Semaphore::new(16),
        }))
}
pub async fn serve(host: Arc<dyn HttpHost>, config: ServerConfig) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .map_err(|_| ServerError::BindFailed)?;
    let address = listener.local_addr()?;
    eprintln!("Junction HTTP listening on {address}");
    axum::serve(listener, router(host, config))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|_| ServerError::ListenerFailed.into())
}
fn failure(status: u16, kind: &'static str, reason: &'static str) -> Response {
    response(HttpResponse {
        status,
        body: json!({"status":kind,"reason":reason}),
    })
}
async fn request(State(state): State<Arc<AppState>>, request: Request) -> Response {
    // No browser-origin access or permissive CORS to a credential-bearing local service.
    if request.headers().contains_key(header::ORIGIN) {
        return failure(
            403,
            "origin_rejected",
            "Browser-origin requests are not supported",
        );
    }
    let mut authorization = request.headers().get_all(header::AUTHORIZATION).iter();
    let supplied = authorization
        .next()
        .and_then(|h| h.to_str().ok())
        .and_then(|h| {
            h.get(..7)
                .filter(|prefix| prefix.eq_ignore_ascii_case("Bearer "))
                .and_then(|_| h.get(7..))
        });
    if authorization.next().is_some()
        || supplied.is_none_or(|value| {
            !bool::from(
                value
                    .as_bytes()
                    .ct_eq(state.config.token.expose().as_bytes()),
            )
        })
    {
        return failure(
            401,
            "unauthorized",
            "A valid Junction server bearer token is required",
        );
    }
    let _permit = match state.bodies.try_acquire() {
        Ok(permit) => permit,
        Err(_) => return failure(429, "server_busy", "Request capacity is exhausted"),
    };
    let (parts, body) = request.into_parts();
    if parts.uri.scheme().is_some() || parts.uri.authority().is_some() {
        return failure(
            400,
            "invalid_request",
            "Absolute request targets are not supported",
        );
    }
    if parts.method == axum::http::Method::POST
        && parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .is_none_or(|h| {
                !h.split(';')
                    .next()
                    .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
            })
    {
        return failure(415, "invalid_request", "POST requires application/json");
    }
    let body =
        match tokio::time::timeout(Duration::from_secs(10), to_bytes(body, MAX_BODY_BYTES)).await {
            Ok(Ok(body)) => body,
            Ok(Err(_)) => {
                return failure(
                    413,
                    "invalid_request",
                    "Request body could not be read within its limit",
                );
            }
            Err(_) => return failure(408, "request_timed_out", "Request body timeout exceeded"),
        };
    let target = parts
        .uri
        .path_and_query()
        .map(|v| v.as_str())
        .unwrap_or("/");
    response(
        state
            .host
            .handle(parts.method.as_str(), target, &body)
            .await,
    )
}
struct Bounded(Vec<u8>);
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_BODY_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("response limit exceeded"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn response(value: HttpResponse) -> Response {
    let mut buffer = Bounded(Vec::new());
    let status = if serde_json::to_writer(&mut buffer, &value.body).is_ok() {
        value.status
    } else {
        buffer.0 = br#"{"status":"response_too_large","reason":"Reduce retrieval bounds or narrow API projections","execution_may_have_completed":true}"#.to_vec();
        413
    };
    let mut builder = Response::builder();
    if status == 401 {
        builder = builder.header(header::WWW_AUTHENTICATE, "Bearer realm=\"Junction\"");
    }
    builder
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff")
        .body(Body::from(buffer.0))
        .expect("fixed valid response headers")
}
