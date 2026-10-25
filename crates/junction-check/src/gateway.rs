//! The only path from a check to Microsoft.
//!
//! Checks call catalogue operations by id through a [`Gateway`]. The live gateway
//! runs every call through Junction's registry, read-only policy and bounded
//! transport; the fixture gateway in [`crate::testkit`] replays recorded responses
//! after the same registry and policy checks. [`Governed`] wraps either with
//! per-host concurrency limits and `Retry-After`-aware backoff.
use crate::catalog;
use junction_auth::{AccessToken, AuthFlow, TokenRequest};
use junction_core::cloud::{CloudEndpoints, CloudService};
use junction_runtime::{ExecutionContext, Executor, PageOptions};
use junction_watch::backoff::Backoff;
pub use junction_watch::upstream::{CallError, FailureKind};
use serde_json::Value;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{Mutex, Semaphore};

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Environment flag that forbids live Microsoft calls (set in CI and by the
/// fixture harness). Any live call then fails before a token is requested.
pub const OFFLINE_ENV: &str = "JUNCTION_CHECK_OFFLINE";

#[derive(Debug, Clone)]
pub enum GatewayError {
    /// Microsoft, or token acquisition, answered with a failure.
    Call(CallError),
    /// Junction's policy refused the operation.
    Denied(String),
    /// The call could not be attempted: operation missing from the catalogue,
    /// service unavailable in the configured cloud, network disabled, or no
    /// recorded fixture.
    Unavailable(String),
}

impl std::fmt::Display for GatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Call(e) => write!(f, "{}", e.summary()),
            Self::Denied(r) => write!(f, "policy denied: {r}"),
            Self::Unavailable(r) => write!(f, "unavailable: {r}"),
        }
    }
}
impl std::error::Error for GatewayError {}

impl GatewayError {
    pub fn call(&self) -> Option<&CallError> {
        match self {
            Self::Call(e) => Some(e),
            _ => None,
        }
    }
    /// The credential itself was refused: the whole tenant is unreachable.
    pub fn is_credential(&self) -> bool {
        matches!(self, Self::Call(e) if e.kind == FailureKind::Credential || e.status == Some(401))
    }
}

/// Items from a paged listing.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Listing {
    pub items: Vec<Value>,
    /// More items existed than the page limits allowed.
    pub truncated: bool,
}

pub trait Gateway: Send + Sync {
    fn tenant_id(&self) -> &str;
    /// One request. `input` is the operation envelope
    /// `{"parameters": {...}, "body": {...}}`; `api-version` is filled in.
    fn get<'a>(
        &'a self,
        operation: &'a str,
        input: Value,
    ) -> BoxFut<'a, Result<Value, GatewayError>>;
    /// A listing, following the operation's declared paging within limits.
    fn list<'a>(
        &'a self,
        operation: &'a str,
        input: Value,
    ) -> BoxFut<'a, Result<Listing, GatewayError>>;
}

/// Add the catalogue's `api-version` when the operation declares one and the
/// caller did not.
pub fn with_api_version(operation: &str, mut input: Value) -> Value {
    let Some(op) = catalog::versions(operation).into_iter().next() else {
        return input;
    };
    if !input.is_object() {
        input = serde_json::json!({});
    }
    if let (Some(version), true) = (
        &op.api_version,
        op.parameters.iter().any(|p| p.name == "api-version"),
    ) {
        let parameters = input
            .as_object_mut()
            .expect("object")
            .entry("parameters")
            .or_insert_with(|| serde_json::json!({}));
        if let Some(map) = parameters.as_object_mut() {
            map.entry("api-version")
                .or_insert_with(|| Value::String(version.clone()));
        }
    }
    input
}

/// Items of a non-paged listing response.
pub fn items_of(body: Value) -> Vec<Value> {
    match body {
        Value::Array(items) => items,
        Value::Object(mut map) => match map.remove("value").or_else(|| map.remove("Results")) {
            Some(Value::Array(items)) => items,
            _ => vec![Value::Object(map)],
        },
        Value::Null => vec![],
        other => vec![other],
    }
}

/// Per-host concurrency and throttling-aware retries around any gateway.
pub struct Governed {
    inner: Arc<dyn Gateway>,
    per_host: usize,
    backoff: Backoff,
    hosts: std::sync::Mutex<BTreeMap<String, Arc<Semaphore>>>,
}

impl Governed {
    pub fn new(inner: Arc<dyn Gateway>, per_host: usize, backoff: Backoff) -> Self {
        Self {
            inner,
            per_host: per_host.max(1),
            backoff,
            hosts: Default::default(),
        }
    }
    fn semaphore(&self, operation: &str) -> Arc<Semaphore> {
        let mut hosts = self.hosts.lock().expect("host limits");
        hosts
            .entry(catalog::host_key(operation))
            .or_insert_with(|| Arc::new(Semaphore::new(self.per_host)))
            .clone()
    }
    async fn retry<T, F, Fut>(&self, operation: &str, mut call: F) -> Result<T, GatewayError>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, GatewayError>>,
    {
        let semaphore = self.semaphore(operation);
        let mut attempt = 0;
        loop {
            let result = {
                let _permit = semaphore.acquire().await.expect("semaphore open");
                call().await
            };
            match result {
                Err(GatewayError::Call(error))
                    if error.is_transient()
                        && attempt + 1 < self.backoff.attempts
                        && error.retry_after.is_none_or(|d| d <= self.backoff.cap) =>
                {
                    let delay = self.backoff.delay(attempt, &error);
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    attempt += 1;
                }
                other => return other,
            }
        }
    }
}

impl Gateway for Governed {
    fn tenant_id(&self) -> &str {
        self.inner.tenant_id()
    }
    fn get<'a>(
        &'a self,
        operation: &'a str,
        input: Value,
    ) -> BoxFut<'a, Result<Value, GatewayError>> {
        Box::pin(async move {
            self.retry(operation, || self.inner.get(operation, input.clone()))
                .await
        })
    }
    fn list<'a>(
        &'a self,
        operation: &'a str,
        input: Value,
    ) -> BoxFut<'a, Result<Listing, GatewayError>> {
        Box::pin(async move {
            self.retry(operation, || self.inner.list(operation, input.clone()))
                .await
        })
    }
}

/// Acquires access tokens for one tenant and audience. The Junction binary
/// implements this with the selected context's credential flow.
pub trait TokenProvider: Send + Sync {
    fn token<'a>(&'a self, request: TokenRequest) -> BoxFut<'a, Result<AccessToken, CallError>>;
}

/// Everything needed to reach one tenant, without secrets.
#[derive(Debug, Clone)]
pub struct LiveTarget {
    pub tenant_id: String,
    pub endpoints: CloudEndpoints,
    pub credential_profile: String,
    pub flow: AuthFlow,
}

/// Whether live calls may leave the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkGuard {
    Allowed,
    Offline,
}

impl NetworkGuard {
    pub fn from_env() -> Self {
        match std::env::var(OFFLINE_ENV) {
            Ok(v) if !v.is_empty() && v != "0" => Self::Offline,
            _ => Self::Allowed,
        }
    }
}

/// Limits for check runs: higher than interactive defaults, still bounded.
pub fn check_policy() -> junction_policy::Policy {
    junction_policy::Policy {
        limits: junction_policy::Limits {
            max_requests_per_minute: 300,
            max_pages: 200,
            max_parallel_requests: 10,
            max_batch_operations: 100,
            max_items: 50_000,
        },
        // Read-only regardless of any context policy: checks never write.
        ..junction_policy::Policy::default()
    }
}

pub struct LiveGateway {
    executor: Executor,
    target: LiveTarget,
    tokens: Arc<dyn TokenProvider>,
    cache: Mutex<BTreeMap<String, Arc<AccessToken>>>,
    guard: NetworkGuard,
}

impl LiveGateway {
    pub fn new(
        target: LiveTarget,
        tokens: Arc<dyn TokenProvider>,
        guard: NetworkGuard,
    ) -> anyhow::Result<Self> {
        target.endpoints.validate()?;
        Ok(Self {
            executor: Executor::new(catalog::registry()?, check_policy())?,
            target,
            tokens,
            cache: Mutex::new(BTreeMap::new()),
            guard,
        })
    }

    async fn token(&self, route: &catalog::Route) -> Result<Arc<AccessToken>, GatewayError> {
        let mut cache = self.cache.lock().await;
        if let Some(token) = cache.get(&route.audience)
            && token.metadata().expires_at > SystemTime::now() + Duration::from_secs(300)
        {
            return Ok(token.clone());
        }
        let request = TokenRequest {
            tenant: self.target.tenant_id.clone(),
            authority: self.target.endpoints.authority.clone(),
            audience: route.audience.clone(),
            scopes: vec![],
            credential_profile: self.target.credential_profile.clone(),
            flow: self.target.flow,
            api_key: None,
        };
        let token = Arc::new(
            self.tokens
                .token(request)
                .await
                .map_err(GatewayError::Call)?,
        );
        cache.insert(route.audience.clone(), token.clone());
        Ok(token)
    }

    async fn prepare(
        &self,
        operation: &str,
        input: &Value,
    ) -> Result<(catalog::Route, Arc<AccessToken>, bool), GatewayError> {
        if self.guard == NetworkGuard::Offline {
            return Err(GatewayError::Unavailable(format!(
                "live Microsoft calls are disabled ({OFFLINE_ENV} is set)"
            )));
        }
        let preview = catalog::preview_only(operation);
        let op = self
            .executor
            .registry()
            .resolve(operation, None, preview)
            .map_err(|_| {
                GatewayError::Unavailable(format!("{operation} is not in the check catalogue"))
            })?;
        let route = catalog::route(op, &self.target.endpoints).map_err(|e| {
            GatewayError::Unavailable(format!("{operation}: {e} in the configured cloud"))
        })?;
        // Policy and input are checked before any credential is requested.
        self.executor
            .preflight(
                operation,
                input,
                &self.target.tenant_id,
                &route.endpoint,
                None,
                preview,
            )
            .map_err(classify_preflight_error)?;
        let token = self.token(&route).await?;
        Ok((route, token, preview))
    }
}

/// Map a refusal from `Executor::preflight` (policy or input validation, before
/// anything is sent).
pub fn classify_preflight_error(error: anyhow::Error) -> GatewayError {
    match error.downcast_ref::<junction_runtime::ExecutionDenied>() {
        Some(denied) => GatewayError::Denied(format!("{:?}", denied.0)),
        None => GatewayError::Unavailable(format!("invalid operation input: {error}")),
    }
}

/// Map a runtime error to safe failure metadata. Never carries bodies or URLs.
pub fn classify_runtime_error(error: anyhow::Error) -> GatewayError {
    if let Some(denied) = error.downcast_ref::<junction_runtime::ExecutionDenied>() {
        return GatewayError::Denied(format!("{:?}", denied.0));
    }
    if let Some(status) = error.downcast_ref::<junction_http::HttpStatusError>() {
        return GatewayError::Call(CallError {
            kind: FailureKind::Http,
            status: Some(status.status),
            code: status.upstream.as_ref().and_then(|u| u.code.clone()),
            message: status.upstream.as_ref().and_then(|u| u.message.clone()),
            retry_after: status.retry_after,
        });
    }
    if let Some(auth) =
        error.downcast_ref::<junction_runtime::authorization::AuthorizationFailure>()
    {
        return GatewayError::Call(CallError {
            kind: FailureKind::Http,
            status: Some(auth.http_status),
            code: auth.upstream.as_ref().and_then(|u| u.code.clone()),
            message: auth.upstream.as_ref().and_then(|u| u.message.clone()),
            retry_after: None,
        });
    }
    let text = error.to_string();
    if text == "request admission rejected" {
        return GatewayError::Call(CallError::other(FailureKind::LocalThrottle, &text));
    }
    if text.starts_with("credential_") {
        return GatewayError::Call(CallError::other(FailureKind::Credential, &text));
    }
    GatewayError::Call(CallError::other(FailureKind::Transport, &text))
}

impl Gateway for LiveGateway {
    fn tenant_id(&self) -> &str {
        &self.target.tenant_id
    }
    fn get<'a>(
        &'a self,
        operation: &'a str,
        input: Value,
    ) -> BoxFut<'a, Result<Value, GatewayError>> {
        Box::pin(async move {
            let input = with_api_version(operation, input);
            let (route, token, preview) = self.prepare(operation, &input).await?;
            let context = ExecutionContext {
                tenant: &self.target.tenant_id,
                audience: &route.audience,
                endpoint: &route.endpoint,
                token: &token,
            };
            self.executor
                .execute(operation, input, context, None, preview)
                .await
                .map(|response| response.body)
                .map_err(classify_runtime_error)
        })
    }
    fn list<'a>(
        &'a self,
        operation: &'a str,
        input: Value,
    ) -> BoxFut<'a, Result<Listing, GatewayError>> {
        Box::pin(async move {
            let input = with_api_version(operation, input);
            let (route, token, preview) = self.prepare(operation, &input).await?;
            let pageable = self
                .executor
                .registry()
                .resolve(operation, None, preview)
                .map(|op| op.pageable.is_some() || op.query_continuation.is_some())
                .unwrap_or(false);
            let context = ExecutionContext {
                tenant: &self.target.tenant_id,
                audience: &route.audience,
                endpoint: &route.endpoint,
                token: &token,
            };
            if !pageable {
                let body = self
                    .executor
                    .execute(operation, input, context, None, preview)
                    .await
                    .map_err(classify_runtime_error)?
                    .body;
                return Ok(Listing {
                    items: items_of(body),
                    truncated: false,
                });
            }
            let limits = check_policy().limits;
            let result = self
                .executor
                .execute_pages(
                    operation,
                    input,
                    context,
                    PageOptions {
                        max_items: limits.max_items,
                        max_pages: limits.max_pages,
                        api_version: None,
                        allow_preview: preview,
                    },
                )
                .await
                .map_err(classify_runtime_error)?;
            Ok(Listing {
                truncated: result.continuation.is_some(),
                items: result.items,
            })
        })
    }
}

/// The cloud service an operation's token is issued for (for permission docs).
pub fn token_service(operation: &str) -> Option<CloudService> {
    let endpoints = junction_core::cloud::MicrosoftCloud::Public
        .endpoints()
        .ok()?;
    let op = catalog::versions(operation).into_iter().next()?;
    catalog::route(op, &endpoints).ok().map(|r| r.service)
}

#[cfg(test)]
mod tests {
    use super::*;
    use junction_core::cloud::MicrosoftCloud;

    struct NoTokens(std::sync::atomic::AtomicUsize);
    impl TokenProvider for NoTokens {
        fn token<'a>(&'a self, _: TokenRequest) -> BoxFut<'a, Result<AccessToken, CallError>> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { Err(CallError::other(FailureKind::Credential, "no tokens")) })
        }
    }

    #[tokio::test]
    async fn offline_guard_blocks_live_calls_before_any_token_request() {
        let tokens = Arc::new(NoTokens(Default::default()));
        let gateway = LiveGateway::new(
            LiveTarget {
                tenant_id: "00000000-0000-4000-8000-000000000001".into(),
                endpoints: MicrosoftCloud::Public.endpoints().unwrap(),
                credential_profile: "test".into(),
                flow: AuthFlow::ClientCredentials,
            },
            tokens.clone(),
            NetworkGuard::Offline,
        )
        .unwrap();
        let error = gateway
            .get("graph.organization.list", serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(
            matches!(&error, GatewayError::Unavailable(m) if m.contains(OFFLINE_ENV)),
            "{error}"
        );
        assert!(
            gateway
                .list("graph.users.list", serde_json::json!({}))
                .await
                .is_err()
        );
        assert_eq!(tokens.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn unknown_operations_never_reach_the_network() {
        let tokens = Arc::new(NoTokens(Default::default()));
        let gateway = LiveGateway::new(
            LiveTarget {
                tenant_id: "00000000-0000-4000-8000-000000000001".into(),
                endpoints: MicrosoftCloud::Public.endpoints().unwrap(),
                credential_profile: "test".into(),
                flow: AuthFlow::ClientCredentials,
            },
            tokens.clone(),
            NetworkGuard::Allowed,
        )
        .unwrap();
        let error = gateway
            .get("graph.users.delete", serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(matches!(error, GatewayError::Unavailable(_)));
        assert_eq!(tokens.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn api_version_is_filled_only_when_declared() {
        let arm = with_api_version("azure.log_analytics.workspaces.list", serde_json::json!({}));
        assert!(arm["parameters"]["api-version"].is_string());
        let graph = with_api_version("graph.users.list", serde_json::json!({"parameters":{}}));
        assert!(graph["parameters"].get("api-version").is_none());
    }
}
