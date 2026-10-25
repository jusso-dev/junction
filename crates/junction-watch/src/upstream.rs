//! The only path from the watchdog to Microsoft. Collectors and probes depend on
//! the [`Upstream`] trait so integration tests can script every HTTP outcome.
use junction_auth::{AccessToken, AuthFlow, TokenRequest};
use junction_core::cloud::{CloudService, MicrosoftCloud};
use junction_http::{HttpStatusError, HttpTransport, RequestHeaders};
use serde_json::Value;
use std::{collections::BTreeMap, future::Future, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Api {
    Graph,
    ManagementActivity,
}

#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    pub body: Value,
    pub next_page: Option<Url>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// Microsoft answered with a non-success status.
    Http,
    /// A token could not be obtained (bad or expired credential, consent missing).
    Credential,
    /// Junction's own request governor refused the attempt; wait and retry.
    LocalThrottle,
    /// Network, TLS, timeout, oversized or non-JSON response.
    Transport,
    /// Microsoft answered successfully but the content broke the documented
    /// contract (wrong JSON shape, page link off the listing endpoint).
    Malformed,
}

/// Safe failure metadata. Never carries response bodies, URLs or credentials.
#[derive(Debug, Clone)]
pub struct CallError {
    pub kind: FailureKind,
    pub status: Option<u16>,
    pub code: Option<String>,
    pub message: Option<String>,
    pub retry_after: Option<Duration>,
}

impl CallError {
    pub fn http(status: u16, code: Option<&str>, message: Option<&str>) -> Self {
        Self {
            kind: FailureKind::Http,
            status: Some(status),
            code: code.map(str::to_owned),
            message: message.map(str::to_owned),
            retry_after: None,
        }
    }
    pub fn other(kind: FailureKind, message: &str) -> Self {
        Self {
            kind,
            status: None,
            code: None,
            message: Some(message.to_owned()),
            retry_after: None,
        }
    }
    /// Worth retrying in this run: throttling, transient server errors, network.
    pub fn is_transient(&self) -> bool {
        match self.kind {
            FailureKind::LocalThrottle | FailureKind::Transport => true,
            FailureKind::Credential | FailureKind::Malformed => false,
            FailureKind::Http => {
                matches!(self.status, Some(408 | 429 | 500 | 502 | 503 | 504))
                    // Management Activity API throttles with 403 AF429 and asks
                    // callers to retry internal errors (AF50000).
                    || matches!(self.code.as_deref(), Some("AF429" | "AF50000"))
            }
        }
    }
    pub fn summary(&self) -> String {
        let mut out = match (self.kind, self.status) {
            (FailureKind::Http, Some(status)) => format!("HTTP {status}"),
            (FailureKind::Credential, _) => "credential unavailable".to_owned(),
            (FailureKind::LocalThrottle, _) => "local request limit".to_owned(),
            (FailureKind::Malformed, _) => format!(
                "malformed response: {}",
                self.message.as_deref().unwrap_or("unexpected shape")
            ),
            _ => "transport failure".to_owned(),
        };
        if let Some(code) = &self.code {
            out.push_str(&format!(" {code}"));
        }
        out
    }
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.summary())
    }
}
impl std::error::Error for CallError {}

pub trait Upstream: Send + Sync {
    /// Service root, e.g. `https://graph.microsoft.com` or `https://manage.office.com`.
    fn base(&self, api: Api) -> Url;
    fn tenant_id(&self) -> &str;
    fn get(&self, api: Api, url: Url) -> impl Future<Output = Result<Reply, CallError>> + Send;
    fn post(
        &self,
        api: Api,
        url: Url,
        body: Option<Value>,
    ) -> impl Future<Output = Result<Reply, CallError>> + Send;
    /// Application roles in the current access token, for display only. The token
    /// was issued to us over TLS by Entra; this never authorises anything locally.
    fn granted_roles(
        &self,
        api: Api,
    ) -> impl Future<Output = Result<Vec<String>, CallError>> + Send;
}

/// Production upstream over Junction's bounded transport and environment credentials.
pub struct LiveUpstream {
    tenant_id: String,
    flow: AuthFlow,
    authority: String,
    bases: BTreeMap<Api, (Url, String)>,
    transport: HttpTransport,
    tokens: Mutex<BTreeMap<Api, Arc<AccessToken>>>,
}

impl LiveUpstream {
    pub fn new(
        tenant_id: &str,
        cloud: MicrosoftCloud,
        flow: AuthFlow,
        transport: HttpTransport,
    ) -> anyhow::Result<Self> {
        let endpoints = cloud.endpoints()?;
        endpoints.validate()?;
        let mut bases = BTreeMap::new();
        for (api, service) in [
            (Api::Graph, CloudService::Graph),
            (Api::ManagementActivity, CloudService::Office365Management),
        ] {
            let target = endpoints.target(service)?;
            let audience = target
                .audience
                .clone()
                .ok_or_else(|| anyhow::anyhow!("service audience unavailable"))?;
            let base = Url::parse(&target.endpoint)?;
            bases.insert(api, (base, audience));
        }
        Ok(Self {
            tenant_id: tenant_id.to_owned(),
            flow,
            authority: endpoints.authority.clone(),
            bases,
            transport,
            tokens: Mutex::new(BTreeMap::new()),
        })
    }

    fn request(&self, api: Api) -> TokenRequest {
        TokenRequest {
            tenant: self.tenant_id.clone(),
            authority: self.authority.clone(),
            audience: self.bases[&api].1.clone(),
            scopes: vec![],
            credential_profile: "watch".into(),
            flow: self.flow,
            api_key: None,
        }
    }

    async fn token(&self, api: Api) -> Result<Arc<AccessToken>, CallError> {
        let mut tokens = self.tokens.lock().await;
        if let Some(token) = tokens.get(&api) {
            let fresh = token.metadata().expires_at
                > std::time::SystemTime::now() + Duration::from_secs(120);
            if fresh {
                return Ok(token.clone());
            }
        }
        let request = self.request(api);
        let credential =
            junction_auth::environment::EnvironmentCredential::from_environment_for(&self.flow)
                .map_err(|e| CallError::other(FailureKind::Credential, &e.to_string()))?;
        let token = credential.acquire(&request).await.map_err(|e| {
            match e.downcast_ref::<HttpStatusError>() {
                Some(status) => CallError {
                    kind: FailureKind::Credential,
                    status: Some(status.status),
                    code: status.upstream.as_ref().and_then(|u| u.code.clone()),
                    message: status.upstream.as_ref().and_then(|u| u.message.clone()),
                    retry_after: status.retry_after,
                },
                None => CallError::other(FailureKind::Credential, &e.to_string()),
            }
        })?;
        let token = Arc::new(token);
        tokens.insert(api, token.clone());
        Ok(token)
    }

    async fn send(
        &self,
        api: Api,
        method: &str,
        url: Url,
        body: Option<Value>,
    ) -> Result<Reply, CallError> {
        let base = &self.bases[&api].0;
        // Credentials are bound to the audience host; refuse anything else.
        if url.origin() != base.origin() {
            return Err(CallError::other(
                FailureKind::Transport,
                "request left the service origin",
            ));
        }
        let token = self.token(api).await?;
        let headers = RequestHeaders::new();
        // Junction's governor refuses immediately once the per-minute budget is
        // spent. A collector should queue, not fail: wait for a slot to free up
        // (the window is 60 seconds) before giving up.
        let deadline = std::time::Instant::now() + Duration::from_secs(65);
        let result = loop {
            let attempt = self
                .transport
                .send_with_headers_retries(
                    method,
                    url.clone(),
                    body.as_ref(),
                    Some(&token.credential()),
                    &headers,
                )
                .await;
            match attempt {
                Err(e)
                    if e.to_string() == "request admission rejected"
                        && std::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                other => break other,
            }
        };
        match result {
            Ok(response) => Ok(Reply {
                status: response.status,
                body: response.body,
                next_page: response.next_page_uri,
            }),
            Err(error) => Err(match error.downcast_ref::<HttpStatusError>() {
                Some(status) => {
                    if status.status == 401 {
                        // Force a fresh token next time; the cached one was rejected.
                        self.tokens.lock().await.remove(&api);
                    }
                    CallError {
                        kind: FailureKind::Http,
                        status: Some(status.status),
                        code: status.upstream.as_ref().and_then(|u| u.code.clone()),
                        message: status.upstream.as_ref().and_then(|u| u.message.clone()),
                        retry_after: status.retry_after,
                    }
                }
                None if error.to_string() == "request admission rejected" => {
                    CallError::other(FailureKind::LocalThrottle, "request admission rejected")
                }
                None => CallError::other(FailureKind::Transport, &error.to_string()),
            }),
        }
    }
}

impl Upstream for LiveUpstream {
    fn base(&self, api: Api) -> Url {
        self.bases[&api].0.clone()
    }
    fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
    async fn get(&self, api: Api, url: Url) -> Result<Reply, CallError> {
        self.send(api, "GET", url, None).await
    }
    async fn post(&self, api: Api, url: Url, body: Option<Value>) -> Result<Reply, CallError> {
        self.send(api, "POST", url, body).await
    }
    async fn granted_roles(&self, api: Api) -> Result<Vec<String>, CallError> {
        let token = self.token(api).await?;
        Ok(roles_claim(token.expose()))
    }
}

/// Read the `roles` claim from a JWT payload without verifying it. Display only.
pub fn roles_claim(jwt: &str) -> Vec<String> {
    use base64::Engine;
    let Some(payload) = jwt.split('.').nth(1) else {
        return vec![];
    };
    let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload) else {
        return vec![];
    };
    let Ok(claims) = serde_json::from_slice::<Value>(&bytes) else {
        return vec![];
    };
    let mut roles: Vec<String> = claims
        .get("roles")
        .and_then(Value::as_array)
        .map(|roles| {
            roles
                .iter()
                .filter_map(Value::as_str)
                .filter(|r| r.len() <= 128 && r.bytes().all(|b| b.is_ascii_graphic()))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    roles.sort();
    roles.dedup();
    roles
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roles_claim_is_bounded_and_tolerant() {
        use base64::Engine;
        let enc = |v: &Value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap())
        };
        let jwt = format!(
            "{}.{}.sig",
            enc(&serde_json::json!({"alg":"none"})),
            enc(
                &serde_json::json!({"roles":["AuditLog.Read.All","ActivityFeed.Read","bad role", 7]})
            )
        );
        assert_eq!(
            roles_claim(&jwt),
            ["ActivityFeed.Read", "AuditLog.Read.All"]
        );
        assert!(roles_claim("garbage").is_empty());
        assert!(roles_claim("a.!!!.c").is_empty());
    }
    #[test]
    fn transient_classification() {
        assert!(CallError::http(429, None, None).is_transient());
        assert!(CallError::http(503, None, None).is_transient());
        assert!(!CallError::http(403, None, None).is_transient());
        assert!(CallError::http(403, Some("AF429"), None).is_transient());
        assert!(!CallError::other(FailureKind::Credential, "x").is_transient());
        assert!(CallError::other(FailureKind::LocalThrottle, "x").is_transient());
    }
}
