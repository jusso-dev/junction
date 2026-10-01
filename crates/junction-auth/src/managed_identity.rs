//! Explicit Azure VM managed identity acquisition through the local IMDS endpoint.
use crate::{AccessToken, AuthFlow, Secret, TokenMetadata, TokenRequest};
use anyhow::{Result, bail};
use serde::Deserialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;
use zeroize::Zeroizing;

type ProviderEntries = std::collections::BTreeMap<
    (crate::CacheKey, Option<String>),
    std::sync::Arc<ManagedIdentityProvider>,
>;
/// Bounded in-process providers, isolated by acquisition context and identity.
#[derive(Default)]
pub struct ManagedIdentityPool {
    providers: std::sync::Mutex<ProviderEntries>,
}
impl ManagedIdentityPool {
    fn provider(
        &self,
        request: &TokenRequest,
        client_id: Option<&str>,
    ) -> Result<std::sync::Arc<ManagedIdentityProvider>> {
        // Validate even cache hits; invalid delegated scopes must never reuse tokens.
        endpoint(request, client_id)?;
        let key = (request.key()?, client_id.map(str::to_owned));
        let mut providers = self
            .providers
            .lock()
            .map_err(|_| anyhow::anyhow!("managed identity cache unavailable"))?;
        if let Some(provider) = providers.get(&key) {
            return Ok(std::sync::Arc::clone(provider));
        }
        let provider =
            std::sync::Arc::new(ManagedIdentityProvider::new(request.clone(), client_id)?);
        if providers.len() >= 64 {
            providers.pop_first();
        }
        providers.insert(key, std::sync::Arc::clone(&provider));
        Ok(provider)
    }
    pub async fn acquire(
        &self,
        request: &TokenRequest,
        client_id: Option<&str>,
    ) -> Result<AccessToken> {
        self.provider(request, client_id)?.acquire().await
    }
}

/// The operator must bind this VM's identity to its concrete tenant and authority.
/// IMDS does not take a tenant parameter and cannot switch identities across tenants.
pub struct ManagedIdentityProvider {
    client: reqwest::Client,
    request: TokenRequest,
    endpoint: Url,
    cached: tokio::sync::Mutex<Option<AccessToken>>,
}
impl ManagedIdentityProvider {
    pub fn new(request: TokenRequest, client_id: Option<&str>) -> Result<Self> {
        let endpoint = endpoint(&request, client_id)?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| anyhow::anyhow!("managed identity transport initialization failed"))?;
        Ok(Self {
            client,
            request,
            endpoint,
            cached: tokio::sync::Mutex::new(None),
        })
    }
    pub async fn acquire(&self) -> Result<AccessToken> {
        tokio::time::timeout(Duration::from_secs(120), async {
            // Serialize acquisition and reuse only this provider's fixed identity.
            // The async lock includes refresh to prevent concurrent IMDS storms.
            let mut cached = self.cached.lock().await;
            if let Some(token) = cached
                .as_ref()
                .filter(|token| cache_usable(token, SystemTime::now()))
            {
                return copy_token(token);
            }
            // Evict expired secrets even when the following refresh fails.
            *cached = None;
            let token = self.acquire_with_retries().await?;
            let returned = copy_token(&token)?;
            *cached = Some(token);
            Ok(returned)
        })
        .await
        .map_err(|_| anyhow::anyhow!("managed identity acquisition deadline exceeded"))?
    }
    async fn acquire_with_retries(&self) -> Result<AccessToken> {
        let mut attempt = 0;
        let mut response = loop {
            let response = self
                .client
                .get(self.endpoint.clone())
                .header("Metadata", "true")
                .send()
                .await
                .map_err(|_| anyhow::anyhow!("managed identity request failed"))?;
            if response.status().is_success() {
                break response;
            }
            let delay = retry_delay(response.status(), response.headers(), attempt);
            // Drop the response without reading or retaining an error body.
            drop(response);
            let Some(delay) = delay else {
                bail!("managed identity authentication rejected");
            };
            tokio::time::sleep(delay).await;
            attempt += 1;
        };
        const MAX_BYTES: usize = 64 * 1024;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_BYTES as u64)
        {
            bail!("managed identity response too large");
        }
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow::anyhow!("managed identity response read failed"))?
        {
            if bytes.len().saturating_add(chunk.len()) > MAX_BYTES {
                bail!("managed identity response too large");
            }
            bytes.extend_from_slice(&chunk);
        }
        parse_response(&bytes, &self.request, SystemTime::now())
    }
}
fn cache_usable(token: &AccessToken, now: SystemTime) -> bool {
    token
        .metadata()
        .expires_at
        .duration_since(now)
        .is_ok_and(|remaining| remaining > Duration::from_secs(60))
}
fn copy_token(token: &AccessToken) -> Result<AccessToken> {
    Ok(AccessToken::new(
        Secret::new(token.expose().to_owned())?,
        token.metadata().clone(),
    ))
}
// Five attempts, with Microsoft's IMDS exponential backoff and a hard outer
// deadline. A 410 indicates an IMDS upgrade, which can take up to 70 seconds.
fn retry_delay(
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
    attempt: usize,
) -> Option<Duration> {
    const DELAYS: [u64; 4] = [2, 6, 14, 30];
    let mut seconds = *DELAYS.get(attempt)?;
    if !matches!(status.as_u16(), 404 | 410 | 429 | 500..=599) {
        return None;
    }
    if status == reqwest::StatusCode::GONE {
        seconds = 70;
    }
    if let Some(value) = headers.get(reqwest::header::RETRY_AFTER) {
        // Never retry sooner than a server-specified delay. Unsupported dates
        // and delays exceeding our bound stop acquisition instead.
        let requested = value.to_str().ok()?.parse::<u64>().ok()?;
        if requested > 70 {
            return None;
        }
        seconds = seconds.max(requested);
    }
    Some(Duration::from_secs(seconds))
}
fn endpoint(request: &TokenRequest, client_id: Option<&str>) -> Result<Url> {
    request.validate()?;
    if request.flow != AuthFlow::ManagedIdentity {
        bail!("managed identity flow required");
    }
    if !request.scopes.is_empty() && request.scopes != [format!("{}/.default", request.audience)] {
        bail!("managed identity requires the audience default scope");
    }
    validate_client_id(client_id)?;
    let mut url = Url::parse("http://169.254.169.254/metadata/identity/oauth2/token")?;
    url.query_pairs_mut()
        .append_pair("api-version", "2018-02-01")
        .append_pair("resource", &request.audience);
    if let Some(id) = client_id {
        url.query_pairs_mut().append_pair("client_id", id);
    }
    Ok(url)
}
pub(crate) fn validate_client_id(client_id: Option<&str>) -> Result<()> {
    if client_id.is_some_and(|id| {
        id.len() != 36
            || id.bytes().enumerate().any(|(index, byte)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    byte != b'-'
                } else {
                    !byte.is_ascii_hexdigit()
                }
            })
    }) {
        bail!("invalid managed identity client identifier");
    }
    Ok(())
}
#[derive(Deserialize)]
struct Response {
    access_token: Zeroizing<String>,
    token_type: String,
    expires_on: String,
    resource: String,
}
fn parse_response(bytes: &[u8], request: &TokenRequest, now: SystemTime) -> Result<AccessToken> {
    let response: Response = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("invalid managed identity response"))?;
    if !response.token_type.eq_ignore_ascii_case("Bearer") || response.resource != request.audience
    {
        bail!("managed identity response binding mismatch");
    }
    // RFC 6750 bearer syntax; reject whitespace/header delimiters before dispatch.
    let token = response.access_token.trim_end_matches('=');
    if token.is_empty()
        || !token.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
    {
        bail!("invalid managed identity bearer token");
    }
    let seconds = response
        .expires_on
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("invalid managed identity expiry"))?;
    let expiry = UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .ok_or_else(|| anyhow::anyhow!("invalid managed identity expiry"))?;
    let remaining = expiry
        .duration_since(now)
        .map_err(|_| anyhow::anyhow!("managed identity token expired"))?;
    if remaining <= Duration::from_secs(60) || remaining > Duration::from_secs(7 * 86400) {
        bail!("invalid managed identity token lifetime");
    }
    Ok(AccessToken::new(
        Secret::new(response.access_token.to_string())?,
        TokenMetadata {
            tenant: request.tenant.clone(),
            audience: request.audience.clone(),
            expires_at: expiry,
            scopes: request.scopes.clone(),
            roles: Vec::new(),
            account: None,
        },
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> TokenRequest {
        TokenRequest {
            tenant: "tenant-a".into(),
            authority: "https://login.microsoftonline.us".into(),
            audience: "https://management.usgovcloudapi.net/".into(),
            scopes: vec![],
            credential_profile: "vm-a".into(),
            flow: AuthFlow::ManagedIdentity,
        }
    }
    #[test]
    fn pool_isolates_contexts_and_identity_selection_and_bounds_retention() {
        use std::sync::Arc;
        let pool = ManagedIdentityPool::default();
        let request = request();
        let first = pool.provider(&request, None).unwrap();
        assert!(Arc::ptr_eq(&first, &pool.provider(&request, None).unwrap()));
        for field in ["tenant", "authority", "audience", "profile", "scopes"] {
            let mut other = request.clone();
            match field {
                "tenant" => other.tenant = "tenant-b".into(),
                "authority" => other.authority = "https://login.microsoftonline.com".into(),
                "audience" => other.audience = "https://graph.microsoft.com".into(),
                "profile" => other.credential_profile = "vm-b".into(),
                _ => other.scopes = vec![format!("{}/.default", other.audience)],
            }
            assert!(!Arc::ptr_eq(&first, &pool.provider(&other, None).unwrap()));
        }
        assert!(!Arc::ptr_eq(
            &first,
            &pool
                .provider(&request, Some("00000000-0000-0000-0000-000000000001"))
                .unwrap()
        ));
        let mut invalid = request.clone();
        invalid.scopes = vec!["User.Read".into()];
        assert!(pool.provider(&invalid, None).is_err());
        invalid = request.clone();
        invalid.flow = AuthFlow::DeviceCode;
        assert!(pool.provider(&invalid, None).is_err());
        for index in 0..100 {
            let mut other = request.clone();
            other.credential_profile = format!("profile-{index}");
            pool.provider(&other, None).unwrap();
        }
        assert_eq!(pool.providers.lock().unwrap().len(), 64);
    }
    #[tokio::test]
    async fn provider_cache_reuses_valid_tokens_and_stays_instance_bound() {
        let request = request();
        let provider = ManagedIdentityProvider::new(request.clone(), None).unwrap();
        let now = SystemTime::now();
        let token = AccessToken::new(
            Secret::new("private-cached-token".into()).unwrap(),
            TokenMetadata {
                tenant: request.tenant.clone(),
                audience: request.audience.clone(),
                expires_at: now + Duration::from_secs(3600),
                scopes: vec![],
                roles: vec![],
                account: None,
            },
        );
        assert!(cache_usable(&token, now));
        assert!(!cache_usable(&token, now + Duration::from_secs(3540)));
        assert!(!cache_usable(&token, now + Duration::from_secs(3601)));
        *provider.cached.lock().await = Some(token);
        // Any accidental IMDS acquisition here would fail outside Azure.
        let (first, second) = tokio::join!(provider.acquire(), provider.acquire());
        for token in [first.unwrap(), second.unwrap()] {
            assert_eq!(token.expose(), "private-cached-token");
            assert_eq!(token.metadata().tenant, request.tenant);
            assert!(!format!("{token:?}").contains("private-cached-token"));
        }
        let other =
            ManagedIdentityProvider::new(request, Some("00000000-0000-0000-0000-000000000001"))
                .unwrap();
        assert!(other.cached.lock().await.is_none());
    }
    #[test]
    fn retry_policy_is_bounded_and_honors_server_delays() {
        use reqwest::{
            StatusCode,
            header::{HeaderMap, HeaderValue, RETRY_AFTER},
        };
        let mut headers = HeaderMap::new();
        for status in [404, 429, 500, 503, 599] {
            for (attempt, seconds) in [2, 6, 14, 30].into_iter().enumerate() {
                assert_eq!(
                    retry_delay(StatusCode::from_u16(status).unwrap(), &headers, attempt),
                    Some(Duration::from_secs(seconds))
                );
            }
            assert_eq!(
                retry_delay(StatusCode::from_u16(status).unwrap(), &headers, 4),
                None
            );
        }
        for status in [200, 302, 400, 401, 403] {
            assert_eq!(
                retry_delay(StatusCode::from_u16(status).unwrap(), &headers, 0),
                None
            );
        }
        assert_eq!(
            retry_delay(StatusCode::GONE, &headers, 0),
            Some(Duration::from_secs(70))
        );
        headers.insert(RETRY_AFTER, HeaderValue::from_static("40"));
        assert_eq!(
            retry_delay(StatusCode::TOO_MANY_REQUESTS, &headers, 0),
            Some(Duration::from_secs(40))
        );
        for value in ["71", "-1", "private-token", "Wed, 21 Oct 2015 07:28:00 GMT"] {
            headers.insert(RETRY_AFTER, HeaderValue::from_str(value).unwrap());
            assert_eq!(
                retry_delay(StatusCode::TOO_MANY_REQUESTS, &headers, 0),
                None
            );
        }
    }
    #[test]
    fn fixed_imds_endpoint_preserves_resource_and_rejects_delegated_flows() {
        let mut request = request();
        let url = endpoint(&request, Some("00000000-0000-0000-0000-000000000001")).unwrap();
        assert_eq!(url.host_str(), Some("169.254.169.254"));
        assert_eq!(
            url.query_pairs()
                .find(|(key, _)| key == "resource")
                .unwrap()
                .1,
            request.audience
        );
        assert!(endpoint(&request, Some("unsafe&resource=other")).is_err());
        request.scopes = vec!["User.Read".into()];
        assert!(endpoint(&request, None).is_err());
        request.scopes.clear();
        request.flow = AuthFlow::DeviceCode;
        assert!(endpoint(&request, None).is_err());
    }
    #[test]
    fn malformed_bearer_values_are_rejected_before_header_construction() {
        let request = request();
        let now = UNIX_EPOCH + Duration::from_secs(1000);
        for value in [
            "",
            "private token",
            "private\ttoken",
            "private\r\ntoken",
            "private;token",
            "private=token",
            "=",
            "privateé",
        ] {
            let body = serde_json::json!({"access_token":value,"token_type":"Bearer",
                "expires_on":"2000","resource":request.audience});
            let error =
                parse_response(&serde_json::to_vec(&body).unwrap(), &request, now).unwrap_err();
            assert_eq!(error.to_string(), "invalid managed identity bearer token");
        }
        let body = serde_json::json!({"access_token":"opaque._~+/-==","token_type":"Bearer",
            "expires_on":"2000","resource":request.audience});
        assert!(parse_response(&serde_json::to_vec(&body).unwrap(), &request, now).is_ok());
    }
    #[test]
    fn response_binding_and_expiration_are_enforced_without_token_echo() {
        let request = request();
        let now = UNIX_EPOCH + Duration::from_secs(1000);
        let base = serde_json::json!({"access_token":"private-token","token_type":"Bearer",
            "expires_on":"2000","resource":request.audience});
        let token = parse_response(&serde_json::to_vec(&base).unwrap(), &request, now).unwrap();
        assert_eq!(token.metadata().tenant, "tenant-a");
        assert!(!format!("{token:?}").contains("private-token"));
        for (field, value) in [
            ("resource", "wrong"),
            ("token_type", "Basic"),
            ("expires_on", "999"),
            ("expires_on", "1060"),
            ("expires_on", "999999999"),
            ("expires_on", "private-token"),
        ] {
            let mut body = base.clone();
            body[field] = value.into();
            let error =
                parse_response(&serde_json::to_vec(&body).unwrap(), &request, now).unwrap_err();
            assert!(!error.to_string().contains("private-token"));
        }
    }
}

#[cfg(test)]
mod transport_tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    async fn server(response: String) -> (Url, tokio::task::JoinHandle<String>) {
        let (url, task) = sequence_server(vec![response]).await;
        (
            url,
            tokio::spawn(async move { task.await.unwrap().remove(0) }),
        )
    }
    async fn sequence_server(
        responses: Vec<String>,
    ) -> (Url, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!(
            "http://{}/metadata/identity/oauth2/token",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut buffer = [0; 1024];
                    let size = stream.read(&mut buffer).await.unwrap();
                    assert_ne!(size, 0);
                    request.extend_from_slice(&buffer[..size]);
                    if request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                        break;
                    }
                }
                let _ = stream.write_all(response.as_bytes()).await;
                requests.push(String::from_utf8(request).unwrap());
            }
            requests
        });
        (url, task)
    }
    fn request() -> TokenRequest {
        TokenRequest {
            tenant: "tenant-a".into(),
            authority: "https://login.microsoftonline.com".into(),
            audience: "https://management.azure.com/".into(),
            scopes: vec![],
            credential_profile: "vm-a".into(),
            flow: AuthFlow::ManagedIdentity,
        }
    }
    fn rejected(status: &str) -> String {
        format!("HTTP/1.1 {status}\r\nContent-Length: 13\r\nConnection: close\r\n\r\nprivate-token")
    }
    #[tokio::test]
    async fn transient_imds_failures_recover_without_changing_identity_headers() {
        let request = request();
        let expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let body = serde_json::json!({"access_token":"private-token","token_type":"Bearer",
            "expires_on":expiry.to_string(),"resource":request.audience})
        .to_string();
        let success = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let (url, task) = sequence_server(vec![
            rejected("429 Too Many Requests"),
            rejected("503 Unavailable"),
            success,
        ])
        .await;
        let mut provider = ManagedIdentityProvider::new(request, None).unwrap();
        provider.endpoint = url;
        let start = tokio::time::Instant::now();
        let token = provider.acquire().await.unwrap();
        assert_eq!(token.expose(), "private-token");
        assert!(start.elapsed() >= Duration::from_secs(8));
        let requests = task.await.unwrap();
        assert_eq!(requests.len(), 3);
        for headers in &requests {
            assert!(
                headers
                    .to_ascii_lowercase()
                    .contains("\r\nmetadata: true\r\n")
            );
            assert!(!headers.to_ascii_lowercase().contains("authorization:"));
        }
        assert!(requests.windows(2).all(|pair| pair[0] == pair[1]));
    }
    #[tokio::test]
    async fn transient_imds_failures_stop_after_five_attempts_without_error_body_echo() {
        let (url, task) = sequence_server(vec![rejected("503 Unavailable"); 5]).await;
        let mut provider = ManagedIdentityProvider::new(request(), None).unwrap();
        provider.endpoint = url;
        let error = provider.acquire().await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "managed identity authentication rejected"
        );
        assert_eq!(task.await.unwrap().len(), 5);
    }
    #[tokio::test]
    async fn imds_transport_sets_metadata_header_and_rejects_redirects_and_oversize_bodies() {
        let request = TokenRequest {
            tenant: "tenant-a".into(),
            authority: "https://login.microsoftonline.com".into(),
            audience: "https://management.azure.com/".into(),
            scopes: vec![],
            credential_profile: "vm-a".into(),
            flow: AuthFlow::ManagedIdentity,
        };
        let mut provider = ManagedIdentityProvider::new(request.clone(), None).unwrap();
        let expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let body = serde_json::json!({"access_token":"private-token","token_type":"Bearer",
            "expires_on":expiry.to_string(),"resource":request.audience})
        .to_string();
        let (url, task) = server(format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        ))
        .await;
        // Local endpoint injection exists only in this private unit test.
        provider.endpoint = url;
        let token = provider.acquire().await.unwrap();
        assert_eq!(token.expose(), "private-token");
        let headers = task.await.unwrap().to_ascii_lowercase();
        assert!(headers.contains("\r\nmetadata: true\r\n"));
        assert!(!headers.contains("authorization:"));
        for response in [
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/private-token\r\nContent-Length: 0\r\n\r\n".to_owned(),
            "HTTP/1.1 403 Forbidden\r\nContent-Length: 13\r\n\r\nprivate-token".to_owned(),
            "HTTP/1.1 200 OK\r\nContent-Length: 65537\r\n\r\n".to_owned(),
            format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10001\r\n{}\r\n0\r\n\r\n", "x".repeat(65537)),
        ] {
            let (url, task) = server(response).await;
            provider.endpoint = url;
            *provider.cached.lock().await = None;
            let error = provider.acquire().await.unwrap_err();
            assert!(!error.to_string().contains("private-token"));
            task.await.unwrap();
        }
    }
}
