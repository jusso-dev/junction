//! Bounded HTTP transport. Never forward credentials through redirects.
use anyhow::{Result, bail};
use junction_auth::Secret;
use junction_policy::RequestGovernor;
use serde_json::Value;
use std::time::{Duration, SystemTime};
use url::Url;
mod async_links;
mod correlation;
pub use async_links::AsyncLinks;
pub use correlation::CorrelationIds;

pub use junction_core::is_json_media_type;
pub use reqwest::header::HeaderMap as RequestHeaders;
/// Declared operation headers cannot replace transport or credential headers.
pub fn request_headers(
    values: impl IntoIterator<Item = (String, String)>,
) -> Result<RequestHeaders> {
    let mut headers = RequestHeaders::new();
    for (name, value) in values {
        let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| anyhow::anyhow!("invalid request header name"))?;
        let mut value = reqwest::header::HeaderValue::from_str(&value)
            .map_err(|_| anyhow::anyhow!("invalid request header value"))?;
        value.set_sensitive(true);
        if headers.insert(name, value).is_some() {
            bail!("duplicate request header");
        }
    }
    validate_headers(&headers)?;
    Ok(headers)
}
fn validate_headers(headers: &RequestHeaders) -> Result<()> {
    let mut size: usize = 0;
    for (name, value) in headers {
        if matches!(
            name.as_str(),
            "authorization"
                | "proxy-authorization"
                | "host"
                | "cookie"
                | "content-length"
                | "transfer-encoding"
                | "connection"
                | "upgrade"
                | "trailer"
                | "te"
                | "expect"
                | "proxy-connection"
                | "x-ms-authorization-auxiliary"
                | "x-api-key"
                | "api-key"
                | "x-functions-key"
                | "ocp-apim-subscription-key"
                | "client-request-id"
                | "x-ms-client-request-id"
                | "return-client-request-id"
        ) {
            bail!("reserved request header");
        }
        // Bodies are always serialized as JSON; only JSON media types may be declared.
        if name.as_str() == "content-type" && !value.to_str().is_ok_and(is_json_media_type) {
            bail!("reserved request header");
        }
        size = size
            .saturating_add(name.as_str().len())
            .saturating_add(value.as_bytes().len());
        if value.as_bytes().len() > 8192 {
            bail!("request header size exceeded");
        }
    }
    if headers.len() > 100 || size > 65536 {
        bail!("request header bounds exceeded");
    }
    Ok(())
}
pub struct HttpResponse {
    pub continuation_token: Option<Secret>,
    pub async_links: AsyncLinks,
    pub correlation: CorrelationIds,
    pub status: u16,
    pub body: Value,
    pub retry_after: Option<Duration>,
}
/// Safe upstream error metadata; response bodies and request URLs are excluded.
#[derive(Debug)]
pub struct HttpStatusError {
    pub correlation: CorrelationIds,
    pub status: u16,
    pub retry_after: Option<Duration>,
}
impl std::fmt::Display for HttpStatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "upstream HTTP error {}", self.status)
    }
}
impl std::error::Error for HttpStatusError {}

fn retry_after(value: Option<&str>, now: SystemTime) -> Option<Duration> {
    let value = value?;
    value
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
        .or_else(|| {
            httpdate::parse_http_date(value)
                .ok()
                .map(|date| date.duration_since(now).unwrap_or_default())
        })
}
fn retry_delay(
    method: &str,
    error: &HttpStatusError,
    attempt: u32,
    elapsed: Duration,
) -> Option<Duration> {
    if !matches!(method, "GET" | "HEAD")
        || attempt >= 3
        || !matches!(error.status, 408 | 429 | 500 | 502 | 503 | 504)
    {
        return None;
    }
    let delay = error
        .retry_after
        .unwrap_or_else(|| Duration::from_millis(250 * (1 << attempt)));
    // Honor upstream delay exactly, or return the failure when it exceeds our budget.
    (elapsed.saturating_add(delay) < Duration::from_secs(10)).then_some(delay)
}
/// Append a SAS token (`sv=...&sig=...`) to the request URL. The token must
/// contain a signature and must not override parameters already present.
fn append_sas(url: &mut Url, secret: &junction_auth::Secret) -> Result<()> {
    let token = secret.expose().trim_start_matches('?');
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(token.as_bytes())
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    let existing: Vec<String> = url
        .query_pairs()
        .map(|(name, _)| name.into_owned())
        .collect();
    if pairs.is_empty()
        || pairs.len() > 32
        || !pairs.iter().any(|(name, _)| name == "sig")
        || pairs.iter().any(|(name, value)| {
            name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                || value.chars().any(char::is_control)
                || existing.contains(name)
        })
    {
        bail!("invalid shared access signature");
    }
    url.query_pairs_mut().extend_pairs(pairs);
    Ok(())
}
/// Build the sensitive request header that presents a credential.
fn credential_header(
    credential: &junction_auth::Credential<'_>,
) -> Result<(reqwest::header::HeaderName, reqwest::header::HeaderValue)> {
    let (name, value) = match credential {
        junction_auth::Credential::Bearer(secret) => (
            reqwest::header::AUTHORIZATION,
            zeroize::Zeroizing::new(format!("Bearer {}", secret.expose())),
        ),
        junction_auth::Credential::Header { placement, secret } => {
            placement.validate()?;
            let name = reqwest::header::HeaderName::from_bytes(placement.header.as_bytes())
                .map_err(|_| anyhow::anyhow!("invalid credential header"))?;
            let value = match placement.prefix.as_deref() {
                // Azure DevOps personal access tokens use Basic with an empty user.
                Some("Basic") => {
                    use base64::Engine;
                    let pair = zeroize::Zeroizing::new(format!(":{}", secret.expose()));
                    format!(
                        "Basic {}",
                        base64::engine::general_purpose::STANDARD.encode(pair.as_bytes())
                    )
                }
                Some(prefix) => format!("{prefix} {}", secret.expose()),
                None => secret.expose().to_owned(),
            };
            (name, zeroize::Zeroizing::new(value))
        }
    };
    let mut header = reqwest::header::HeaderValue::from_str(&value)
        .map_err(|_| anyhow::anyhow!("invalid credential"))?;
    header.set_sensitive(true);
    Ok((name, header))
}
#[derive(Clone)]
pub struct HttpTransport {
    client: reqwest::Client,
    governor: RequestGovernor,
    max_response_bytes: usize,
}
impl HttpTransport {
    pub fn new(
        governor: RequestGovernor,
        timeout: Duration,
        max_response_bytes: usize,
    ) -> Result<Self> {
        if timeout.is_zero() || max_response_bytes == 0 || max_response_bytes > 128 * 1024 * 1024 {
            bail!("invalid transport bounds");
        }
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()
            .map_err(|_| anyhow::anyhow!("transport initialization failed"))?;
        Ok(Self {
            client,
            governor,
            max_response_bytes,
        })
    }
    /// Retry transient HTTP failures for reads only, with at most four attempts
    /// and a ten-second delay budget. Every attempt consumes a policy permit.
    pub async fn send_with_retries(
        &self,
        method: &str,
        url: Url,
        body: Option<&Value>,
        bearer: Option<&junction_auth::Credential<'_>>,
    ) -> Result<HttpResponse> {
        self.send_with_headers_retries(method, url, body, bearer, &RequestHeaders::new())
            .await
    }
    pub async fn send_with_headers_retries(
        &self,
        method: &str,
        url: Url,
        body: Option<&Value>,
        bearer: Option<&junction_auth::Credential<'_>>,
        headers: &RequestHeaders,
    ) -> Result<HttpResponse> {
        validate_headers(headers)?;
        let started = std::time::Instant::now();
        for attempt in 0..4 {
            match self
                .send_with_headers(method, url.clone(), body, bearer, headers)
                .await
            {
                Ok(response) => return Ok(response),
                Err(error) => {
                    let delay = error
                        .downcast_ref::<HttpStatusError>()
                        .and_then(|status| retry_delay(method, status, attempt, started.elapsed()));
                    match delay {
                        Some(delay) => tokio::time::sleep(delay).await,
                        None => return Err(error),
                    }
                }
            }
        }
        unreachable!("last attempt cannot retry")
    }
    /// Caller must bind credentials to the trusted target audience and tenant.
    /// Authorization and input validation belong to the executor, before this call.
    pub async fn send(
        &self,
        method: &str,
        url: Url,
        body: Option<&Value>,
        bearer: Option<&junction_auth::Credential<'_>>,
    ) -> Result<HttpResponse> {
        self.send_with_headers(method, url, body, bearer, &RequestHeaders::new())
            .await
    }
    pub async fn send_with_headers(
        &self,
        method: &str,
        url: Url,
        body: Option<&Value>,
        bearer: Option<&junction_auth::Credential<'_>>,
        headers: &RequestHeaders,
    ) -> Result<HttpResponse> {
        validate_headers(headers)?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            bail!("invalid request endpoint");
        }
        let method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|_| anyhow::anyhow!("invalid HTTP method"))?;
        let _permit = self
            .governor
            .admit()
            .map_err(|_| anyhow::anyhow!("request admission rejected"))?;
        let mut url = url;
        let credential = match bearer {
            Some(junction_auth::Credential::Header { placement, secret })
                if placement.header == junction_auth::ApiKeyPlacement::SAS_QUERY =>
            {
                append_sas(&mut url, secret)?;
                None
            }
            other => other,
        };
        let client_request_id = correlation::new_id()?;
        let mut builder = self
            .client
            .request(method, url)
            .headers(headers.clone())
            .header("client-request-id", &client_request_id)
            .header("x-ms-client-request-id", &client_request_id)
            .header("return-client-request-id", "true");
        if let Some(credential) = credential {
            let (name, header) = credential_header(credential)?;
            builder = builder.header(name, header);
        }
        if let Some(body) = body {
            builder = builder.json(body);
        }
        let mut response = builder
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("HTTP request failed"))?;
        let status = response.status().as_u16();
        let async_links = AsyncLinks::from_headers(response.headers(), response.url());
        let correlation = correlation::response_ids(client_request_id, response.headers());
        if response.status().is_redirection() {
            bail!("HTTP redirect rejected");
        }
        let retry_after = retry_after(
            response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|h| h.to_str().ok()),
            SystemTime::now(),
        );
        // Only return response bodies on success. Error payloads may echo secrets.
        if !response.status().is_success() {
            return Err(HttpStatusError {
                correlation,
                status,
                retry_after,
            }
            .into());
        }
        if response
            .content_length()
            .is_some_and(|n| n > self.max_response_bytes as u64)
        {
            bail!("response size limit exceeded");
        }
        let mut bytes = Vec::new();
        let continuation_token = continuation_token(response.headers())?;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow::anyhow!("HTTP response read failed"))?
        {
            if bytes.len().saturating_add(chunk.len()) > self.max_response_bytes {
                bail!("response size limit exceeded");
            }
            bytes.extend_from_slice(&chunk);
        }
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .map_err(|_| anyhow::anyhow!("upstream response is not JSON"))?
        };
        Ok(HttpResponse {
            continuation_token,
            async_links,
            correlation,
            status,
            body,
            retry_after,
        })
    }
}
fn continuation_token(headers: &reqwest::header::HeaderMap) -> Result<Option<Secret>> {
    let mut values = headers.get_all("x-ms-continuationtoken").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        bail!("ambiguous continuation header");
    }
    let value = value
        .to_str()
        .map_err(|_| anyhow::anyhow!("invalid continuation header"))?;
    if value.len() > 16384 || value.chars().any(char::is_control) {
        bail!("invalid continuation header");
    }
    (!value.is_empty())
        .then(|| Secret::new(value.to_owned()))
        .transpose()
}
#[cfg(test)]
mod credential_tests {
    #[test]
    fn sas_tokens_are_appended_once_and_validated() {
        let secret =
            junction_auth::Secret::new("?sv=2024-11-04&ss=b&sig=abc%2B123".into()).unwrap();
        let mut url =
            url::Url::parse("https://acct.blob.core.windows.net/c?restype=container").unwrap();
        super::append_sas(&mut url, &secret).unwrap();
        assert_eq!(
            url.query_pairs().find(|(k, _)| k == "sig").unwrap().1,
            "abc+123"
        );
        assert!(url.query().unwrap().starts_with("restype=container&"));
        for bad in ["sv=1", "sig=a&restype=x", "si g=a&sig=b"] {
            let mut url =
                url::Url::parse("https://acct.blob.core.windows.net/c?restype=container").unwrap();
            let secret = junction_auth::Secret::new(bad.into()).unwrap();
            assert!(super::append_sas(&mut url, &secret).is_err(), "{bad}");
        }
        let placement = junction_auth::ApiKeyPlacement {
            header: "sas-query".into(),
            prefix: None,
        };
        placement.validate().unwrap();
        let bad = junction_auth::ApiKeyPlacement {
            header: "sas-query".into(),
            prefix: Some("Token".into()),
        };
        assert!(bad.validate().is_err());
    }
    #[test]
    fn api_keys_use_their_validated_header_and_scheme() {
        let secret = junction_auth::Secret::new("key-123".into()).unwrap();
        let placement = junction_auth::ApiKeyPlacement {
            header: "authorization".into(),
            prefix: Some("Token".into()),
        };
        let (name, value) = super::credential_header(&junction_auth::Credential::Header {
            placement: &placement,
            secret: &secret,
        })
        .unwrap();
        assert_eq!(name, reqwest::header::AUTHORIZATION);
        assert_eq!(value, "Token key-123");
        assert!(value.is_sensitive());
        let placement = junction_auth::ApiKeyPlacement {
            header: "ocp-apim-subscription-key".into(),
            prefix: None,
        };
        let (name, value) = super::credential_header(&junction_auth::Credential::Header {
            placement: &placement,
            secret: &secret,
        })
        .unwrap();
        assert_eq!(name.as_str(), "ocp-apim-subscription-key");
        assert_eq!(value, "key-123");
        let basic = junction_auth::ApiKeyPlacement {
            header: "authorization".into(),
            prefix: Some("Basic".into()),
        };
        let (_, value) = super::credential_header(&junction_auth::Credential::Header {
            placement: &basic,
            secret: &secret,
        })
        .unwrap();
        assert_eq!(value, "Basic OmtleS0xMjM=");
        let (_, value) = super::credential_header(&(&secret).into()).unwrap();
        assert_eq!(value, "Bearer key-123");
        let forbidden = junction_auth::ApiKeyPlacement {
            header: "cookie".into(),
            prefix: None,
        };
        assert!(
            super::credential_header(&junction_auth::Credential::Header {
                placement: &forbidden,
                secret: &secret,
            })
            .is_err()
        );
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn continuation_header_is_bounded_redacted_and_unambiguous() {
        let mut headers = reqwest::header::HeaderMap::new();
        assert!(continuation_token(&headers).unwrap().is_none());
        headers.insert(
            "x-ms-continuationtoken",
            "private-page-token".parse().unwrap(),
        );
        let token = continuation_token(&headers).unwrap().unwrap();
        assert_eq!(token.expose(), "private-page-token");
        assert!(!format!("{token:?}").contains("private-page-token"));
        headers.append("x-ms-continuationtoken", "another-token".parse().unwrap());
        assert!(continuation_token(&headers).is_err());
        headers.clear();
        headers.insert("x-ms-continuationtoken", "a".repeat(16385).parse().unwrap());
        assert!(continuation_token(&headers).is_err());
    }
    use junction_policy::Policy;
    #[test]
    fn operation_headers_cannot_override_transport_or_credentials() {
        for name in [
            "Authorization",
            "HOST",
            "Content-Length",
            "Cookie",
            "x-ms-authorization-auxiliary",
            "client-request-id",
            "X-MS-Client-Request-ID",
            "return-client-request-id",
        ] {
            assert!(request_headers([(name.into(), "secret".into())]).is_err());
        }
        assert!(
            request_headers([(
                "ConsistencyLevel".into(),
                "eventual\r\nAuthorization: secret".into()
            )])
            .is_err()
        );
        assert!(
            request_headers([
                ("If-Match".into(), "a".into()),
                ("if-match".into(), "b".into())
            ])
            .is_err()
        );
        let headers = request_headers([("ConsistencyLevel".into(), "eventual".into())]).unwrap();
        assert_eq!(headers["consistencylevel"], "eventual");
        assert!(!format!("{headers:?}").contains("eventual"));
    }
    #[test]
    fn retry_policy_bounds_and_write_safety() {
        let error = HttpStatusError {
            correlation: CorrelationIds::default(),
            status: 429,
            retry_after: Some(Duration::from_secs(2)),
        };
        assert_eq!(
            retry_delay("GET", &error, 0, Duration::ZERO),
            Some(Duration::from_secs(2))
        );
        assert!(retry_delay("POST", &error, 0, Duration::ZERO).is_none());
        assert!(retry_delay("DELETE", &error, 0, Duration::ZERO).is_none());
        assert!(retry_delay("GET", &error, 3, Duration::ZERO).is_none());
        assert!(retry_delay("GET", &error, 0, Duration::from_secs(8)).is_none());
        for status in [401, 403, 404, 409] {
            assert!(
                retry_delay(
                    "GET",
                    &HttpStatusError {
                        correlation: CorrelationIds::default(),
                        status,
                        retry_after: None
                    },
                    0,
                    Duration::ZERO
                )
                .is_none()
            );
        }
        assert_eq!(error.to_string(), "upstream HTTP error 429");
    }
    #[test]
    fn parses_safe_retry_after_metadata() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(784111777);
        assert_eq!(retry_after(Some("12"), now), Some(Duration::from_secs(12)));
        assert_eq!(
            retry_after(Some("Sun, 06 Nov 1994 08:49:37 GMT"), now),
            Some(Duration::ZERO)
        );
        assert_eq!(retry_after(Some("secret-token"), now), None);
        assert_eq!(retry_after(Some("-1"), now), None);
    }
    #[test]
    fn transport_bounds_are_required() {
        let governor = RequestGovernor::new(&Policy::default()).unwrap();
        assert!(HttpTransport::new(governor.clone(), Duration::ZERO, 1024).is_err());
        assert!(HttpTransport::new(governor.clone(), Duration::from_secs(30), 0).is_err());
        assert!(HttpTransport::new(governor, Duration::from_secs(30), 1024).is_ok());
    }
}
