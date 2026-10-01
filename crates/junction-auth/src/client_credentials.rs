use crate::{AccessToken, AuthFlow, Secret, TokenMetadata, TokenRequest};
use anyhow::{Result, bail};
use serde::Deserialize;
use std::time::{Duration, SystemTime};
use zeroize::Zeroizing;

pub struct ClientCredentialsProvider {
    client: reqwest::Client,
    client_id: String,
    secret: Secret,
    assertion: bool,
}
impl ClientCredentialsProvider {
    /// Authority is supplied by trusted context configuration, never operation input.
    pub fn new(client_id: String, secret: Secret) -> Result<Self> {
        if client_id.is_empty()
            || !client_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            bail!("invalid client identifier");
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .https_only(true)
            .build()
            .map_err(|_| anyhow::anyhow!("could not initialize authentication transport"))?;
        Ok(Self {
            client,
            client_id,
            secret,
            assertion: false,
        })
    }
    /// Exchange an externally issued workload assertion; Entra verifies the federation trust.
    pub fn with_workload_assertion(client_id: String, assertion: Secret) -> Result<Self> {
        if assertion.expose().len() > 1024 * 1024 {
            bail!("workload assertion too large");
        }
        let mut provider = Self::new(client_id, assertion)?;
        provider.assertion = true;
        Ok(provider)
    }
    fn validate_flow(&self, request: &TokenRequest) -> Result<()> {
        let expected = if self.assertion {
            AuthFlow::WorkloadIdentity
        } else {
            AuthFlow::ClientCredentials
        };
        if request.flow != expected {
            bail!("credential provider flow mismatch");
        }
        Ok(())
    }
    pub(crate) fn form<'a>(&'a self, scope: &'a str) -> Vec<(&'static str, &'a str)> {
        let mut fields = vec![
            ("client_id", self.client_id.as_str()),
            ("scope", scope),
            ("grant_type", "client_credentials"),
        ];
        if self.assertion {
            fields.push(("client_assertion", self.secret.expose()));
            fields.push((
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ));
        } else {
            fields.push(("client_secret", self.secret.expose()));
        }
        fields
    }
    pub async fn acquire(&self, request: &TokenRequest) -> Result<AccessToken> {
        request.key()?;
        self.validate_flow(request)?;
        let scope = format!("{}/.default", request.audience);
        if !request.scopes.is_empty() && request.scopes != [scope.clone()] {
            bail!("client credentials require the audience default scope");
        }
        let endpoint = format!(
            "{}/{}/oauth2/v2.0/token",
            request.authority.trim_end_matches('/'),
            request.tenant
        );
        self.fetch(request, &endpoint, &scope).await
    }
    async fn fetch(
        &self,
        request: &TokenRequest,
        endpoint: &str,
        scope: &str,
    ) -> Result<AccessToken> {
        self.fetch_form(request, endpoint, &self.form(scope)).await
    }
    pub(crate) async fn fetch_form(
        &self,
        request: &TokenRequest,
        endpoint: &str,
        fields: &[(&str, &str)],
    ) -> Result<AccessToken> {
        let mut response = self
            .client
            .post(endpoint)
            .form(fields)
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("token endpoint request failed"))?;
        if !response.status().is_success() {
            bail!(
                "token endpoint rejected authentication (HTTP {})",
                response.status().as_u16()
            );
        }
        const LIMIT: usize = 1024 * 1024;
        if response
            .content_length()
            .is_some_and(|size| size > LIMIT as u64)
        {
            bail!("token response too large");
        }
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow::anyhow!("token response read failed"))?
        {
            if bytes.len().saturating_add(chunk.len()) > LIMIT {
                bail!("token response too large");
            }
            bytes.extend_from_slice(&chunk);
        }
        decode(&bytes, request)
    }
}
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
}
pub(crate) fn decode(bytes: &[u8], request: &TokenRequest) -> Result<AccessToken> {
    let response: TokenResponse =
        serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("invalid token response"))?;
    let secret = Secret::new(response.access_token)?;
    if !response.token_type.eq_ignore_ascii_case("bearer")
        || response.expires_in <= 60
        || response.expires_in > 86400
    {
        bail!("unsupported token type or lifetime");
    }
    Ok(AccessToken::new(
        secret,
        TokenMetadata {
            tenant: request.tenant.clone(),
            audience: request.audience.clone(),
            expires_at: SystemTime::now() + Duration::from_secs(response.expires_in),
            // .default is a request scope, not evidence of granted scopes or roles.
            scopes: vec![],
            roles: vec![],
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
            authority: "https://login.example.com".into(),
            audience: "https://resource.example.com".into(),
            scopes: vec![],
            credential_profile: "default".into(),
            flow: AuthFlow::ClientCredentials,
        }
    }
    #[test]
    fn response_metadata_is_safe_and_permissions_are_not_invented() {
        let token = decode(
            br#"{"access_token":"sensitive","token_type":"Bearer","expires_in":3600}"#,
            &request(),
        )
        .unwrap();
        assert_eq!(token.expose(), "sensitive");
        assert!(token.metadata().roles.is_empty() && token.metadata().scopes.is_empty());
        assert!(!format!("{token:?}").contains("sensitive"));
    }
    #[test]
    fn workload_assertions_use_federated_form_and_require_matching_flow() {
        let provider = ClientCredentialsProvider::with_workload_assertion(
            "client-a".into(),
            Secret::new("external.jwt.assertion".into()).unwrap(),
        )
        .unwrap();
        let fields = provider.form("https://resource.example.com/.default");
        assert!(fields.contains(&("client_assertion", "external.jwt.assertion")));
        assert!(fields.contains(&(
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        )));
        assert!(!fields.iter().any(|(name, _)| *name == "client_secret"));
        let mut request = request();
        assert!(provider.validate_flow(&request).is_err());
        request.flow = AuthFlow::WorkloadIdentity;
        assert!(provider.validate_flow(&request).is_ok());
    }
    #[test]
    fn federated_wire_request_encodes_assertion_and_scope_without_secret_fields() {
        let provider = ClientCredentialsProvider::with_workload_assertion(
            "client-a".into(),
            Secret::new("assertion&=+ value".into()).unwrap(),
        )
        .unwrap();
        let request = provider
            .client
            .post("https://login.example.com/tenant/oauth2/v2.0/token")
            .form(&provider.form("https://management.example.com//.default"))
            .build()
            .unwrap();
        assert_eq!(
            request.headers()["content-type"],
            "application/x-www-form-urlencoded"
        );
        let body = request.body().unwrap().as_bytes().unwrap();
        let fields: std::collections::BTreeMap<_, _> =
            url::form_urlencoded::parse(body).into_owned().collect();
        assert_eq!(fields["client_assertion"], "assertion&=+ value");
        assert_eq!(fields["scope"], "https://management.example.com//.default");
        assert_eq!(fields["grant_type"], "client_credentials");
        assert_eq!(
            fields["client_assertion_type"],
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        );
        assert!(!fields.contains_key("client_secret"));
    }
    #[test]
    fn invalid_responses_do_not_expose_payloads() {
        for payload in [
            br#"{"access_token":"sensitive","token_type":"MAC","expires_in":3600}"#.as_slice(),
            br#"{"access_token":"sensitive","token_type":"Bearer","expires_in":0}"#,
            b"sensitive",
        ] {
            let error = decode(payload, &request()).unwrap_err().to_string();
            assert!(!error.contains("sensitive"));
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
    async fn server(response: String) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/token", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            loop {
                let mut chunk = [0u8; 4096];
                let n = socket.read(&mut chunk).await.unwrap();
                if n == 0 {
                    break;
                }
                bytes.extend_from_slice(&chunk[..n]);
                if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&bytes[..end]).to_lowercase();
                    let len: usize = headers
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length: "))
                        .unwrap()
                        .parse()
                        .unwrap();
                    if bytes.len() >= end + 4 + len {
                        break;
                    }
                }
            }
            let _ = socket.write_all(response.as_bytes()).await;
            String::from_utf8(bytes).unwrap()
        });
        (endpoint, task)
    }
    fn provider() -> ClientCredentialsProvider {
        ClientCredentialsProvider {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap(),
            client_id: "client-a".into(),
            secret: Secret::new("secret&=+ value".into()).unwrap(),
            assertion: false,
        }
    }
    fn request() -> TokenRequest {
        TokenRequest {
            tenant: "tenant-a".into(),
            authority: "https://login.example.com".into(),
            audience: "https://resource.example.com".into(),
            scopes: vec![],
            credential_profile: "default".into(),
            flow: AuthFlow::ClientCredentials,
        }
    }
    #[tokio::test]
    async fn form_encoding_and_success() {
        let body = r#"{"access_token":"test-token","token_type":"Bearer","expires_in":3600}"#;
        let (url, task) = server(format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        ))
        .await;
        let token = provider()
            .fetch(&request(), &url, "https://resource.example.com/.default")
            .await
            .unwrap();
        assert_eq!(token.expose(), "test-token");
        let received = task.await.unwrap();
        assert!(received.contains("client_secret=secret%26%3D%2B+value"));
        assert!(received.contains("grant_type=client_credentials"));
        assert!(received.contains("scope=https%3A%2F%2Fresource.example.com%2F.default"));
    }
    #[tokio::test]
    async fn federated_exchange_roundtrip_uses_assertion_and_preserves_context() {
        let body =
            r#"{"access_token":"federated-access-token","token_type":"Bearer","expires_in":3600}"#;
        let (url, task) = server(format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        ))
        .await;
        let mut provider = provider();
        provider.assertion = true;
        let mut request = request();
        request.flow = AuthFlow::WorkloadIdentity;
        let token = provider
            .fetch(&request, &url, "https://resource.example.com/.default")
            .await
            .unwrap();
        let received = task.await.unwrap();
        assert!(received.contains("client_assertion=secret%26%3D%2B+value"));
        assert!(received.contains(
            "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"
        ));
        assert!(!received.contains("client_secret="));
        assert_eq!(token.metadata().tenant, "tenant-a");
        assert_eq!(token.metadata().audience, "https://resource.example.com");
        assert!(!format!("{token:?}").contains("federated-access-token"));
    }
    #[tokio::test]
    async fn redirects_errors_and_oversized_responses_are_rejected() {
        for (status, headers, body, expected) in [
            (
                "302 Found",
                "Location: http://127.0.0.1:1/leak\r\n",
                "sensitive-echo",
                "HTTP 302",
            ),
            ("401 Unauthorized", "", "sensitive-echo", "HTTP 401"),
            ("200 OK", "Content-Length: 1048577\r\n", "", "too large"),
        ] {
            let framing = if headers.contains("Content-Length") {
                String::new()
            } else {
                format!("Content-Length: {}\r\n", body.len())
            };
            let (url, task) = server(format!(
                "HTTP/1.1 {status}\r\n{headers}{framing}Connection: close\r\n\r\n{body}"
            ))
            .await;
            let error = provider()
                .fetch(&request(), &url, "resource/.default")
                .await
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected), "{error}");
            assert!(!error.contains("sensitive-echo"));
            task.await.unwrap();
        }
    }
}
