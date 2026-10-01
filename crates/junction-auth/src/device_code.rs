//! Tenant-bound OAuth device authorization with redacted secrets and bounded polling.
use crate::{AccessToken, AuthFlow, Secret, TokenRequest};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub struct DeviceCodeProvider {
    client: reqwest::Client,
    client_id: String,
}
#[derive(Debug, Serialize)]
pub struct DevicePrompt {
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
}
/// Not serializable or printable: device_code is an authorization credential.
pub struct DeviceSession {
    prompt: DevicePrompt,
    device_code: Secret,
    request: TokenRequest,
    client_id: String,
    expires: Instant,
    next_poll: Instant,
    interval: Duration,
    finished: bool,
    refresh: Option<crate::refresh::RefreshCredential>,
}
impl DeviceSession {
    pub fn take_refresh_credential(&mut self) -> Option<crate::refresh::RefreshCredential> {
        self.refresh.take()
    }
    pub fn prompt(&self) -> &DevicePrompt {
        &self.prompt
    }
}
pub enum DevicePoll {
    Pending { retry_after_seconds: u64 },
    Authenticated(AccessToken),
}
impl DeviceCodeProvider {
    pub fn new(client_id: String) -> Result<Self> {
        if client_id.is_empty()
            || client_id.len() > 256
            || !client_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            bail!("invalid client identifier");
        }
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| anyhow::anyhow!("could not initialize authentication transport"))?;
        Ok(Self { client, client_id })
    }
    /// Call only when the operator is ready to sign in; display the returned prompt.
    pub async fn begin(&self, request: &TokenRequest) -> Result<DeviceSession> {
        validate(request)?;
        let endpoint = endpoint(request, "devicecode");
        let scopes = request.scopes.join(" ");
        let started = Instant::now();
        let response = self
            .client
            .post(endpoint)
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("scope", scopes.as_str()),
            ])
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("device authorization request failed"))?;
        if !response.status().is_success() {
            bail!("device authorization rejected");
        }
        let bytes = read(response).await?;
        decode_session(&bytes, request, &self.client_id, started)
    }
    /// Poll once when eligible. The session fixes tenant, audience, authority and
    /// scopes; callers cannot supply a different acquisition context mid-flow.
    pub async fn poll(&self, session: &mut DeviceSession) -> Result<DevicePoll> {
        if session.client_id != self.client_id {
            bail!("device authorization client mismatch");
        }
        let now = Instant::now();
        if session.finished || now >= session.expires {
            session.finished = true;
            bail!("device authorization expired or completed");
        }
        if now < session.next_poll {
            return Ok(DevicePoll::Pending {
                retry_after_seconds: remaining(session.next_poll.min(session.expires), now),
            });
        }
        // Reserve the next poll before transport so failures cannot cause busy retries.
        session.next_poll = now + session.interval;
        let response = self
            .client
            .post(endpoint(&session.request, "token"))
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", session.device_code.expose()),
            ])
            .send()
            .await;
        let response = match response {
            Ok(response) => response,
            Err(_) => {
                backoff(session, Instant::now());
                bail!("device token request failed");
            }
        };
        let success = response.status().is_success();
        let bytes = match read(response).await {
            Ok(bytes) => bytes,
            Err(error) => {
                backoff(session, Instant::now());
                return Err(error);
            }
        };
        apply_response(session, success, &bytes, Instant::now())
    }
}
fn backoff(session: &mut DeviceSession, now: Instant) {
    session.interval = session
        .interval
        .saturating_mul(2)
        .min(Duration::from_secs(3600));
    session.next_poll = now + session.interval;
}
pub(crate) fn validate(request: &TokenRequest) -> Result<()> {
    request.validate()?;
    if request.flow != AuthFlow::DeviceCode {
        bail!("credential provider flow mismatch");
    }
    let audience_prefix = format!("{}/", request.audience.trim_end_matches('/'));
    if request.scopes.is_empty()
        || request.scopes.len() > 64
        || request.scopes.iter().any(|scope| {
            scope.len() > 2048
                || !(scope.starts_with(&audience_prefix)
                    || ["openid", "profile", "email", "offline_access"].contains(&scope.as_str()))
        })
    {
        bail!("device scopes must target the configured audience");
    }
    if !request
        .scopes
        .iter()
        .any(|scope| scope.starts_with(&audience_prefix))
    {
        bail!("device scopes require an audience permission");
    }
    Ok(())
}
fn endpoint(request: &TokenRequest, route: &str) -> String {
    format!(
        "{}/{}/oauth2/v2.0/{route}",
        request.authority.trim_end_matches('/'),
        request.tenant
    )
}
async fn read(mut response: reqwest::Response) -> Result<Zeroizing<Vec<u8>>> {
    const LIMIT: usize = 1024 * 1024;
    if response
        .content_length()
        .is_some_and(|bytes| bytes > LIMIT as u64)
    {
        bail!("device response too large");
    }
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow::anyhow!("device response read failed"))?
    {
        if bytes.len().saturating_add(chunk.len()) > LIMIT {
            bail!("device response too large");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
#[derive(Deserialize)]
struct AuthorizationResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: Option<u64>,
}
fn decode_session(
    bytes: &[u8],
    request: &TokenRequest,
    client_id: &str,
    now: Instant,
) -> Result<DeviceSession> {
    validate(request)?;
    let response: AuthorizationResponse = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("invalid device authorization response"))?;
    let device_code = Secret::new(response.device_code)?;
    let uri = url::Url::parse(&response.verification_uri)
        .map_err(|_| anyhow::anyhow!("invalid device verification URI"))?;
    let interval = response.interval.unwrap_or(5);
    if device_code.expose().len() > 16 * 1024
        || response.user_code.is_empty()
        || response.user_code.len() > 128
        || !response
            .user_code
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        || uri.scheme() != "https"
        || uri.host_str().is_none()
        || !uri.username().is_empty()
        || uri.password().is_some()
        || uri.query().is_some()
        || uri.fragment().is_some()
        || !(1..=3600).contains(&response.expires_in)
        || !(1..=60).contains(&interval)
    {
        bail!("invalid device authorization response");
    }
    Ok(DeviceSession {
        prompt: DevicePrompt {
            user_code: response.user_code,
            verification_uri: uri.to_string(),
            expires_in: response.expires_in,
        },
        device_code,
        request: request.clone(),
        client_id: client_id.into(),
        expires: now + Duration::from_secs(response.expires_in),
        next_poll: now + Duration::from_secs(interval),
        interval: Duration::from_secs(interval),
        finished: false,
        refresh: None,
    })
}
fn remaining(deadline: Instant, now: Instant) -> u64 {
    let duration = deadline.saturating_duration_since(now);
    duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() > 0))
}

fn apply_response(
    session: &mut DeviceSession,
    success: bool,
    bytes: &[u8],
    now: Instant,
) -> Result<DevicePoll> {
    if now >= session.expires || session.finished {
        session.finished = true;
        bail!("device authorization expired or completed");
    }
    if success {
        session.finished = true;
        let (token, refresh) =
            crate::refresh::decode_interactive(bytes, &session.request, &session.client_id)?;
        session.refresh = refresh;
        return Ok(DevicePoll::Authenticated(token));
    }
    #[derive(Deserialize)]
    struct ErrorResponse {
        error: String,
    }
    session.finished = true;
    let error: ErrorResponse = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("invalid device token response"))?;
    match error.error.as_str() {
        "authorization_pending" => {}
        "slow_down" => {
            session.interval = session
                .interval
                .saturating_add(Duration::from_secs(5))
                .min(Duration::from_secs(3600));
        }
        "authorization_declined" | "access_denied" => {
            session.finished = true;
            bail!("device authorization declined");
        }
        "expired_token" => {
            session.finished = true;
            bail!("device authorization expired");
        }
        _ => {
            session.finished = true;
            bail!("device token request rejected");
        }
    }
    session.finished = false;
    session.next_poll = now + session.interval;
    Ok(DevicePoll::Pending {
        retry_after_seconds: remaining(session.next_poll.min(session.expires), now),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> TokenRequest {
        TokenRequest {
            tenant: "tenant-a".into(),
            authority: "https://login.example.invalid".into(),
            audience: "https://resource.example.invalid".into(),
            scopes: vec![
                "https://resource.example.invalid/read".into(),
                "openid".into(),
            ],
            credential_profile: "user-a".into(),
            flow: AuthFlow::DeviceCode,
        }
    }
    fn session(now: Instant) -> DeviceSession {
        decode_session(br#"{"device_code":"private-device-secret","user_code":"ABCD-EFGH","verification_uri":"https://login.example.invalid/device","expires_in":900,"interval":5}"#, &request(), "client-a", now).unwrap()
    }
    #[test]
    fn polling_pending_slowdown_success_and_terminal_errors_are_bounded() {
        let now = Instant::now();
        let mut session = session(now);
        assert!(matches!(
            apply_response(
                &mut session,
                false,
                br#"{"error":"authorization_pending"}"#,
                now
            )
            .unwrap(),
            DevicePoll::Pending { .. }
        ));
        assert_eq!(session.interval, Duration::from_secs(5));
        apply_response(&mut session, false, br#"{"error":"slow_down"}"#, now).unwrap();
        assert_eq!(session.interval, Duration::from_secs(10));
        apply_response(
            &mut session,
            false,
            br#"{"error":"authorization_pending"}"#,
            now,
        )
        .unwrap();
        assert_eq!(session.interval, Duration::from_secs(10));
        let DevicePoll::Authenticated(token) = apply_response(&mut session, true, br#"{"access_token":"private-access-secret","token_type":"Bearer","expires_in":3600,"refresh_token":"private-refresh-secret"}"#, now).unwrap() else { panic!() };
        assert_eq!(token.metadata().tenant, "tenant-a");
        assert_eq!(
            token.metadata().audience,
            "https://resource.example.invalid"
        );
        assert!(!format!("{token:?}").contains("private-access-secret"));
        assert!(session.finished);
        assert!(apply_response(&mut session, true, b"{}", now).is_err());
        for error in [
            "authorization_declined",
            "access_denied",
            "expired_token",
            "bad_verification_code",
            "secret-arbitrary-value",
        ] {
            let mut session = super::tests::session(now);
            let bytes = serde_json::to_vec(
                &serde_json::json!({"error":error,"error_description":"private-error-detail"}),
            )
            .unwrap();
            let error = apply_response(&mut session, false, &bytes, now)
                .err()
                .unwrap()
                .to_string();
            assert!(session.finished);
            assert!(
                !error.contains("private-error-detail")
                    && !error.contains("secret-arbitrary-value")
            );
        }
    }
    #[test]
    fn completed_device_sessions_retain_only_requested_refresh_credentials() {
        let now = Instant::now();
        let mut session = session(now);
        session.request.scopes.push("offline_access".into());
        assert!(session.take_refresh_credential().is_none());
        apply_response(&mut session, true, br#"{"access_token":"private-access","token_type":"Bearer","expires_in":3600,"refresh_token":"private-refresh"}"#, now).unwrap();
        let refresh = session.take_refresh_credential().unwrap();
        assert_eq!(refresh.client_id(), "client-a");
        assert!(refresh.matches(&session.request).unwrap());
        assert!(!format!("{refresh:?}").contains("private-refresh"));
        assert!(session.take_refresh_credential().is_none());
    }
    #[tokio::test]
    async fn premature_polls_do_not_use_network_and_client_binding_is_enforced() {
        let provider = DeviceCodeProvider::new("client-a".into()).unwrap();
        let mut session = session(Instant::now());
        assert!(matches!(
            provider.poll(&mut session).await.unwrap(),
            DevicePoll::Pending { .. }
        ));
        let other = DeviceCodeProvider::new("client-b".into()).unwrap();
        assert!(other.poll(&mut session).await.is_err());
        let now = Instant::now();
        backoff(&mut session, now);
        assert_eq!(session.interval, Duration::from_secs(10));
        session.expires = now + Duration::from_secs(1);
        let DevicePoll::Pending {
            retry_after_seconds,
        } = provider.poll(&mut session).await.unwrap()
        else {
            panic!()
        };
        assert!(retry_after_seconds <= 1);
        session.expires = Instant::now();
        assert!(provider.poll(&mut session).await.is_err());
    }
    #[test]
    fn invalid_context_and_response_data_fail_without_secret_echo() {
        let mut invalid = request();
        invalid.scopes = vec!["https://other.invalid/read".into()];
        assert!(validate(&invalid).is_err());
        invalid.scopes = vec!["openid".into()];
        assert!(validate(&invalid).is_err());
        invalid = request();
        invalid.flow = AuthFlow::ClientCredentials;
        assert!(validate(&invalid).is_err());
        invalid = request();
        invalid.tenant = "common".into();
        assert!(validate(&invalid).is_err());
        let now = Instant::now();
        let session = session(now);
        assert!(
            !serde_json::to_string(session.prompt())
                .unwrap()
                .contains("private-device-secret")
        );
        for (field, value) in [
            ("expires_in", serde_json::json!(0)),
            ("interval", serde_json::json!(0)),
            (
                "verification_uri",
                serde_json::json!("https://user:private@evil.invalid"),
            ),
            ("user_code", serde_json::json!("private\ncode")),
        ] {
            let mut response = serde_json::json!({"device_code":"private-device-secret","user_code":"ABCD-EFGH","verification_uri":"https://login.example.invalid/device","expires_in":900,"interval":5});
            response[field] = value;
            let error = decode_session(
                &serde_json::to_vec(&response).unwrap(),
                &request(),
                "client-a",
                now,
            )
            .err()
            .unwrap()
            .to_string();
            assert!(!error.contains("private"));
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
    async fn server(
        status: &str,
        body: &str,
        extra: &str,
    ) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let authority = format!("http://{}", listener.local_addr().unwrap());
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}",
            body.len()
        );
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            loop {
                let mut chunk = [0; 4096];
                let count = socket.read(&mut chunk).await.unwrap();
                if count == 0 {
                    break;
                }
                bytes.extend_from_slice(&chunk[..count]);
                if let Some(end) = bytes.windows(4).position(|value| value == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
                    let size: usize = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length: "))
                        .unwrap()
                        .parse()
                        .unwrap();
                    if bytes.len() >= end + 4 + size {
                        break;
                    }
                }
                assert!(bytes.len() < 32 * 1024);
            }
            let _ = socket.write_all(response.as_bytes()).await;
            String::from_utf8(bytes).unwrap()
        });
        (authority, task)
    }
    fn provider() -> DeviceCodeProvider {
        DeviceCodeProvider {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap(),
            client_id: "client-a".into(),
        }
    }
    fn session(authority: String) -> DeviceSession {
        let now = Instant::now();
        let request = TokenRequest {
            tenant: "tenant-a".into(),
            authority: "https://login.example.invalid".into(),
            audience: "https://resource.example.invalid".into(),
            scopes: vec!["https://resource.example.invalid/read".into()],
            credential_profile: "user-a".into(),
            flow: AuthFlow::DeviceCode,
        };
        let mut session = decode_session(br#"{"device_code":"private&=+ code","user_code":"ABCD-EFGH","verification_uri":"https://login.example.invalid/device","expires_in":900,"interval":5}"#, &request, "client-a", now).unwrap();
        // Only the test transport uses plaintext loopback; production sessions
        // are immutable and production constructors enforce HTTPS.
        session.request.authority = authority;
        session.next_poll = now;
        session
    }
    #[tokio::test]
    async fn poll_encodes_secret_and_uses_bound_tenant() {
        let (authority, received) = server(
            "200 OK",
            r#"{"access_token":"private-token","token_type":"Bearer","expires_in":3600}"#,
            "",
        )
        .await;
        let mut session = session(authority);
        let DevicePoll::Authenticated(token) = provider().poll(&mut session).await.unwrap() else {
            panic!()
        };
        assert_eq!(token.metadata().tenant, "tenant-a");
        let received = received.await.unwrap();
        assert!(received.starts_with("POST /tenant-a/oauth2/v2.0/token "));
        assert!(received.contains("device_code=private%26%3D%2B+code"));
        assert!(
            received.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code")
        );
        assert!(!received.to_ascii_lowercase().contains("authorization:"));
        assert!(!format!("{token:?}").contains("private-token"));
    }
    #[tokio::test]
    async fn redirects_and_private_error_details_are_not_forwarded() {
        let (authority, received) = server(
            "302 Found",
            r#"{"error":"private-error","error_description":"private-description"}"#,
            "Location: https://evil.invalid/private\r\n",
        )
        .await;
        let mut session = session(authority);
        let error = provider()
            .poll(&mut session)
            .await
            .err()
            .unwrap()
            .to_string();
        assert_eq!(error, "device token request rejected");
        assert!(session.finished);
        received.await.unwrap();
    }
}
