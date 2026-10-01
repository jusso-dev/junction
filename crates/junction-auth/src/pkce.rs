//! OAuth authorization-code exchange with S256 PKCE and single-use callback state.
use crate::{AccessToken, AuthFlow, Secret, TokenRequest};
use anyhow::{Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
use url::Url;
use zeroize::Zeroizing;

pub struct PkceProvider {
    client: reqwest::Client,
    client_id: String,
    redirect_uri: Url,
    client_secret: Option<Secret>,
}
/// Contains secrets and intentionally implements neither Debug nor Serialize.
pub struct AuthorizationSession {
    authorization_url: Url,
    verifier: Secret,
    state: Secret,
    request: TokenRequest,
    client_id: String,
    redirect_uri: Url,
    expires: Instant,
    consumed: bool,
    confidential: bool,
    refresh: Option<crate::refresh::RefreshCredential>,
}
impl AuthorizationSession {
    pub fn take_refresh_credential(&mut self) -> Option<crate::refresh::RefreshCredential> {
        self.refresh.take()
    }
    /// Explicitly hand this URL to the operator's browser; it includes CSRF state.
    pub fn authorization_url(&self) -> &Url {
        &self.authorization_url
    }
}
impl PkceProvider {
    pub fn new(client_id: String, redirect_uri: &str) -> Result<Self> {
        if client_id.is_empty()
            || client_id.len() > 256
            || !client_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            bail!("invalid client identifier");
        }
        let redirect_uri = redirect(redirect_uri)?;
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| anyhow::anyhow!("could not initialize authentication transport"))?;
        Ok(Self {
            client,
            client_id,
            redirect_uri,
            client_secret: None,
        })
    }
    /// Confidential web clients authenticate at the token endpoint; PKCE stays
    /// enabled and secrets never enter the browser authorization URL.
    pub fn with_client_secret(
        client_id: String,
        redirect_uri: &str,
        secret: Secret,
    ) -> Result<Self> {
        if secret.expose().len() > 16 * 1024 {
            bail!("client secret too large");
        }
        let mut provider = Self::new(client_id, redirect_uri)?;
        provider.client_secret = Some(secret);
        Ok(provider)
    }
    fn validate_request(&self, request: &TokenRequest) -> Result<()> {
        let expected = if self.client_secret.is_some() {
            AuthFlow::AuthorizationCode
        } else {
            AuthFlow::Pkce
        };
        if request.flow != expected {
            bail!("credential provider flow mismatch");
        }
        validate(request)
    }
    fn form<'a>(
        &'a self,
        session: &'a AuthorizationSession,
        code: &'a Secret,
        scope: &'a str,
    ) -> Vec<(&'static str, &'a str)> {
        let mut fields = vec![
            ("client_id", self.client_id.as_str()),
            ("grant_type", "authorization_code"),
            ("code", code.expose()),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("code_verifier", session.verifier.expose()),
            ("scope", scope),
        ];
        if let Some(secret) = &self.client_secret {
            fields.push(("client_secret", secret.expose()));
        }
        fields
    }
    pub fn begin(&self, request: &TokenRequest) -> Result<AuthorizationSession> {
        self.validate_request(request)?;
        let verifier = random_secret()?;
        let state = random_secret()?;
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.expose().as_bytes()));
        let mut authorization_url = Url::parse(&endpoint(request, "authorize"))
            .map_err(|_| anyhow::anyhow!("invalid authorization endpoint"))?;
        authorization_url.query_pairs_mut().extend_pairs([
            ("client_id", self.client_id.as_str()),
            ("response_type", "code"),
            ("response_mode", "query"),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("scope", request.scopes.join(" ").as_str()),
            ("state", state.expose()),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ]);
        Ok(AuthorizationSession {
            authorization_url,
            verifier,
            state,
            request: request.clone(),
            client_id: self.client_id.clone(),
            redirect_uri: self.redirect_uri.clone(),
            expires: Instant::now() + Duration::from_secs(900),
            consumed: false,
            confidential: self.client_secret.is_some(),
            refresh: None,
        })
    }
    pub async fn exchange(
        &self,
        session: &mut AuthorizationSession,
        callback_uri: &str,
    ) -> Result<AccessToken> {
        if session.client_id != self.client_id
            || session.redirect_uri != self.redirect_uri
            || session.confidential != self.client_secret.is_some()
        {
            bail!("authorization session provider mismatch");
        }
        self.validate_request(&session.request)?;
        let code = accept_callback(session, callback_uri, Instant::now())?;
        let scope = session.request.scopes.join(" ");
        let mut response = self
            .client
            .post(endpoint(&session.request, "token"))
            .form(&self.form(session, &code, &scope))
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("authorization token request failed"))?;
        if !response.status().is_success() {
            bail!("authorization token request rejected");
        }
        let mut bytes = Zeroizing::new(Vec::new());
        const LIMIT: usize = 1024 * 1024;
        if response
            .content_length()
            .is_some_and(|size| size > LIMIT as u64)
        {
            bail!("authorization token response too large");
        }
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow::anyhow!("authorization token response read failed"))?
        {
            if bytes.len().saturating_add(chunk.len()) > LIMIT {
                bail!("authorization token response too large");
            }
            bytes.extend_from_slice(&chunk);
        }
        if Instant::now() >= session.expires {
            bail!("authorization session expired");
        }
        let (token, refresh) =
            crate::refresh::decode_interactive(&bytes, &session.request, &self.client_id)?;
        session.refresh = refresh;
        Ok(token)
    }
}
fn random_secret() -> Result<Secret> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut())
        .map_err(|_| anyhow::anyhow!("authorization randomness unavailable"))?;
    Secret::new(URL_SAFE_NO_PAD.encode(bytes.as_ref()))
}
pub(crate) fn validate(request: &TokenRequest) -> Result<()> {
    request.validate()?;
    if !matches!(request.flow, AuthFlow::Pkce | AuthFlow::AuthorizationCode) {
        bail!("credential provider flow mismatch");
    }
    let prefix = format!("{}/", request.audience.trim_end_matches('/'));
    if request.scopes.is_empty()
        || request.scopes.len() > 64
        || !request
            .scopes
            .iter()
            .any(|scope| scope.starts_with(&prefix))
        || request.scopes.iter().any(|scope| {
            scope.len() > 2048
                || !(scope.starts_with(&prefix)
                    || ["openid", "profile", "email", "offline_access"].contains(&scope.as_str()))
        })
    {
        bail!("authorization scopes must target the configured audience");
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
fn redirect(input: &str) -> Result<Url> {
    if input.len() > 4096 {
        bail!("invalid authorization redirect URI");
    }
    let uri =
        Url::parse(input).map_err(|_| anyhow::anyhow!("invalid authorization redirect URI"))?;
    let loopback = matches!(uri.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if !(uri.scheme() == "https" || (uri.scheme() == "http" && loopback))
        || uri.host_str().is_none()
        || !uri.username().is_empty()
        || uri.password().is_some()
        || uri.query().is_some()
        || uri.fragment().is_some()
    {
        bail!("authorization redirect must be HTTPS or HTTP loopback without credentials or query");
    }
    Ok(uri)
}
fn accept_callback(
    session: &mut AuthorizationSession,
    input: &str,
    now: Instant,
) -> Result<Secret> {
    if session.consumed || now >= session.expires {
        bail!("authorization session expired or consumed");
    }
    if input.len() > 16 * 1024 || input.chars().any(char::is_control) {
        bail!("authorization callback too large");
    }
    let mut callback =
        Url::parse(input).map_err(|_| anyhow::anyhow!("invalid authorization callback"))?;
    if callback.fragment().is_some() {
        bail!("authorization callback must use query response mode");
    }
    if let Some(query) = callback.query() {
        let bytes = query.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'%' {
                if index + 2 >= bytes.len()
                    || !bytes[index + 1].is_ascii_hexdigit()
                    || !bytes[index + 2].is_ascii_hexdigit()
                {
                    bail!("invalid authorization callback encoding");
                }
                index += 3;
            } else {
                index += 1;
            }
        }
    }
    let mut parameters = BTreeMap::new();
    for (key, value) in callback.query_pairs() {
        if parameters
            .insert(key.into_owned(), Zeroizing::new(value.into_owned()))
            .is_some()
        {
            bail!("duplicate authorization callback parameter");
        }
    }
    callback.set_query(None);
    if callback != session.redirect_uri {
        bail!("authorization callback redirect mismatch");
    }
    let state = parameters
        .get("state")
        .ok_or_else(|| anyhow::anyhow!("authorization callback state missing"))?;
    if !equal(state.as_bytes(), session.state.expose().as_bytes()) {
        bail!("authorization callback state mismatch");
    }
    if parameters.contains_key("error") {
        session.consumed = true;
        bail!("authorization request rejected");
    }
    let code = parameters
        .remove("code")
        .ok_or_else(|| anyhow::anyhow!("authorization callback code missing"))?;
    if code.is_empty()
        || code.len() > 4096
        || !code.is_ascii()
        || code.chars().any(char::is_whitespace)
    {
        bail!("invalid authorization code");
    }
    session.consumed = true;
    Secret::new(code.to_string())
}
fn equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
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
            flow: AuthFlow::Pkce,
        }
    }
    fn provider() -> PkceProvider {
        PkceProvider::new("client-a".into(), "http://127.0.0.1:8400/callback").unwrap()
    }
    fn callback(session: &AuthorizationSession, code: &str) -> String {
        let mut uri = session.redirect_uri.clone();
        uri.query_pairs_mut()
            .append_pair("state", session.state.expose())
            .append_pair("code", code);
        uri.to_string()
    }
    #[test]
    fn challenge_matches_rfc7636_and_sessions_have_unique_secrets() {
        assert_eq!(
            URL_SAFE_NO_PAD.encode(Sha256::digest(
                b"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
            )),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        let first = provider().begin(&request()).unwrap();
        let second = provider().begin(&request()).unwrap();
        assert_ne!(first.verifier.expose(), second.verifier.expose());
        assert_ne!(first.state.expose(), second.state.expose());
        assert_eq!(first.verifier.expose().len(), 43);
        let query: BTreeMap<_, _> = first.authorization_url.query_pairs().collect();
        assert_eq!(query["code_challenge_method"], "S256");
        assert_eq!(
            query["code_challenge"],
            URL_SAFE_NO_PAD.encode(Sha256::digest(first.verifier.expose().as_bytes()))
        );
        assert!(
            !first
                .authorization_url
                .as_str()
                .contains(first.verifier.expose())
        );
        assert_eq!(query["redirect_uri"], "http://127.0.0.1:8400/callback");
        assert_eq!(
            first.authorization_url.path(),
            "/tenant-a/oauth2/v2.0/authorize"
        );
    }
    #[test]
    fn callbacks_require_state_exact_redirect_and_single_use() {
        let mut session = provider().begin(&request()).unwrap();
        let valid = callback(&session, "private&=+code");
        for bad in [
            valid.replace("127.0.0.1", "localhost"),
            valid.replace("8400", "8401"),
            format!("{valid}&code=duplicate"),
            format!("{valid}#fragment"),
            valid.replace(session.state.expose(), "wrong-state"),
            format!("{valid}&invalid=%ZZ"),
        ] {
            let error = accept_callback(&mut session, &bad, Instant::now())
                .err()
                .unwrap()
                .to_string();
            assert!(!error.contains("private"));
            assert!(!session.consumed);
        }
        let code = accept_callback(&mut session, &valid, Instant::now()).unwrap();
        assert_eq!(code.expose(), "private&=+code");
        assert!(!format!("{code:?}").contains("private"));
        assert!(accept_callback(&mut session, &valid, Instant::now()).is_err());
    }
    #[tokio::test]
    async fn confidential_secrets_stay_out_of_browser_urls_and_modes_cannot_mix() {
        let confidential = PkceProvider::with_client_secret(
            "client-a".into(),
            "https://app.example.invalid/callback",
            Secret::new("private&=+secret".into()).unwrap(),
        )
        .unwrap();
        let mut request = request();
        assert!(confidential.begin(&request).is_err());
        request.flow = AuthFlow::AuthorizationCode;
        let mut session = confidential.begin(&request).unwrap();
        assert!(!session.authorization_url.as_str().contains("private"));
        assert!(
            !session
                .authorization_url
                .query_pairs()
                .any(|(key, _)| key == "client_secret")
        );
        let code = Secret::new("private-code".into()).unwrap();
        let scope = request.scopes.join(" ");
        let fields = confidential.form(&session, &code, &scope);
        assert_eq!(
            fields
                .iter()
                .filter(|(key, _)| *key == "client_secret")
                .count(),
            1
        );
        let encoded = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish();
        assert!(encoded.contains("client_secret=private%26%3D%2Bsecret"));
        assert!(encoded.contains("code_verifier="));
        let public =
            PkceProvider::new("client-a".into(), "https://app.example.invalid/callback").unwrap();
        assert!(public.begin(&request).is_err());
        let valid = callback(&session, "private-code");
        assert!(public.exchange(&mut session, &valid).await.is_err());
        assert!(!session.consumed);
    }
    #[test]
    fn expiry_rejections_and_context_validation_are_safe() {
        for uri in [
            "http://remote.invalid/callback",
            "https://user:private@host.invalid",
            "https://host.invalid?code=private",
            "https://host.invalid#fragment",
        ] {
            assert!(PkceProvider::new("client-a".into(), uri).is_err());
        }
        let mut session = provider().begin(&request()).unwrap();
        let mut denied = session.redirect_uri.clone();
        denied
            .query_pairs_mut()
            .append_pair("state", session.state.expose())
            .append_pair("error", "private-code")
            .append_pair("error_description", "private-detail");
        assert_eq!(
            accept_callback(&mut session, denied.as_str(), Instant::now())
                .err()
                .unwrap()
                .to_string(),
            "authorization request rejected"
        );
        assert!(session.consumed);
        let mut session = provider().begin(&request()).unwrap();
        session.expires = Instant::now();
        let valid = callback(&session, "private-code");
        assert!(accept_callback(&mut session, &valid, Instant::now()).is_err());
        let mut request = request();
        request.scopes = vec!["https://other.invalid/read".into()];
        assert!(provider().begin(&request).is_err());
        request = super::tests::request();
        request.tenant = "common".into();
        assert!(provider().begin(&request).is_err());
    }
}
