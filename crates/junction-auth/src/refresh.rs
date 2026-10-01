//! Refresh credentials stay pinned to their original acquisition context.
use crate::{AccessToken, AuthFlow, Secret, TokenRequest};
use anyhow::{Result, bail};
use serde::Deserialize;
use std::time::Duration;
use zeroize::Zeroizing;

/// Intentionally neither serializable nor clonable. Debug redacts the credential.
#[derive(Debug)]
pub struct RefreshCredential {
    pub(crate) request: TokenRequest,
    pub(crate) client_id: String,
    pub(crate) secret: Secret,
}
impl RefreshCredential {
    pub(crate) fn new(request: &TokenRequest, client_id: String, secret: Secret) -> Result<Self> {
        validate(request)?;
        validate_client(&client_id)?;
        if secret.expose().len() > 16 * 1024 {
            bail!("refresh credential exceeds size limit");
        }
        Ok(Self {
            request: request.clone(),
            client_id,
            secret,
        })
    }
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
    pub(crate) fn matches(&self, request: &TokenRequest) -> Result<bool> {
        Ok(self.request.key()? == request.key()?)
    }
}
/// Contains credentials; callers must persist the new pair together after success.
#[derive(Debug)]
pub struct RefreshedTokens {
    pub access_token: AccessToken,
    pub refresh_credential: RefreshCredential,
}
pub struct RefreshTokenProvider {
    client: reqwest::Client,
    client_id: String,
    client_secret: Option<Secret>,
}
impl RefreshTokenProvider {
    pub fn new(client_id: String) -> Result<Self> {
        validate_client(&client_id)?;
        Ok(Self {
            client: reqwest::Client::builder()
                .https_only(true)
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(30))
                .build()
                .map_err(|_| anyhow::anyhow!("could not initialize refresh transport"))?,
            client_id,
            client_secret: None,
        })
    }
    pub fn with_client_secret(client_id: String, secret: Secret) -> Result<Self> {
        if secret.expose().len() > 16 * 1024 {
            bail!("client secret exceeds size limit");
        }
        let mut provider = Self::new(client_id)?;
        provider.client_secret = Some(secret);
        Ok(provider)
    }
    fn validate(&self, credential: &RefreshCredential) -> Result<()> {
        validate(&credential.request)?;
        if self.client_id != credential.client_id
            || (credential.request.flow == AuthFlow::AuthorizationCode)
                != self.client_secret.is_some()
        {
            bail!("refresh provider does not match the original client application");
        }
        Ok(())
    }
    fn form<'a>(
        &'a self,
        credential: &'a RefreshCredential,
        scope: &'a str,
    ) -> Vec<(&'static str, &'a str)> {
        let mut fields = vec![
            ("client_id", self.client_id.as_str()),
            ("grant_type", "refresh_token"),
            ("refresh_token", credential.secret.expose()),
            ("scope", scope),
        ];
        if let Some(secret) = &self.client_secret {
            fields.push(("client_secret", secret.expose()));
        }
        fields
    }
    /// No caller-supplied tenant, authority, audience or scopes can change this grant.
    pub async fn acquire(&self, credential: &RefreshCredential) -> Result<RefreshedTokens> {
        self.validate(credential)?;
        let scope = credential.request.scopes.join(" ");
        let endpoint = format!(
            "{}/{}/oauth2/v2.0/token",
            credential.request.authority.trim_end_matches('/'),
            credential.request.tenant
        );
        let mut response = self
            .client
            .post(endpoint)
            .form(&self.form(credential, &scope))
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("refresh token request failed"))?;
        if !response.status().is_success() {
            bail!("refresh token request rejected; interactive login may be required");
        }
        const LIMIT: usize = 1024 * 1024;
        if response
            .content_length()
            .is_some_and(|size| size > LIMIT as u64)
        {
            bail!("refresh token response too large");
        }
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow::anyhow!("refresh response read failed"))?
        {
            if bytes.len().saturating_add(chunk.len()) > LIMIT {
                bail!("refresh token response too large");
            }
            bytes.extend_from_slice(&chunk);
        }
        self.decode(credential, &bytes)
    }
    fn decode(&self, credential: &RefreshCredential, bytes: &[u8]) -> Result<RefreshedTokens> {
        let (access_token, renewal) =
            decode_interactive(bytes, &credential.request, &self.client_id)?;
        let refresh_credential = match renewal {
            Some(renewal) => renewal,
            None => RefreshCredential::new(
                &credential.request,
                credential.client_id.clone(),
                Secret::new(credential.secret.expose().to_owned())?,
            )?,
        };
        Ok(RefreshedTokens {
            access_token,
            refresh_credential,
        })
    }
}
pub(crate) fn decode_interactive(
    bytes: &[u8],
    request: &TokenRequest,
    client_id: &str,
) -> Result<(AccessToken, Option<RefreshCredential>)> {
    let token = crate::client_credentials::decode(bytes, request)?;
    #[derive(Deserialize)]
    struct Response {
        refresh_token: Option<Zeroizing<String>>,
    }
    let response: Response = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("invalid interactive token response"))?;
    let refresh = if request.scopes.iter().any(|scope| scope == "offline_access") {
        response
            .refresh_token
            .map(|secret| {
                RefreshCredential::new(
                    request,
                    client_id.to_owned(),
                    Secret::new(secret.to_string())?,
                )
            })
            .transpose()?
    } else {
        None
    };
    Ok((token, refresh))
}
fn validate_client(client_id: &str) -> Result<()> {
    if client_id.is_empty()
        || client_id.len() > 256
        || !client_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        bail!("invalid refresh client identifier");
    }
    Ok(())
}
fn validate(request: &TokenRequest) -> Result<()> {
    match request.flow {
        AuthFlow::DeviceCode => crate::device_code::validate(request)?,
        AuthFlow::Pkce | AuthFlow::AuthorizationCode => crate::pkce::validate(request)?,
        _ => bail!("refresh requires an interactive acquisition context"),
    }
    if !request.scopes.iter().any(|scope| scope == "offline_access") {
        bail!("refresh requires the originally requested offline_access scope");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> TokenRequest {
        TokenRequest {
            tenant: "tenant-a".into(),
            authority: "https://login.microsoftonline.us".into(),
            audience: "https://graph.microsoft.us".into(),
            scopes: vec![
                "https://graph.microsoft.us/User.Read".into(),
                "offline_access".into(),
            ],
            credential_profile: "operator-a".into(),
            flow: AuthFlow::DeviceCode,
        }
    }
    fn credential() -> RefreshCredential {
        RefreshCredential::new(
            &request(),
            "client-a".into(),
            Secret::new("private&=+refresh".into()).unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn grant_is_encoded_pinned_and_client_modes_are_isolated() {
        let credential = credential();
        let provider = RefreshTokenProvider::new("client-a".into()).unwrap();
        assert!(provider.validate(&credential).is_ok());
        let scope = credential.request.scopes.join(" ");
        let wire = provider
            .client
            .post("https://login.microsoftonline.us/tenant-a/oauth2/v2.0/token")
            .form(&provider.form(&credential, &scope))
            .build()
            .unwrap();
        let fields: std::collections::BTreeMap<_, _> =
            url::form_urlencoded::parse(wire.body().unwrap().as_bytes().unwrap())
                .into_owned()
                .collect();
        assert_eq!(fields["refresh_token"], "private&=+refresh");
        assert_eq!(fields["grant_type"], "refresh_token");
        assert_eq!(fields["client_id"], "client-a");
        assert_eq!(fields["scope"], scope);
        assert!(!fields.contains_key("client_secret"));
        assert!(!wire.headers().contains_key("authorization"));
        assert!(!format!("{credential:?}").contains("private&=+refresh"));
        assert!(
            RefreshTokenProvider::new("other-client".into())
                .unwrap()
                .validate(&credential)
                .is_err()
        );
        let confidential = RefreshTokenProvider::with_client_secret(
            "client-a".into(),
            Secret::new("private-client-secret".into()).unwrap(),
        )
        .unwrap();
        assert!(confidential.validate(&credential).is_err());
        let mut web = request();
        web.flow = AuthFlow::AuthorizationCode;
        let web = RefreshCredential::new(
            &web,
            "client-a".into(),
            Secret::new("private-web-refresh".into()).unwrap(),
        )
        .unwrap();
        assert!(provider.validate(&web).is_err());
        assert!(confidential.validate(&web).is_ok());
        assert!(
            confidential
                .form(&web, &scope)
                .contains(&("client_secret", "private-client-secret"))
        );
    }
    #[test]
    fn rotation_replaces_secrets_and_missing_rotation_preserves_existing_grant() {
        let provider = RefreshTokenProvider::new("client-a".into()).unwrap();
        let credential = credential();
        let rotated = provider.decode(&credential, br#"{"access_token":"private-access","token_type":"Bearer","expires_in":3600,"refresh_token":"private-new-refresh"}"#).unwrap();
        assert_eq!(
            rotated.refresh_credential.secret.expose(),
            "private-new-refresh"
        );
        assert_eq!(rotated.access_token.metadata().tenant, "tenant-a");
        assert_eq!(
            rotated.access_token.metadata().audience,
            "https://graph.microsoft.us"
        );
        assert!(!format!("{rotated:?}").contains("private-access"));
        assert!(!format!("{rotated:?}").contains("private-new-refresh"));
        let reused = provider
            .decode(
                &credential,
                br#"{"access_token":"new-access","token_type":"Bearer","expires_in":3600}"#,
            )
            .unwrap();
        assert_eq!(
            reused.refresh_credential.secret.expose(),
            credential.secret.expose()
        );
        assert_eq!(credential.secret.expose(), "private&=+refresh");
        let error = provider.decode(&credential, br#"{"access_token":"private-access","token_type":"Bearer","expires_in":3600,"refresh_token":""}"#).unwrap_err().to_string();
        assert!(!error.contains("private-access"));
    }
    #[test]
    fn offline_access_and_interactive_context_are_required() {
        let mut request = request();
        request.scopes.pop();
        assert!(
            RefreshCredential::new(
                &request,
                "client-a".into(),
                Secret::new("private-refresh".into()).unwrap()
            )
            .is_err()
        );
        let (_, refresh) = decode_interactive(br#"{"access_token":"access","token_type":"Bearer","expires_in":3600,"refresh_token":"unrequested-refresh"}"#, &request, "client-a").unwrap();
        assert!(refresh.is_none());
        request.flow = AuthFlow::ClientCredentials;
        assert!(
            RefreshCredential::new(
                &request,
                "client-a".into(),
                Secret::new("private-refresh".into()).unwrap()
            )
            .is_err()
        );
    }
}
