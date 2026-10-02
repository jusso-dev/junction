//! Delegated token exchange for a trusted middle-tier service.
use crate::{
    AccessToken, AuthFlow, Secret, TokenRequest, client_credentials::ClientCredentialsProvider,
};
use anyhow::{Result, bail};
use std::time::{Duration, SystemTime};

/// One provider per incoming user assertion. No Debug, serialization, refresh
/// token persistence, or use of the application-wide token cache.
pub struct OnBehalfOfProvider {
    confidential_client: ClientCredentialsProvider,
    incoming: AccessToken,
}

impl OnBehalfOfProvider {
    /// The caller must have authenticated the incoming user token, including its
    /// signature, issuer, tenant and middle-tier audience. Unverified JWT claims
    /// must not supply AccessToken metadata. Entra also validates the assertion.
    pub fn new(
        client_id: String,
        client_secret: Secret,
        middle_tier_audience: &str,
        incoming: AccessToken,
    ) -> Result<Self> {
        if middle_tier_audience.trim().is_empty()
            || incoming.metadata().audience != middle_tier_audience
            || incoming.expose().len() > 1024 * 1024
            || incoming.expose().chars().any(char::is_whitespace)
        {
            bail!("invalid on-behalf-of assertion context");
        }
        Ok(Self {
            confidential_client: ClientCredentialsProvider::new(client_id, client_secret)?,
            incoming,
        })
    }
    fn validate(&self, request: &TokenRequest) -> Result<()> {
        request.validate()?;
        if request.flow != AuthFlow::OnBehalfOf {
            bail!("credential provider flow mismatch");
        }
        if !self
            .incoming
            .metadata()
            .tenant
            .eq_ignore_ascii_case(&request.tenant)
            || self.incoming.metadata().expires_at <= SystemTime::now() + Duration::from_secs(60)
        {
            bail!("on-behalf-of assertion tenant or expiry mismatch");
        }
        if request.scopes.is_empty()
            || request
                .scopes
                .iter()
                .any(|scope| !scope.starts_with(&format!("{}/", request.audience)))
        {
            bail!("on-behalf-of scopes must target the configured audience");
        }
        Ok(())
    }
    fn form<'a>(&'a self, scope: &'a str) -> Vec<(&'static str, &'a str)> {
        let mut fields = self.confidential_client.form(scope);
        fields.retain(|(key, _)| *key != "grant_type");
        fields.extend([
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("requested_token_use", "on_behalf_of"),
            ("assertion", self.incoming.expose()),
        ]);
        fields
    }
    pub async fn acquire(&self, request: &TokenRequest) -> Result<AccessToken> {
        self.validate(request)?;
        let endpoint = format!(
            "{}/{}/oauth2/v2.0/token",
            request.authority.trim_end_matches('/'),
            request.tenant
        );
        let scope = request.scopes.join(" ");
        self.confidential_client
            .fetch_form(request, &endpoint, &self.form(&scope))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> TokenRequest {
        TokenRequest {
            tenant: "tenant-a".into(),
            authority: "https://login.example.com".into(),
            audience: "https://resource.example.com".into(),
            scopes: vec!["https://resource.example.com/read".into()],
            credential_profile: "middle-tier".into(),
            flow: AuthFlow::OnBehalfOf,
            api_key: None,
        }
    }
    fn incoming() -> AccessToken {
        AccessToken::new(
            Secret::new("incoming.jwt.assertion".into()).unwrap(),
            crate::TokenMetadata {
                tenant: "tenant-a".into(),
                audience: "api://middle-tier".into(),
                expires_at: SystemTime::now() + Duration::from_secs(3600),
                scopes: vec![],
                roles: vec![],
                account: Some("user-a".into()),
            },
        )
    }
    fn provider() -> OnBehalfOfProvider {
        OnBehalfOfProvider::new(
            "client-a".into(),
            Secret::new("client&secret".into()).unwrap(),
            "api://middle-tier",
            incoming(),
        )
        .unwrap()
    }
    #[test]
    fn exchange_form_uses_delegated_grant_and_distinct_secrets() {
        let provider = provider();
        let fields = provider.form("https://resource.example.com/read");
        let encoded = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish();
        let fields: std::collections::BTreeMap<_, _> =
            url::form_urlencoded::parse(encoded.as_bytes())
                .into_owned()
                .collect();
        assert_eq!(
            fields["grant_type"],
            "urn:ietf:params:oauth:grant-type:jwt-bearer"
        );
        assert_eq!(fields["requested_token_use"], "on_behalf_of");
        assert_eq!(fields["assertion"], "incoming.jwt.assertion");
        assert_eq!(fields["client_secret"], "client&secret");
        assert!(!fields.contains_key("client_assertion"));
    }
    #[tokio::test]
    async fn context_failures_precede_transport_and_omit_assertions() {
        let provider = provider();
        let mut request = request();
        assert!(provider.validate(&request).is_ok());
        request.tenant = "tenant-b".into();
        let error = provider.acquire(&request).await.unwrap_err().to_string();
        assert!(error.contains("tenant or expiry"));
        assert!(!error.contains("incoming.jwt.assertion"));
        request = self::request();
        request.scopes = vec!["https://resource.example.com.attacker/read".into()];
        assert!(provider.acquire(&request).await.is_err());
        request = self::request();
        request.flow = AuthFlow::ClientCredentials;
        assert!(provider.acquire(&request).await.is_err());
        let mut expired = incoming();
        expired.metadata.expires_at = SystemTime::now();
        let provider = OnBehalfOfProvider::new(
            "client-a".into(),
            Secret::new("secret".into()).unwrap(),
            "api://middle-tier",
            expired,
        )
        .unwrap();
        assert!(provider.acquire(&self::request()).await.is_err());
        assert!(
            OnBehalfOfProvider::new(
                "client-a".into(),
                Secret::new("secret".into()).unwrap(),
                "api://another-tier",
                incoming()
            )
            .is_err()
        );
    }
    #[test]
    fn application_cache_cannot_mix_on_behalf_of_users() {
        let request = request();
        let cache = crate::TokenCache::default();
        let token = AccessToken::new(
            Secret::new("downstream-token".into()).unwrap(),
            crate::TokenMetadata {
                tenant: request.tenant.clone(),
                audience: request.audience.clone(),
                expires_at: SystemTime::now() + Duration::from_secs(3600),
                scopes: vec![],
                roles: vec![],
                account: Some("user-a".into()),
            },
        );
        assert!(cache.insert(&request, token).is_err());
        assert!(
            cache
                .with_token(&request, |_| panic!("must not expose another user's token"))
                .unwrap()
                .is_none()
        );
    }
}
