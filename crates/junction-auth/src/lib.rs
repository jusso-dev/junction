//! Credential boundaries shared by future token providers and all execution surfaces.
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt,
    sync::Mutex,
    time::{Duration, SystemTime},
};
use url::Url;
use zeroize::Zeroizing;

/// Intentionally not Serialize or Display. Access requires explicit exposure.
pub struct Secret(Zeroizing<String>);
impl Secret {
    pub fn new(value: String) -> Result<Self> {
        if value.is_empty() || value.chars().any(char::is_control) {
            bail!("invalid credential value");
        }
        Ok(Self(Zeroizing::new(value)))
    }
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AuthFlow {
    AuthorizationCode,
    Pkce,
    ClientCredentials,
    DeviceCode,
    ManagedIdentity,
    WorkloadIdentity,
    Certificate,
    OnBehalfOf,
    ExternalBearer,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRequest {
    pub tenant: String,
    pub authority: String,
    pub audience: String,
    pub scopes: Vec<String>,
    pub credential_profile: String,
    pub flow: AuthFlow,
}
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CacheKey {
    tenant: String,
    authority: String,
    audience: String,
    scopes: Vec<String>,
    profile: String,
    flow: AuthFlow,
}
impl TokenRequest {
    /// Validate acquisition context without obtaining or exposing credentials.
    pub fn validate(&self) -> Result<()> {
        self.key().map(|_| ())
    }
    fn key(&self) -> Result<CacheKey> {
        if self.tenant.is_empty()
            || !self
                .tenant
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.'))
            || ["common", "organizations", "consumers"]
                .contains(&self.tenant.to_ascii_lowercase().as_str())
        {
            bail!("token cache requires a concrete tenant");
        }
        if self.credential_profile.trim().is_empty() {
            bail!("credential profile is required");
        }
        let authority =
            Url::parse(&self.authority).map_err(|_| anyhow::anyhow!("invalid authority"))?;
        if authority.scheme() != "https"
            || authority.host_str().is_none()
            || !authority.username().is_empty()
            || authority.password().is_some()
            || authority.query().is_some()
            || authority.fragment().is_some()
            || authority.path() != "/"
        {
            bail!("authority must be an HTTPS origin");
        }
        if self.audience.trim().is_empty() || self.audience.chars().any(char::is_control) {
            bail!("audience is required");
        }
        let mut scopes = self.scopes.clone();
        if scopes
            .iter()
            .any(|s| s.is_empty() || s.chars().any(char::is_whitespace))
        {
            bail!("invalid scope");
        }
        scopes.sort();
        scopes.dedup();
        Ok(CacheKey {
            tenant: self.tenant.to_ascii_lowercase(),
            authority: authority.to_string(),
            audience: self.audience.clone(),
            scopes,
            profile: self.credential_profile.clone(),
            flow: self.flow,
        })
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct TokenMetadata {
    pub tenant: String,
    pub audience: String,
    pub expires_at: SystemTime,
    pub scopes: Vec<String>,
    pub roles: Vec<String>,
    pub account: Option<String>,
}
#[derive(Debug)]
pub struct AccessToken {
    secret: Secret,
    metadata: TokenMetadata,
}
impl AccessToken {
    /// Providers must supply tenant/audience from their trusted acquisition context.
    /// Unverified JWT claims must not authorize cache insertion.
    pub fn new(secret: Secret, metadata: TokenMetadata) -> Self {
        Self { secret, metadata }
    }
    pub fn expose(&self) -> &str {
        self.secret.expose()
    }
    pub fn bearer_secret(&self) -> &Secret {
        &self.secret
    }
    pub fn metadata(&self) -> &TokenMetadata {
        &self.metadata
    }
}
#[derive(Default)]
pub struct TokenCache {
    entries: Mutex<BTreeMap<CacheKey, AccessToken>>,
}
impl TokenCache {
    pub fn insert(&self, request: &TokenRequest, token: AccessToken) -> Result<()> {
        let key = request.key()?;
        if request.flow == AuthFlow::OnBehalfOf {
            bail!("on-behalf-of tokens require a user-bound cache");
        }
        if !token.metadata.tenant.eq_ignore_ascii_case(&request.tenant)
            || token.metadata.audience != request.audience
        {
            bail!("token context mismatch");
        }
        if token.metadata.expires_at <= SystemTime::now() + Duration::from_secs(60) {
            bail!("token expires too soon");
        }
        self.entries
            .lock()
            .map_err(|_| anyhow::anyhow!("credential cache unavailable"))?
            .insert(key, token);
        Ok(())
    }
    /// Borrow a credential only within a callback; cache does not expose serializable entries.
    pub fn with_token<T>(
        &self,
        request: &TokenRequest,
        use_token: impl FnOnce(&AccessToken) -> T,
    ) -> Result<Option<T>> {
        let key = request.key()?;
        if request.flow == AuthFlow::OnBehalfOf {
            return Ok(None);
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("credential cache unavailable"))?;
        if entries.get(&key).is_some_and(|token| {
            token.metadata.expires_at <= SystemTime::now() + Duration::from_secs(60)
        }) {
            entries.remove(&key);
        }
        Ok(entries.get(&key).map(use_token))
    }
    pub fn logout(&self, tenant: &str, profile: &str) -> Result<()> {
        self.entries
            .lock()
            .map_err(|_| anyhow::anyhow!("credential cache unavailable"))?
            .retain(|key, _| !(key.tenant.eq_ignore_ascii_case(tenant) && key.profile == profile));
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> TokenRequest {
        TokenRequest {
            tenant: "customer-a".into(),
            authority: "https://login.example.com".into(),
            audience: "resource-a".into(),
            scopes: vec!["read".into()],
            credential_profile: "default".into(),
            flow: AuthFlow::ExternalBearer,
        }
    }
    fn token(request: &TokenRequest) -> AccessToken {
        AccessToken::new(
            Secret::new("sensitive-token".into()).unwrap(),
            TokenMetadata {
                tenant: request.tenant.clone(),
                audience: request.audience.clone(),
                expires_at: SystemTime::now() + Duration::from_secs(3600),
                scopes: request.scopes.clone(),
                roles: vec![],
                account: None,
            },
        )
    }
    #[test]
    fn isolation_covers_every_credential_dimension() {
        let request = request();
        let cache = TokenCache::default();
        cache.insert(&request, token(&request)).unwrap();
        assert_eq!(
            cache
                .with_token(&request, |t| t.expose().to_owned())
                .unwrap()
                .as_deref(),
            Some("sensitive-token")
        );
        for field in 0..6 {
            let mut other = request.clone();
            match field {
                0 => other.tenant = "customer-b".into(),
                1 => other.authority = "https://other.example.com".into(),
                2 => other.audience = "resource-b".into(),
                3 => other.scopes.push("write".into()),
                4 => other.credential_profile = "other".into(),
                _ => other.flow = AuthFlow::DeviceCode,
            }
            assert!(cache.with_token(&other, |_| ()).unwrap().is_none());
        }
        cache.logout("customer-b", "default").unwrap();
        assert!(cache.with_token(&request, |_| ()).unwrap().is_some());
        cache.logout("customer-a", "default").unwrap();
        assert!(cache.with_token(&request, |_| ()).unwrap().is_none());
    }
    #[test]
    fn redaction_mismatch_and_expiry() {
        let request = request();
        let cache = TokenCache::default();
        let mut t = token(&request);
        assert!(!format!("{t:?}").contains("sensitive-token"));
        t.metadata.tenant = "customer-b".into();
        assert!(cache.insert(&request, t).is_err());
        let mut t = token(&request);
        t.metadata.expires_at = SystemTime::now();
        assert!(cache.insert(&request, t).is_err());
        let mut r = request.clone();
        r.tenant = "common".into();
        assert!(r.key().is_err());
    }
}

pub mod client_credentials;

pub mod environment;

pub mod external;
pub mod on_behalf_of;

pub mod device_code;

pub mod pkce;

pub mod refresh;
pub mod storage;

pub mod certificate;
pub mod managed_identity;
