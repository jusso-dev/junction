//! Externally supplied credentials and operator-attested metadata, never unverified JWT claims.
use crate::{AccessToken, AuthFlow, Secret, TokenMetadata, TokenRequest};
use anyhow::{Result, bail};
use std::time::{Duration, SystemTime};

pub struct ExternalBearerProvider {
    secret: Secret,
    metadata: TokenMetadata,
}
impl ExternalBearerProvider {
    /// The credential broker/operator is responsible for supplying correct token metadata.
    pub fn new(secret: Secret, metadata: TokenMetadata) -> Result<Self> {
        if secret.expose().len() > 1024 * 1024
            || secret.expose().chars().any(char::is_whitespace)
            || metadata.tenant.is_empty()
            || metadata.audience.is_empty()
        {
            bail!("invalid external credential");
        }
        Ok(Self { secret, metadata })
    }
    pub fn acquire(&self, request: &TokenRequest) -> Result<AccessToken> {
        request.validate()?;
        if request.flow != AuthFlow::ExternalBearer
            || !request.tenant.eq_ignore_ascii_case(&self.metadata.tenant)
            || request.audience != self.metadata.audience
        {
            bail!("external credential context mismatch");
        }
        if self.metadata.expires_at <= SystemTime::now() + Duration::from_secs(60) {
            bail!("external credential expired");
        }
        if request
            .scopes
            .iter()
            .any(|scope| !self.metadata.scopes.contains(scope))
        {
            bail!("external credential requested scopes unavailable");
        }
        Ok(AccessToken::new(
            Secret::new(self.secret.expose().to_owned())?,
            self.metadata.clone(),
        ))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn external_credentials_are_bound_to_attested_context_and_expiry() {
        let metadata = TokenMetadata {
            tenant: "a".into(),
            audience: "resource".into(),
            expires_at: SystemTime::now() + Duration::from_secs(3600),
            scopes: vec!["read".into()],
            roles: vec![],
            account: None,
        };
        let provider = ExternalBearerProvider::new(
            Secret::new("opaque-secret-token".into()).unwrap(),
            metadata.clone(),
        )
        .unwrap();
        let request = TokenRequest {
            tenant: "a".into(),
            audience: "resource".into(),
            authority: "https://login.example.com".into(),
            scopes: vec!["read".into()],
            credential_profile: "injected".into(),
            flow: AuthFlow::ExternalBearer,
            api_key: None,
        };
        let token = provider.acquire(&request).unwrap();
        assert!(!format!("{token:?}").contains("opaque-secret-token"));
        for field in 0..4 {
            let mut bad = request.clone();
            match field {
                0 => bad.tenant = "b".into(),
                1 => bad.audience = "other".into(),
                2 => bad.flow = AuthFlow::ClientCredentials,
                _ => bad.scopes = vec!["write".into()],
            }
            assert!(provider.acquire(&bad).is_err());
        }
        let provider = ExternalBearerProvider::new(
            Secret::new("opaque-secret-token".into()).unwrap(),
            TokenMetadata {
                expires_at: SystemTime::now(),
                ..metadata
            },
        )
        .unwrap();
        assert!(provider.acquire(&request).is_err());
    }
}
