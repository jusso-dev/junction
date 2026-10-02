//! Headless client-secret and explicit workload credentials. Secrets are never command-line arguments.
use crate::{
    AccessToken, AuthFlow, Secret, TokenRequest, client_credentials::ClientCredentialsProvider,
};
use anyhow::{Result, bail};

pub struct EnvironmentCredential {
    tenant: String,
    provider: EnvironmentProvider,
}
enum EnvironmentProvider {
    ManagedIdentity {
        client_id: Option<String>,
    },
    OnBehalfOf(crate::on_behalf_of::OnBehalfOfProvider),
    External(crate::external::ExternalBearerProvider),
    ClientSecret(ClientCredentialsProvider),
    Certificate {
        client_id: String,
        certificate_path: std::path::PathBuf,
        key_path: std::path::PathBuf,
    },
    Workload {
        client_id: String,
        path: std::path::PathBuf,
    },
}
impl EnvironmentCredential {
    pub fn from_environment() -> Result<Self> {
        Self::from_values(
            read("AZURE_TENANT_ID")?,
            read("AZURE_CLIENT_ID")?,
            Secret::new(read("AZURE_CLIENT_SECRET")?)?,
        )
    }
    /// Select exactly the requested flow; no implicit fallback to another credential.
    pub fn from_environment_for(flow: &AuthFlow) -> Result<Self> {
        match flow {
            AuthFlow::Certificate => {
                let tenant = read("AZURE_TENANT_ID")?;
                validate_tenant(&tenant)?;
                let client_id = read("AZURE_CLIENT_ID")?;
                crate::certificate::validate_client_id(&client_id)?;
                let path = |name| {
                    std::env::var_os(name)
                        .filter(|value| !value.is_empty())
                        .map(std::path::PathBuf::from)
                        .ok_or_else(|| anyhow::anyhow!("certificate credential path unavailable"))
                };
                Ok(Self {
                    tenant,
                    provider: EnvironmentProvider::Certificate {
                        client_id,
                        certificate_path: path("AZURE_CLIENT_CERTIFICATE_PATH")?,
                        key_path: path("AZURE_CLIENT_PRIVATE_KEY_PATH")?,
                    },
                })
            }
            AuthFlow::ManagedIdentity => {
                let tenant = read("AZURE_TENANT_ID")?;
                validate_tenant(&tenant)?;
                let client_id = match std::env::var("AZURE_CLIENT_ID") {
                    Ok(value) => Some(value),
                    Err(std::env::VarError::NotPresent) => None,
                    Err(_) => bail!("invalid managed identity client identifier"),
                };
                crate::managed_identity::validate_client_id(client_id.as_deref())?;
                Ok(Self {
                    tenant,
                    provider: EnvironmentProvider::ManagedIdentity { client_id },
                })
            }
            AuthFlow::OnBehalfOf => {
                let tenant = read("AZURE_TENANT_ID")?;
                validate_tenant(&tenant)?;
                let incoming_tenant = read("JUNCTION_OBO_TENANT")?;
                if !tenant.eq_ignore_ascii_case(&incoming_tenant) {
                    bail!("on-behalf-of assertion tenant mismatch");
                }
                let seconds: u64 = read("JUNCTION_OBO_EXPIRES_AT")?
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid on-behalf-of assertion expiry"))?;
                let expires_at = std::time::UNIX_EPOCH
                    .checked_add(std::time::Duration::from_secs(seconds))
                    .ok_or_else(|| anyhow::anyhow!("invalid on-behalf-of assertion expiry"))?;
                let audience = read("JUNCTION_OBO_MIDDLE_TIER_AUDIENCE")?;
                let incoming = AccessToken::new(
                    Secret::new(read("JUNCTION_OBO_ASSERTION")?)?,
                    crate::TokenMetadata {
                        tenant: incoming_tenant,
                        audience: audience.clone(),
                        expires_at,
                        scopes: vec![],
                        roles: vec![],
                        account: None,
                    },
                );
                let provider = crate::on_behalf_of::OnBehalfOfProvider::new(
                    read("AZURE_CLIENT_ID")?,
                    Secret::new(read("AZURE_CLIENT_SECRET")?)?,
                    &audience,
                    incoming,
                )?;
                Ok(Self {
                    tenant,
                    provider: EnvironmentProvider::OnBehalfOf(provider),
                })
            }
            AuthFlow::ClientCredentials => Self::from_environment(),
            AuthFlow::WorkloadIdentity => Self::workload(
                read("AZURE_TENANT_ID")?,
                read("AZURE_CLIENT_ID")?,
                std::env::var_os("AZURE_FEDERATED_TOKEN_FILE")
                    .filter(|path| !path.is_empty())
                    .map(std::path::PathBuf::from)
                    .ok_or_else(|| anyhow::anyhow!("workload token file unavailable"))?,
            ),
            AuthFlow::ExternalBearer => {
                let tenant = read("JUNCTION_TOKEN_TENANT")?;
                validate_tenant(&tenant)?;
                let seconds: u64 = read("JUNCTION_TOKEN_EXPIRES_AT")?
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid external token expiry"))?;
                let expires_at = std::time::UNIX_EPOCH
                    .checked_add(std::time::Duration::from_secs(seconds))
                    .ok_or_else(|| anyhow::anyhow!("invalid external token expiry"))?;
                let provider = crate::external::ExternalBearerProvider::new(
                    Secret::new(read("JUNCTION_ACCESS_TOKEN")?)?,
                    crate::TokenMetadata {
                        tenant: tenant.clone(),
                        audience: read("JUNCTION_TOKEN_AUDIENCE")?,
                        expires_at,
                        scopes: vec![],
                        roles: vec![],
                        account: None,
                    },
                )?;
                Ok(Self {
                    tenant,
                    provider: EnvironmentProvider::External(provider),
                })
            }
            _ => bail!("environment credential flow unsupported"),
        }
    }
    fn workload(tenant: String, client_id: String, path: std::path::PathBuf) -> Result<Self> {
        validate_tenant(&tenant)?;
        if client_id.is_empty()
            || !client_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            bail!("invalid client identifier");
        }
        Ok(Self {
            tenant,
            provider: EnvironmentProvider::Workload { client_id, path },
        })
    }
    fn from_values(tenant: String, client_id: String, secret: Secret) -> Result<Self> {
        validate_tenant(&tenant)?;
        Ok(Self {
            tenant,
            provider: EnvironmentProvider::ClientSecret(ClientCredentialsProvider::new(
                client_id, secret,
            )?),
        })
    }
    pub async fn acquire(&self, request: &TokenRequest) -> Result<AccessToken> {
        self.validate_request(request)?;
        match &self.provider {
            EnvironmentProvider::Certificate {
                client_id,
                certificate_path,
                key_path,
            } => {
                let certificate = crate::certificate::read_der(certificate_path, false)?;
                let key = crate::certificate::read_der(key_path, true)?;
                crate::certificate::CertificateCredentialsProvider::new(
                    client_id.clone(),
                    &certificate,
                    key,
                )?
                .acquire(request)
                .await
            }
            EnvironmentProvider::ManagedIdentity { client_id } => {
                static POOL: std::sync::OnceLock<crate::managed_identity::ManagedIdentityPool> =
                    std::sync::OnceLock::new();
                POOL.get_or_init(crate::managed_identity::ManagedIdentityPool::default)
                    .acquire(request, client_id.as_deref())
                    .await
            }
            EnvironmentProvider::OnBehalfOf(provider) => provider.acquire(request).await,
            EnvironmentProvider::External(provider) => provider.acquire(request),
            EnvironmentProvider::ClientSecret(provider) => provider.acquire(request).await,
            EnvironmentProvider::Workload { client_id, path } => {
                let assertion = read_assertion(path)?;
                ClientCredentialsProvider::with_workload_assertion(client_id.clone(), assertion)?
                    .acquire(request)
                    .await
            }
        }
    }
    fn validate_request(&self, request: &TokenRequest) -> Result<()> {
        request.key()?;
        if !self.tenant.eq_ignore_ascii_case(&request.tenant) {
            bail!("environment credential tenant mismatch");
        }
        let expected = match self.provider {
            EnvironmentProvider::Certificate { .. } => AuthFlow::Certificate,
            EnvironmentProvider::ManagedIdentity { .. } => AuthFlow::ManagedIdentity,
            EnvironmentProvider::OnBehalfOf(_) => AuthFlow::OnBehalfOf,
            EnvironmentProvider::External(_) => AuthFlow::ExternalBearer,
            EnvironmentProvider::ClientSecret(_) => AuthFlow::ClientCredentials,
            EnvironmentProvider::Workload { .. } => AuthFlow::WorkloadIdentity,
        };
        if request.flow != expected {
            bail!("environment credential flow mismatch");
        }
        Ok(())
    }
}
fn validate_tenant(tenant: &str) -> Result<()> {
    if tenant.is_empty()
        || !tenant
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.'))
    {
        bail!("invalid environment tenant");
    }
    Ok(())
}
fn read_assertion(path: &std::path::Path) -> Result<Secret> {
    use std::io::Read;
    let file =
        std::fs::File::open(path).map_err(|_| anyhow::anyhow!("workload token file unreadable"))?;
    if !file
        .metadata()
        .map_err(|_| anyhow::anyhow!("workload token file unreadable"))?
        .is_file()
    {
        bail!("invalid workload token file");
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("workload token file unreadable"))?;
    if bytes.len() > 1024 * 1024 {
        bail!("workload assertion too large");
    }
    let assertion = std::str::from_utf8(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid workload assertion encoding"))?
        .trim();
    if assertion.is_empty() || assertion.chars().any(char::is_whitespace) {
        bail!("invalid workload assertion");
    }
    Secret::new(assertion.to_owned())
}
fn read(name: &str) -> Result<String> {
    std::env::var(name)
        .map_err(|_| anyhow::anyhow!("required credential environment variable unavailable"))
}
#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn certificate_credentials_reject_tenant_and_flow_before_reading_files() {
        let credential = super::EnvironmentCredential {
            tenant: "tenant-a".into(),
            provider: super::EnvironmentProvider::Certificate {
                client_id: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".into(),
                certificate_path: "missing-private-certificate".into(),
                key_path: "missing-private-key".into(),
            },
        };
        let mut request = crate::TokenRequest {
            tenant: "tenant-b".into(),
            authority: "https://login.example.invalid".into(),
            audience: "resource".into(),
            scopes: vec![],
            credential_profile: "cert".into(),
            flow: crate::AuthFlow::Certificate,
            api_key: None,
        };
        assert_eq!(
            credential
                .acquire(&request)
                .await
                .err()
                .unwrap()
                .to_string(),
            "environment credential tenant mismatch"
        );
        request.tenant = "tenant-a".into();
        request.flow = crate::AuthFlow::ClientCredentials;
        assert_eq!(
            credential
                .acquire(&request)
                .await
                .err()
                .unwrap()
                .to_string(),
            "environment credential flow mismatch"
        );
    }
    use super::*;
    #[tokio::test]
    async fn managed_identity_selection_rejects_cross_tenant_and_delegated_scope_before_http() {
        let credential = EnvironmentCredential {
            tenant: "tenant-a".into(),
            provider: EnvironmentProvider::ManagedIdentity { client_id: None },
        };
        let mut request = TokenRequest {
            tenant: "tenant-b".into(),
            authority: "https://login.microsoftonline.com".into(),
            audience: "https://management.azure.com/".into(),
            scopes: vec![],
            credential_profile: "azure-vm".into(),
            flow: AuthFlow::ManagedIdentity,
            api_key: None,
        };
        assert!(
            credential
                .acquire(&request)
                .await
                .unwrap_err()
                .to_string()
                .contains("tenant mismatch")
        );
        request.tenant = "TENANT-A".into();
        assert!(credential.validate_request(&request).is_ok());
        request.flow = AuthFlow::ClientCredentials;
        assert!(
            credential
                .acquire(&request)
                .await
                .unwrap_err()
                .to_string()
                .contains("flow mismatch")
        );
        request.flow = AuthFlow::ManagedIdentity;
        request.scopes = vec!["User.Read".into()];
        assert!(
            credential
                .acquire(&request)
                .await
                .unwrap_err()
                .to_string()
                .contains("default scope")
        );
        assert!(crate::managed_identity::validate_client_id(Some("")).is_err());
        assert!(crate::managed_identity::validate_client_id(None).is_ok());
    }
    #[tokio::test]
    async fn on_behalf_of_environment_provider_enforces_flow_and_tenant() {
        let incoming = AccessToken::new(
            Secret::new("incoming.jwt.assertion".into()).unwrap(),
            crate::TokenMetadata {
                tenant: "a".into(),
                audience: "api://middle-tier".into(),
                expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
                scopes: vec![],
                roles: vec![],
                account: None,
            },
        );
        let provider = crate::on_behalf_of::OnBehalfOfProvider::new(
            "client-a".into(),
            Secret::new("private-client-secret".into()).unwrap(),
            "api://middle-tier",
            incoming,
        )
        .unwrap();
        let credential = EnvironmentCredential {
            tenant: "a".into(),
            provider: EnvironmentProvider::OnBehalfOf(provider),
        };
        let mut request = TokenRequest {
            tenant: "a".into(),
            authority: "https://login.example.com".into(),
            audience: "https://resource.example.com".into(),
            scopes: vec![],
            credential_profile: "obo".into(),
            flow: AuthFlow::OnBehalfOf,
            api_key: None,
        };
        assert!(credential.validate_request(&request).is_ok());
        // Empty target scopes fail in the selected OBO provider before HTTP.
        let error = credential.acquire(&request).await.unwrap_err().to_string();
        assert!(error.contains("scopes must target"));
        assert!(!error.contains("private-client-secret"));
        request.tenant = "b".into();
        assert!(
            credential
                .acquire(&request)
                .await
                .unwrap_err()
                .to_string()
                .contains("tenant mismatch")
        );
        request.tenant = "a".into();
        request.flow = AuthFlow::ClientCredentials;
        assert!(
            credential
                .acquire(&request)
                .await
                .unwrap_err()
                .to_string()
                .contains("flow mismatch")
        );
    }
    #[test]
    fn workload_files_are_bounded_reread_and_tenant_isolated() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("assertion");
        std::fs::write(&path, " first.jwt.assertion\n").unwrap();
        assert_eq!(
            read_assertion(&path).unwrap().expose(),
            "first.jwt.assertion"
        );
        std::fs::write(&path, "second.jwt.assertion").unwrap();
        assert_eq!(
            read_assertion(&path).unwrap().expose(),
            "second.jwt.assertion"
        );
        let credential =
            EnvironmentCredential::workload("a".into(), "client-a".into(), path.clone()).unwrap();
        let mut request = TokenRequest {
            tenant: "b".into(),
            authority: "https://login.example.com".into(),
            audience: "https://resource.example.com".into(),
            scopes: vec![],
            credential_profile: "workload".into(),
            flow: AuthFlow::WorkloadIdentity,
            api_key: None,
        };
        assert!(credential.validate_request(&request).is_err());
        request.tenant = "a".into();
        assert!(credential.validate_request(&request).is_ok());
        request.flow = AuthFlow::ClientCredentials;
        assert!(credential.validate_request(&request).is_err());
        for bytes in [
            vec![b'x'; 1024 * 1024 + 1],
            b"secret with whitespace".to_vec(),
            vec![255],
        ] {
            std::fs::write(&path, bytes).unwrap();
            assert!(read_assertion(&path).is_err());
        }
    }
    #[test]
    fn rejects_cross_tenant_and_wrong_flow_without_network() {
        let credential = EnvironmentCredential::from_values(
            "customer-a".into(),
            "client-a".into(),
            Secret::new("secret-value".into()).unwrap(),
        )
        .unwrap();
        let mut request = TokenRequest {
            tenant: "CUSTOMER-A".into(),
            authority: "https://login.example.com".into(),
            audience: "https://resource.example.com".into(),
            scopes: vec![],
            credential_profile: "default".into(),
            flow: AuthFlow::ClientCredentials,
            api_key: None,
        };
        assert!(credential.validate_request(&request).is_ok());
        request.tenant = "customer-b".into();
        let error = credential
            .validate_request(&request)
            .unwrap_err()
            .to_string();
        assert!(!error.contains("secret-value"));
        request.tenant = "customer-a".into();
        request.flow = AuthFlow::DeviceCode;
        assert!(credential.validate_request(&request).is_err());
    }
}
