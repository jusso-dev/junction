//! Tenant-bound credential persistence. No plaintext-file fallback is provided.
use crate::{AccessToken, AuthFlow, Secret, TokenMetadata, TokenRequest};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime};
use zeroize::Zeroizing;

const LIMIT: usize = 64 * 1024;
#[cfg(target_os = "macos")]
const SERVICE: &str = "dev.jusso.junction.tokens.v1";

/// Implementations must use an operator-owned secure credential service.
/// They must never include credential values in errors or diagnostics.
pub trait CredentialStore {
    fn read(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>>;
    fn write(&self, account: &str, bytes: &[u8]) -> Result<()>;
    fn delete(&self, account: &str) -> Result<()>;
}

/// Native macOS Keychain adapter. Other platforms currently fail closed.
pub struct OsCredentialStore;
impl OsCredentialStore {
    pub fn available() -> bool {
        cfg!(target_os = "macos")
    }
}
impl CredentialStore for OsCredentialStore {
    fn read(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        validate_account(account)?;
        #[cfg(target_os = "macos")]
        {
            use security_framework::passwords::{PasswordOptions, generic_password};
            match generic_password(PasswordOptions::new_generic_password(SERVICE, account)) {
                Ok(bytes) => {
                    let bytes = Zeroizing::new(bytes);
                    if bytes.len() > LIMIT {
                        bail!("stored credential exceeds size limit");
                    }
                    Ok(Some(bytes))
                }
                Err(error) if error.code() == -25300 => Ok(None), // errSecItemNotFound
                Err(_) => bail!("OS credential store read failed"),
            }
        }
        #[cfg(not(target_os = "macos"))]
        bail!("OS credential storage is unavailable on this platform");
    }
    fn write(&self, account: &str, bytes: &[u8]) -> Result<()> {
        validate_account(account)?;
        if bytes.is_empty() || bytes.len() > LIMIT {
            bail!("invalid stored credential size");
        }
        #[cfg(target_os = "macos")]
        {
            security_framework::passwords::set_generic_password(SERVICE, account, bytes)
                .map_err(|_| anyhow::anyhow!("OS credential store write failed"))
        }
        #[cfg(not(target_os = "macos"))]
        bail!("OS credential storage is unavailable on this platform");
    }
    fn delete(&self, account: &str) -> Result<()> {
        validate_account(account)?;
        #[cfg(target_os = "macos")]
        {
            match security_framework::passwords::delete_generic_password(SERVICE, account) {
                Ok(()) => Ok(()),
                Err(error) if error.code() == -25300 => Ok(()),
                Err(_) => bail!("OS credential store delete failed"),
            }
        }
        #[cfg(not(target_os = "macos"))]
        bail!("OS credential storage is unavailable on this platform");
    }
}
fn validate_account(account: &str) -> Result<()> {
    if account.len() != 64 || !account.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("invalid credential storage account");
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    request: TokenRequest,
    access_token: Zeroizing<String>,
    expires_at: SystemTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refresh_token: Option<Zeroizing<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
}

/// Persistence of access credentials for explicitly selected interactive profiles.
/// Refresh credentials are retained separately from safe metadata.
pub struct StoredTokens<S> {
    store: S,
}
impl<S: CredentialStore> StoredTokens<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }
    pub fn save(&self, request: &TokenRequest, token: &AccessToken) -> Result<()> {
        self.save_with_refresh(request, token, None)
    }
    pub fn save_with_refresh(
        &self,
        request: &TokenRequest,
        token: &AccessToken,
        refresh: Option<&crate::refresh::RefreshCredential>,
    ) -> Result<()> {
        let account = account(request)?;
        if let Some(refresh) = refresh
            && !refresh.matches(request)?
        {
            bail!("refresh credential context mismatch");
        }
        let metadata = token.metadata();
        if !metadata.tenant.eq_ignore_ascii_case(&request.tenant)
            || metadata.audience != request.audience
        {
            bail!("stored token context mismatch");
        }
        validate_expiry(metadata.expires_at, request.flow)?;
        if token.expose().len() > 16 * 1024 {
            bail!("access credential exceeds size limit");
        }
        let record = Record {
            version: 1,
            request: request.clone(),
            access_token: Zeroizing::new(token.expose().to_owned()),
            expires_at: metadata.expires_at,
            refresh_token: refresh
                .map(|refresh| Zeroizing::new(refresh.secret.expose().to_owned())),
            client_id: refresh.map(|refresh| refresh.client_id.clone()),
        };
        let bytes = Zeroizing::new(
            serde_json::to_vec(&record)
                .map_err(|_| anyhow::anyhow!("credential encoding failed"))?,
        );
        if bytes.len() > LIMIT {
            bail!("stored credential exceeds size limit");
        }
        self.store.write(&account, &bytes)
    }
    pub fn load(&self, request: &TokenRequest) -> Result<Option<AccessToken>> {
        let Some(record) = self.read_record(request)? else {
            return Ok(None);
        };
        if record.expires_at <= SystemTime::now() + Duration::from_secs(60) {
            // Do not delete during reads: another process may have replaced this entry.
            return Ok(None);
        }
        validate_expiry(record.expires_at, request.flow)?;
        Ok(Some(AccessToken::new(
            Secret::new(record.access_token.to_string())?,
            TokenMetadata {
                tenant: request.tenant.clone(),
                audience: request.audience.clone(),
                expires_at: record.expires_at,
                scopes: vec![],
                roles: vec![],
                account: None,
            },
        )))
    }
    /// Renewal is available even when the saved access credential has expired.
    /// The caller must coordinate renewal writes with logout and other processes.
    pub fn load_refresh(
        &self,
        request: &TokenRequest,
    ) -> Result<Option<crate::refresh::RefreshCredential>> {
        let Some(record) = self.read_record(request)? else {
            return Ok(None);
        };
        match (record.client_id, record.refresh_token) {
            (Some(client_id), Some(secret)) => Ok(Some(crate::refresh::RefreshCredential::new(
                request,
                client_id,
                Secret::new(secret.to_string())?,
            )?)),
            (None, None) => Ok(None),
            _ => bail!("invalid stored refresh credential"),
        }
    }
    fn read_record(&self, request: &TokenRequest) -> Result<Option<Record>> {
        let account = account(request)?;
        let Some(bytes) = self.store.read(&account)? else {
            return Ok(None);
        };
        if bytes.len() > LIMIT {
            bail!("stored credential exceeds size limit");
        }
        let record: Record = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid stored credential"))?;
        if record.version != 1 || record.request.key()? != request.key()? {
            bail!("stored credential context mismatch");
        }
        if record.access_token.len() > 16 * 1024 {
            bail!("access credential exceeds size limit");
        }
        let lifetime = if request.flow == AuthFlow::ApiKey {
            Duration::from_secs(400 * 86400)
        } else {
            Duration::from_secs(86400)
        };
        if record.expires_at > SystemTime::now() + lifetime
            || record.client_id.is_some() != record.refresh_token.is_some()
            || record
                .refresh_token
                .as_ref()
                .is_some_and(|secret| secret.is_empty() || secret.len() > 16 * 1024)
        {
            bail!("invalid stored credential metadata");
        }
        Ok(Some(record))
    }
    /// Delete this exact acquisition context; other tenants/profiles remain intact.
    pub fn logout(&self, request: &TokenRequest) -> Result<()> {
        self.store.delete(&account(request)?)
    }
}
fn validate_expiry(expires_at: SystemTime, flow: AuthFlow) -> Result<()> {
    let now = SystemTime::now();
    // Access tokens live at most a day; operator-supplied API keys are kept
    // until replaced or removed with `junction auth logout`.
    let limit = if flow == AuthFlow::ApiKey {
        Duration::from_secs(400 * 86400)
    } else {
        Duration::from_secs(86400)
    };
    if expires_at <= now + Duration::from_secs(60) || expires_at > now + limit {
        bail!("unsupported stored credential lifetime");
    }
    Ok(())
}
fn account(request: &TokenRequest) -> Result<String> {
    if request.tenant.len() > 256
        || request.authority.len() > 4096
        || request.audience.len() > 4096
        || request.credential_profile.len() > 256
        || request.scopes.len() > 64
        || request.scopes.iter().any(|scope| scope.len() > 2048)
    {
        bail!("credential storage context exceeds size limit");
    }
    let key = request.key()?;
    if !matches!(
        request.flow,
        AuthFlow::DeviceCode | AuthFlow::Pkce | AuthFlow::AuthorizationCode | AuthFlow::ApiKey
    ) {
        bail!("persistent tokens require an interactive or operator-supplied credential profile");
    }
    let bytes = serde_json::to_vec(&(
        1u8,
        key.tenant,
        key.authority,
        key.audience,
        key.scopes,
        key.profile,
        key.flow,
    ))
    .map_err(|_| anyhow::anyhow!("credential context encoding failed"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

/// Stable opaque identifier for coordinating processes using this acquisition context.
pub fn credential_id(request: &TokenRequest) -> Result<String> {
    account(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::BTreeMap};

    #[derive(Default)]
    struct MemoryStore(RefCell<BTreeMap<String, Zeroizing<Vec<u8>>>>);
    impl CredentialStore for MemoryStore {
        fn read(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
            Ok(self.0.borrow().get(account).cloned())
        }
        fn write(&self, account: &str, bytes: &[u8]) -> Result<()> {
            self.0
                .borrow_mut()
                .insert(account.into(), Zeroizing::new(bytes.to_vec()));
            Ok(())
        }
        fn delete(&self, account: &str) -> Result<()> {
            self.0.borrow_mut().remove(account);
            Ok(())
        }
    }
    fn request() -> TokenRequest {
        TokenRequest {
            tenant: "tenant-a".into(),
            authority: "https://login.example.invalid".into(),
            audience: "https://resource.example.invalid".into(),
            scopes: vec![
                "https://resource.example.invalid/read".into(),
                "openid".into(),
            ],
            credential_profile: "operator-a".into(),
            flow: AuthFlow::DeviceCode,
            api_key: None,
        }
    }
    fn token(request: &TokenRequest) -> AccessToken {
        AccessToken::new(
            Secret::new("private-access-token".into()).unwrap(),
            TokenMetadata {
                tenant: request.tenant.clone(),
                audience: request.audience.clone(),
                expires_at: SystemTime::now() + Duration::from_secs(3600),
                scopes: vec!["unverified-scope".into()],
                roles: vec!["unverified-role".into()],
                account: None,
            },
        )
    }
    #[test]
    fn api_keys_persist_for_a_year_but_access_tokens_only_a_day() {
        let tokens = StoredTokens::new(MemoryStore::default());
        let mut request = request();
        request.scopes.clear();
        request.flow = AuthFlow::ApiKey;
        request.api_key = Some(crate::ApiKeyPlacement {
            header: "authorization".into(),
            prefix: Some("Token".into()),
        });
        let metadata = |days: u64| TokenMetadata {
            tenant: request.tenant.clone(),
            audience: request.audience.clone(),
            expires_at: SystemTime::now() + Duration::from_secs(days * 86400),
            scopes: vec![],
            roles: vec![],
            account: None,
        };
        let key = AccessToken::api_key(
            Secret::new("private-key".into()).unwrap(),
            metadata(365),
            request.api_key.clone().unwrap(),
        )
        .unwrap();
        tokens.save(&request, &key).unwrap();
        assert_eq!(
            tokens.load(&request).unwrap().unwrap().expose(),
            "private-key"
        );
        let too_long = AccessToken::api_key(
            Secret::new("private-key".into()).unwrap(),
            metadata(500),
            request.api_key.clone().unwrap(),
        )
        .unwrap();
        assert!(tokens.save(&request, &too_long).is_err());
        let device = super::tests::request();
        let mut long_token = token(&device);
        long_token.metadata.expires_at = SystemTime::now() + Duration::from_secs(2 * 86400);
        assert!(tokens.save(&device, &long_token).is_err());
    }
    #[test]
    fn persisted_tokens_are_bound_to_every_context_dimension() {
        let tokens = StoredTokens::new(MemoryStore::default());
        let request = request();
        assert!(tokens.load(&request).unwrap().is_none());
        tokens.save(&request, &token(&request)).unwrap();
        let loaded = tokens.load(&request).unwrap().unwrap();
        assert_eq!(loaded.expose(), "private-access-token");
        assert!(!format!("{loaded:?}").contains("private-access-token"));
        assert!(loaded.metadata().scopes.is_empty());
        assert!(loaded.metadata().roles.is_empty());
        for field in 0..6 {
            let mut other = request.clone();
            match field {
                0 => other.tenant = "tenant-b".into(),
                1 => other.authority = "https://other.example.invalid".into(),
                2 => other.audience = "https://other.example.invalid".into(),
                3 => other.scopes.push("profile".into()),
                4 => other.credential_profile = "operator-b".into(),
                _ => other.flow = AuthFlow::Pkce,
            }
            assert!(tokens.load(&other).unwrap().is_none());
        }
        let mut equivalent = request.clone();
        equivalent.tenant = "TENANT-A".into();
        equivalent.authority.push('/');
        equivalent.scopes.reverse();
        equivalent.scopes.push("openid".into());
        assert!(tokens.load(&equivalent).unwrap().is_some());
        let mut other = request.clone();
        other.tenant = "tenant-b".into();
        tokens.save(&other, &token(&other)).unwrap();
        tokens.logout(&request).unwrap();
        assert!(tokens.load(&request).unwrap().is_none());
        assert!(tokens.load(&other).unwrap().is_some());
        tokens.logout(&request).unwrap();
    }
    #[test]
    fn expiry_mismatch_corruption_and_oversize_fail_safely() {
        let tokens = StoredTokens::new(MemoryStore::default());
        let request = request();
        let mut mismatch = request.clone();
        mismatch.tenant = "tenant-b".into();
        assert!(tokens.save(&request, &token(&mismatch)).is_err());
        tokens.save(&request, &token(&request)).unwrap();
        let key = account(&request).unwrap();
        let bytes = tokens.store.read(&key).unwrap().unwrap();
        let mut record: Record = serde_json::from_slice(&bytes).unwrap();
        record.expires_at = SystemTime::now();
        tokens
            .store
            .write(&key, &serde_json::to_vec(&record).unwrap())
            .unwrap();
        assert!(tokens.load(&request).unwrap().is_none());
        record.expires_at = SystemTime::now() + Duration::from_secs(172800);
        tokens
            .store
            .write(&key, &serde_json::to_vec(&record).unwrap())
            .unwrap();
        assert!(tokens.load(&request).is_err());
        record.request.tenant = "tenant-b".into();
        tokens
            .store
            .write(&key, &serde_json::to_vec(&record).unwrap())
            .unwrap();
        assert!(tokens.load(&request).is_err());
        for bytes in [b"private-access-token".to_vec(), vec![b'x'; LIMIT + 1]] {
            tokens.store.write(&key, &bytes).unwrap();
            let error = tokens.load(&request).unwrap_err().to_string();
            assert!(!error.contains("private-access-token"));
        }
        let mut noninteractive = request.clone();
        noninteractive.flow = AuthFlow::OnBehalfOf;
        assert!(
            tokens
                .save(&noninteractive, &token(&noninteractive))
                .is_err()
        );
        assert!(OsCredentialStore.read("../escape").is_err());
        assert!(OsCredentialStore.write(&key, &vec![0; LIMIT + 1]).is_err());
    }
    #[test]
    fn refresh_pairs_survive_access_expiry_and_replace_together() {
        let tokens = StoredTokens::new(MemoryStore::default());
        let mut request = request();
        request.scopes.push("offline_access".into());
        let refresh = crate::refresh::RefreshCredential::new(
            &request,
            "client-a".into(),
            Secret::new("private-old-refresh".into()).unwrap(),
        )
        .unwrap();
        tokens
            .save_with_refresh(&request, &token(&request), Some(&refresh))
            .unwrap();
        let key = account(&request).unwrap();
        let mut record: Record =
            serde_json::from_slice(&tokens.store.read(&key).unwrap().unwrap()).unwrap();
        record.expires_at = SystemTime::now() - Duration::from_secs(60);
        tokens
            .store
            .write(&key, &serde_json::to_vec(&record).unwrap())
            .unwrap();
        assert!(tokens.load(&request).unwrap().is_none());
        let loaded = tokens.load_refresh(&request).unwrap().unwrap();
        assert_eq!(loaded.secret.expose(), "private-old-refresh");
        assert_eq!(loaded.client_id(), "client-a");
        assert!(!format!("{loaded:?}").contains("private-old-refresh"));
        let replacement = crate::refresh::RefreshCredential::new(
            &request,
            "client-a".into(),
            Secret::new("private-new-refresh".into()).unwrap(),
        )
        .unwrap();
        tokens
            .save_with_refresh(&request, &token(&request), Some(&replacement))
            .unwrap();
        assert_eq!(
            tokens
                .load_refresh(&request)
                .unwrap()
                .unwrap()
                .secret
                .expose(),
            "private-new-refresh"
        );
        let mut other = request.clone();
        other.tenant = "tenant-b".into();
        assert!(
            tokens
                .save_with_refresh(&other, &token(&other), Some(&replacement))
                .is_err()
        );
        assert!(tokens.load_refresh(&other).unwrap().is_none());
        tokens.logout(&request).unwrap();
        assert!(tokens.load_refresh(&request).unwrap().is_none());
        assert!(tokens.load(&request).unwrap().is_none());
    }
}
