//! Explicit interactive login. Execution surfaces only read saved credentials.
use crate::{AuthCommand, Cli, OutputOptions, context_store, context_token_request};
use anyhow::{Result, bail};
use junction_auth::{
    AccessToken, AuthFlow, TokenRequest,
    device_code::{DeviceCodeProvider, DevicePoll},
    storage::{OsCredentialStore, StoredTokens},
};
use serde_json::json;
use std::{path::PathBuf, time::Duration};

fn request(cli: &Cli, file: &Option<PathBuf>) -> Result<TokenRequest> {
    let bytes = match (file, cli.context.as_deref()) {
        (Some(file), None) => context_store::read_file(file)?,
        (None, Some(name)) => context_store::read(&cli.contexts_directory, name)?,
        _ => bail!("select exactly one named context or context file"),
    };
    context_token_request(&bytes)
}
/// No interactive fallback: an agent cannot accidentally initiate a login prompt.
pub async fn acquire(request: &TokenRequest) -> Result<AccessToken> {
    acquire_with(request, false).await
}
/// Operator CLI execution may ask for an out-of-band API key on the terminal.
pub async fn acquire_interactive(request: &TokenRequest) -> Result<AccessToken> {
    acquire_with(request, true).await
}
async fn acquire_with(request: &TokenRequest, interactive: bool) -> Result<AccessToken> {
    if request.flow == AuthFlow::ApiKey {
        return crate::api_key::acquire(request, interactive);
    }
    if request.flow == AuthFlow::AzureCli {
        return junction_auth::azure_cli::acquire(request).await;
    }
    if request.flow == AuthFlow::DeviceCode {
        if !OsCredentialStore::available() {
            bail!("OS credential storage is unavailable on this platform");
        }
        let _lock = crate::credential_lock::CredentialLock::acquire(request)?;
        return acquire_saved(
            request,
            &StoredTokens::new(OsCredentialStore),
            |refresh| async move {
                junction_auth::refresh::RefreshTokenProvider::new(refresh.client_id().to_owned())?
                    .acquire(&refresh)
                    .await
            },
        )
        .await;
    }
    junction_auth::environment::EnvironmentCredential::from_environment_for(&request.flow)?
        .acquire(request)
        .await
}
/// Caller holds the credential transaction lock for this complete future.
async fn acquire_saved<S, F, Fut>(
    request: &TokenRequest,
    tokens: &StoredTokens<S>,
    renew: F,
) -> Result<AccessToken>
where
    S: junction_auth::storage::CredentialStore,
    F: FnOnce(junction_auth::refresh::RefreshCredential) -> Fut,
    Fut: std::future::Future<Output = Result<junction_auth::refresh::RefreshedTokens>>,
{
    if let Some(token) = tokens.load(request)? {
        return Ok(token);
    }
    let refresh = tokens.load_refresh(request)?.ok_or_else(|| {
        anyhow::anyhow!("interactive credential missing or expired; run junction auth login")
    })?;
    let renewed = renew(refresh).await?;
    tokens.save_with_refresh(
        request,
        &renewed.access_token,
        Some(&renewed.refresh_credential),
    )?;
    Ok(renewed.access_token)
}
fn status(request: &TokenRequest) -> Result<serde_json::Value> {
    saved_status(request, &StoredTokens::new(OsCredentialStore))
}
fn saved_status<S: junction_auth::storage::CredentialStore>(
    request: &TokenRequest,
    tokens: &StoredTokens<S>,
) -> Result<serde_json::Value> {
    if request.flow == AuthFlow::ApiKey {
        let environment = std::env::var_os(crate::api_key::environment_variable(request)).is_some();
        let saved =
            !environment && OsCredentialStore::available() && tokens.load(request)?.is_some();
        return Ok(json!({
            "tenant": request.tenant,
            "audience": request.audience,
            "credential_profile": request.credential_profile,
            "flow": request.flow,
            "status": if environment { "api_key_environment" } else if saved { "api_key_saved" } else { "api_key_required" },
            "environment_variable": crate::api_key::environment_variable(request),
        }));
    }
    let interactive = request.flow == AuthFlow::DeviceCode;
    let token = if interactive {
        tokens.load(request)?
    } else {
        None
    };
    let renewable = interactive && token.is_none() && tokens.load_refresh(request)?.is_some();
    Ok(json!({
        "tenant": request.tenant,
        "audience": request.audience,
        "credential_profile": request.credential_profile,
        "flow": request.flow,
        "status": if token.is_some() { "authenticated" } else if renewable { "renewal_available" } else if interactive { "login_required" } else { "environment_credential" },
        "metadata": token.as_ref().map(AccessToken::metadata),
    }))
}
pub async fn run(cli: &Cli, command: &AuthCommand, output: &OutputOptions) -> Result<()> {
    match command {
        AuthCommand::Accounts => {
            let mut accounts = Vec::new();
            for name in context_store::list(&cli.contexts_directory)? {
                let request =
                    context_token_request(&context_store::read(&cli.contexts_directory, &name)?)?;
                if matches!(request.flow, AuthFlow::DeviceCode | AuthFlow::ApiKey) {
                    let mut account = status(&request)?;
                    account["context"] = json!(name);
                    accounts.push(account);
                }
            }
            output.emit(&json!({"accounts": accounts}))
        }
        AuthCommand::Status { context_file } => output.emit(&status(&request(cli, context_file)?)?),
        AuthCommand::Logout { context_file } => {
            let request = request(cli, context_file)?;
            if !OsCredentialStore::available() {
                bail!("OS credential storage is unavailable on this platform");
            }
            let _lock = crate::credential_lock::CredentialLock::acquire(&request)?;
            StoredTokens::new(OsCredentialStore).logout(&request)?;
            output.emit(&json!({"status": "logged_out", "tenant": request.tenant, "credential_profile": request.credential_profile}))
        }
        AuthCommand::TokenInfo { context_file } => {
            let token = acquire(&request(cli, context_file)?).await?;
            output.emit(token.metadata())
        }
        AuthCommand::Login {
            context_file,
            client_id,
            timeout_seconds,
        } => {
            let request = request(cli, context_file)?;
            if request.flow == AuthFlow::ApiKey {
                // Out-of-band keys are typed by the operator, never passed as arguments.
                let token = crate::api_key::prompt(&request, false)?;
                crate::api_key::save(&request, &token)?;
                return output.emit(&json!({"status": "api_key_saved", "tenant": request.tenant, "credential_profile": request.credential_profile}));
            }
            if request.flow != AuthFlow::DeviceCode {
                bail!("CLI interactive login requires a device_code or api_key context");
            }
            let client_id = client_id
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("device code login requires --client-id"))?;
            if !OsCredentialStore::available() {
                bail!("OS credential storage is unavailable on this platform");
            }
            let provider = DeviceCodeProvider::new(client_id.clone())?;
            let _lock = crate::credential_lock::CredentialLock::acquire(&request)?;
            let login = async {
                let mut session = provider.begin(&request).await?;
                // The human-facing user_code is intended for display; the secret
                // device_code never enters this message or structured output.
                eprintln!(
                    "Open {} and enter {}",
                    session.prompt().verification_uri,
                    session.prompt().user_code
                );
                loop {
                    match provider.poll(&mut session).await? {
                        DevicePoll::Pending {
                            retry_after_seconds,
                        } => {
                            tokio::time::sleep(Duration::from_secs(retry_after_seconds.max(1)))
                                .await
                        }
                        DevicePoll::Authenticated(token) => {
                            let refresh = session.take_refresh_credential();
                            StoredTokens::new(OsCredentialStore).save_with_refresh(
                                &request,
                                &token,
                                refresh.as_ref(),
                            )?;
                            return Ok::<_, anyhow::Error>(token);
                        }
                    }
                }
            };
            let token = tokio::select! {
                result = tokio::time::timeout(Duration::from_secs(*timeout_seconds), login) => {
                    result.map_err(|_| anyhow::anyhow!("interactive login timed out"))??
                }
                _ = tokio::signal::ctrl_c() => bail!("interactive login cancelled"),
            };
            output.emit(&json!({"status": "authenticated", "metadata": token.metadata()}))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use junction_auth::{
        Secret, TokenMetadata, refresh::RefreshedTokens, storage::CredentialStore,
    };
    use std::{
        cell::{Cell, RefCell},
        time::SystemTime,
    };

    struct MemoryStore {
        bytes: RefCell<Option<Vec<u8>>>,
        fail_write: Cell<bool>,
    }
    impl CredentialStore for &MemoryStore {
        fn read(&self, _: &str) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
            Ok(self.bytes.borrow().clone().map(zeroize::Zeroizing::new))
        }
        fn write(&self, _: &str, bytes: &[u8]) -> Result<()> {
            if self.fail_write.get() {
                bail!("credential write failed")
            }
            *self.bytes.borrow_mut() = Some(bytes.to_vec());
            Ok(())
        }
        fn delete(&self, _: &str) -> Result<()> {
            *self.bytes.borrow_mut() = None;
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
                "offline_access".into(),
            ],
            credential_profile: "operator".into(),
            flow: AuthFlow::DeviceCode,
            api_key: None,
        }
    }
    fn fixture(request: &TokenRequest, expired: bool, refresh: Option<&str>) -> MemoryStore {
        let expiry = if expired {
            SystemTime::now() - Duration::from_secs(60)
        } else {
            SystemTime::now() + Duration::from_secs(3600)
        };
        let mut record = json!({"version":1, "request":request, "access_token":"private-old-access", "expires_at":expiry});
        if let Some(refresh) = refresh {
            record["refresh_token"] = json!(refresh);
            record["client_id"] = json!("client-a");
        }
        MemoryStore {
            bytes: RefCell::new(Some(serde_json::to_vec(&record).unwrap())),
            fail_write: Cell::new(false),
        }
    }
    fn access(request: &TokenRequest) -> AccessToken {
        AccessToken::new(
            Secret::new("private-new-access".into()).unwrap(),
            TokenMetadata {
                tenant: request.tenant.clone(),
                audience: request.audience.clone(),
                expires_at: SystemTime::now() + Duration::from_secs(3600),
                scopes: vec![],
                roles: vec![],
                account: None,
            },
        )
    }
    #[tokio::test]
    async fn cached_tokens_skip_renewal_and_missing_grants_do_not_invoke_it() {
        let request = request();
        let store = fixture(&request, false, Some("private-old-refresh"));
        let tokens = StoredTokens::new(&store);
        let cached = acquire_saved(&request, &tokens, |_| async { bail!("unexpected renewal") })
            .await
            .unwrap();
        assert_eq!(cached.expose(), "private-old-access");
        let missing = fixture(&request, true, None);
        let called = Cell::new(false);
        assert!(
            acquire_saved(&request, &StoredTokens::new(&missing), |_| async {
                called.set(true);
                bail!("unexpected renewal")
            })
            .await
            .is_err()
        );
        assert!(!called.get());
    }
    #[test]
    fn status_distinguishes_available_renewal_without_printing_credentials() {
        let request = request();
        let expired = fixture(&request, true, Some("private-old-refresh"));
        let status = saved_status(&request, &StoredTokens::new(&expired)).unwrap();
        assert_eq!(status["status"], "renewal_available");
        assert!(status["metadata"].is_null());
        let serialized = serde_json::to_string(&status).unwrap();
        assert!(!serialized.contains("private-old-refresh"));
        assert!(!serialized.contains("private-old-access"));
        let missing = fixture(&request, true, None);
        assert_eq!(
            saved_status(&request, &StoredTokens::new(&missing)).unwrap()["status"],
            "login_required"
        );
        let valid = fixture(&request, false, None);
        assert_eq!(
            saved_status(&request, &StoredTokens::new(&valid)).unwrap()["status"],
            "authenticated"
        );
    }
    #[tokio::test]
    async fn renewal_rotates_pair_and_failures_preserve_saved_credentials() {
        let request = request();
        let store = fixture(&request, true, Some("private-old-refresh"));
        let tokens = StoredTokens::new(&store);
        let original = store.bytes.borrow().clone();
        let error = acquire_saved(&request, &tokens, |_| async { bail!("renewal rejected") })
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "renewal rejected");
        assert_eq!(*store.bytes.borrow(), original);
        let mut other = request.clone();
        other.tenant = "tenant-b".into();
        let foreign_store = fixture(&other, true, Some("private-foreign-refresh"));
        let pair = RefreshedTokens {
            access_token: access(&request),
            refresh_credential: StoredTokens::new(&foreign_store)
                .load_refresh(&other)
                .unwrap()
                .unwrap(),
        };
        assert!(
            acquire_saved(&request, &tokens, |_| async { Ok(pair) })
                .await
                .is_err()
        );
        assert_eq!(*store.bytes.borrow(), original);
        let pair = RefreshedTokens {
            access_token: access(&other),
            refresh_credential: tokens.load_refresh(&request).unwrap().unwrap(),
        };
        assert!(
            acquire_saved(&request, &tokens, |_| async { Ok(pair) })
                .await
                .is_err()
        );
        assert_eq!(*store.bytes.borrow(), original);
        let rotated = fixture(&request, true, Some("private-new-refresh"));
        store.fail_write.set(true);
        let pair = RefreshedTokens {
            access_token: access(&request),
            refresh_credential: StoredTokens::new(&rotated)
                .load_refresh(&request)
                .unwrap()
                .unwrap(),
        };
        assert!(
            acquire_saved(&request, &tokens, |_| async { Ok(pair) })
                .await
                .is_err()
        );
        assert_eq!(*store.bytes.borrow(), original);
        store.fail_write.set(false);
        let pair = RefreshedTokens {
            access_token: access(&request),
            refresh_credential: StoredTokens::new(&rotated)
                .load_refresh(&request)
                .unwrap()
                .unwrap(),
        };
        let token = acquire_saved(&request, &tokens, |_| async { Ok(pair) })
            .await
            .unwrap();
        assert_eq!(token.expose(), "private-new-access");
        assert_eq!(
            tokens.load(&request).unwrap().unwrap().expose(),
            "private-new-access"
        );
        let saved: serde_json::Value =
            serde_json::from_slice(store.bytes.borrow().as_ref().unwrap()).unwrap();
        assert_eq!(saved["refresh_token"], "private-new-refresh");
        assert!(!format!("{token:?}").contains("private-new-access"));
    }
}
