//! `junction check` environment: named contexts, credentials and the operator
//! terminal. Checks reuse each context's tenant, cloud and credential flow, and
//! request a token per Microsoft API audience; the context's own service and
//! policy are not used (checks always run read-only).
use anyhow::{Context, Result, bail};
use junction_check::gateway::{BoxFut, CallError, FailureKind, LiveTarget, TokenProvider};
use junction_core::cloud::MicrosoftCloud;
use std::path::PathBuf;
use std::sync::Arc;

pub struct Environment {
    contexts: PathBuf,
}

impl Environment {
    pub fn new(contexts: PathBuf) -> Self {
        Self { contexts }
    }
}

/// Tenant, cloud and credential of a saved context, without secrets.
pub fn live_target(bytes: &[u8]) -> Result<LiveTarget> {
    let value = crate::validated_context(bytes)?;
    if value.get("cloud").is_some() {
        let config: crate::CloudExecutionConfig =
            serde_json::from_value(value).map_err(|_| anyhow::anyhow!("invalid cloud context"))?;
        let endpoints = match (config.cloud, config.custom_endpoints) {
            (MicrosoftCloud::Custom, Some(endpoints)) => endpoints,
            (MicrosoftCloud::Custom, None) => bail!("custom endpoints required"),
            (cloud, _) => cloud.endpoints()?,
        };
        return Ok(LiveTarget {
            tenant_id: config.tenant,
            endpoints,
            credential_profile: config.credential_profile,
            flow: config.flow,
        });
    }
    // Explicit contexts name one endpoint; infer the cloud from the authority.
    let request = crate::ExecutionConfig::parse(bytes)?.token_request;
    let cloud = match url::Url::parse(&request.authority)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .as_deref()
    {
        Some("login.microsoftonline.com") => MicrosoftCloud::Public,
        Some("login.microsoftonline.us") => MicrosoftCloud::UsGovernment,
        Some("login.chinacloudapi.cn") => MicrosoftCloud::China,
        _ => bail!("use a cloud context (with `cloud` and `tenant`) for checks"),
    };
    Ok(LiveTarget {
        tenant_id: request.tenant,
        endpoints: cloud.endpoints()?,
        credential_profile: request.credential_profile,
        flow: request.flow,
    })
}

/// Tokens from the context's credential flow (saved login, Azure CLI, secret,
/// certificate, managed or workload identity). Errors carry no secrets.
struct Tokens;

impl TokenProvider for Tokens {
    fn token<'a>(
        &'a self,
        request: junction_auth::TokenRequest,
    ) -> BoxFut<'a, Result<junction_auth::AccessToken, CallError>> {
        Box::pin(async move {
            request
                .validate()
                .map_err(|_| CallError::other(FailureKind::Credential, "invalid token request"))?;
            crate::auth_cli::acquire_interactive(&request)
                .await
                .map_err(|error| {
                    let status = error
                        .downcast_ref::<junction_http::HttpStatusError>()
                        .map(|s| (s.status, s.upstream.clone()));
                    match status {
                        Some((status, upstream)) => CallError {
                            kind: FailureKind::Credential,
                            status: Some(status),
                            code: upstream.as_ref().and_then(|u| u.code.clone()),
                            message: upstream.and_then(|u| u.message),
                            retry_after: None,
                        },
                        None => CallError::other(
                            FailureKind::Credential,
                            "no usable credential for this context and tenant (run `junction auth login` or check the credential environment)",
                        ),
                    }
                })
        })
    }
}

impl junction_check::cli::Environment for Environment {
    fn context_names(&self) -> Result<Vec<String>> {
        crate::context_store::list(&self.contexts)
    }
    fn live_target(&self, context: &str) -> Result<LiveTarget> {
        live_target(&crate::context_store::read(&self.contexts, context)?)
            .with_context(|| format!("context {context}"))
    }
    fn tokens(&self) -> Arc<dyn TokenProvider> {
        Arc::new(Tokens)
    }
    fn confirm_push(&self, context: &str, endpoint: &str, summary: &str) -> Result<()> {
        let target = self.live_target(context)?;
        let operation = junction_check::push::operation();
        crate::approval_cli::confirm(&crate::approval_cli::Summary {
            operation: &operation,
            reason: summary,
            tenant: &target.tenant_id,
            cloud: &MicrosoftCloud::Public,
            endpoint,
            audience: "https://monitor.azure.com",
            credential_profile: &target.credential_profile,
            input: &serde_json::json!({"rows": "check results (no raw tenant data)"}),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloud_and_explicit_contexts_resolve_without_secrets() {
        let cloud = serde_json::json!({
            "cloud": "public", "tenant": "00000000-0000-4000-8000-000000000001", "service": "graph",
            "credential_profile": "checks", "flow": "client_credentials"
        });
        let target = live_target(&serde_json::to_vec(&cloud).unwrap()).unwrap();
        assert_eq!(target.tenant_id, "00000000-0000-4000-8000-000000000001");
        assert_eq!(
            target.endpoints.authority,
            "https://login.microsoftonline.com"
        );
        let explicit = serde_json::json!({
            "endpoint": "https://graph.microsoft.com/v1.0",
            "token_request": {"tenant": "00000000-0000-4000-8000-000000000002",
                "authority": "https://login.microsoftonline.com", "audience": "https://graph.microsoft.com",
                "scopes": [], "credential_profile": "checks", "flow": "client_credentials"}
        });
        assert_eq!(
            live_target(&serde_json::to_vec(&explicit).unwrap())
                .unwrap()
                .tenant_id,
            "00000000-0000-4000-8000-000000000002"
        );
    }
}
