//! Optional convenience: reuse an existing Azure CLI sign-in. Junction never
//! requires the Azure CLI; this flow only works when `az` is installed and
//! signed in. The token is bound to the requested tenant and resource.
use crate::{AccessToken, AuthFlow, Secret, TokenMetadata, TokenRequest};
use anyhow::{Result, bail};
use serde::Deserialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CliToken {
    access_token: Zeroizing<String>,
    tenant: Option<String>,
    token_type: Option<String>,
    /// Newer CLI versions report a POSIX timestamp.
    #[serde(rename = "expires_on")]
    expires_on_unix: Option<u64>,
}

/// Arguments for `az account get-access-token`; values are validated by
/// `TokenRequest::validate` and passed as separate arguments (no shell).
pub fn arguments(request: &TokenRequest) -> Result<Vec<String>> {
    request.validate()?;
    if request.flow != AuthFlow::AzureCli {
        bail!("azure_cli flow required");
    }
    if request.audience.starts_with('-') || request.tenant.starts_with('-') {
        bail!("invalid Azure CLI argument");
    }
    Ok(vec![
        "account".into(),
        "get-access-token".into(),
        "--resource".into(),
        request.audience.clone(),
        "--tenant".into(),
        request.tenant.clone(),
        "--output".into(),
        "json".into(),
    ])
}

pub fn parse(bytes: &[u8], request: &TokenRequest, now: SystemTime) -> Result<AccessToken> {
    if bytes.len() > 64 * 1024 {
        bail!("Azure CLI response too large");
    }
    let token: CliToken =
        serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("invalid Azure CLI response"))?;
    if token
        .token_type
        .as_deref()
        .is_some_and(|kind| !kind.eq_ignore_ascii_case("Bearer"))
    {
        bail!("Azure CLI returned a non-bearer token");
    }
    if !token
        .tenant
        .as_deref()
        .is_some_and(|tenant| tenant.eq_ignore_ascii_case(&request.tenant))
    {
        bail!("Azure CLI token tenant does not match the context tenant");
    }
    let expires_at = token
        .expires_on_unix
        .and_then(|seconds| UNIX_EPOCH.checked_add(Duration::from_secs(seconds)))
        .ok_or_else(|| anyhow::anyhow!("Azure CLI response lacks expiry; update the Azure CLI"))?;
    let remaining = expires_at
        .duration_since(now)
        .map_err(|_| anyhow::anyhow!("Azure CLI token expired"))?;
    if remaining <= Duration::from_secs(60) || remaining > Duration::from_secs(2 * 86400) {
        bail!("invalid Azure CLI token lifetime");
    }
    Ok(AccessToken::new(
        Secret::new(token.access_token.to_string())?,
        TokenMetadata {
            tenant: request.tenant.clone(),
            audience: request.audience.clone(),
            expires_at,
            scopes: Vec::new(),
            roles: Vec::new(),
            account: None,
        },
    ))
}

/// Run `az` (az.cmd on Windows) with a bounded wait. Errors never include
/// CLI output, which can contain account details.
pub async fn acquire(request: &TokenRequest) -> Result<AccessToken> {
    let arguments = arguments(request)?;
    let program = if cfg!(windows) { "az.cmd" } else { "az" };
    let output = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::task::spawn_blocking(move || {
            std::process::Command::new(program)
                .args(&arguments)
                .stdin(std::process::Stdio::null())
                .output()
        }),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Azure CLI token request timed out"))?
    .map_err(|_| anyhow::anyhow!("Azure CLI token request failed"))?
    .map_err(|_| anyhow::anyhow!("Azure CLI is not installed or not on PATH"))?;
    if !output.status.success() {
        bail!(
            "Azure CLI could not issue a token; run `az login --tenant {}`",
            request.tenant
        );
    }
    let stdout = Zeroizing::new(output.stdout);
    parse(&stdout, request, SystemTime::now())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> TokenRequest {
        TokenRequest {
            tenant: "11111111-2222-3333-4444-555555555555".into(),
            authority: "https://login.microsoftonline.com".into(),
            audience: "https://management.azure.com".into(),
            scopes: vec![],
            credential_profile: "az".into(),
            flow: AuthFlow::AzureCli,
            api_key: None,
        }
    }
    #[test]
    fn cli_tokens_are_bound_to_tenant_and_expiry() {
        let request = request();
        let now = SystemTime::now();
        let expires = now.duration_since(UNIX_EPOCH).unwrap().as_secs() + 3600;
        let good = serde_json::json!({"accessToken":"private-cli-token","expiresOn":"2026-01-01 00:00:00.000000","expires_on":expires,"subscription":"s","tenant":"11111111-2222-3333-4444-555555555555","tokenType":"Bearer"});
        let token = parse(&serde_json::to_vec(&good).unwrap(), &request, now).unwrap();
        assert_eq!(token.expose(), "private-cli-token");
        let mut other = good.clone();
        other["tenant"] = "99999999-2222-3333-4444-555555555555".into();
        assert!(parse(&serde_json::to_vec(&other).unwrap(), &request, now).is_err());
        let mut legacy = good.clone();
        legacy.as_object_mut().unwrap().remove("expires_on");
        assert!(parse(&serde_json::to_vec(&legacy).unwrap(), &request, now).is_err());
        let error = parse(b"not json private-cli-token", &request, now).unwrap_err();
        assert!(!error.to_string().contains("private-cli-token"));
        assert_eq!(
            arguments(&request).unwrap()[3],
            "https://management.azure.com"
        );
        let mut wrong = request.clone();
        wrong.flow = AuthFlow::ClientCredentials;
        assert!(arguments(&wrong).is_err());
    }
}
