//! Out-of-band service credentials (API tokens and keys) that Microsoft issues
//! outside Entra ID, such as Defender for Cloud Apps API tokens.
//!
//! Lookup order: `JUNCTION_API_KEY_<PROFILE>` environment variable, then the OS
//! credential store, then (CLI only) a hidden prompt on the controlling
//! terminal. Agent surfaces (MCP, HTTP) never prompt; they receive a
//! structured `credential_required` error telling the operator what to do.
use anyhow::{Result, bail};
use junction_auth::{
    AccessToken, AuthFlow, Secret, TokenMetadata, TokenRequest,
    storage::{OsCredentialStore, StoredTokens},
};
use std::io::{BufRead, Write};
use std::time::{Duration, SystemTime};

/// Keys do not expire from Junction's point of view; revocation is upstream.
const KEY_LIFETIME: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// Fixed, secret-free guidance when no key is available.
#[derive(Debug, serde::Serialize)]
pub struct CredentialRequired {
    pub error: &'static str,
    pub flow: &'static str,
    pub tenant: String,
    pub audience: String,
    pub credential_profile: String,
    pub environment_variable: String,
    pub remediation: String,
}
impl std::fmt::Display for CredentialRequired {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("API key required")
    }
}
impl std::error::Error for CredentialRequired {}

pub fn environment_variable(request: &TokenRequest) -> String {
    let profile: String = request
        .credential_profile
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("JUNCTION_API_KEY_{profile}")
}

fn required(request: &TokenRequest) -> anyhow::Error {
    let variable = environment_variable(request);
    CredentialRequired {
        error: "credential_required",
        flow: "api_key",
        tenant: request.tenant.clone(),
        audience: request.audience.clone(),
        credential_profile: request.credential_profile.clone(),
        remediation: format!(
            "Provide the service API key out of band: run `junction auth login` with this context on an interactive terminal, or set {variable}."
        ),
        environment_variable: variable,
    }
    .into()
}

fn token(request: &TokenRequest, key: String) -> Result<AccessToken> {
    let key = key.trim().to_owned();
    if key.is_empty() || key.len() > 16 * 1024 || key.chars().any(|c| c.is_whitespace()) {
        bail!("invalid API key format");
    }
    let placement = request
        .api_key
        .clone()
        .ok_or_else(|| anyhow::anyhow!("api_key flow requires an api_key placement"))?;
    AccessToken::api_key(
        Secret::new(key)?,
        TokenMetadata {
            tenant: request.tenant.clone(),
            audience: request.audience.clone(),
            expires_at: SystemTime::now() + KEY_LIFETIME,
            scopes: Vec::new(),
            roles: Vec::new(),
            account: None,
        },
        placement,
    )
}

/// Existing key without prompting: environment first, then the OS store.
pub fn saved(request: &TokenRequest) -> Result<Option<AccessToken>> {
    if request.flow != AuthFlow::ApiKey {
        bail!("not an api_key context");
    }
    request.validate()?;
    if let Ok(key) = std::env::var(environment_variable(request)) {
        return token(request, key).map(Some);
    }
    if OsCredentialStore::available()
        && let Some(stored) = StoredTokens::new(OsCredentialStore).load(request)?
    {
        return token(request, stored.expose().to_owned()).map(Some);
    }
    Ok(None)
}

pub fn acquire(request: &TokenRequest, interactive: bool) -> Result<AccessToken> {
    if let Some(token) = saved(request)? {
        return Ok(token);
    }
    if !interactive {
        return Err(required(request));
    }
    prompt(request, true).map_err(|error| {
        if error.is::<NoTerminal>() {
            required(request)
        } else {
            error
        }
    })
}

#[derive(Debug)]
struct NoTerminal;
impl std::fmt::Display for NoTerminal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("no operator terminal")
    }
}
impl std::error::Error for NoTerminal {}

fn terminal() -> Result<(std::fs::File, std::fs::File)> {
    #[cfg(windows)]
    let (input, output) = ("CONIN$", "CONOUT$");
    #[cfg(not(windows))]
    let (input, output) = ("/dev/tty", "/dev/tty");
    let reader = std::fs::OpenOptions::new()
        .read(true)
        .open(input)
        .map_err(|_| NoTerminal)?;
    let writer = std::fs::OpenOptions::new()
        .write(true)
        .open(output)
        .map_err(|_| NoTerminal)?;
    Ok((reader, writer))
}

/// Ask the operator for the key on the controlling terminal with echo
/// disabled, then optionally save it in the OS credential store.
pub fn prompt(request: &TokenRequest, offer_save: bool) -> Result<AccessToken> {
    let (reader, mut writer) = terminal()?;
    let placement = request
        .api_key
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("api_key flow requires an api_key placement"))?;
    let clean = |text: &str| -> String {
        text.chars()
            .map(|c| if c.is_control() { '?' } else { c })
            .collect()
    };
    let audience = request.audience.to_ascii_lowercase();
    let hint = if audience.contains("cloudappsecurity") {
        "Create one in the Microsoft Defender portal: Settings > Cloud Apps > API tokens."
    } else if audience.contains("dev.azure.com") || audience.contains("visualstudio.com") {
        "Create an Azure DevOps personal access token: User settings > Personal access tokens."
    } else {
        "Create one in the service's admin portal."
    };
    writeln!(
        writer,
        "\nJunction needs an API key that Microsoft issues outside Entra ID.\n\
         tenant:             {}\n\
         service:            {}\n\
         credential profile: {}\n\
         sent as header:     {}{}\n\
         {hint} Input is hidden.",
        clean(&request.tenant),
        clean(&request.audience),
        clean(&request.credential_profile),
        placement.header,
        placement
            .prefix
            .as_deref()
            .map(|prefix| format!(" ({prefix} <key>)"))
            .unwrap_or_default(),
    )?;
    writer.flush()?;
    let key = read_hidden(&reader, &mut writer)?;
    let token = token(request, key.to_string())?;
    if offer_save && OsCredentialStore::available() {
        write!(writer, "Save this key in the OS credential store? [y/N] ")?;
        writer.flush()?;
        let mut answer = String::new();
        std::io::BufReader::new(reader).read_line(&mut answer)?;
        if answer.trim().eq_ignore_ascii_case("y") {
            save(request, &token)?;
            writeln!(writer, "Saved.")?;
        }
    }
    Ok(token)
}

/// Read one line with terminal echo disabled before the prompt is shown, so
/// fast typing or pasting can never be echoed.
#[cfg(unix)]
fn read_hidden(
    reader: &std::fs::File,
    writer: &mut std::fs::File,
) -> Result<zeroize::Zeroizing<String>> {
    use std::os::fd::AsRawFd;
    struct Restore(i32, libc::termios);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                libc::tcsetattr(self.0, libc::TCSANOW, &self.1);
            }
        }
    }
    let fd = reader.as_raw_fd();
    let mut original: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
        return Err(NoTerminal.into());
    }
    let mut hidden = original;
    hidden.c_lflag &= !(libc::ECHO | libc::ECHONL);
    hidden.c_lflag |= libc::ICANON;
    if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &hidden) } != 0 {
        return Err(NoTerminal.into());
    }
    let restore = Restore(fd, original);
    write!(writer, "API key: ")?;
    writer.flush()?;
    let mut line = zeroize::Zeroizing::new(String::new());
    std::io::BufReader::new(reader).read_line(&mut line)?;
    drop(restore);
    writeln!(writer)?;
    Ok(line)
}
#[cfg(not(unix))]
fn read_hidden(
    _reader: &std::fs::File,
    _writer: &mut std::fs::File,
) -> Result<zeroize::Zeroizing<String>> {
    // The Windows console prompt disables echo before reading.
    rpassword::prompt_password("API key: ")
        .map(zeroize::Zeroizing::new)
        .map_err(|_| NoTerminal.into())
}

pub fn save(request: &TokenRequest, token: &AccessToken) -> Result<()> {
    if !OsCredentialStore::available() {
        bail!(
            "OS credential storage is unavailable on this platform; use the environment variable"
        );
    }
    let _lock = crate::credential_lock::CredentialLock::acquire(request)?;
    StoredTokens::new(OsCredentialStore).save(request, token)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> TokenRequest {
        TokenRequest {
            tenant: "contoso-tenant".into(),
            authority: "https://login.microsoftonline.com".into(),
            audience: "https://contoso.us3.portal.cloudappsecurity.com".into(),
            scopes: vec![],
            credential_profile: "mdca-prod".into(),
            flow: AuthFlow::ApiKey,
            api_key: Some(junction_auth::ApiKeyPlacement {
                header: "authorization".into(),
                prefix: Some("Token".into()),
            }),
        }
    }
    #[test]
    fn missing_keys_produce_secret_free_guidance() {
        let request = request();
        assert_eq!(environment_variable(&request), "JUNCTION_API_KEY_MDCA_PROD");
        let error = required(&request);
        let value =
            serde_json::to_value(error.downcast_ref::<CredentialRequired>().unwrap()).unwrap();
        assert_eq!(value["error"], "credential_required");
        assert!(
            value["remediation"]
                .as_str()
                .unwrap()
                .contains("JUNCTION_API_KEY_MDCA_PROD")
        );
    }
    #[test]
    fn keys_are_validated_and_presented_with_the_configured_scheme() {
        let request = request();
        assert!(token(&request, "has space".into()).is_err());
        let token = token(&request, "  abc123  ".into()).unwrap();
        match token.credential() {
            junction_auth::Credential::Header { placement, secret } => {
                assert_eq!(placement.prefix.as_deref(), Some("Token"));
                assert_eq!(secret.expose(), "abc123");
            }
            _ => panic!("expected header credential"),
        }
        let mut bad = request.clone();
        bad.api_key = Some(junction_auth::ApiKeyPlacement {
            header: "x-forwarded-for".into(),
            prefix: None,
        });
        assert!(bad.validate().is_err());
        bad.api_key = None;
        assert!(bad.validate().is_err());
        let mut mismatched = request.clone();
        mismatched.flow = AuthFlow::ClientCredentials;
        assert!(mismatched.validate().is_err());
    }
}
