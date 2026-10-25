//! Watchdog configuration. Secret-free by design: credentials come from the
//! environment (Junction convention) and never from this file.
use anyhow::{Context, Result, bail};
use junction_auth::AuthFlow;
use junction_core::cloud::MicrosoftCloud;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchConfig {
    /// Directory (tenant) GUID.
    pub tenant_id: String,
    /// Primary domain, for display (for example `club.org.au`).
    pub tenant_domain: String,
    /// Application (client) ID of the watchdog app registration.
    pub client_id: String,
    #[serde(default = "default_cloud")]
    pub cloud: MicrosoftCloud,
    #[serde(default = "default_flow")]
    pub auth: AuthFlow,
    #[serde(default = "default_store")]
    pub store: PathBuf,
    #[serde(default = "default_poll")]
    pub poll_interval_minutes: u64,
    #[serde(default = "default_content_types")]
    pub content_types: Vec<String>,
    #[serde(default = "default_rpm")]
    pub max_requests_per_minute: usize,
    #[serde(default)]
    pub web: WebConfig,
    #[serde(default)]
    pub notifications: crate::notify::NotificationConfig,
    #[serde(default)]
    pub rules: crate::rules::RuleSettings,
    #[serde(default)]
    pub snapshot_directory: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebConfig {
    #[serde(default = "default_bind")]
    pub bind: String,
    /// Session lifetime in hours.
    #[serde(default = "default_session_hours")]
    pub session_hours: u64,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            session_hours: default_session_hours(),
        }
    }
}

fn default_cloud() -> MicrosoftCloud {
    MicrosoftCloud::Public
}
fn default_flow() -> AuthFlow {
    AuthFlow::Certificate
}
fn default_store() -> PathBuf {
    PathBuf::from(".junction/watch/watch.db")
}
fn default_poll() -> u64 {
    15
}
fn default_rpm() -> usize {
    100
}
fn default_bind() -> String {
    "127.0.0.1:8787".into()
}
fn default_session_hours() -> u64 {
    8
}
fn default_content_types() -> Vec<String> {
    crate::catalog::CONTENT_TYPES
        .iter()
        .map(|s| s.to_string())
        .collect()
}

impl WatchConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).context("watch configuration unavailable")?;
        if text.len() > 64 * 1024 {
            bail!("watch configuration too large");
        }
        let config: Self = toml::from_str(&text).context("invalid watch configuration")?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        crate::store::validate_tenant(&self.tenant_id)?;
        crate::store::validate_tenant(&self.client_id)
            .context("client_id must be the application GUID")?;
        if self.tenant_domain.is_empty()
            || self.tenant_domain.len() > 253
            || !self
                .tenant_domain
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        {
            bail!("invalid tenant domain");
        }
        if !matches!(
            self.auth,
            AuthFlow::Certificate
                | AuthFlow::ClientCredentials
                | AuthFlow::ManagedIdentity
                | AuthFlow::WorkloadIdentity
        ) {
            bail!(
                "watch requires an unattended app-only flow: certificate, client_credentials, managed_identity or workload_identity"
            );
        }
        if !(5..=1440).contains(&self.poll_interval_minutes) {
            bail!("poll_interval_minutes must be between 5 and 1440");
        }
        if !(10..=1000).contains(&self.max_requests_per_minute) {
            bail!("max_requests_per_minute must be between 10 and 1000");
        }
        for ct in &self.content_types {
            if !crate::catalog::CONTENT_TYPES.contains(&ct.as_str()) {
                bail!("unsupported content type");
            }
        }
        let bind: std::net::SocketAddr =
            self.web.bind.parse().context("invalid web bind address")?;
        if !bind.ip().is_loopback() {
            bail!(
                "the dashboard only binds to loopback; put a TLS reverse proxy in front for remote access"
            );
        }
        if !(1..=24).contains(&self.web.session_hours) {
            bail!("session_hours must be between 1 and 24");
        }
        self.notifications.validate(&self.tenant_domain)?;
        if !(2..=10_000).contains(&self.rules.bulk_threshold)
            || !(2..=100).contains(&self.rules.baseline_multiplier)
        {
            bail!("invalid detection thresholds");
        }
        Ok(())
    }

    /// Environment credentials must target this tenant and app.
    pub fn check_environment(&self) -> Result<()> {
        if let Ok(t) = std::env::var("AZURE_TENANT_ID")
            && !t.eq_ignore_ascii_case(&self.tenant_id)
        {
            bail!("AZURE_TENANT_ID does not match tenant_id in the watch configuration");
        }
        if let Ok(c) = std::env::var("AZURE_CLIENT_ID")
            && !c.eq_ignore_ascii_case(&self.client_id)
        {
            bail!("AZURE_CLIENT_ID does not match client_id in the watch configuration");
        }
        Ok(())
    }

    pub fn example(tenant_id: &str, domain: &str, client_id: &str) -> String {
        format!(
            r#"# Junction M365 watchdog configuration. Contains no secrets.
# Credentials come from the environment:
#   AZURE_TENANT_ID, AZURE_CLIENT_ID,
#   AZURE_CLIENT_CERTIFICATE_PATH (DER certificate),
#   AZURE_CLIENT_PRIVATE_KEY_PATH (DER PKCS#8 key, mode 0600)
tenant_id = "{tenant_id}"
tenant_domain = "{domain}"
client_id = "{client_id}"
cloud = "public"
auth = "certificate"
store = ".junction/watch/watch.db"
poll_interval_minutes = 15
content_types = ["Audit.AzureActiveDirectory", "Audit.Exchange", "Audit.SharePoint", "Audit.General"]
max_requests_per_minute = 100

[web]
bind = "127.0.0.1:8787"
session_hours = 8
"#
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const T: &str = "11111111-1111-4111-8111-111111111111";
    #[test]
    fn example_round_trips_and_validation_rejects_unsafe_values() {
        let text = WatchConfig::example(T, "club.org.au", "22222222-2222-4222-8222-222222222222");
        let config: WatchConfig = toml::from_str(&text).unwrap();
        config.validate().unwrap();
        assert_eq!(config.poll_interval_minutes, 15);
        let mut bad = config.clone();
        bad.web.bind = "0.0.0.0:8787".into();
        assert!(bad.validate().is_err(), "dashboard must stay on loopback");
        let mut bad = config.clone();
        bad.auth = AuthFlow::DeviceCode;
        assert!(
            bad.validate().is_err(),
            "interactive flows cannot run unattended"
        );
        let mut bad = config.clone();
        bad.content_types.push("DLP.All".into());
        assert!(bad.validate().is_err());
        let mut bad = config;
        bad.tenant_id = "club.onmicrosoft.com".into();
        assert!(bad.validate().is_err());
        assert!(
            toml::from_str::<WatchConfig>(&format!("{text}\nclient_secret = \"x\"")).is_err(),
            "unknown keys such as secrets are rejected"
        );
    }
}
