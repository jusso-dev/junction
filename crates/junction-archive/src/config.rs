//! Archive configuration. Secret-free by design: tenant and storage credentials
//! come from the environment (Junction convention) and never from this file.
use crate::store::{
    AzureBlobStore, EnvironmentTokens, LiveHttp, LocalStore, ObjectStore, R2Credentials, R2Store,
    Retry,
};
use anyhow::{Context, Result, bail};
use junction_auth::AuthFlow;
use junction_core::cloud::MicrosoftCloud;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

/// Every source the archive can collect. Defender sources are opt-in.
pub const ALL_SOURCES: [&str; 8] = [
    "o365:Audit.AzureActiveDirectory",
    "o365:Audit.Exchange",
    "o365:Audit.SharePoint",
    "o365:Audit.General",
    "graph:directoryAudits",
    "graph:signIns",
    "graph:alerts_v2",
    "graph:incidents",
];

/// Collected unless the operator lists sources explicitly.
pub const DEFAULT_SOURCES: [&str; 6] = [
    "o365:Audit.AzureActiveDirectory",
    "o365:Audit.Exchange",
    "o365:Audit.SharePoint",
    "o365:Audit.General",
    "graph:directoryAudits",
    "graph:signIns",
];

pub const DEFAULT_RETENTION_DAYS: u32 = 365;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveConfig {
    /// Directory (tenant) GUID being archived.
    pub tenant_id: String,
    #[serde(default = "default_cloud")]
    pub cloud: MicrosoftCloud,
    /// Credential flow for Microsoft Graph and the Management Activity API.
    #[serde(default = "default_flow")]
    pub auth: AuthFlow,
    #[serde(default = "default_sources")]
    pub sources: Vec<String>,
    /// Local, private state: checkpoints and the forward cursor. Not evidence.
    #[serde(default = "default_state")]
    pub state_directory: PathBuf,
    #[serde(default = "default_rpm")]
    pub max_requests_per_minute: usize,
    pub storage: StorageConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StorageConfig {
    /// Azure Blob container with version-level immutability.
    AzureBlob {
        /// `https://<account>.blob.core.windows.net/`
        account_url: String,
        container: String,
        /// Retention the container's immutability policy is expected to give,
        /// in days. `doctor` checks the service reports at least this.
        #[serde(default = "default_retention")]
        retention_days: u32,
        /// Credential flow for the storage identity (may differ from the
        /// tenant collector's).
        #[serde(default = "default_storage_flow")]
        auth: AuthFlow,
    },
    /// Cloudflare R2 bucket with bucket lock rules.
    R2 {
        account_id: String,
        bucket: String,
        #[serde(default = "default_jurisdiction")]
        jurisdiction: String,
        #[serde(default = "default_retention")]
        retention_days: u32,
    },
    /// A local directory. Not immutable; for trials and tests only.
    Local { path: PathBuf },
}

fn default_cloud() -> MicrosoftCloud {
    MicrosoftCloud::Public
}
fn default_flow() -> AuthFlow {
    AuthFlow::Certificate
}
fn default_storage_flow() -> AuthFlow {
    AuthFlow::Certificate
}
fn default_sources() -> Vec<String> {
    DEFAULT_SOURCES.iter().map(|s| s.to_string()).collect()
}
fn default_state() -> PathBuf {
    PathBuf::from(".junction/archive/state")
}
fn default_rpm() -> usize {
    100
}
fn default_retention() -> u32 {
    DEFAULT_RETENTION_DAYS
}
fn default_jurisdiction() -> String {
    "default".into()
}

impl ArchiveConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).context("archive configuration unavailable")?;
        if text.len() > 64 * 1024 {
            bail!("archive configuration too large");
        }
        let config: Self = toml::from_str(&text).context("invalid archive configuration")?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        junction_watch::store::validate_tenant(&self.tenant_id)?;
        if self.sources.is_empty() {
            bail!("sources must list at least one source");
        }
        for source in &self.sources {
            if !ALL_SOURCES.contains(&source.as_str()) {
                bail!("unknown source {source:?}; see `junction archive permissions`");
            }
        }
        if !(1..=6000).contains(&self.max_requests_per_minute) {
            bail!("max_requests_per_minute must be between 1 and 6000");
        }
        match &self.storage {
            StorageConfig::AzureBlob {
                account_url,
                retention_days,
                ..
            } => {
                crate::store::parse_account_url(account_url)?;
                validate_retention(*retention_days)?;
            }
            StorageConfig::R2 { retention_days, .. } => validate_retention(*retention_days)?,
            StorageConfig::Local { .. } => {}
        }
        Ok(())
    }

    pub fn retention_days(&self) -> Option<u32> {
        match &self.storage {
            StorageConfig::AzureBlob { retention_days, .. }
            | StorageConfig::R2 { retention_days, .. } => Some(*retention_days),
            StorageConfig::Local { .. } => None,
        }
    }

    /// Open the configured store. Credentials are read from the environment.
    pub fn open_store(&self) -> Result<Arc<dyn ObjectStore>> {
        let http =
            || -> Result<Arc<LiveHttp>> { Ok(Arc::new(LiveHttp::new(Duration::from_secs(120))?)) };
        Ok(match &self.storage {
            StorageConfig::AzureBlob {
                account_url,
                container,
                auth,
                ..
            } => {
                let endpoints = self.cloud.endpoints()?;
                let tokens = EnvironmentTokens::new(
                    &storage_tenant(&self.tenant_id),
                    &endpoints.authority,
                    *auth,
                    "archive-storage",
                );
                Arc::new(AzureBlobStore::new(
                    account_url,
                    container,
                    http()?,
                    Arc::new(tokens),
                    Retry::default(),
                )?)
            }
            StorageConfig::R2 {
                account_id,
                bucket,
                jurisdiction,
                ..
            } => Arc::new(R2Store::new(
                account_id,
                jurisdiction,
                bucket,
                R2Credentials::from_environment()?,
                http()?,
                Retry::default(),
            )?),
            StorageConfig::Local { path } => Arc::new(LocalStore::new(path)?),
        })
    }

    /// A commented starting configuration.
    pub fn example(tenant_id: &str) -> String {
        format!(
            r#"# junction archive configuration. Contains no secrets.
# Credentials come from the environment; see docs/ARCHIVE.md.
tenant_id = "{tenant_id}"
# cloud = "public"
# auth = "certificate"            # tenant collector credential flow
# sources = [                     # default: Unified Audit Log and Entra ID logs
#   "o365:Audit.AzureActiveDirectory", "o365:Audit.Exchange",
#   "o365:Audit.SharePoint", "o365:Audit.General",
#   "graph:directoryAudits", "graph:signIns",
#   "graph:alerts_v2", "graph:incidents",   # opt-in Defender records
# ]
# state_directory = ".junction/archive/state"

[storage]
kind = "azure_blob"
account_url = "https://<account>.blob.core.windows.net/"
container = "junction-archive"
retention_days = {DEFAULT_RETENTION_DAYS}
# auth = "certificate"            # storage identity credential flow

# Cloudflare R2 instead:
# [storage]
# kind = "r2"
# account_id = "<32-character account id>"
# bucket = "junction-archive"
# jurisdiction = "default"        # default, eu or fedramp
# retention_days = {DEFAULT_RETENTION_DAYS}
"#
        )
    }
}

/// The storage identity is in the same Entra tenant as the collector unless
/// `JUNCTION_ARCHIVE_STORAGE_TENANT_ID` names another one (for example a
/// separate security subscription's tenant).
fn storage_tenant(default: &str) -> String {
    std::env::var("JUNCTION_ARCHIVE_STORAGE_TENANT_ID")
        .ok()
        .filter(|v| junction_watch::store::validate_tenant(v).is_ok())
        .unwrap_or_else(|| default.to_owned())
}

fn validate_retention(days: u32) -> Result<()> {
    if !(1..=146_000).contains(&days) {
        bail!("retention_days must be between 1 and 146000 (Azure's maximum)");
    }
    Ok(())
}

/// Create `path` with `contents` (mode 0600) only if it does not exist.
pub fn write_new_private(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("{} already exists or cannot be created", path.display()))?;
    file.write_all(contents.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const T: &str = "11111111-1111-4111-8111-111111111111";

    #[test]
    fn example_parses_and_validates() {
        let config: ArchiveConfig =
            toml::from_str(&ArchiveConfig::example(T).replace("<account>", "acct")).unwrap();
        config.validate().unwrap();
        assert_eq!(config.retention_days(), Some(365));
        assert_eq!(config.sources.len(), 6);
    }

    #[test]
    fn rejects_secrets_and_unknown_sources() {
        let base = format!("tenant_id = \"{T}\"\n[storage]\nkind = \"local\"\npath = \"x\"\n");
        let config: ArchiveConfig = toml::from_str(&base).unwrap();
        config.validate().unwrap();
        assert!(
            toml::from_str::<ArchiveConfig>(&format!("{base}secret_access_key = \"x\"\n")).is_err(),
            "unknown keys are refused, so a secret cannot be pasted in"
        );
        let sas = format!(
            "tenant_id = \"{T}\"\n[storage]\nkind = \"azure_blob\"\naccount_url = \"https://a.blob.core.windows.net/?sig=x\"\ncontainer = \"abc\"\n"
        );
        assert!(
            toml::from_str::<ArchiveConfig>(&sas)
                .unwrap()
                .validate()
                .is_err()
        );
        let bad = format!(
            "tenant_id = \"{T}\"\nsources = [\"intune:devices\"]\n[storage]\nkind = \"local\"\npath = \"x\"\n"
        );
        assert!(
            toml::from_str::<ArchiveConfig>(&bad)
                .unwrap()
                .validate()
                .is_err()
        );
    }
}
