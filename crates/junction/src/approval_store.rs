//! Durable, single-use operator approvals.
//!
//! `junction approvals issue` validates a destructive or privileged request,
//! has the operator confirm it on the controlling terminal, and writes a
//! private record. An agent host (MCP or HTTP) may later execute exactly that
//! request once by naming the record's ID: the host consumes the record
//! atomically, re-checks every binding (operation, input, tenant, endpoint,
//! audience, credential profile, policy) against its own trusted
//! configuration, and only then issues an in-process approval grant.
//!
//! Records live in an operator-owned private directory. Processes running as
//! the same OS user can read that directory, so durable approvals assume
//! agents do not have direct filesystem access to it.
use anyhow::{Result, bail};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const MAX_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub format: String,
    pub id: String,
    pub operation: String,
    pub api_version: Option<String>,
    pub allow_preview: bool,
    pub input: serde_json::Value,
    pub tenant: String,
    pub endpoint: String,
    pub audience: String,
    pub credential_profile: String,
    pub policy_sha256: String,
    pub issued_at: u64,
    pub expires_at: u64,
}
const FORMAT: &str = "junction-approval-v1";

pub fn policy_fingerprint(policy: &junction_policy::Policy) -> Result<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&serde_json::to_value(policy)?)?)
    ))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn validate_id(id: &str) -> Result<()> {
    if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("invalid approval identifier");
    }
    Ok(())
}

fn prepare(directory: &Path) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(directory)
        .map_err(|_| anyhow::anyhow!("approval directory unavailable"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::symlink_metadata(directory)?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            bail!("approval directory must be private");
        }
    }
    Ok(())
}

/// Write a new record and return its identifier.
#[allow(clippy::too_many_arguments)]
pub fn issue(
    directory: &Path,
    operation: &str,
    api_version: Option<&str>,
    allow_preview: bool,
    input: &serde_json::Value,
    tenant: &str,
    endpoint: &str,
    audience: &str,
    credential_profile: &str,
    policy: &junction_policy::Policy,
    lifetime: Duration,
) -> Result<Record> {
    if lifetime.is_zero() || lifetime > MAX_LIFETIME {
        bail!("approval lifetime must be between 1 minute and 24 hours");
    }
    prepare(directory)?;
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(|_| anyhow::anyhow!("random source unavailable"))?;
    let id: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let issued_at = now();
    let record = Record {
        format: FORMAT.into(),
        id: id.clone(),
        operation: operation.into(),
        api_version: api_version.map(str::to_owned),
        allow_preview,
        input: input.clone(),
        tenant: tenant.to_ascii_lowercase(),
        endpoint: endpoint.into(),
        audience: audience.into(),
        credential_profile: credential_profile.into(),
        policy_sha256: policy_fingerprint(policy)?,
        issued_at,
        expires_at: issued_at + lifetime.as_secs(),
    };
    let bytes = serde_json::to_vec(&record)?;
    if bytes.len() > 256 * 1024 {
        bail!("approval input too large");
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(directory.join(format!("{id}.json")))
        .map_err(|_| anyhow::anyhow!("approval record creation failed"))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(record)
}

fn read(path: &Path) -> Result<Record> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| anyhow::anyhow!("approval unavailable or already used"))?
        .take(256 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    let record: Record =
        serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid approval record"))?;
    if record.format != FORMAT {
        bail!("invalid approval record");
    }
    Ok(record)
}

/// Atomically claim a record: rename it so no other process can use it,
/// then read and delete it. Expired records are removed and rejected.
pub fn consume(directory: &Path, id: &str) -> Result<Record> {
    validate_id(id)?;
    let source = directory.join(format!("{id}.json"));
    let claimed: PathBuf = directory.join(format!("{id}.claimed-{}", std::process::id()));
    std::fs::rename(&source, &claimed)
        .map_err(|_| anyhow::anyhow!("approval unavailable or already used"))?;
    let record = read(&claimed);
    let _ = std::fs::remove_file(&claimed);
    let record = record?;
    if record.id != id || now() >= record.expires_at {
        bail!("approval expired");
    }
    Ok(record)
}

pub fn list(directory: &Path) -> Result<Vec<Record>> {
    let mut records = Vec::new();
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Ok(records);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json")
            && let Ok(record) = read(&path)
        {
            records.push(record);
        }
    }
    records.sort_by_key(|record| record.issued_at);
    Ok(records)
}

pub fn revoke(directory: &Path, id: &str) -> Result<()> {
    validate_id(id)?;
    std::fs::remove_file(directory.join(format!("{id}.json")))
        .map_err(|_| anyhow::anyhow!("approval unavailable or already used"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn records_are_private_single_use_and_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let approvals = directory.path().join("approvals");
        let policy = junction_policy::Policy::parse("[agent]\nmode='full'\n").unwrap();
        let input = serde_json::json!({"parameters":{"id":"vm1"}});
        let issue = |lifetime| {
            super::issue(
                &approvals,
                "azure.compute.virtual_machines.delete",
                None,
                false,
                &input,
                "Tenant-A",
                "https://management.azure.com",
                "https://management.azure.com/",
                "operator",
                &policy,
                lifetime,
            )
        };
        assert!(issue(Duration::from_secs(25 * 3600)).is_err());
        let record = issue(Duration::from_secs(600)).unwrap();
        assert_eq!(record.tenant, "tenant-a");
        assert_eq!(list(&approvals).unwrap().len(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(approvals.join(format!("{}.json", record.id)))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0);
        }
        let consumed = consume(&approvals, &record.id).unwrap();
        assert_eq!(consumed, record);
        assert!(consume(&approvals, &record.id).is_err());
        assert!(consume(&approvals, "../../etc/passwd").is_err());
        let other = issue(Duration::from_secs(600)).unwrap();
        revoke(&approvals, &other.id).unwrap();
        assert!(consume(&approvals, &other.id).is_err());
        assert_ne!(
            policy_fingerprint(&policy).unwrap(),
            policy_fingerprint(
                &junction_policy::Policy::parse("[agent]\nmode='safe-write'\n").unwrap()
            )
            .unwrap()
        );
    }
}
