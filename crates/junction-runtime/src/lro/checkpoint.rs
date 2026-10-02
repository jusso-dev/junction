use super::*;
use std::{
    io::{Read, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
const LIMIT: usize = 64 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredHandle {
    format_version: u32,
    operation_id: String,
    operation: String,
    version: Option<String>,
    allow_preview: bool,
    tenant: String,
    audience: String,
    endpoint: String,
    poll_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request_url: Option<String>,
    #[serde(default)]
    final_url: Option<String>,
    #[serde(default)]
    final_protocol: Option<PollProtocol>,
    protocol: PollProtocol,
    progress: OperationProgress,
    max_polls: usize,
    not_before: u64,
}
impl LroHandle {
    /// Write a new operator-owned checkpoint. Existing files are never overwritten.
    pub fn save(&self, path: &Path) -> Result<()> {
        let delay = self.retry_after();
        let not_before = SystemTime::now()
            .checked_add(delay)
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .and_then(|time| {
                time.as_secs()
                    .checked_add(u64::from(time.subsec_nanos() > 0))
            })
            .ok_or_else(|| anyhow::anyhow!("invalid operation checkpoint delay"))?;
        let stored = StoredHandle {
            format_version: 1,
            operation_id: self.operation_id.clone(),
            operation: self.operation.clone(),
            version: self.version.clone(),
            allow_preview: self.allow_preview,
            tenant: self.tenant.clone(),
            audience: self.audience.clone(),
            endpoint: self.endpoint.clone(),
            poll_url: self.poll_url.to_string(),
            request_url: self.request_url.as_ref().map(Url::to_string),
            final_url: self.final_target.as_ref().map(|(url, _)| url.to_string()),
            final_protocol: self.final_target.as_ref().map(|(_, protocol)| *protocol),
            protocol: self.tracker.protocol,
            progress: self.tracker.progress,
            max_polls: self.tracker.max_polls,
            not_before,
        };
        let bytes = serde_json::to_vec(&stored)
            .map_err(|_| anyhow::anyhow!("operation checkpoint encoding failed"))?;
        if bytes.len() > LIMIT {
            bail!("operation checkpoint size limit exceeded");
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
            .map_err(|_| anyhow::anyhow!("operation checkpoint creation failed"))?;
        if file
            .write_all(&bytes)
            .and_then(|_| file.sync_all())
            .is_err()
        {
            drop(file);
            let _ = std::fs::remove_file(path);
            bail!("operation checkpoint write failed");
        }
        Ok(())
    }
    /// Checkpoints are trusted operator files, never agent-supplied operation handles.
    pub fn load(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path)
            .map_err(|_| anyhow::anyhow!("operation checkpoint unavailable"))?;
        let metadata = file
            .metadata()
            .map_err(|_| anyhow::anyhow!("operation checkpoint unavailable"))?;
        if !metadata.is_file() || metadata.len() > LIMIT as u64 {
            bail!("invalid operation checkpoint file");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                bail!("operation checkpoint must be private");
            }
        }
        let mut bytes = Vec::new();
        file.take(LIMIT as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| anyhow::anyhow!("operation checkpoint read failed"))?;
        if bytes.len() > LIMIT {
            bail!("operation checkpoint size limit exceeded");
        }
        let stored: StoredHandle = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid operation checkpoint"))?;
        if stored.format_version != 1
            || stored.operation_id.len() != 36
            || !stored.operation_id.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            })
            || stored.operation.is_empty()
            || stored.operation.len() > 512
            || !stored
                .operation
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.'))
            || stored.tenant.is_empty()
            || stored.tenant.len() > 256
            || !stored
                .tenant
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'))
            || stored.audience.is_empty()
            || stored.audience.len() > 4096
            || stored.audience.chars().any(char::is_control)
            || stored
                .version
                .as_ref()
                .is_some_and(|v| v.len() > 256 || v.chars().any(char::is_control))
            || !(1..=10_000).contains(&stored.max_polls)
            || stored.progress.polls > stored.max_polls
        {
            bail!("invalid operation checkpoint metadata");
        }
        let endpoint = Url::parse(&stored.endpoint)
            .map_err(|_| anyhow::anyhow!("invalid operation checkpoint endpoint"))?;
        let poll_url = Url::parse(&stored.poll_url)
            .map_err(|_| anyhow::anyhow!("invalid operation checkpoint endpoint"))?;
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || poll_url.scheme() != "https"
            || poll_url.origin() != endpoint.origin()
            || !poll_url.username().is_empty()
            || poll_url.password().is_some()
            || poll_url.fragment().is_some()
        {
            bail!("invalid operation checkpoint endpoint");
        }
        let not_before = UNIX_EPOCH
            .checked_add(Duration::from_secs(stored.not_before))
            .ok_or_else(|| anyhow::anyhow!("invalid operation checkpoint delay"))?;
        let delay = not_before
            .duration_since(SystemTime::now())
            .unwrap_or_default();
        let ready_at = Instant::now()
            .checked_add(delay)
            .ok_or_else(|| anyhow::anyhow!("invalid operation checkpoint delay"))?;
        let request_url = stored
            .request_url
            .map(|url| {
                let url = Url::parse(&url)
                    .map_err(|_| anyhow::anyhow!("invalid operation checkpoint endpoint"))?;
                if url.scheme() != "https"
                    || url.origin() != endpoint.origin()
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.fragment().is_some()
                {
                    bail!("invalid operation checkpoint endpoint");
                }
                Ok(url)
            })
            .transpose()?;
        let final_target = match (stored.final_url, stored.final_protocol) {
            (None, None) => None,
            (Some(url), Some(protocol)) => {
                let url = Url::parse(&url)
                    .map_err(|_| anyhow::anyhow!("invalid operation checkpoint endpoint"))?;
                if url.scheme() != "https"
                    || url.origin() != endpoint.origin()
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.fragment().is_some()
                {
                    bail!("invalid operation checkpoint endpoint");
                }
                Some((url, protocol))
            }
            _ => bail!("invalid operation checkpoint final result binding"),
        };
        Ok(Self {
            operation_id: stored.operation_id,
            operation: stored.operation,
            version: stored.version,
            allow_preview: stored.allow_preview,
            tenant: stored.tenant,
            audience: stored.audience,
            endpoint: stored.endpoint,
            poll_url,
            request_url,
            final_target,
            tracker: LroTracker {
                protocol: stored.protocol,
                progress: stored.progress,
                max_polls: stored.max_polls,
            },
            ready_at,
        })
    }
}
