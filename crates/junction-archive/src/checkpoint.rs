//! Local collection state: one private JSON file per tenant.
//!
//! The checkpoint is not evidence. Losing it only causes a replay, and replays
//! are absorbed by content-addressed object keys and record-id deduplication
//! on read. It is written atomically (temporary file, fsync, rename) so a crash
//! leaves either the old state or the new one, never a torn file.
use anyhow::{Context, Result, bail};
use junction_watch::clock::Instant;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

pub const STATE_SCHEMA: &str = "junction.archive.state/1";
/// Archived content blob ids are remembered this long: past the 7-day content
/// window plus the listing overlap, so a re-list never re-fetches them.
pub const BLOB_MEMORY_DAYS: u64 = 8;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceState {
    /// Everything before this instant has been stored and recorded in a manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watermark: Option<String>,
    /// Management Activity content ids already archived, with their `contentCreated`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub archived_blobs: BTreeMap<String, String>,
    /// Consecutive transient failures per content id.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub blob_failures: BTreeMap<String, u32>,
    /// Do not call the source again before this instant (server `Retry-After`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<String>,
    /// Graph record ids stored inside the overlap window, with their event
    /// time, so the next run's overlap does not store them again.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub recent_records: BTreeMap<String, String>,
    /// Hash of this source's latest manifest, chaining the next one to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_manifest_sha256: Option<String>,
    /// Graph window length in use after a run hit its page budget; absent
    /// means the default (one day).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_seconds: Option<u64>,
    /// Last capability problem (`requires_licence`, `requires_permission`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable: Option<String>,
}

impl SourceState {
    pub fn watermark(&self) -> Option<Instant> {
        self.watermark
            .as_deref()
            .and_then(|w| Instant::parse(w).ok())
    }
    pub fn set_watermark(&mut self, at: Instant) {
        // Never move backwards: a replayed window must not rewind progress.
        if self.watermark().is_none_or(|w| at > w) {
            self.watermark = Some(at.to_rfc3339());
        }
    }
    pub fn retry_after(&self) -> Option<Instant> {
        self.retry_after
            .as_deref()
            .and_then(|w| Instant::parse(w).ok())
    }
    /// Forget archived blob ids older than [`BLOB_MEMORY_DAYS`].
    pub fn prune(&mut self, now: Instant) {
        let floor = now
            .minus(std::time::Duration::from_secs(BLOB_MEMORY_DAYS * 86_400))
            .to_rfc3339();
        self.archived_blobs.retain(|_, created| *created >= floor);
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct State {
    pub schema: String,
    pub tenant_id: String,
    #[serde(default)]
    pub sources: BTreeMap<String, SourceState>,
}

/// Largest state file accepted or written.
pub const MAX_STATE_BYTES: usize = 256 * 1024 * 1024;

/// The checkpoint file for one tenant, held under an exclusive OS lock for as
/// long as this value lives, so overlapping runs cannot overwrite each
/// other's progress. The lock is released by the OS if the process dies.
pub struct Checkpoint {
    path: PathBuf,
    _lock: std::fs::File,
    pub state: State,
}

impl Checkpoint {
    pub fn open(directory: &Path, tenant: &str) -> Result<Self> {
        junction_watch::store::validate_tenant(tenant)?;
        std::fs::create_dir_all(directory).context("archive state directory unavailable")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
        }
        let tenant = tenant.to_ascii_lowercase();
        let lock_path = directory.join(format!("{tenant}.lock"));
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .context("archive state lock unavailable")?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => bail!(
                "another junction archive run is using this tenant's state; wait for it to finish"
            ),
            Err(std::fs::TryLockError::Error(_)) => bail!("archive state lock unavailable"),
        }
        let path = directory.join(format!("{tenant}.json"));
        let state = match std::fs::read(&path) {
            Ok(bytes) => {
                if bytes.len() > MAX_STATE_BYTES {
                    bail!("archive state file too large");
                }
                let state: State =
                    serde_json::from_slice(&bytes).context("archive state file is not valid")?;
                if state.schema != STATE_SCHEMA || !state.tenant_id.eq_ignore_ascii_case(&tenant) {
                    bail!("archive state file belongs to another tenant or schema");
                }
                state
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State {
                schema: STATE_SCHEMA.into(),
                tenant_id: tenant.clone(),
                sources: BTreeMap::new(),
            },
            Err(_) => bail!("archive state file unreadable"),
        };
        Ok(Self {
            path,
            _lock: lock,
            state,
        })
    }

    pub fn source(&mut self, source: &str) -> &mut SourceState {
        self.state.sources.entry(source.to_owned()).or_default()
    }

    pub fn get(&self, source: &str) -> Option<&SourceState> {
        self.state.sources.get(source)
    }

    /// Atomically replace the file with the current state.
    pub fn save(&self) -> Result<()> {
        use std::io::Write;
        let bytes = serde_json::to_vec(&self.state)?;
        if bytes.len() > MAX_STATE_BYTES {
            bail!("archive state would exceed {MAX_STATE_BYTES} bytes; not saved");
        }
        let tmp = self
            .path
            .with_extension(format!("json.tmp-{}", std::process::id()));
        {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&tmp).context("archive state write failed")?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path).context("archive state write failed")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const T: &str = "11111111-1111-4111-8111-111111111111";

    #[test]
    fn state_round_trips_and_watermark_never_rewinds() {
        let dir = tempfile::tempdir().unwrap();
        let mut cp = Checkpoint::open(dir.path(), T).unwrap();
        let a = Instant::parse("2026-11-01T00:00:00Z").unwrap();
        let b = Instant::parse("2026-11-02T00:00:00Z").unwrap();
        cp.source("graph:signIns").set_watermark(b);
        cp.source("graph:signIns").set_watermark(a);
        cp.save().unwrap();
        drop(cp);
        let again = Checkpoint::open(dir.path(), T).unwrap();
        assert_eq!(again.get("graph:signIns").unwrap().watermark(), Some(b));
        assert!(
            Checkpoint::open(dir.path(), "22222222-2222-4222-8222-222222222222")
                .unwrap()
                .state
                .sources
                .is_empty()
        );
    }

    #[test]
    fn foreign_or_corrupt_state_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(format!("{T}.json")), b"{not json").unwrap();
        assert!(Checkpoint::open(dir.path(), T).is_err());
        std::fs::write(
            dir.path().join(format!("{T}.json")),
            br#"{"schema":"junction.archive.state/1","tenantId":"22222222-2222-4222-8222-222222222222"}"#,
        )
        .unwrap();
        assert!(Checkpoint::open(dir.path(), T).is_err());
    }

    #[test]
    fn a_second_open_is_refused_while_the_first_is_held() {
        let dir = tempfile::tempdir().unwrap();
        let first = Checkpoint::open(dir.path(), T).unwrap();
        let second = Checkpoint::open(dir.path(), T);
        assert!(second.is_err(), "overlapping runs must not share state");
        drop(first);
        Checkpoint::open(dir.path(), T).unwrap();
    }

    #[test]
    fn prune_forgets_old_blobs() {
        let mut s = SourceState::default();
        s.archived_blobs
            .insert("old".into(), "2026-10-01T00:00:00.000Z".into());
        s.archived_blobs
            .insert("new".into(), "2026-11-20T00:00:00.000Z".into());
        s.prune(Instant::parse("2026-11-22T00:00:00Z").unwrap());
        assert_eq!(s.archived_blobs.keys().collect::<Vec<_>>(), ["new"]);
    }
}
