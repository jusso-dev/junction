use anyhow::{Result, bail};
use junction_runtime::lro::LroHandle;
use std::path::{Path, PathBuf};

fn path(directory: &Path, id: &str, extension: &str) -> Result<PathBuf> {
    if id.len() != 36
        || !id.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
            }
        })
    {
        bail!("invalid operation handle identifier");
    }
    Ok(directory.join(format!("{id}.{extension}")))
}

/// Probe storage before issuing the initial mutation.
pub fn prepare(directory: &Path) -> Result<()> {
    std::fs::create_dir_all(directory)
        .map_err(|_| anyhow::anyhow!("could not prepare operation store"))?;
    let probe = tempfile::tempdir_in(directory)
        .map_err(|_| anyhow::anyhow!("operation store is not writable"))?;
    probe
        .close()
        .map_err(|_| anyhow::anyhow!("operation store probe cleanup failed"))
}

pub fn save_initial(directory: &Path, handle: &LroHandle) -> Result<()> {
    handle.save(&path(directory, handle.snapshot().operation_id, "json")?)
}

pub fn load(directory: &Path, id: &str) -> Result<LroHandle> {
    let handle = LroHandle::load(&path(directory, id, "json")?)?;
    if handle.snapshot().operation_id != id {
        bail!("operation checkpoint identifier mismatch");
    }
    Ok(handle)
}

/// Exclusive ownership covers loading, polling and replacing a checkpoint.
pub struct LockedHandle {
    lock: PathBuf,
    target: PathBuf,
    pub handle: LroHandle,
}
impl LockedHandle {
    pub fn checkpoint_path(&self) -> PathBuf {
        self.target.clone()
    }
    pub fn acquire(directory: &Path, id: &str) -> Result<Self> {
        let lock = path(directory, id, "lock")?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(&lock)
            .map_err(|_| anyhow::anyhow!("operation handle is locked or unavailable"))?;
        drop(file);
        match load(directory, id) {
            Ok(handle) => Ok(Self {
                lock,
                target: path(directory, id, "json")?,
                handle,
            }),
            Err(error) => {
                let _ = std::fs::remove_file(lock);
                Err(error)
            }
        }
    }
    pub fn persist(&self) -> Result<()> {
        persist_at(&self.target, &self.handle)
    }
}
pub fn persist_at(target: &Path, handle: &LroHandle) -> Result<()> {
    let directory = target.parent().expect("store path has a parent");
    let staging = tempfile::tempdir_in(directory)
        .map_err(|_| anyhow::anyhow!("could not stage operation checkpoint"))?;
    let staged = staging.path().join("state.json");
    handle.save(&staged)?;
    std::fs::rename(staged, target)
        .map_err(|_| anyhow::anyhow!("could not replace operation checkpoint"))?;
    Ok(())
}
impl Drop for LockedHandle {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.lock);
    }
}
