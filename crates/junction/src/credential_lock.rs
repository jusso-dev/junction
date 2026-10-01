//! Stable, secret-free locks shared by CLI processes regardless of working directory.
use anyhow::{Result, bail};
use junction_auth::TokenRequest;
use std::{fs::File, path::Path};

#[derive(Debug)]
pub struct CredentialBusy;
impl std::fmt::Display for CredentialBusy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "credential is busy; retry after the active credential transaction completes",
        )
    }
}
impl std::error::Error for CredentialBusy {}
impl CredentialBusy {
    pub fn response(&self) -> serde_json::Value {
        serde_json::json!({
            "error": "credential_busy",
            "retryable": true,
            "message": "Retry after the active login, renewal or logout completes"
        })
    }
}

pub struct CredentialLock {
    _file: File,
}
impl CredentialLock {
    pub fn acquire(request: &TokenRequest) -> Result<Self> {
        let home = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .filter(|path| path.is_absolute())
            .ok_or_else(|| anyhow::anyhow!("credential lock home unavailable"))?;
        Self::in_directory(&home.join(".junction-credential-locks"), request)
    }
    fn in_directory(directory: &Path, request: &TokenRequest) -> Result<Self> {
        let id = junction_auth::storage::credential_id(request)?;
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => bail!("credential lock directory unavailable"),
        }
        let metadata = std::fs::symlink_metadata(directory)
            .map_err(|_| anyhow::anyhow!("credential lock directory unavailable"))?;
        if !metadata.is_dir() {
            bail!("invalid credential lock directory");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
                bail!("credential lock directory must be private and operator-owned");
            }
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options
            .open(directory.join(format!("{id}.lock")))
            .map_err(|_| anyhow::anyhow!("credential lock unavailable"))?;
        let metadata = file
            .metadata()
            .map_err(|_| anyhow::anyhow!("credential lock unavailable"))?;
        if !metadata.is_file() {
            bail!("invalid credential lock file");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
                || metadata.nlink() != 1
            {
                bail!("credential lock file must be private and operator-owned");
            }
        }
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Err(CredentialBusy.into()),
            Err(std::fs::TryLockError::Error(_)) => bail!("credential lock unavailable"),
        }
        // Never unlink lock files: doing so would permit locking a second inode.
        Ok(Self { _file: file })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> TokenRequest {
        TokenRequest {
            tenant: "tenant-a".into(),
            authority: "https://login.example.invalid".into(),
            audience: "https://resource.example.invalid".into(),
            scopes: vec![],
            credential_profile: "operator".into(),
            flow: junction_auth::AuthFlow::DeviceCode,
        }
    }
    fn released_lock(directory: &Path, request: &TokenRequest) -> CredentialLock {
        // Concurrent process-spawning tests may briefly inherit open descriptors
        // between fork and exec, even when the descriptor is close-on-exec.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match CredentialLock::in_directory(directory, request) {
                Ok(lock) => return lock,
                Err(error) => {
                    assert!(std::time::Instant::now() < deadline, "{error}");
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
        }
    }
    #[test]
    fn overlapping_handles_conflict_and_other_tenants_remain_independent() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("locks");
        let request = request();
        let first = CredentialLock::in_directory(&directory, &request).unwrap();
        let error = CredentialLock::in_directory(&directory, &request)
            .err()
            .unwrap();
        let busy = error.downcast_ref::<CredentialBusy>().unwrap();
        assert_eq!(busy.response()["error"], "credential_busy");
        assert_eq!(busy.response()["retryable"], true);
        assert!(
            !serde_json::to_string(&busy.response())
                .unwrap()
                .contains("tenant-a")
        );
        let mut other = request.clone();
        other.tenant = "tenant-b".into();
        let _other = CredentialLock::in_directory(&directory, &other).unwrap();
        drop(first);
        let _released = released_lock(&directory, &request);
        for entry in std::fs::read_dir(&directory).unwrap() {
            assert_eq!(std::fs::read(entry.unwrap().path()).unwrap(), b"");
        }
    }
    #[test]
    fn child_attempt() {
        let Some(directory) = std::env::var_os("JUNCTION_TEST_LOCK_DIRECTORY") else {
            return;
        };
        let expected = std::env::var("JUNCTION_TEST_LOCK_AVAILABLE").unwrap() == "true";
        assert_eq!(
            CredentialLock::in_directory(Path::new(&directory), &request()).is_ok(),
            expected
        );
    }
    #[test]
    fn independent_processes_share_the_lock_and_release_on_exit() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("locks");
        let lock = CredentialLock::in_directory(&directory, &request()).unwrap();
        let child = |available: bool| {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "credential_lock::tests::child_attempt"])
                .env("JUNCTION_TEST_LOCK_DIRECTORY", &directory)
                .env("JUNCTION_TEST_LOCK_AVAILABLE", available.to_string())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
        };
        child(false);
        drop(lock);
        child(true);
        let _released = released_lock(&directory, &request());
    }
    #[cfg(unix)]
    #[test]
    fn symlinks_and_public_permissions_are_rejected() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("locks");
        symlink(temporary.path(), &directory).unwrap();
        assert!(CredentialLock::in_directory(&directory, &request()).is_err());
        std::fs::remove_file(&directory).unwrap();
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(CredentialLock::in_directory(&directory, &request()).is_err());
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let id = junction_auth::storage::credential_id(&request()).unwrap();
        symlink(
            temporary.path().join("victim"),
            directory.join(format!("{id}.lock")),
        )
        .unwrap();
        assert!(CredentialLock::in_directory(&directory, &request()).is_err());
        assert!(!temporary.path().join("victim").exists());
    }
}
