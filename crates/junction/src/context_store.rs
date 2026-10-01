//! Secret-free, bounded local context files. Create-only writes never replace an existing context.
use anyhow::{Result, bail};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 80
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        bail!("invalid context name");
    }
    Ok(())
}
fn path(directory: &Path, name: &str) -> Result<PathBuf> {
    validate_name(name)?;
    Ok(directory.join(format!("{name}.json")))
}
pub fn read_file(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 64 * 1024 {
        bail!("context size limit exceeded");
    }
    Ok(bytes)
}
pub fn read(directory: &Path, name: &str) -> Result<Vec<u8>> {
    read_file(&path(directory, name)?)
}
/// Input must first be parsed and validated as a secret-free context by the caller.
pub fn add(directory: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let path = path(directory, name)?;
    if bytes.len() > 64 * 1024 {
        bail!("context size limit exceeded");
    }
    std::fs::create_dir_all(directory)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path)?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(error.into());
    }
    Ok(())
}
pub fn list(directory: &Path) -> Result<Vec<String>> {
    if !directory.exists() {
        return Ok(vec![]);
    }
    let mut names = Vec::new();
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|p| p.to_str()) != Some("json") {
            continue;
        }
        if let Some(name) = path.file_stem().and_then(|p| p.to_str())
            && validate_name(name).is_ok()
        {
            names.push(name.to_owned());
        }
    }
    names.sort();
    Ok(names)
}
pub fn remove(directory: &Path, name: &str) -> Result<()> {
    std::fs::remove_file(path(directory, name)?)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn names_are_contained_and_existing_contexts_are_preserved() {
        let directory = tempfile::tempdir().unwrap();
        for name in ["", "..", "../escape", "/absolute", "a/b", "a\\b", ".hidden"] {
            assert!(add(directory.path(), name, b"{}").is_err());
        }
        add(directory.path(), "customer-b", b"{}").unwrap();
        add(directory.path(), "customer-a", b"{}").unwrap();
        assert!(add(directory.path(), "customer-a", b"replacement").is_err());
        assert_eq!(read(directory.path(), "customer-a").unwrap(), b"{}");
        assert_eq!(
            list(directory.path()).unwrap(),
            ["customer-a", "customer-b"]
        );
        remove(directory.path(), "customer-a").unwrap();
        assert_eq!(list(directory.path()).unwrap(), ["customer-b"]);
    }
}
