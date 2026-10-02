//! Private files that resume request-body paging (Azure Resource Graph
//! `$skipToken`). A file is bound to the exact operation and input that
//! produced it and is never overwritten.
use anyhow::{Result, bail};
use std::io::{Read, Write};
use std::path::Path;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    format: String,
    operation: String,
    input: String,
    token: String,
}
const FORMAT: &str = "junction-body-continuation-v1";

pub fn save(path: &Path, operation: &str, input: &serde_json::Value, token: &str) -> Result<()> {
    let bytes = serde_json::to_vec(&Stored {
        format: FORMAT.into(),
        operation: operation.into(),
        input: serde_json::to_string(input)?,
        token: token.into(),
    })?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| anyhow::anyhow!("continuation output already exists or is unwritable"))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

pub fn load(path: &Path, operation: &str, input: &serde_json::Value) -> Result<String> {
    let file =
        std::fs::File::open(path).map_err(|_| anyhow::anyhow!("continuation unavailable"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if file.metadata()?.permissions().mode() & 0o077 != 0 {
            bail!("continuation file must be private");
        }
    }
    let mut bytes = Vec::new();
    file.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 64 * 1024 {
        bail!("continuation file too large");
    }
    let stored: Stored =
        serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid continuation"))?;
    if stored.format != FORMAT
        || stored.operation != operation
        || stored.input != serde_json::to_string(input)?
    {
        bail!("continuation context mismatch");
    }
    Ok(stored.token)
}

#[cfg(test)]
mod tests {
    #[test]
    fn continuations_are_private_bound_and_single_write() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("next.json");
        let input = serde_json::json!({"body":{"query":"Resources"}});
        super::save(
            &path,
            "azure.resource_graph.resources.post",
            &input,
            "token-1",
        )
        .unwrap();
        assert!(
            super::save(
                &path,
                "azure.resource_graph.resources.post",
                &input,
                "token-2"
            )
            .is_err()
        );
        assert_eq!(
            super::load(&path, "azure.resource_graph.resources.post", &input).unwrap(),
            "token-1"
        );
        assert!(super::load(&path, "other", &input).is_err());
        assert!(
            super::load(
                &path,
                "azure.resource_graph.resources.post",
                &serde_json::json!({})
            )
            .is_err()
        );
    }
}
