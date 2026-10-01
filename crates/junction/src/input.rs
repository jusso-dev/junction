use anyhow::{Result, bail};
use std::{io::Read, path::Path};
const LIMIT: usize = 16 * 1024 * 1024;

pub fn load(inline: Option<&str>, path: Option<&Path>) -> Result<String> {
    match (inline, path) {
        (Some(_), Some(_)) => bail!("select exactly one JSON input source"),
        (Some(value), None) if value.len() <= LIMIT => Ok(value.to_owned()),
        (Some(_), None) => bail!("input size limit exceeded"),
        (None, None) => Ok("{}".into()),
        (None, Some(path)) if path == Path::new("-") => bounded(std::io::stdin().lock()),
        (None, Some(path)) => {
            let metadata = std::fs::metadata(path)
                .map_err(|_| anyhow::anyhow!("JSON input file unavailable"))?;
            if !metadata.is_file() {
                bail!("JSON input must be a regular file");
            }
            if metadata.len() > LIMIT as u64 {
                bail!("input size limit exceeded");
            }
            let file = std::fs::File::open(path)
                .map_err(|_| anyhow::anyhow!("JSON input file unavailable"))?;
            bounded(file)
        }
    }
}
fn bounded(reader: impl Read) -> Result<String> {
    let mut bytes = Vec::new();
    reader
        .take(LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("JSON input read failed"))?;
    if bytes.len() > LIMIT {
        bail!("input size limit exceeded");
    }
    String::from_utf8(bytes).map_err(|_| anyhow::anyhow!("JSON input must be UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn input_sources_are_bounded_and_errors_do_not_echo_data() {
        assert_eq!(load(None, None).unwrap(), "{}");
        assert!(load(Some("private-value"), Some(Path::new("private-path"))).is_err());
        assert_eq!(bounded("{}".as_bytes()).unwrap(), "{}");
        assert_eq!(
            bounded(&[255][..]).unwrap_err().to_string(),
            "JSON input must be UTF-8"
        );
        let bytes = vec![b'x'; LIMIT + 1];
        assert_eq!(
            bounded(bytes.as_slice()).unwrap_err().to_string(),
            "input size limit exceeded"
        );
        let directory = tempfile::tempdir().unwrap();
        assert!(load(None, Some(directory.path())).is_err());
        let file = directory.path().join("input.json");
        std::fs::write(&file, b"{}").unwrap();
        assert_eq!(load(None, Some(&file)).unwrap(), "{}");
    }
}
