use anyhow::{Result, bail};
use junction_runtime::pagination::Continuation;
use std::{collections::BTreeSet, sync::Mutex};
const LIMIT: usize = 64;

/// Session-local private files; agents see only random identifiers, never paths or URLs.
pub struct Store {
    directory: tempfile::TempDir,
    handles: Mutex<BTreeSet<String>>,
}
pub struct Prepared {
    previous: Option<String>,
    next: String,
    pub continuation: Option<Continuation>,
}
impl Store {
    /// Validate delivery size before consuming an existing continuation.
    pub fn finish_page(
        &self,
        prepared: Prepared,
        result: junction_runtime::pagination::PageResult,
    ) -> Result<serde_json::Value> {
        let payload = serde_json::json!({"items":result.items,"pages":result.pages,
            "continuation":result.continuation.as_ref().map(|_| prepared.next.as_str())});
        if !junction_mcp::tool_result_fits(&payload)? {
            return Err(junction_mcp::ResponseTooLarge.into());
        }
        self.finish(prepared, result.continuation)?;
        Ok(payload)
    }
    pub fn new() -> Result<Self> {
        Ok(Self {
            directory: tempfile::tempdir()?,
            handles: Mutex::new(BTreeSet::new()),
        })
    }
    pub fn prepare(&self, previous: Option<&str>) -> Result<Prepared> {
        let handles = self
            .handles
            .lock()
            .map_err(|_| anyhow::anyhow!("continuation store unavailable"))?;
        let continuation = if let Some(id) = previous {
            if id.len() != 64
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || !handles.contains(id)
            {
                bail!("unknown continuation handle");
            }
            Some(Continuation::load(&self.directory.path().join(id))?)
        } else {
            if handles.len() >= LIMIT {
                bail!("continuation store limit exceeded");
            }
            None
        };
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|_| anyhow::anyhow!("continuation entropy unavailable"))?;
        let next: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        if handles.contains(&next) {
            bail!("continuation identifier collision");
        }
        Ok(Prepared {
            previous: previous.map(str::to_owned),
            next,
            continuation,
        })
    }
    /// Keep the previous checkpoint until the replacement has been safely written.
    pub fn finish(
        &self,
        prepared: Prepared,
        continuation: Option<Continuation>,
    ) -> Result<Option<String>> {
        let mut handles = self
            .handles
            .lock()
            .map_err(|_| anyhow::anyhow!("continuation store unavailable"))?;
        if let Some(previous) = &prepared.previous {
            if !handles.contains(previous) {
                bail!("continuation already consumed");
            }
        } else if handles.len() >= LIMIT {
            bail!("continuation store limit exceeded");
        }
        let next = if let Some(continuation) = continuation {
            continuation.save(&self.directory.path().join(&prepared.next))?;
            handles.insert(prepared.next.clone());
            Some(prepared.next)
        } else {
            None
        };
        if let Some(previous) = prepared.previous {
            handles.remove(&previous);
            let _ = std::fs::remove_file(self.directory.path().join(previous));
        }
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn continuation() -> Continuation {
        let url = url::Url::parse("https://example.invalid/users?private=secret").unwrap();
        let mut pages = junction_runtime::pagination::PageAccumulator::new(
            url.clone(),
            1,
            1,
            &Default::default(),
        )
        .unwrap();
        pages.begin_page(&url).unwrap();
        pages
            .accept(&json!({"value":[1,2],"nextLink":"?private=next-secret"}))
            .unwrap()
            .1
            .unwrap()
            .continuation
            .unwrap()
    }
    #[test]
    fn private_handles_rotate_preserve_failed_resumes_and_bound_storage() {
        let store = Store::new().unwrap();
        let prepared = store.prepare(None).unwrap();
        let id = store
            .finish(prepared, Some(continuation()))
            .unwrap()
            .unwrap();
        assert_eq!(id.len(), 64);
        assert!(!id.contains("secret"));
        assert_eq!(
            store
                .prepare(Some(&id))
                .unwrap()
                .continuation
                .unwrap()
                .buffered_items(),
            1
        );
        let failed_resume = store.prepare(Some(&id)).unwrap();
        drop(failed_resume);
        let prepared = store.prepare(Some(&id)).unwrap();
        let next = store
            .finish(prepared, Some(continuation()))
            .unwrap()
            .unwrap();
        assert_ne!(id, next);
        assert!(store.prepare(Some(&id)).is_err());
        let prepared = store.prepare(Some(&next)).unwrap();
        assert!(store.finish(prepared, None).unwrap().is_none());
        assert!(store.prepare(Some(&next)).is_err());
        assert!(store.prepare(Some("../private-file")).is_err());
        for _ in 0..LIMIT {
            store
                .finish(store.prepare(None).unwrap(), Some(continuation()))
                .unwrap();
        }
        assert!(store.prepare(None).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for entry in std::fs::read_dir(store.directory.path()).unwrap() {
                assert_eq!(
                    entry.unwrap().metadata().unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
    }
    #[test]
    fn oversized_delivery_preserves_previous_handle_for_a_smaller_retry() {
        let store = Store::new().unwrap();
        let id = store
            .finish(store.prepare(None).unwrap(), Some(continuation()))
            .unwrap()
            .unwrap();
        let result = junction_runtime::pagination::PageResult {
            items: vec![json!({"private":"x".repeat(9*1024*1024)})],
            pages: 1,
            continuation: None,
        };
        let error = store
            .finish_page(store.prepare(Some(&id)).unwrap(), result)
            .unwrap_err();
        assert!(
            error
                .downcast_ref::<junction_mcp::ResponseTooLarge>()
                .is_some()
        );
        assert_eq!(
            store
                .prepare(Some(&id))
                .unwrap()
                .continuation
                .unwrap()
                .buffered_items(),
            1
        );
        let result = junction_runtime::pagination::PageResult {
            items: vec![json!(2)],
            pages: 0,
            continuation: None,
        };
        let payload = store
            .finish_page(store.prepare(Some(&id)).unwrap(), result)
            .unwrap();
        assert_eq!(payload["items"], json!([2]));
        assert_eq!(payload["continuation"], serde_json::Value::Null);
        assert!(store.prepare(Some(&id)).is_err());
        assert!(store.handles.lock().unwrap().is_empty());
    }
}
