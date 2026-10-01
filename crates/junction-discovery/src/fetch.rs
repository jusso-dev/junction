//! Bounded retrieval from approved official GitHub repositories. Raw document
//! downloads are unauthenticated; an optional `GITHUB_TOKEN` is attached only to
//! read-only `api.github.com` metadata requests to avoid anonymous rate limits.
use crate::sources::{ApiSource, SourceType, validate_official_url, validate_source_path};
use anyhow::{Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::Duration;
use url::Url;

/// Safe download diagnostics: never retains URLs, response bodies or transport errors.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FetchFailureKind {
    Transport,
    Timeout,
    HttpStatus,
    ResponseRead,
    SizeLimit,
}
#[derive(Debug, Serialize)]
pub struct FetchFailure {
    pub kind: FetchFailureKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
}
impl FetchFailure {
    fn new(kind: FetchFailureKind) -> Self {
        Self {
            kind,
            http_status: None,
        }
    }
    fn transport(error: reqwest::Error, fallback: FetchFailureKind) -> Self {
        Self::new(if error.is_timeout() {
            FetchFailureKind::Timeout
        } else {
            fallback
        })
    }
}
impl std::fmt::Display for FetchFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("source download failed")
    }
}
impl std::error::Error for FetchFailure {}

#[derive(Debug, Serialize)]
pub struct FetchReceipt {
    pub source: String,
    pub upstream: String,
    pub revision: String,
    pub path: String,
    pub sha256: String,
    pub bytes: usize,
}
pub struct FetchedDocument {
    pub receipt: FetchReceipt,
    pub bytes: Vec<u8>,
}
#[derive(Debug, Serialize)]
pub struct DiscoveredDocument {
    pub path: String,
    pub blob_sha: String,
    pub bytes: u64,
    pub upstream: String,
}
#[derive(Debug, Serialize)]
pub struct SourceInventory {
    pub source: String,
    pub revision: String,
    pub tree_sha: String,
    pub documents: Vec<DiscoveredDocument>,
}

pub struct OfficialFetcher {
    client: reqwest::Client,
    max_bytes: usize,
    api_token: Option<reqwest::header::HeaderValue>,
}
impl OfficialFetcher {
    pub fn new(max_bytes: usize) -> Result<Self> {
        if max_bytes == 0 || max_bytes > 128 * 1024 * 1024 {
            bail!("invalid source download limit");
        }
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(60))
            .user_agent(concat!("junction/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| anyhow::anyhow!("source transport initialization failed"))?;
        let api_token = std::env::var("GITHUB_TOKEN")
            .ok()
            .filter(|token| {
                !token.is_empty()
                    && token.len() <= 1024
                    && token.bytes().all(|b| b.is_ascii_graphic())
            })
            .map(|token| {
                let mut value = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
                    .map_err(|_| anyhow::anyhow!("invalid GitHub API token"))?;
                value.set_sensitive(true);
                Ok::<_, anyhow::Error>(value)
            })
            .transpose()?;
        Ok(Self {
            client,
            max_bytes,
            api_token,
        })
    }
    /// Resolve latest default-branch commit when revision is absent, then download
    /// an immutable raw URL. No GitHub or Microsoft credentials are attached.
    pub async fn fetch(
        &self,
        source: &ApiSource,
        path: &str,
        revision: Option<&str>,
    ) -> Result<FetchedDocument> {
        let (owner, repository) = repository(source, path)?;
        let revision = self.resolve_revision(&owner, &repository, revision).await?;
        let url = raw_url(&owner, &repository, &revision, path)?;
        let bytes = self.download(url.clone(), self.max_bytes).await?;
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        Ok(FetchedDocument {
            receipt: FetchReceipt {
                source: source.id.clone(),
                upstream: url.to_string(),
                revision,
                path: path.into(),
                sha256,
                bytes: bytes.len(),
            },
            bytes,
        })
    }
    async fn resolve_revision(
        &self,
        owner: &str,
        repository: &str,
        revision: Option<&str>,
    ) -> Result<String> {
        Ok(match revision {
            Some(revision) => {
                validate_revision(revision)?;
                revision.to_ascii_lowercase()
            }
            None => {
                let mut url = Url::parse("https://api.github.com")?;
                url.path_segments_mut()
                    .map_err(|_| anyhow::anyhow!("invalid source API URL"))?
                    .extend(["repos", owner, repository, "commits"]);
                url.query_pairs_mut().append_pair("per_page", "1");
                let bytes = self.download(url, 1024 * 1024).await?;
                let commits: serde_json::Value = serde_json::from_slice(&bytes)
                    .map_err(|_| anyhow::anyhow!("invalid source revision response"))?;
                let revision = commits[0]["sha"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("source revision unavailable"))?;
                validate_revision(revision)?;
                revision.to_ascii_lowercase()
            }
        })
    }
    /// Enumerate candidate documents without downloading or interpreting their contents.
    /// Truncated recursive trees fall back to bounded scoped subtree traversal.
    pub async fn discover(
        &self,
        source: &ApiSource,
        revision: Option<&str>,
    ) -> Result<SourceInventory> {
        let (owner, repository) = repository_identity(source)?;
        let revision = self.resolve_revision(&owner, &repository, revision).await?;
        let mut url = Url::parse("https://api.github.com")?;
        url.path_segments_mut()
            .map_err(|_| anyhow::anyhow!("invalid source API URL"))?
            .extend(["repos", &owner, &repository, "git", "trees", &revision]);
        let root_url = url.clone();
        url.query_pairs_mut().append_pair("recursive", "1");
        let tree: serde_json::Value = match self.download(url, 8 * 1024 * 1024).await {
            Ok(bytes) => {
                let tree: serde_json::Value = serde_json::from_slice(&bytes)
                    .map_err(|_| anyhow::anyhow!("invalid source tree response"))?;
                if tree["truncated"].as_bool() != Some(true) {
                    return inventory(source, &owner, &repository, &revision, &bytes);
                }
                tree
            }
            // Very large repositories exceed the recursive response bound; fall
            // back to the same scoped subtree traversal used for truncated trees.
            Err(error)
                if error
                    .downcast_ref::<FetchFailure>()
                    .is_some_and(|failure| matches!(failure.kind, FetchFailureKind::SizeLimit)) =>
            {
                serde_json::from_slice(&self.download(root_url, 8 * 1024 * 1024).await?)
                    .map_err(|_| anyhow::anyhow!("invalid source tree response"))?
            }
            Err(error) => return Err(error),
        };
        let root_sha = tree["sha"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("source tree identifier unavailable"))?;
        let mut walker = TreeWalker::new(root_sha)?;
        let started = std::time::Instant::now();
        while let Some((prefix, sha, ancestors)) = walker.next()? {
            if started.elapsed() > Duration::from_secs(300) {
                bail!("source enumeration time limit exceeded");
            }
            let mut url = Url::parse("https://api.github.com")?;
            url.path_segments_mut()
                .map_err(|_| anyhow::anyhow!("invalid source API URL"))?
                .extend(["repos", &owner, &repository, "git", "trees", &sha]);
            if walker.is_recursive(&prefix) {
                url.query_pairs_mut().append_pair("recursive", "1");
            }
            let bytes = match self.download(url, 8 * 1024 * 1024).await {
                Ok(bytes) => bytes,
                Err(error)
                    if walker.is_recursive(&prefix)
                        && error.downcast_ref::<FetchFailure>().is_some_and(|failure| {
                            matches!(failure.kind, FetchFailureKind::SizeLimit)
                        }) =>
                {
                    walker.retry_level_by_level(&prefix, &sha)?;
                    continue;
                }
                Err(error) => return Err(error),
            };
            if started.elapsed() > Duration::from_secs(300) {
                bail!("source enumeration time limit exceeded");
            }
            walker.accept(source, &prefix, &sha, &ancestors, &bytes)?;
        }
        let bytes = walker.finish()?;
        inventory(source, &owner, &repository, &revision, &bytes)
    }
    async fn download(&self, url: Url, max_bytes: usize) -> Result<Vec<u8>> {
        let api = url.host_str() == Some("api.github.com");
        let mut request = self.client.get(url);
        if let (true, Some(token)) = (api, &self.api_token) {
            request = request.header(reqwest::header::AUTHORIZATION, token.clone());
        }
        let mut response = request
            .send()
            .await
            .map_err(|error| FetchFailure::transport(error, FetchFailureKind::Transport))?;
        if !response.status().is_success() {
            return Err(FetchFailure {
                kind: FetchFailureKind::HttpStatus,
                http_status: Some(response.status().as_u16()),
            }
            .into());
        }
        if response
            .content_length()
            .is_some_and(|len| len > max_bytes as u64)
        {
            return Err(FetchFailure::new(FetchFailureKind::SizeLimit).into());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| FetchFailure::transport(error, FetchFailureKind::ResponseRead))?
        {
            if bytes.len().saturating_add(chunk.len()) > max_bytes {
                return Err(FetchFailure::new(FetchFailureKind::SizeLimit).into());
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}
pub(crate) fn repository(source: &ApiSource, path: &str) -> Result<(String, String)> {
    let identity = repository_identity(source)?;
    validate_source_path(path)?;
    if !source.paths.iter().any(|allowed| {
        path == allowed
            || path
                .strip_prefix(allowed)
                .is_some_and(|suffix| suffix.starts_with('/'))
    }) {
        bail!("document path outside configured source scope");
    }
    let extensions: &[&str] = if matches!(source.source_type, SourceType::OData) {
        &["xml", "csdl"]
    } else {
        &["json", "yaml", "yml"]
    };
    if !extensions
        .iter()
        .any(|extension| path.ends_with(&format!(".{extension}")))
    {
        bail!("source path does not match the configured document format");
    }
    Ok(identity)
}
fn repository_identity(source: &ApiSource) -> Result<(String, String)> {
    source.validate()?;
    if !source.enabled {
        bail!("source is disabled");
    }
    if !matches!(source.source_type, SourceType::OpenApi | SourceType::OData) {
        bail!("source adapter not implemented");
    }
    let url = Url::parse(&source.upstream)?;
    if url.host_str() != Some("github.com") {
        bail!("fetch adapter requires an official GitHub repository URL");
    }
    let parts: Vec<_> = url
        .path_segments()
        .into_iter()
        .flatten()
        .filter(|p| !p.is_empty())
        .collect();
    if parts.len() != 2
        || !parts.iter().all(|part| {
            part.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        })
    {
        bail!("source must name a repository without a branch or subtree");
    }
    Ok((parts[0].into(), parts[1].into()))
}
type PendingTree = (String, String, Vec<String>);
struct TreeWalker {
    root_sha: String,
    pending: std::collections::VecDeque<PendingTree>,
    entries: Vec<serde_json::Value>,
    paths: std::collections::BTreeSet<String>,
    requests: usize,
    bytes: usize,
    entry_count: usize,
    active: Option<(String, String)>,
    active_ancestors: Option<Vec<String>>,
    /// Subtrees fully inside a configured scope are listed with one recursive
    /// request; a truncated response falls back to level-by-level traversal.
    recursive: std::collections::BTreeSet<String>,
}
impl TreeWalker {
    fn new(root_sha: &str) -> Result<Self> {
        validate_revision(root_sha)?;
        let root_sha = root_sha.to_ascii_lowercase();
        Ok(Self {
            root_sha: root_sha.clone(),
            pending: std::collections::VecDeque::from([(
                String::new(),
                root_sha.clone(),
                vec![root_sha],
            )]),
            entries: Vec::new(),
            paths: std::collections::BTreeSet::new(),
            requests: 0,
            bytes: 0,
            entry_count: 0,
            active: None,
            active_ancestors: None,
            recursive: std::collections::BTreeSet::new(),
        })
    }
    fn is_recursive(&self, prefix: &str) -> bool {
        self.recursive.contains(prefix)
    }
    /// Requeue the active recursive subtree for nonrecursive traversal.
    fn retry_level_by_level(&mut self, prefix: &str, sha: &str) -> Result<()> {
        if self
            .active
            .as_ref()
            .is_none_or(|(expected_prefix, expected_sha)| {
                expected_prefix != prefix || expected_sha != sha
            })
            || !self.recursive.remove(prefix)
        {
            bail!("unexpected source subtree response");
        }
        let ancestors = self
            .active_ancestors
            .take()
            .ok_or_else(|| anyhow::anyhow!("unexpected source subtree response"))?;
        self.active = None;
        self.pending
            .push_front((prefix.to_owned(), sha.to_owned(), ancestors));
        Ok(())
    }
    fn next(&mut self) -> Result<Option<PendingTree>> {
        if self.active.is_some() {
            bail!("source subtree response is pending");
        }
        if self.pending.is_empty() {
            return Ok(None);
        }
        if self.requests >= 1024 {
            bail!("source enumeration request limit exceeded");
        }
        self.requests += 1;
        let next = self.pending.pop_front();
        if let Some((prefix, sha, ancestors)) = &next {
            self.active = Some((prefix.clone(), sha.clone()));
            self.active_ancestors = Some(ancestors.clone());
        }
        Ok(next)
    }
    fn accept(
        &mut self,
        source: &ApiSource,
        prefix: &str,
        sha: &str,
        ancestors: &[String],
        bytes: &[u8],
    ) -> Result<()> {
        if self
            .active
            .as_ref()
            .is_none_or(|(expected_prefix, expected_sha)| {
                expected_prefix != prefix || expected_sha != sha
            })
        {
            bail!("unexpected source subtree response");
        }
        self.bytes = self.bytes.saturating_add(bytes.len());
        if bytes.len() > 8 * 1024 * 1024 || self.bytes > 128 * 1024 * 1024 {
            bail!("source enumeration byte limit exceeded");
        }
        let tree: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|_| anyhow::anyhow!("invalid source tree response"))?;
        let recursive = self.recursive.contains(prefix);
        if recursive && tree["truncated"].as_bool() == Some(true) {
            return self.retry_level_by_level(prefix, sha);
        }
        if tree["truncated"].as_bool() != Some(false) {
            bail!("source subtree completeness unavailable");
        }
        if !tree["sha"]
            .as_str()
            .is_some_and(|value| value.eq_ignore_ascii_case(sha))
        {
            bail!("source subtree identifier mismatch");
        }
        let entries = tree["tree"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("source tree entries unavailable"))?;
        self.entry_count = self.entry_count.saturating_add(entries.len());
        if self.entry_count > 200_000 {
            bail!("source enumeration entry limit exceeded");
        }
        for entry in entries {
            let name = entry["path"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("source tree path unavailable"))?;
            validate_source_path(name)?;
            if name.contains('/') && !recursive {
                bail!("nonrecursive source tree contains nested paths");
            }
            let path = if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}/{name}")
            };
            if path.len() > 4096 || path.split('/').count() > 64 {
                bail!("source enumeration path limit exceeded");
            }
            if !self.paths.insert(path.clone()) {
                bail!("duplicate source subtree path");
            }
            let mode = entry["mode"].as_str();
            match entry["type"].as_str() {
                // A recursive listing already includes every nested entry.
                Some("tree") if mode == Some("040000") && recursive => {}
                Some("tree") if mode == Some("040000") => {
                    let intersects = source.paths.iter().any(|scope| {
                        path == *scope
                            || path
                                .strip_prefix(scope)
                                .is_some_and(|suffix| suffix.starts_with('/'))
                            || scope
                                .strip_prefix(&path)
                                .is_some_and(|suffix| suffix.starts_with('/'))
                    });
                    if !intersects {
                        continue;
                    }
                    let child_sha = entry["sha"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("source subtree identifier unavailable"))?;
                    validate_revision(child_sha)?;
                    let child_sha = child_sha.to_ascii_lowercase();
                    if ancestors.contains(&child_sha) {
                        bail!("cyclic source subtree reference");
                    }
                    if self.pending.len() >= 1024 {
                        bail!("source enumeration queue limit exceeded");
                    }
                    let mut child_ancestors = ancestors.to_vec();
                    child_ancestors.push(child_sha.clone());
                    if source.paths.iter().any(|scope| {
                        path == *scope
                            || path
                                .strip_prefix(scope)
                                .is_some_and(|suffix| suffix.starts_with('/'))
                    }) {
                        self.recursive.insert(path.clone());
                    }
                    self.pending.push_back((path, child_sha, child_ancestors));
                }
                Some("blob") if matches!(mode, Some("100644" | "100755")) => {
                    let mut entry = entry.clone();
                    entry["path"] = serde_json::json!(path);
                    self.entries.push(entry);
                }
                Some("blob") if mode == Some("120000") => {}
                Some("commit") if mode == Some("160000") => {}
                _ => bail!("invalid source tree entry kind"),
            }
        }
        self.active = None;
        self.active_ancestors = None;
        Ok(())
    }
    fn finish(self) -> Result<Vec<u8>> {
        if self.active.is_some() || !self.pending.is_empty() {
            bail!("source enumeration is incomplete");
        }
        let bytes = serde_json::to_vec(
            &serde_json::json!({"sha":self.root_sha,"truncated":false,"tree":self.entries}),
        )?;
        if bytes.len() > 128 * 1024 * 1024 {
            bail!("source inventory exceeds size limit");
        }
        Ok(bytes)
    }
}

fn inventory(
    source: &ApiSource,
    owner: &str,
    repository_name: &str,
    revision: &str,
    bytes: &[u8],
) -> Result<SourceInventory> {
    if bytes.len() > 128 * 1024 * 1024 {
        bail!("source inventory exceeds size limit");
    }
    let tree: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("invalid source tree response"))?;
    match tree["truncated"].as_bool() {
        Some(false) => {}
        Some(true) => bail!("source tree is truncated; subtree enumeration is required"),
        None => bail!("source tree completeness unavailable"),
    }
    let tree_sha = tree["sha"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("source tree identifier unavailable"))?;
    validate_revision(tree_sha)?;
    let entries = tree["tree"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("source tree entries unavailable"))?;
    if entries.len() > 200_000 {
        bail!("source tree exceeds entry limit");
    }
    let mut documents = std::collections::BTreeMap::new();
    for entry in entries {
        if entry["type"].as_str() != Some("blob")
            || !matches!(entry["mode"].as_str(), Some("100644" | "100755"))
        {
            continue;
        }
        let path = entry["path"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("source tree path unavailable"))?;
        if !source.paths.iter().any(|allowed| {
            path == allowed
                || path
                    .strip_prefix(allowed)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        }) {
            continue;
        }
        let extensions: &[&str] = if matches!(source.source_type, SourceType::OData) {
            &["xml", "csdl"]
        } else {
            &["json", "yaml", "yml"]
        };
        if !extensions
            .iter()
            .any(|extension| path.ends_with(&format!(".{extension}")))
        {
            continue;
        }
        if path.len() > 4096 {
            bail!("source tree path exceeds limit");
        }
        repository(source, path)?;
        let sha = entry["sha"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("source blob identifier unavailable"))?;
        validate_revision(sha)?;
        let size = entry["size"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("source blob size unavailable"))?;
        let document = DiscoveredDocument {
            path: path.into(),
            blob_sha: sha.to_ascii_lowercase(),
            bytes: size,
            upstream: raw_url(owner, repository_name, revision, path)?.to_string(),
        };
        if documents.insert(path.to_owned(), document).is_some() {
            bail!("duplicate source tree document path");
        }
    }
    Ok(SourceInventory {
        source: source.id.clone(),
        revision: revision.into(),
        tree_sha: tree_sha.to_ascii_lowercase(),
        documents: documents.into_values().collect(),
    })
}

fn validate_revision(revision: &str) -> Result<()> {
    if revision.len() != 40 || !revision.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("revision must be a full Git commit identifier");
    }
    Ok(())
}
pub(crate) fn raw_url(owner: &str, repository: &str, revision: &str, path: &str) -> Result<Url> {
    validate_revision(revision)?;
    validate_source_path(path)?;
    let mut url = Url::parse("https://raw.githubusercontent.com")?;
    url.path_segments_mut()
        .map_err(|_| anyhow::anyhow!("invalid source URL"))?
        .extend([owner, repository, revision])
        .extend(path.split('/'));
    validate_official_url(url.as_str())?;
    Ok(url)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn source() -> ApiSource {
        serde_json::from_value(serde_json::json!({"id":"graph","product":"graph","source_type":"open_api","upstream":"https://github.com/microsoftgraph/msgraph-metadata","paths":["openapi/v1.0/openapi.yaml"],"authority":"microsoft","clouds":["public"],"enabled":true})).unwrap()
    }
    #[test]
    fn subtree_walk_is_scoped_complete_and_allows_shared_tree_objects() {
        let mut source = source();
        source.paths = vec![
            "specification/compute".into(),
            "specification/storage".into(),
        ];
        let root = "a".repeat(40);
        let specification = "b".repeat(40);
        let shared = "c".repeat(40);
        let blob = "d".repeat(40);
        let entry = |path: &str, sha: &str, mode: &str, kind: &str| serde_json::json!({"path":path,"sha":sha,"mode":mode,"type":kind,"size":5});
        let response = |sha: &str, entries: Vec<serde_json::Value>| {
            serde_json::to_vec(&serde_json::json!({"sha":sha,"truncated":false,"tree":entries}))
                .unwrap()
        };
        let mut walker = TreeWalker::new(&root).unwrap();
        while let Some((prefix, sha, ancestors)) = walker.next().unwrap() {
            let entries = match prefix.as_str() {
                "" => vec![
                    entry("specification", &specification, "040000", "tree"),
                    entry("outside", &shared, "040000", "tree"),
                ],
                "specification" => vec![
                    entry("compute", &shared, "040000", "tree"),
                    entry("storage", &shared, "040000", "tree"),
                    entry("compute-evil", &shared, "040000", "tree"),
                ],
                "specification/compute" | "specification/storage" => vec![
                    entry("api.json", &blob, "100644", "blob"),
                    entry("link.json", &blob, "120000", "blob"),
                ],
                _ => panic!("unexpected branch"),
            };
            walker
                .accept(&source, &prefix, &sha, &ancestors, &response(&sha, entries))
                .unwrap();
        }
        assert_eq!(walker.requests, 4);
        let inventory = inventory(
            &source,
            "microsoftgraph",
            "msgraph-metadata",
            &root,
            &walker.finish().unwrap(),
        )
        .unwrap();
        assert_eq!(
            inventory
                .documents
                .iter()
                .map(|document| document.path.as_str())
                .collect::<Vec<_>>(),
            [
                "specification/compute/api.json",
                "specification/storage/api.json"
            ]
        );
    }
    #[test]
    fn scoped_subtrees_list_recursively_and_fall_back_when_truncated() {
        let mut source = source();
        source.paths = vec!["specification/security".into()];
        let root = "a".repeat(40);
        let specification = "b".repeat(40);
        let security = "c".repeat(40);
        let stable = "e".repeat(40);
        let blob = "d".repeat(40);
        let entry = |path: &str, sha: &str, mode: &str, kind: &str| serde_json::json!({"path":path,"sha":sha,"mode":mode,"type":kind,"size":5});
        let response = |sha: &str, truncated: bool, entries: Vec<serde_json::Value>| {
            serde_json::to_vec(&serde_json::json!({"sha":sha,"truncated":truncated,"tree":entries}))
                .unwrap()
        };
        for truncate_first in [false, true] {
            let mut walker = TreeWalker::new(&root).unwrap();
            let mut truncated_once = false;
            while let Some((prefix, sha, ancestors)) = walker.next().unwrap() {
                let recursive = walker.is_recursive(&prefix);
                let body = match (prefix.as_str(), recursive) {
                    ("", false) => response(
                        &sha,
                        false,
                        vec![entry("specification", &specification, "040000", "tree")],
                    ),
                    ("specification", false) => response(
                        &sha,
                        false,
                        vec![
                            entry("security", &security, "040000", "tree"),
                            entry("storage", &security, "040000", "tree"),
                        ],
                    ),
                    ("specification/security", true) if truncate_first && !truncated_once => {
                        truncated_once = true;
                        response(&sha, true, vec![])
                    }
                    ("specification/security", true) => response(
                        &sha,
                        false,
                        vec![
                            entry("stable", &stable, "040000", "tree"),
                            entry("stable/alerts.json", &blob, "100644", "blob"),
                            entry("stable/examples/a.json", &blob, "100644", "blob"),
                        ],
                    ),
                    ("specification/security", false) => response(
                        &sha,
                        false,
                        vec![entry("stable", &stable, "040000", "tree")],
                    ),
                    ("specification/security/stable", true) => response(
                        &sha,
                        false,
                        vec![
                            entry("alerts.json", &blob, "100644", "blob"),
                            entry("examples/a.json", &blob, "100644", "blob"),
                        ],
                    ),
                    other => panic!("unexpected request {other:?}"),
                };
                walker
                    .accept(&source, &prefix, &sha, &ancestors, &body)
                    .unwrap();
            }
            assert_eq!(walker.requests, if truncate_first { 5 } else { 3 });
            let inventory = inventory(
                &source,
                "Azure",
                "azure-rest-api-specs",
                &root,
                &walker.finish().unwrap(),
            )
            .unwrap();
            assert_eq!(
                inventory
                    .documents
                    .iter()
                    .map(|d| d.path.as_str())
                    .collect::<Vec<_>>(),
                [
                    "specification/security/stable/alerts.json",
                    "specification/security/stable/examples/a.json"
                ]
            );
        }
        // Nested paths are still rejected outside recursive scoped listings.
        let mut walker = TreeWalker::new(&root).unwrap();
        let (prefix, sha, ancestors) = walker.next().unwrap().unwrap();
        assert!(
            walker
                .accept(
                    &source,
                    &prefix,
                    &sha,
                    &ancestors,
                    &response(
                        &sha,
                        false,
                        vec![entry(
                            "specification/security/x.json",
                            &blob,
                            "100644",
                            "blob"
                        )]
                    )
                )
                .is_err()
        );
    }
    #[test]
    fn subtree_walk_rejects_incomplete_mismatched_cyclic_and_over_budget_responses() {
        let mut source = source();
        source.paths = vec!["openapi".into()];
        let root = "a".repeat(40);
        let entry = serde_json::json!({"path":"openapi","sha":root,"mode":"040000","type":"tree"});
        let tree = serde_json::json!({"sha":root,"truncated":false,"tree":[entry]});
        for document in [
            tree.clone(),
            {
                let mut value = tree.clone();
                value["truncated"] = serde_json::json!(true);
                value
            },
            {
                let mut value = tree.clone();
                value["sha"] = serde_json::json!("b".repeat(40));
                value
            },
            {
                let mut value = tree.clone();
                value["tree"][0]["path"] = serde_json::json!("private-secret/../bad");
                value
            },
        ] {
            let mut walker = TreeWalker::new(&root).unwrap();
            let (prefix, sha, ancestors) = walker.next().unwrap().unwrap();
            let error = walker
                .accept(
                    &source,
                    &prefix,
                    &sha,
                    &ancestors,
                    &serde_json::to_vec(&document).unwrap(),
                )
                .unwrap_err()
                .to_string();
            assert!(!error.contains("private-secret"));
            assert!(walker.finish().is_err());
        }
        let mut walker = TreeWalker::new(&root).unwrap();
        walker.requests = 1024;
        assert!(walker.next().is_err());
        let mut walker = TreeWalker::new(&root).unwrap();
        walker.next().unwrap();
        assert!(walker.next().is_err());
        assert!(walker.finish().is_err());
        let mut walker = TreeWalker::new(&root).unwrap();
        let (prefix, sha, ancestors) = walker.next().unwrap().unwrap();
        walker.bytes = 128 * 1024 * 1024;
        assert!(
            walker
                .accept(&source, &prefix, &sha, &ancestors, b"x")
                .is_err()
        );
    }

    #[test]
    fn source_inventory_is_sorted_scoped_pinned_and_excludes_links() {
        let mut source = source();
        source.paths = vec!["openapi".into()];
        let sha = "a".repeat(40);
        let entry = |path: &str, mode: &str, kind: &str| serde_json::json!({"path":path,"mode":mode,"type":kind,"sha":sha,"size":123,"url":"https://private-secret.invalid"});
        let tree = serde_json::json!({"sha":sha,"truncated":false,"tree":[entry("openapi/z.yaml","100644","blob"),entry("openapi/a.json","100755","blob"),entry("openapi/link.yaml","120000","blob"),entry("openapi/module.json","160000","commit"),entry("openapi/dir.json","040000","tree"),entry("openapi/a.txt","100644","blob"),entry("openapi-evil/spec.yaml","100644","blob"),entry("outside/spec.yaml","100644","blob")]});
        let result = inventory(
            &source,
            "microsoftgraph",
            "msgraph-metadata",
            &sha,
            &serde_json::to_vec(&tree).unwrap(),
        )
        .unwrap();
        assert_eq!(
            result
                .documents
                .iter()
                .map(|d| d.path.as_str())
                .collect::<Vec<_>>(),
            ["openapi/a.json", "openapi/z.yaml"]
        );
        assert_eq!(result.revision, sha);
        assert_eq!(result.documents[0].blob_sha, sha);
        assert!(
            result.documents[0]
                .upstream
                .contains(&format!("/{sha}/openapi/a.json"))
        );
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("private-secret")
        );
        for mutated in [
            {
                let mut tree = tree.clone();
                tree["truncated"] = serde_json::json!(true);
                tree
            },
            {
                let mut tree = tree.clone();
                tree["truncated"] = serde_json::Value::Null;
                tree
            },
            {
                let mut tree = tree.clone();
                tree["tree"][0]["sha"] = serde_json::json!("private-secret");
                tree
            },
            {
                let mut tree = tree.clone();
                tree["tree"][0]["path"] = serde_json::json!("openapi/../private-secret.yaml");
                tree
            },
            {
                let mut tree = tree.clone();
                tree["tree"][0]["size"] = serde_json::json!(-1);
                tree
            },
            {
                let mut tree = tree.clone();
                tree["tree"][0] = tree["tree"][1].clone();
                tree
            },
        ] {
            let error = inventory(
                &source,
                "microsoftgraph",
                "msgraph-metadata",
                &sha,
                &serde_json::to_vec(&mutated).unwrap(),
            )
            .unwrap_err()
            .to_string();
            assert!(!error.contains("private-secret"));
        }
        source.source_type = SourceType::OData;
        let tree = serde_json::json!({"sha":sha,"truncated":false,"tree":[entry("openapi/schema.xml","100644","blob"),entry("openapi/schema.csdl","100644","blob"),entry("openapi/spec.yaml","100644","blob")]});
        let result = inventory(
            &source,
            "microsoftgraph",
            "msgraph-metadata",
            &sha,
            &serde_json::to_vec(&tree).unwrap(),
        )
        .unwrap();
        assert_eq!(result.documents.len(), 2);
    }

    #[test]
    fn source_scope_and_immutable_urls_are_enforced() {
        let source = source();
        assert!(repository(&source, "openapi/v1.0/openapi.yaml").is_ok());
        for path in [
            "openapi/beta/openapi.yaml",
            "openapi/v1.0/openapi.yaml-evil",
            "../openapi.yaml",
            "openapi/%2e%2e/openapi.yaml",
            "https://evil.example/spec.json",
        ] {
            assert!(repository(&source, path).is_err());
        }
        let revision = "a".repeat(40);
        let url = raw_url(
            "microsoftgraph",
            "msgraph-metadata",
            &revision,
            "openapi/v1.0/openapi.yaml",
        )
        .unwrap();
        assert_eq!(
            url.as_str(),
            format!(
                "https://raw.githubusercontent.com/microsoftgraph/msgraph-metadata/{revision}/openapi/v1.0/openapi.yaml"
            )
        );
        assert!(raw_url("attacker", "repo", &revision, "spec.json").is_err());
        assert!(validate_revision("main").is_err());
        let mut disabled = source;
        disabled.enabled = false;
        assert!(repository(&disabled, "openapi/v1.0/openapi.yaml").is_err());
    }
    #[test]
    fn odata_sources_keep_official_scope_and_format_guards() {
        let mut source = source();
        source.source_type = SourceType::OData;
        source.paths = vec!["schemas/v1.0-USNat.csdl".into()];
        assert!(repository(&source, "schemas/v1.0-USNat.csdl").is_ok());
        assert!(repository(&source, "schemas/beta-USNat.csdl").is_err());
        source.paths = vec!["schemas".into()];
        assert!(repository(&source, "schemas/spec.yaml").is_err());
        source.source_type = SourceType::OpenApi;
        assert!(repository(&source, "schemas/v1.0-USNat.csdl").is_err());
    }
}

#[cfg(test)]
mod transport_tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    async fn server(response: &str) -> (Url, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!(
            "http://{}/spec.yaml",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let response = response.to_owned();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            loop {
                let mut buffer = [0; 1024];
                let n = stream.read(&mut buffer).await.unwrap();
                assert_ne!(n, 0);
                bytes.extend_from_slice(&buffer[..n]);
                if bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = stream.write_all(response.as_bytes()).await;
            String::from_utf8(bytes).unwrap()
        });
        (url, task)
    }
    fn fetcher() -> OfficialFetcher {
        // HTTP is permitted only by this private local mock client.
        OfficialFetcher {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap(),
            max_bytes: 1024,
            // A configured API token must never reach non-API hosts.
            api_token: Some(reqwest::header::HeaderValue::from_static(
                "Bearer private-api-token",
            )),
        }
    }
    #[tokio::test]
    async fn bounded_download_does_not_attach_credentials_or_echo_errors() {
        let (url, task) =
            server("HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc").await;
        assert_eq!(fetcher().download(url, 10).await.unwrap(), b"abc");
        assert!(
            !task
                .await
                .unwrap()
                .to_ascii_lowercase()
                .contains("authorization:")
        );
        for (response, expected) in [
            (
                "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/leak\r\nContent-Length: 0\r\n\r\n",
                serde_json::json!({"kind":"http_status","http_status":302}),
            ),
            (
                "HTTP/1.1 403 Forbidden\r\nContent-Length: 11\r\n\r\nsecret-echo",
                serde_json::json!({"kind":"http_status","http_status":403}),
            ),
            (
                "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n",
                serde_json::json!({"kind":"size_limit"}),
            ),
            (
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nB\r\nsecret-echo\r\n0\r\n\r\n",
                serde_json::json!({"kind":"size_limit"}),
            ),
        ] {
            let (url, task) = server(response).await;
            let error = fetcher().download(url, 10).await.unwrap_err();
            assert_eq!(
                serde_json::to_value(error.downcast_ref::<FetchFailure>().unwrap()).unwrap(),
                expected
            );
            assert!(!error.to_string().contains("secret-echo"));
            task.await.unwrap();
        }
    }
}

#[cfg(test)]
mod failure_tests {
    use super::*;
    #[test]
    fn safe_download_diagnostics_survive_refresh_context() {
        let failure = FetchFailure {
            kind: FetchFailureKind::HttpStatus,
            http_status: Some(403),
        };
        let error = anyhow::Error::new(failure).context(crate::refresh::RefreshFailure {
            stage: crate::refresh::RefreshStage::Inventory,
        });
        let diagnostic = error.downcast_ref::<FetchFailure>().unwrap();
        assert_eq!(
            serde_json::to_value(diagnostic).unwrap(),
            serde_json::json!({"kind":"http_status", "http_status":403})
        );
        assert!(
            error
                .downcast_ref::<crate::refresh::RefreshFailure>()
                .is_some()
        );
        assert_eq!(diagnostic.to_string(), "source download failed");
        assert!(std::error::Error::source(diagnostic).is_none());
    }
}
