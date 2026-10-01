//! Discover, fetch, import and combine an official source without partial publication.
use crate::{
    fetch::{FetchedDocument, OfficialFetcher, SourceInventory},
    sources::{ApiSource, SourceType},
};
use anyhow::{Result, bail};
use junction_core::RegistryManifest;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshStage {
    Configuration,
    Inventory,
    Download,
    DocumentValidation,
    DependencyResolution,
    Normalization,
    Deadline,
}
#[derive(Debug)]
pub struct RefreshFailure {
    pub stage: RefreshStage,
}
impl std::fmt::Display for RefreshFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self.stage {
            RefreshStage::Deadline => "source refresh deadline exceeded",
            _ => "source refresh failed",
        })
    }
}
impl std::error::Error for RefreshFailure {}
fn stage<T>(result: Result<T>, stage: RefreshStage) -> Result<T> {
    result.map_err(|error| error.context(RefreshFailure { stage }))
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshLimit {
    Documents,
    Bytes,
}
#[derive(Debug, serde::Serialize)]
pub struct RefreshLimitExceeded {
    pub limit: RefreshLimit,
}
impl std::fmt::Display for RefreshLimitExceeded {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("source refresh limit exceeded")
    }
}
impl std::error::Error for RefreshLimitExceeded {}
fn limit_error(limit: RefreshLimit) -> anyhow::Error {
    anyhow::Error::new(RefreshLimitExceeded { limit })
}

pub struct RefreshOptions {
    pub service: Option<String>,
    pub endpoint: Option<String>,
    pub api_version: Option<String>,
    pub max_documents: usize,
    pub max_bytes: usize,
    pub timeout_seconds: u64,
}
impl Default for RefreshOptions {
    fn default() -> Self {
        Self {
            service: None,
            endpoint: None,
            api_version: None,
            max_documents: 256,
            max_bytes: 512 * 1024 * 1024,
            timeout_seconds: 900,
        }
    }
}
impl RefreshOptions {
    fn validate(&self, source: &ApiSource) -> Result<()> {
        source.validate()?;
        if !source.enabled {
            bail!("source is disabled");
        }
        if !(1..=4096).contains(&self.max_documents)
            || self.max_bytes == 0
            || self.max_bytes > 512 * 1024 * 1024
            || !(1..=3600).contains(&self.timeout_seconds)
        {
            bail!("invalid refresh limits");
        }
        if let Some(service) = &self.service
            && (service.is_empty() || junction_core::canonical_component(service) != *service)
        {
            bail!("invalid refresh service name");
        }
        match source.source_type {
            SourceType::OpenApi if self.endpoint.is_none() && self.api_version.is_none() => {}
            SourceType::OData if self.endpoint.is_some() && self.api_version.is_some() => {
                crate::odata::validate_endpoint(
                    self.endpoint.as_deref().unwrap(),
                    self.api_version.as_deref().unwrap(),
                )?;
            }
            SourceType::OpenApi | SourceType::OData => bail!(
                "OData refresh requires endpoint and API version; OpenAPI refresh forbids them"
            ),
            _ => bail!("source refresh adapter not implemented"),
        }
        Ok(())
    }
}
impl OfficialFetcher {
    pub async fn refresh(
        &self,
        source: &ApiSource,
        revision: Option<&str>,
        options: RefreshOptions,
    ) -> Result<RegistryManifest> {
        self.refresh_scoped(source, &[], revision, options).await
    }
    /// Narrow API discovery while allowing referenced dependencies inside the
    /// original configured source scope. All downloads use one pinned revision.
    pub async fn refresh_scoped(
        &self,
        source: &ApiSource,
        paths: &[String],
        revision: Option<&str>,
        options: RefreshOptions,
    ) -> Result<RegistryManifest> {
        stage(options.validate(source), RefreshStage::Configuration)?;
        let duration = std::time::Duration::from_secs(options.timeout_seconds);
        bounded_refresh(
            duration,
            self.refresh_scoped_inner(source, paths, revision, options),
        )
        .await
    }
    async fn refresh_scoped_inner(
        &self,
        source: &ApiSource,
        paths: &[String],
        revision: Option<&str>,
        options: RefreshOptions,
    ) -> Result<RegistryManifest> {
        let selected = stage(source.scoped(paths), RefreshStage::Configuration)?;
        let inventory = stage(
            self.discover(&selected, revision).await,
            RefreshStage::Inventory,
        )?;
        let mut refresh = stage(
            Refresh::new(source, inventory, options),
            RefreshStage::Inventory,
        )?;
        for index in 0..refresh.inventory.documents.len() {
            let document = &refresh.inventory.documents[index];
            let fetched = stage(
                self.fetch(source, &document.path, Some(&refresh.inventory.revision))
                    .await,
                RefreshStage::Download,
            )?;
            stage(refresh.accept(fetched), RefreshStage::DocumentValidation)?;
        }
        if matches!(source.source_type, SourceType::OpenApi) {
            loop {
                let mut missing = std::collections::BTreeSet::new();
                for (path, _, _) in &refresh.entries {
                    missing.extend(stage(
                        crate::bundle::missing_documents(path, &refresh.documents),
                        RefreshStage::DependencyResolution,
                    )?);
                }
                if missing.is_empty() {
                    break;
                }
                if refresh.documents.len().saturating_add(missing.len())
                    > refresh.options.max_documents
                {
                    return stage(
                        Err(limit_error(RefreshLimit::Documents)),
                        RefreshStage::DependencyResolution,
                    );
                }
                let mut resolved = Vec::new();
                for path in missing {
                    let canonical = match crate::fetch::repository(source, &path) {
                        Ok(_) => path.clone(),
                        Err(error) => stage(
                            case_folded_scope_path(source, &path).ok_or(error),
                            RefreshStage::DependencyResolution,
                        )?,
                    };
                    resolved.push((path, canonical));
                }
                for (path, canonical) in resolved {
                    if !refresh.documents.contains_key(&canonical) {
                        let fetched = stage(
                            self.fetch(source, &canonical, Some(&refresh.inventory.revision))
                                .await,
                            RefreshStage::Download,
                        )?;
                        stage(
                            refresh.accept_dependency(fetched),
                            RefreshStage::DocumentValidation,
                        )?;
                    }
                    if path != canonical {
                        stage(
                            refresh.alias_dependency(&path, &canonical),
                            RefreshStage::DependencyResolution,
                        )?;
                    }
                }
            }
        }
        stage(refresh.finish(), RefreshStage::Normalization)
    }
}
/// Some official definitions reference shared directories with the wrong
/// letter case (for example Fabric's `../../Common/definitions.json` for the
/// `common` directory), which only resolves on case-insensitive filesystems.
/// Map such a path onto exactly one configured scope, preserving the remainder.
fn case_folded_scope_path(source: &ApiSource, path: &str) -> Option<String> {
    let mut matches = source.paths.iter().filter_map(|scope| {
        let prefix = path.get(..scope.len())?;
        let rest = path.get(scope.len()..)?;
        (prefix != scope && prefix.eq_ignore_ascii_case(scope) && rest.starts_with('/'))
            .then(|| format!("{scope}{rest}"))
    });
    let candidate = matches.next()?;
    if matches.next().is_some() || crate::fetch::repository(source, &candidate).is_err() {
        return None;
    }
    Some(candidate)
}
async fn bounded_refresh<T>(
    duration: std::time::Duration,
    work: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    let started = std::time::Instant::now();
    let result = tokio::time::timeout(duration, work).await.map_err(|_| {
        anyhow::Error::new(RefreshFailure {
            stage: RefreshStage::Deadline,
        })
    })?;
    // Synchronous import/bundling work may complete inside one future poll.
    // Reject late completion too, so it cannot publish a timed-out registry.
    if started.elapsed() > duration {
        return Err(anyhow::Error::new(RefreshFailure {
            stage: RefreshStage::Deadline,
        }));
    }
    result
}
struct Refresh<'a> {
    source: &'a ApiSource,
    inventory: SourceInventory,
    options: RefreshOptions,
    manifests: Vec<RegistryManifest>,
    documents: BTreeMap<String, serde_json::Value>,
    entries: Vec<(String, String, String)>,
    receipts: Vec<serde_json::Value>,
    bytes: usize,
    dependencies: Vec<serde_json::Value>,
}
impl<'a> Refresh<'a> {
    fn new(
        source: &'a ApiSource,
        inventory: SourceInventory,
        options: RefreshOptions,
    ) -> Result<Self> {
        options.validate(source)?;
        if inventory.source != source.id || inventory.documents.is_empty() {
            bail!("refresh inventory has no matching source documents");
        }
        if inventory.documents.len() > options.max_documents {
            return Err(limit_error(RefreshLimit::Documents));
        }
        let mut total = 0u64;
        for document in &inventory.documents {
            total = total
                .checked_add(document.bytes)
                .ok_or_else(|| limit_error(RefreshLimit::Bytes))?;
            if document.bytes > 128 * 1024 * 1024 || total > options.max_bytes as u64 {
                return Err(limit_error(RefreshLimit::Bytes));
            }
        }
        Ok(Self {
            source,
            inventory,
            options,
            manifests: Vec::new(),
            documents: BTreeMap::new(),
            entries: Vec::new(),
            receipts: Vec::new(),
            bytes: 0,
            dependencies: Vec::new(),
        })
    }
    fn accept(&mut self, fetched: FetchedDocument) -> Result<()> {
        let expected = self
            .inventory
            .documents
            .get(self.receipts.len())
            .ok_or_else(|| anyhow::anyhow!("unexpected refresh document"))?;
        let receipt = &fetched.receipt;
        if receipt.source != self.source.id
            || receipt.path != expected.path
            || receipt.revision != self.inventory.revision
            || receipt.upstream != expected.upstream
            || receipt.bytes != fetched.bytes.len()
            || receipt.bytes as u64 != expected.bytes
            || receipt.sha256 != format!("{:x}", Sha256::digest(&fetched.bytes))
        {
            bail!("refresh document receipt mismatch");
        }
        self.bytes = self
            .bytes
            .checked_add(fetched.bytes.len())
            .ok_or_else(|| limit_error(RefreshLimit::Bytes))?;
        if self.bytes > self.options.max_bytes {
            return Err(limit_error(RefreshLimit::Bytes));
        }
        let service = self.options.service.clone().unwrap_or_else(|| {
            let mut segments = receipt.path.split('/');
            if segments.next() == Some("specification") {
                segments
                    .next()
                    .map(junction_core::canonical_component)
                    .filter(|name| !name.is_empty())
                    .unwrap_or_else(|| junction_core::canonical_component(&self.source.product))
            } else {
                junction_core::canonical_component(&self.source.product)
            }
        });
        let manifest = match self.source.source_type {
            SourceType::OpenApi => {
                let document = crate::parse_document(&fetched.bytes)?;
                let is_api = document.get("openapi").is_some() || document.get("swagger").is_some();
                if self
                    .documents
                    .insert(receipt.path.clone(), document)
                    .is_some()
                {
                    bail!("duplicate refresh document");
                }
                if is_api {
                    self.entries
                        .push((receipt.path.clone(), service, receipt.upstream.clone()));
                }
                self.receipts.push(json!({"receipt":receipt,"status":if is_api { "imported" } else { "not_api_specification" }}));
                return Ok(());
            }
            SourceType::OData => crate::odata::ingest(
                &fetched.bytes,
                &self.source.product,
                &service,
                &receipt.upstream,
                self.options
                    .endpoint
                    .as_deref()
                    .expect("validated endpoint"),
                self.options
                    .api_version
                    .as_deref()
                    .expect("validated version"),
            )?,
            _ => bail!("source refresh adapter not implemented"),
        };
        self.manifests.push(manifest);
        self.receipts
            .push(json!({"receipt":receipt,"status":"imported"}));
        Ok(())
    }
    /// Make a case-variant reference resolve to an already retained document.
    fn alias_dependency(&mut self, alias: &str, canonical: &str) -> Result<()> {
        crate::sources::validate_source_path(alias)?;
        if self.documents.contains_key(alias) || self.documents.len() >= self.options.max_documents
        {
            bail!("invalid refresh dependency alias");
        }
        let document = self
            .documents
            .get(canonical)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("invalid refresh dependency alias"))?;
        self.documents.insert(alias.into(), document);
        Ok(())
    }
    fn accept_dependency(&mut self, fetched: FetchedDocument) -> Result<()> {
        let receipt = &fetched.receipt;
        let (owner, repository) = crate::fetch::repository(self.source, &receipt.path)?;
        let upstream =
            crate::fetch::raw_url(&owner, &repository, &self.inventory.revision, &receipt.path)?;
        if receipt.source != self.source.id
            || receipt.revision != self.inventory.revision
            || receipt.upstream != upstream.as_str()
            || receipt.bytes != fetched.bytes.len()
            || receipt.sha256 != format!("{:x}", Sha256::digest(&fetched.bytes))
        {
            bail!("refresh dependency receipt mismatch");
        }
        if self.documents.contains_key(&receipt.path) {
            bail!("duplicate refresh dependency");
        }
        if self.documents.len() >= self.options.max_documents {
            return Err(limit_error(RefreshLimit::Documents));
        }
        let bytes = self.bytes.saturating_add(fetched.bytes.len());
        if fetched.bytes.len() > 128 * 1024 * 1024 || bytes > self.options.max_bytes {
            return Err(limit_error(RefreshLimit::Bytes));
        }
        let document = crate::parse_document(&fetched.bytes)?;
        self.documents.insert(receipt.path.clone(), document);
        self.bytes = bytes;
        self.dependencies
            .push(json!({"receipt":receipt,"status":"dependency"}));
        Ok(())
    }
    fn finish(mut self) -> Result<RegistryManifest> {
        if self.receipts.len() != self.inventory.documents.len() {
            bail!("source refresh is incomplete");
        }
        for (path, service, upstream) in &self.entries {
            let document = crate::bundle::bundle(path, &self.documents)?;
            self.manifests.push(crate::ingest(
                &document,
                &self.source.product,
                service,
                upstream,
            )?);
        }
        if self.manifests.is_empty() {
            bail!("source refresh found no API specifications");
        }
        let imported = self.manifests.len();
        let mut manifest = crate::merge::merge(self.manifests)?;
        manifest.schemas["x-junction-refresh"] = json!({"inventory":self.inventory,"documents":self.receipts,"dependencies":self.dependencies,"imported":imported,"bytes":self.bytes});
        Ok(manifest)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn case_variant_references_map_only_onto_one_configured_scope() {
        let source: ApiSource = serde_json::from_value(serde_json::json!({"id":"fabric","product":"fabric","source_type":"open_api","upstream":"https://github.com/microsoft/fabric-rest-api-specs","paths":["platform","common"],"authority":"microsoft","clouds":["public"],"enabled":true})).unwrap();
        assert_eq!(
            super::case_folded_scope_path(&source, "Common/definitions.json").as_deref(),
            Some("common/definitions.json")
        );
        for path in [
            "common/definitions.json",
            "Commonx/definitions.json",
            "Warehouse/definitions.json",
            "COMMON",
            "Common/definitions.txt",
        ] {
            assert!(
                super::case_folded_scope_path(&source, path).is_none(),
                "{path}"
            );
        }
    }
    #[test]
    fn refresh_stage_context_retains_cause_without_displaying_it() {
        let error = super::stage::<()>(
            Err(anyhow::anyhow!("private-source-content")),
            super::RefreshStage::Download,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "source refresh failed");
        let failure = error.downcast_ref::<super::RefreshFailure>().unwrap();
        assert_eq!(serde_json::to_value(failure.stage).unwrap(), "download");
        assert!(!failure.to_string().contains("private-source-content"));
    }
    use super::*;
    use crate::fetch::{DiscoveredDocument, FetchReceipt};

    fn source() -> ApiSource {
        toml::from_str(include_str!("../../../sources/azure.toml")).unwrap()
    }
    fn document(version: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({"openapi":"3.1.0","info":{"version":version},
            "servers":[{"url":"https://example.invalid"}],
            "paths":{"/items":{"get":{"operationId":"Items_List","responses":{"200":{"description":"items"}}}}}})).unwrap()
    }
    fn inventory(bytes: &[Vec<u8>]) -> SourceInventory {
        SourceInventory {
            source: "azure".into(), revision: "a".repeat(40), tree_sha: "b".repeat(40),
            documents: bytes.iter().enumerate().map(|(index, bytes)| DiscoveredDocument {
                path: format!("specification/compute/{index}.json"), blob_sha: "c".repeat(40),
                bytes: bytes.len() as u64,
                upstream: format!("https://raw.githubusercontent.com/Azure/azure-rest-api-specs/{}/specification/compute/{index}.json", "a".repeat(40)),
            }).collect(),
        }
    }
    fn fetched(index: usize, bytes: Vec<u8>) -> FetchedDocument {
        let inventory = inventory(&vec![bytes.clone(); index + 1]);
        let expected = &inventory.documents[index];
        FetchedDocument {
            receipt: FetchReceipt {
                source: inventory.source,
                revision: inventory.revision,
                path: expected.path.clone(),
                upstream: expected.upstream.clone(),
                sha256: format!("{:x}", Sha256::digest(&bytes)),
                bytes: bytes.len(),
            },
            bytes,
        }
    }
    #[test]
    fn refresh_merges_versions_and_retains_every_receipt() {
        let source = source();
        let bytes = vec![
            document("2025-01-01"),
            b"{\"example\":true}".to_vec(),
            document("2026-01-01"),
        ];
        let mut refresh =
            Refresh::new(&source, inventory(&bytes), RefreshOptions::default()).unwrap();
        for (index, bytes) in bytes.into_iter().enumerate() {
            refresh.accept(fetched(index, bytes)).unwrap();
        }
        let manifest = refresh.finish().unwrap();
        assert_eq!(manifest.operations.len(), 2);
        assert!(
            manifest
                .operations
                .iter()
                .all(|operation| operation.service == "compute")
        );
        let report = &manifest.schemas["x-junction-refresh"];
        assert_eq!(report["imported"], 2);
        assert_eq!(report["documents"].as_array().unwrap().len(), 3);
        assert_eq!(report["documents"][1]["status"], "not_api_specification");
    }
    #[test]
    fn limits_receipts_and_incomplete_imports_fail_closed() {
        let source = source();
        let bytes = vec![document("2025-01-01"), document("2026-01-01")];
        for (options, expected) in [
            (
                RefreshOptions {
                    max_documents: 1,
                    ..Default::default()
                },
                "documents",
            ),
            (
                RefreshOptions {
                    max_bytes: 1,
                    ..Default::default()
                },
                "bytes",
            ),
        ] {
            let error = match Refresh::new(&source, inventory(&bytes), options) {
                Ok(_) => panic!("over-budget inventory accepted"),
                Err(error) => error,
            };
            let limit = error.downcast_ref::<super::RefreshLimitExceeded>().unwrap();
            assert_eq!(serde_json::to_value(limit.limit).unwrap(), expected);
            assert_eq!(limit.to_string(), "source refresh limit exceeded");
        }
        let mut refresh =
            Refresh::new(&source, inventory(&bytes), RefreshOptions::default()).unwrap();
        let mut wrong = fetched(0, bytes[0].clone());
        wrong.receipt.sha256 = "incorrect".into();
        assert!(refresh.accept(wrong).is_err());
        refresh.accept(fetched(0, bytes[0].clone())).unwrap();
        assert!(refresh.finish().is_err());
        let examples = vec![b"{}".to_vec()];
        let mut refresh =
            Refresh::new(&source, inventory(&examples), RefreshOptions::default()).unwrap();
        refresh.accept(fetched(0, examples[0].clone())).unwrap();
        assert!(refresh.finish().is_err());
    }
    #[test]
    fn fetched_shared_documents_close_external_schema_references() {
        let source = source();
        let entry = serde_json::to_vec(&json!({"openapi":"3.1.0","info":{"version":"2026-01-01"},
            "servers":[{"url":"https://example.invalid"}],
            "paths":{"/items":{"post":{"operationId":"Items_Create","requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"./1.json#/definitions/Item"}}}},"responses":{"200":{"description":"created"}}}}}})).unwrap();
        let shared = serde_json::to_vec(&json!({"definitions":{"Item":{"type":"object","properties":{"value":{"type":"integer"}},"required":["value"]}}})).unwrap();
        let bytes = vec![entry.clone(), shared];
        let mut refresh =
            Refresh::new(&source, inventory(&bytes), RefreshOptions::default()).unwrap();
        for (index, bytes) in bytes.into_iter().enumerate() {
            refresh.accept(fetched(index, bytes)).unwrap();
        }
        let manifest = refresh.finish().unwrap();
        assert_eq!(manifest.schemas["x-junction-refresh"]["imported"], 1);
        let registry = junction_registry::Registry::load(manifest).unwrap();
        let input = registry
            .input_schema("azure.compute.items.create", None, false)
            .unwrap();
        junction_schema::validate_json_schema(&input, &json!({"body":{"value":3}})).unwrap();
        assert!(
            junction_schema::validate_json_schema(&input, &json!({"body":{"value":"invalid"}}))
                .is_err()
        );
        let mut missing = Refresh::new(
            &source,
            inventory(std::slice::from_ref(&entry)),
            RefreshOptions::default(),
        )
        .unwrap();
        missing.accept(fetched(0, entry)).unwrap();
        assert!(missing.finish().is_err());
    }
    #[test]
    fn pinned_dependencies_are_bounded_and_retained_without_importing_extra_apis() {
        let source = source();
        let entry = serde_json::to_vec(&json!({"openapi":"3.1.0","info":{"version":"2026-01-01"},"servers":[{"url":"https://example.invalid"}],
            "paths":{"/items":{"post":{"operationId":"Items_Create","requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"1.json#/definitions/Item"}}}},"responses":{"200":{"description":"created"}}}}}})).unwrap();
        let shared =
            serde_json::to_vec(&json!({"definitions":{"Item":{"type":"integer"}}})).unwrap();
        let mut refresh = Refresh::new(
            &source,
            inventory(std::slice::from_ref(&entry)),
            RefreshOptions::default(),
        )
        .unwrap();
        refresh.accept(fetched(0, entry.clone())).unwrap();
        let mut wrong = fetched(1, shared.clone());
        wrong.receipt.revision = "b".repeat(40);
        assert!(refresh.accept_dependency(wrong).is_err());
        let mut outside = fetched(1, shared.clone());
        outside.receipt.path = "private/shared.json".into();
        assert!(refresh.accept_dependency(outside).is_err());
        refresh
            .accept_dependency(fetched(1, shared.clone()))
            .unwrap();
        assert!(
            refresh
                .accept_dependency(fetched(1, shared.clone()))
                .is_err()
        );
        let manifest = refresh.finish().unwrap();
        assert_eq!(manifest.operations.len(), 1);
        assert_eq!(
            manifest.schemas["x-junction-refresh"]["dependencies"][0]["status"],
            "dependency"
        );
        assert_eq!(
            manifest.schemas["x-junction-refresh"]["bytes"],
            entry.len() + shared.len()
        );
        let mut bounded = Refresh::new(
            &source,
            inventory(std::slice::from_ref(&entry)),
            RefreshOptions {
                max_documents: 1,
                ..Default::default()
            },
        )
        .unwrap();
        bounded.accept(fetched(0, entry)).unwrap();
        let error = super::stage(
            bounded.accept_dependency(fetched(1, shared)),
            super::RefreshStage::DocumentValidation,
        )
        .unwrap_err();
        assert!(matches!(
            error
                .downcast_ref::<super::RefreshLimitExceeded>()
                .unwrap()
                .limit,
            super::RefreshLimit::Documents
        ));
        assert!(error.downcast_ref::<super::RefreshFailure>().is_some());
        assert_eq!(bounded.documents.len(), 1);
        assert!(bounded.dependencies.is_empty());
        assert!(bounded.finish().is_err());
    }
    #[tokio::test]
    async fn deadline_cancels_pending_work_and_rejects_late_completion() {
        let result: Result<()> =
            bounded_refresh(std::time::Duration::from_millis(1), std::future::pending()).await;
        assert_eq!(
            result.unwrap_err().to_string(),
            "source refresh deadline exceeded"
        );
        let completed = bounded_refresh(std::time::Duration::from_secs(1), async { Ok(7) })
            .await
            .unwrap();
        assert_eq!(completed, 7);
        assert!(
            bounded_refresh(std::time::Duration::ZERO, async { Ok(7) })
                .await
                .is_err()
        );
        assert!(
            RefreshOptions {
                timeout_seconds: 0,
                ..Default::default()
            }
            .validate(&source())
            .is_err()
        );
        assert!(
            RefreshOptions {
                timeout_seconds: 3601,
                ..Default::default()
            }
            .validate(&source())
            .is_err()
        );
    }
    #[test]
    fn conflicting_versions_are_not_published() {
        let source = source();
        let first = document("2025-01-01");
        let second = String::from_utf8(first.clone())
            .unwrap()
            .replace("items", "changed")
            .into_bytes();
        let bytes = vec![first, second];
        let mut refresh =
            Refresh::new(&source, inventory(&bytes), RefreshOptions::default()).unwrap();
        for (index, bytes) in bytes.into_iter().enumerate() {
            refresh.accept(fetched(index, bytes)).unwrap();
        }
        assert!(refresh.finish().is_err());
    }
}
