mod input_schema;
pub mod overrides;
use anyhow::{Result, bail};
use junction_core::OperationRisk;
use junction_core::{ApiMaturity, JunctionOperation, RegistryManifest};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Serialize)]
pub struct SearchMatch<'a> {
    pub operation: &'a str,
    pub description: &'a str,
    pub product: &'a str,
    pub service: &'a str,
    pub risk: &'a OperationRisk,
    pub api_version: Option<&'a str>,
    pub required_permissions: Option<Vec<Vec<String>>>,
}
/// Compact imported requirements; no credential acquisition or permission grants.
#[derive(Debug, Serialize)]
pub struct PermissionSummary<'a> {
    pub operation: &'a str,
    pub api_version: Option<&'a str>,
    pub required_permissions: Option<Vec<Vec<String>>>,
    pub metadata_status: &'static str,
    pub source: &'a junction_core::SourceMetadata,
    pub documentation_url: Option<&'a str>,
}
/// Hierarchical filters shared by CLI and agent discovery surfaces.
#[derive(Default)]
pub struct SearchOptions<'a> {
    pub product: Option<&'a str>,
    pub service: Option<&'a str>,
    pub allow_preview: bool,
}
#[derive(Debug, Serialize)]
pub struct RegistryStats {
    pub operations: usize,
    pub versions: usize,
    pub products: usize,
    pub services: usize,
    pub stable: usize,
    pub preview: usize,
    pub beta: usize,
    pub deprecated: usize,
    pub retired: usize,
}

#[derive(Default)]
pub struct Registry {
    schemas: serde_json::Value,
    operations: BTreeMap<String, Vec<JunctionOperation>>,
}
impl Registry {
    /// List one supported version per canonical ID, in deterministic ID order.
    /// Offsets count filtered operations; at most `limit + 1` references are collected.
    pub fn list_filtered(
        &self,
        offset: usize,
        limit: usize,
        options: &SearchOptions<'_>,
    ) -> Result<(Vec<&JunctionOperation>, Option<usize>)> {
        if !(1..=100).contains(&limit) {
            bail!("operation listing limit must be between 1 and 100");
        }
        let mut operations: Vec<_> = self
            .operations
            .keys()
            .filter_map(|id| self.resolve(id, None, options.allow_preview).ok())
            .filter(|op| {
                options.product.is_none_or(|p| p == op.product)
                    && options.service.is_none_or(|s| s == op.service)
            })
            .skip(offset)
            .take(limit + 1)
            .collect();
        let next = if operations.len() > limit {
            operations.pop();
            Some(
                offset
                    .checked_add(limit)
                    .ok_or_else(|| anyhow::anyhow!("listing offset overflow"))?,
            )
        } else {
            None
        };
        Ok((operations, next))
    }
    pub fn permissions(
        &self,
        operation: &str,
        version: Option<&str>,
        allow_preview: bool,
    ) -> Result<PermissionSummary<'_>> {
        let operation = self.resolve(operation, version, allow_preview)?;
        let required_permissions = operation.required_permissions();
        Ok(PermissionSummary {
            operation: &operation.id,
            api_version: operation.api_version.as_deref(),
            metadata_status: if required_permissions.is_some() {
                "imported_scope_requirements"
            } else {
                "unavailable"
            },
            required_permissions,
            source: &operation.source,
            documentation_url: operation.documentation(),
        })
    }

    pub fn load(manifest: RegistryManifest) -> Result<Self> {
        if manifest.format_version != 1 {
            bail!("unsupported manifest format");
        }
        let mut registry = Self {
            schemas: manifest.schemas,
            ..Self::default()
        };
        for mut op in manifest.operations {
            if let Some(continuation) = &op.query_continuation {
                continuation.validate(&op)?;
            }
            if op.documentation().is_none() {
                op.documentation_url = None;
            }
            if op.id.is_empty() || !op.path.starts_with('/') {
                bail!("invalid operation metadata");
            }
            let versions = registry.operations.entry(op.id.clone()).or_default();
            if versions.iter().any(|old| old.api_version == op.api_version) {
                bail!("duplicate operation/version: {}", op.id);
            }
            versions.push(op);
            versions.sort_by(|a, b| {
                compare_versions(b.api_version.as_deref(), a.api_version.as_deref())
            });
        }
        Ok(registry)
    }
    /// Apply exact-ID corrections to every version, failing on catalog drift/unknown IDs.
    pub fn with_risk_overrides(mut self, overrides: overrides::RiskOverrides) -> Result<Self> {
        overrides.validate()?;
        for entry in &overrides.operations {
            if !self.operations.contains_key(&entry.operation) {
                bail!("risk override targets unknown operation");
            }
        }
        for entry in overrides.operations {
            for operation in self
                .operations
                .get_mut(&entry.operation)
                .expect("validated override target")
            {
                operation.risk = entry.risk.clone();
            }
        }
        Ok(self)
    }
    pub fn resolve(
        &self,
        id: &str,
        version: Option<&str>,
        allow_preview: bool,
    ) -> Result<&JunctionOperation> {
        let versions = self
            .operations
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("unknown operation"))?;
        let preview = |op: &&JunctionOperation| {
            op.preview || matches!(op.maturity, ApiMaturity::Preview | ApiMaturity::Beta)
        };
        let eligible = |op: &&JunctionOperation| {
            op.maturity != ApiMaturity::Retired && (allow_preview || !preview(op))
        };
        if let Some(exact) = version.filter(|v| *v != "latest") {
            return versions
                .iter()
                .filter(eligible)
                .find(|op| op.api_version.as_deref() == Some(exact))
                .ok_or_else(|| anyhow::anyhow!("requested version unavailable or disallowed"));
        }
        // Enabling preview permits explicit versions; it never silently displaces stable.
        versions
            .iter()
            .filter(eligible)
            .find(|op| !preview(op) && op.maturity == ApiMaturity::Stable)
            .or_else(|| {
                if allow_preview {
                    versions.iter().filter(eligible).find(|op| preview(op))
                } else {
                    None
                }
            })
            .ok_or_else(|| anyhow::anyhow!("no supported version available"))
    }
    pub fn input_schema(
        &self,
        id: &str,
        version: Option<&str>,
        allow_preview: bool,
    ) -> Result<serde_json::Value> {
        input_schema::build(self.resolve(id, version, allow_preview)?, &self.schemas)
    }
    /// Resolve a source-declared relationship without crossing service/version boundaries.
    pub fn resolve_related(
        &self,
        operation: &JunctionOperation,
        upstream_id: &str,
        allow_preview: bool,
    ) -> Result<&JunctionOperation> {
        let mut matches = self.operations.values().flatten().filter(|candidate| {
            candidate.source.operation_id == upstream_id
                && candidate.product == operation.product
                && candidate.service == operation.service
                && candidate.source.id == operation.source.id
                && candidate.source.upstream == operation.source.upstream
                && candidate.api_version == operation.api_version
        });
        let candidate = matches
            .next()
            .ok_or_else(|| anyhow::anyhow!("related operation unavailable"))?;
        if matches.next().is_some() {
            anyhow::bail!("related operation is ambiguous");
        }
        if candidate.maturity == ApiMaturity::Retired
            || (!allow_preview
                && (candidate.preview
                    || matches!(candidate.maturity, ApiMaturity::Preview | ApiMaturity::Beta)))
        {
            anyhow::bail!("related operation unavailable or disallowed");
        }
        // None identifies a versionless relationship, not a request for latest.
        Ok(candidate)
    }
    pub fn schemas(&self) -> &serde_json::Value {
        &self.schemas
    }
    pub fn products(&self) -> Vec<&str> {
        self.operations
            .values()
            .flatten()
            .map(|op| op.product.as_str())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
    pub fn services(&self, product: Option<&str>) -> Vec<(&str, &str)> {
        self.operations
            .values()
            .flatten()
            .filter(|op| product.is_none_or(|p| p == op.product))
            .map(|op| (op.product.as_str(), op.service.as_str()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
    /// Includes preview/deprecated/retired metadata without selecting it for execution.
    pub fn versions(&self, id: &str) -> Result<&[JunctionOperation]> {
        self.operations
            .get(id)
            .map(Vec::as_slice)
            .ok_or_else(|| anyhow::anyhow!("unknown operation"))
    }
    pub fn stats(&self) -> RegistryStats {
        let mut stats = RegistryStats {
            operations: self.operations.len(),
            versions: 0,
            products: self.products().len(),
            services: self.services(None).len(),
            stable: 0,
            preview: 0,
            beta: 0,
            deprecated: 0,
            retired: 0,
        };
        for op in self.operations.values().flatten() {
            stats.versions += 1;
            match op.maturity {
                ApiMaturity::Stable if op.preview => stats.preview += 1,
                ApiMaturity::Stable => stats.stable += 1,
                ApiMaturity::Preview => stats.preview += 1,
                ApiMaturity::Beta => stats.beta += 1,
                ApiMaturity::Deprecated => stats.deprecated += 1,
                ApiMaturity::Retired => stats.retired += 1,
            }
        }
        stats
    }
    pub fn discover(&self, query: &str, limit: usize) -> Vec<SearchMatch<'_>> {
        self.search(query, limit)
            .into_iter()
            .map(|op| SearchMatch {
                operation: &op.id,
                description: &op.description,
                product: &op.product,
                service: &op.service,
                risk: &op.risk,
                api_version: op.api_version.as_deref(),
                required_permissions: op.required_permissions(),
            })
            .collect()
    }
    pub fn discover_filtered(
        &self,
        query: &str,
        limit: usize,
        options: &SearchOptions<'_>,
    ) -> Vec<SearchMatch<'_>> {
        self.search_filtered(query, limit, options)
            .into_iter()
            .map(|op| SearchMatch {
                operation: &op.id,
                description: &op.description,
                product: &op.product,
                service: &op.service,
                risk: &op.risk,
                api_version: op.api_version.as_deref(),
                required_permissions: op.required_permissions(),
            })
            .collect()
    }
    pub fn search(&self, query: &str, limit: usize) -> Vec<&JunctionOperation> {
        self.search_filtered(query, limit, &SearchOptions::default())
    }
    /// Rank canonical metadata ahead of description-only matches; ties are deterministic.
    pub fn search_filtered(
        &self,
        query: &str,
        limit: usize,
        options: &SearchOptions<'_>,
    ) -> Vec<&JunctionOperation> {
        if limit == 0 || query.len() > 1024 {
            return vec![];
        }
        let normalized = query.trim().to_lowercase();
        let terms: BTreeSet<_> = normalized
            .split(|c: char| !c.is_alphanumeric())
            .filter(|term| {
                !term.is_empty()
                    && !["find", "show", "the", "a", "an", "please", "me"].contains(term)
            })
            .collect();
        if terms.is_empty() || terms.len() > 32 {
            return vec![];
        }
        let mut matches: Vec<_> = self
            .operations
            .values()
            .filter_map(|versions| {
                self.resolve(&versions[0].id, None, options.allow_preview)
                    .ok()
            })
            .filter(|op| {
                options.product.is_none_or(|product| product == op.product)
                    && options.service.is_none_or(|service| service == op.service)
            })
            .filter_map(|op| {
                let id = op.id.to_lowercase();
                let canonical: BTreeSet<_> = id.split(['.', '_', '-']).collect();
                let description = op.description.to_lowercase();
                let metadata =
                    format!("{} {} {}", op.product, op.service, op.resource).to_lowercase();
                let mut score = if id == normalized { 10000 } else { 0 };
                for term in &terms {
                    score += if *term == op.operation.to_lowercase() {
                        100
                    } else if canonical.contains(term) {
                        80
                    } else if id.contains(term) {
                        40
                    } else if metadata.contains(term) {
                        20
                    } else if description.contains(term) {
                        5
                    } else {
                        return None;
                    };
                }
                Some((score, op))
            })
            .collect();
        matches.sort_by(|(a_score, a), (b_score, b)| {
            b_score
                .cmp(a_score)
                .then_with(|| a.id.split('.').count().cmp(&b.id.split('.').count()))
                .then_with(|| a.id.cmp(&b.id))
        });
        matches
            .into_iter()
            .take(limit.min(100))
            .map(|(_, op)| op)
            .collect()
    }
}

/// Natural ordering handles date versions and numeric service versions without v10 < v2.
fn compare_versions(a: Option<&str>, b: Option<&str>) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let (Some(a), Some(b)) = (a, b) else {
        return a.cmp(&b);
    };
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        if a[i].is_ascii_digit() && b[j].is_ascii_digit() {
            let (start_a, start_b) = (i, j);
            while i < a.len() && a[i].is_ascii_digit() {
                i += 1;
            }
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            let mut aa = &a[start_a..i];
            let mut bb = &b[start_b..j];
            while aa.len() > 1 && aa[0] == b'0' {
                aa = &aa[1..];
            }
            while bb.len() > 1 && bb[0] == b'0' {
                bb = &bb[1..];
            }
            let order = aa.len().cmp(&bb.len()).then_with(|| aa.cmp(bb));
            if order != Ordering::Equal {
                return order;
            }
        } else {
            let order = a[i].cmp(&b[j]);
            if order != Ordering::Equal {
                return order;
            }
            i += 1;
            j += 1;
        }
    }
    (a.len() - i).cmp(&(b.len() - j)).then_with(|| a.cmp(b))
}

#[derive(Debug, Serialize)]
pub struct CatalogChanges {
    pub added: Vec<OperationVersion>,
    pub removed: Vec<OperationVersion>,
    pub modified: Vec<OperationChange>,
    pub schemas_changed: bool,
}
#[derive(Debug, Serialize, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct OperationVersion {
    pub operation: String,
    pub api_version: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct OperationChange {
    pub operation: String,
    pub api_version: Option<String>,
    pub fields: Vec<String>,
}

/// Compare validated catalog snapshots independent of operation ordering.
/// Values are never included in reports: only keys and changed field names.
pub fn changes(before: &RegistryManifest, after: &RegistryManifest) -> Result<CatalogChanges> {
    Registry::load(before.clone())?;
    Registry::load(after.clone())?;
    let index =
        |manifest: &RegistryManifest| -> Result<BTreeMap<OperationVersion, serde_json::Value>> {
            manifest
                .operations
                .iter()
                .map(|op| {
                    Ok((
                        OperationVersion {
                            operation: op.id.clone(),
                            api_version: op.api_version.clone(),
                        },
                        serde_json::to_value(op)?,
                    ))
                })
                .collect()
        };
    let old = index(before)?;
    let new = index(after)?;
    let added = new
        .keys()
        .filter(|key| !old.contains_key(*key))
        .cloned()
        .collect();
    let removed = old
        .keys()
        .filter(|key| !new.contains_key(*key))
        .cloned()
        .collect();
    let mut modified = Vec::new();
    for (key, value) in &new {
        if let Some(previous) = old.get(key).filter(|previous| *previous != value) {
            let fields = value
                .as_object()
                .expect("serialized operation is object")
                .iter()
                .filter(|(field, val)| previous.get(*field) != Some(*val))
                .map(|(field, _)| field.clone())
                .collect();
            modified.push(OperationChange {
                operation: key.operation.clone(),
                api_version: key.api_version.clone(),
                fields,
            });
        }
    }
    Ok(CatalogChanges {
        added,
        removed,
        modified,
        schemas_changed: before.schemas != after.schemas,
    })
}
