use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path};
use url::Url;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceType {
    OpenApi,
    TypeSpec,
    #[serde(rename = "odata", alias = "o_data")]
    OData,
    Metadata,
    Documentation,
}
pub use junction_core::cloud::MicrosoftCloud as Cloud;
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Authority {
    Microsoft,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApiSource {
    pub id: String,
    pub product: String,
    pub source_type: SourceType,
    pub upstream: String,
    pub paths: Vec<String>,
    pub authority: Authority,
    pub clouds: Vec<Cloud>,
    pub enabled: bool,
}
impl ApiSource {
    /// Narrow discovery to configured paths or their descendants.
    pub fn scoped(&self, paths: &[String]) -> Result<Self> {
        self.validate()?;
        if paths.is_empty() {
            return Ok(self.clone());
        }
        if paths.len() > 256 {
            bail!("source scope limit exceeded");
        }
        let mut selected = BTreeSet::new();
        for path in paths {
            validate_source_path(path)?;
            if !self.paths.iter().any(|scope| {
                path == scope
                    || path
                        .strip_prefix(scope)
                        .is_some_and(|suffix| suffix.starts_with('/'))
            }) {
                bail!("requested path is outside configured source scope");
            }
            selected.insert(path.clone());
        }
        let mut source = self.clone();
        source.paths = selected.into_iter().collect();
        Ok(source)
    }

    pub fn validate(&self) -> Result<()> {
        for name in [&self.id, &self.product] {
            if name.is_empty()
                || name.chars().any(|c| {
                    !(c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_'))
                })
            {
                bail!("invalid source identifier");
            }
        }
        validate_official_url(&self.upstream)?;
        if self.clouds.is_empty() {
            bail!("source must declare cloud availability");
        }
        for path in &self.paths {
            validate_source_path(path)?;
        }
        Ok(())
    }
}
pub fn validate_source_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains(['\\', ':', '%', '?', '#'])
        || path.chars().any(char::is_control)
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        bail!("invalid source path");
    }
    Ok(())
}
/// Exact host and repository owner checks; HTTPS alone does not establish provenance.
pub fn validate_official_url(input: &str) -> Result<()> {
    let url = Url::parse(input)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("source URL must be plain HTTPS");
    }
    match url.host_str() {
        Some("github.com" | "raw.githubusercontent.com") => {
            let owner = url
                .path_segments()
                .and_then(|mut p| p.next())
                .unwrap_or("")
                .to_ascii_lowercase();
            if !["microsoft", "microsoftdocs", "microsoftgraph", "azure"].contains(&owner.as_str())
            {
                bail!("source repository owner is not approved");
            }
        }
        Some("learn.microsoft.com" | "graph.microsoft.com") => {}
        _ => bail!("source host is not approved"),
    }
    Ok(())
}
/// Read deterministic local source configuration; does not fetch upstream content.
pub fn load_sources(directory: &Path) -> Result<Vec<ApiSource>> {
    let mut files = std::fs::read_dir(directory)?
        .map(|entry| entry.map(|e| e.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    files.sort();
    let mut sources = Vec::new();
    let mut ids = BTreeSet::new();
    for file in files
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "toml"))
    {
        let source: ApiSource = toml::from_str(&std::fs::read_to_string(file)?)?;
        source.validate()?;
        if !ids.insert(source.id.clone()) {
            bail!("duplicate source identifier");
        }
        sources.push(source);
    }
    sources.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(sources)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn official_origins_are_exact() {
        assert!(validate_official_url("https://github.com/Azure/azure-rest-api-specs").is_ok());
        for url in [
            "https://github.com/attacker/azure-rest-api-specs",
            "https://github.com.evil.test/Azure/specs",
            "https://learn.microsoft.com@evil.test/docs",
            "http://learn.microsoft.com/docs",
            "https://learn.microsoft.com/docs?token=secret",
        ] {
            assert!(validate_official_url(url).is_err());
        }
    }
    #[test]
    fn bundled_sources_validate() {
        let sources = load_sources(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../sources")
                .as_path(),
        )
        .unwrap();
        for required in [
            "azure",
            "azure-arc",
            "azure-lighthouse",
            "azure-log-analytics",
            "defender-for-cloud",
            "azure-compute",
            "azure-cost-management",
            "azure-monitor",
            "azure-resource-graph",
            "azure-resources",
            "azure-devops",
            "graph",
            "graph-odata",
            "defender",
            "fabric",
            "intune",
            "m365",
            "power-platform",
            "purview",
            "sentinel",
        ] {
            assert!(
                sources.iter().any(|source| source.id == required),
                "missing required bundled source: {required}"
            );
        }
        assert!(
            sources.iter().any(|source| source.id == "graph-odata"
                && matches!(source.source_type, SourceType::OData))
        );
        assert!(sources.windows(2).all(|s| s[0].id < s[1].id));
        let fabric = sources.iter().find(|source| source.id == "fabric").unwrap();
        assert!(fabric.enabled && matches!(fabric.source_type, SourceType::OpenApi));
        assert_eq!(
            fabric.upstream,
            "https://github.com/microsoft/fabric-rest-api-specs"
        );
        assert_eq!(
            fabric.paths,
            ["platform", "admin", "lakehouse", "notebook", "common"]
        );
        for path in [
            "lakehouse/swagger.json",
            "lakehouse/definitions.json",
            "notebook/swagger.json",
            "notebook/definitions.json",
            "common/definitions.json",
        ] {
            assert!(crate::fetch::repository(fabric, path).is_ok());
        }
        assert!(crate::fetch::repository(fabric, "warehouse/private.json").is_err());
        for id in [
            "azure-arc",
            "azure-lighthouse",
            "azure-log-analytics",
            "defender-for-cloud",
            "azure-compute",
            "azure-cost-management",
            "azure-monitor",
            "azure-resource-graph",
            "azure-resources",
            "sentinel",
            "purview",
        ] {
            let source = sources.iter().find(|source| source.id == id).unwrap();
            assert!(
                crate::fetch::repository(
                    source,
                    "specification/common-types/resource-management/v5/types.json"
                )
                .is_ok(),
                "shared ARM types unavailable to {id}"
            );
            assert!(
                crate::fetch::repository(source, "specification/storage/private.json").is_err()
            );
        }
        let cost = sources
            .iter()
            .find(|source| source.id == "azure-cost-management")
            .unwrap();
        assert!(cost.enabled && matches!(cost.source_type, SourceType::OpenApi));
        assert!(crate::fetch::repository(cost,
            "specification/cost-management/resource-manager/Microsoft.CostManagement/CostManagement/stable/2026-06-01/openapi.json").is_ok());
        assert!(
            crate::fetch::repository(
                cost,
                "specification/billing/resource-manager/Microsoft.Billing/private.json"
            )
            .is_err()
        );
        let resource_graph = sources
            .iter()
            .find(|source| source.id == "azure-resource-graph")
            .unwrap();
        assert!(
            resource_graph.enabled && matches!(resource_graph.source_type, SourceType::OpenApi)
        );
        for document in ["resourcegraph.json", "graphquery.json"] {
            let path = format!(
                "specification/resourcegraph/resource-manager/Microsoft.ResourceGraph/ResourceGraph/stable/2024-04-01/{document}"
            );
            assert!(crate::fetch::repository(resource_graph, &path).is_ok());
        }
        assert!(
            crate::fetch::repository(
                resource_graph,
                "specification/resourcegraph/resource-manager/Microsoft.Other/private.json"
            )
            .is_err()
        );
        let monitor = sources
            .iter()
            .find(|source| source.id == "azure-monitor")
            .unwrap();
        assert!(monitor.enabled && matches!(monitor.source_type, SourceType::OpenApi));
        assert!(crate::fetch::repository(monitor,
            "specification/monitor/resource-manager/Microsoft.Insights/Insights/stable/2024-02-01/metrics.json").is_ok());
        assert!(
            crate::fetch::repository(monitor, "specification/monitor/data-plane/private.json")
                .is_err()
        );
        let sentinel = sources
            .iter()
            .find(|source| source.id == "sentinel")
            .unwrap();
        assert!(
            crate::fetch::repository(
                sentinel,
                "specification/common-types/resource-management/v5/types.json"
            )
            .is_ok()
        );
        assert!(crate::fetch::repository(sentinel, "specification/securityinsights/resource-manager/Microsoft.SecurityInsights/SecurityInsights/stable/2025-09-01/openapi.json").is_ok());
        assert!(crate::fetch::repository(sentinel, "specification/compute/private.json").is_err());
    }
}

#[cfg(test)]
mod scope_tests {
    use super::*;
    #[test]
    fn narrowing_preserves_configuration_and_never_expands_scope() {
        let source: ApiSource =
            toml::from_str(include_str!("../../../sources/azure.toml")).unwrap();
        let scoped = source
            .scoped(&[
                "specification/storage".into(),
                "specification/compute".into(),
                "specification/compute".into(),
            ])
            .unwrap();
        assert_eq!(
            scoped.paths,
            ["specification/compute", "specification/storage"]
        );
        assert_eq!(source.paths, ["specification"]);
        assert_eq!(scoped.upstream, source.upstream);
        assert_eq!(source.scoped(&[]).unwrap().paths, source.paths);
        for path in [
            "specification-evil",
            "specification/../private",
            "private",
            "specification/%2e",
        ] {
            assert!(source.scoped(&[path.into()]).is_err());
        }
        assert!(source.scoped(&vec!["specification".into(); 257]).is_err());
    }
}
