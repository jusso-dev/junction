use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperationRisk {
    ReadOnly,
    Write,
    Destructive,
    Privileged,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ApiMaturity {
    #[default]
    Stable,
    Preview,
    Beta,
    Deprecated,
    Retired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub location: String,
    pub required: bool,
    pub schema: Value,
    #[serde(default)]
    pub serialization: ParameterSerialization,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ParameterSerialization {
    pub style: Option<String>,
    pub explode: Option<bool>,
    pub collection_format: Option<String>,
    pub allow_reserved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceMetadata {
    pub id: String,
    pub upstream: String,
    pub operation_id: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LroFinalStateVia {
    AzureAsyncOperation,
    Location,
    OriginalUri,
    OperationLocation,
}
/// Declared async behavior; absence of a final-state hint preserves upstream defaults.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct LongRunningOperation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<LroProtocol>,
    pub final_state_via: Option<LroFinalStateVia>,
    pub final_state_schema: Option<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LroProtocol {
    Fabric,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pageable {
    pub item_name: String,
    pub next_link_name: Option<String>,
    pub operation_name: Option<String>,
}
impl Pageable {
    pub fn validate(&self) -> anyhow::Result<()> {
        for name in std::iter::once(&self.item_name)
            .chain(self.next_link_name.iter())
            .chain(self.operation_name.iter())
        {
            if name.is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
                anyhow::bail!("invalid pagination field name");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryContinuation {
    pub query_parameter: String,
    pub response_pointer: String,
}
impl QueryContinuation {
    pub fn validate(&self, operation: &JunctionOperation) -> anyhow::Result<()> {
        if self.query_parameter.is_empty()
            || self.query_parameter.len() > 128
            || self.query_parameter.chars().any(char::is_control)
            || !self.response_pointer.starts_with('/')
            || self.response_pointer.len() > 4096
            || self.response_pointer.chars().any(char::is_control)
            || self.response_pointer.split('/').count() > 33
            || operation
                .parameters
                .iter()
                .filter(|parameter| {
                    parameter.location == "query" && parameter.name == self.query_parameter
                })
                .count()
                != 1
            || operation
                .pageable
                .as_ref()
                .is_some_and(|pageable| pageable.operation_name.is_some())
        {
            anyhow::bail!("invalid query continuation metadata");
        }
        for segment in self.response_pointer.split('/').skip(1) {
            let mut bytes = segment.bytes();
            while let Some(byte) = bytes.next() {
                if byte == b'~' && !matches!(bytes.next(), Some(b'0' | b'1')) {
                    anyhow::bail!("invalid continuation response pointer");
                }
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JunctionOperation {
    pub id: String,
    pub product: String,
    pub service: String,
    pub resource: String,
    pub operation: String,
    pub description: String,
    pub method: String,
    pub base_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_template: Option<endpoint::EndpointTemplate>,
    pub path: String,
    pub api_version: Option<String>,
    pub parameters: Vec<Parameter>,
    pub request_body: Option<Value>,
    pub responses: Value,
    pub security: Value,
    #[serde(default)]
    pub documentation_url: Option<String>,
    #[serde(default)]
    pub long_running: Option<LongRunningOperation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pageable: Option<Pageable>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_continuation: Option<QueryContinuation>,
    pub risk: OperationRisk,
    pub preview: bool,
    #[serde(default)]
    pub maturity: ApiMaturity,
    pub source: SourceMetadata,
}

impl JunctionOperation {
    /// Documentation is metadata only, never an execution endpoint. Credential
    /// material in user-info or query/fragment components must not enter diagnostics.
    pub fn documentation(&self) -> Option<&str> {
        self.documentation_url.as_deref().filter(|value| {
            value.len() <= 4096
                && !value.chars().any(char::is_control)
                && url::Url::parse(value).is_ok_and(|url| {
                    url.scheme() == "https"
                        && url.host_str().is_some()
                        && url.username().is_empty()
                        && url.password().is_none()
                        && url.query().is_none()
                        && url.fragment().is_none()
                })
        })
    }
    /// Scope groups imported from OpenAPI security requirements. Outer groups
    /// are alternatives; scopes within a group are jointly required. Unknown
    /// or scope-free metadata returns None, never a claim of unrestricted access.
    /// This does not infer delegated/application permissions or service RBAC.
    pub fn required_permissions(&self) -> Option<Vec<Vec<String>>> {
        let requirements = self.security.as_array()?;
        let mut alternatives = Vec::new();
        for requirement in requirements {
            let mut scopes = std::collections::BTreeSet::new();
            for values in requirement.as_object()?.values() {
                for value in values.as_array()? {
                    let scope = value.as_str()?;
                    if scope.is_empty() || scope.chars().any(char::is_control) {
                        return None;
                    }
                    scopes.insert(scope.to_owned());
                }
            }
            alternatives.push(scopes.into_iter().collect::<Vec<_>>());
        }
        alternatives
            .iter()
            .any(|group| !group.is_empty())
            .then_some(alternatives)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistryManifest {
    pub format_version: u32,
    pub operations: Vec<JunctionOperation>,
    pub schemas: Value,
}

/// Stable ASCII names independent of iteration order or locale.
pub fn canonical_component(input: &str) -> String {
    let mut out = String::new();
    for c in input.chars() {
        if c.is_ascii_alphanumeric() {
            if c.is_ascii_uppercase() && out.ends_with(|c: char| c.is_ascii_lowercase()) {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else if !out.is_empty() && !out.ends_with('_') {
            out.push('_');
        }
    }
    out.trim_matches('_').to_owned()
}

/// JSON-structured media types Junction can serialize: `application/json` or
/// an `application/<subtype>+json` such as `application/json-patch+json`.
pub fn is_json_media_type(value: &str) -> bool {
    value == "application/json"
        || value
            .strip_prefix("application/")
            .and_then(|subtype| subtype.strip_suffix("+json"))
            .is_some_and(|stem| {
                !stem.is_empty()
                    && stem.len() <= 96
                    && stem.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-".contains(&byte)
                    })
            })
}
/// POST endpoints Microsoft documents as queries that return data without
/// changing state (KQL, Resource Graph, Cost Management, search). This fixed,
/// code-owned list is the only way a POST can be treated as a read.
pub fn documented_query(path: &str) -> bool {
    let path = path.trim_end_matches('/').to_ascii_lowercase();
    [
        "/providers/microsoft.resourcegraph/resources",
        "/providers/microsoft.costmanagement/query",
        "/providers/microsoft.costmanagement/forecast",
        "/api/advancedhunting/run",
        "/api/advancedqueries/run",
        "/security/microsoft.graph.security.runhuntingquery",
        "/search/query",
        "/resourcequery/resources/query",
    ]
    .iter()
    .any(|suffix| path.ends_with(suffix))
        || (path.ends_with("/query")
            && (path.starts_with("/workspaces/{") || path == "/{resourceid}/query"))
}

/// Documented request-body continuation: (request token pointer, response
/// token pointer, response items pointer). Azure Resource Graph returns
/// `$skipToken` and expects it back in `options.$skipToken`.
pub fn body_continuation(
    operation: &JunctionOperation,
) -> Option<(&'static str, &'static str, &'static str)> {
    (operation.method == "POST"
        && operation
            .path
            .trim_end_matches('/')
            .to_ascii_lowercase()
            .ends_with("/providers/microsoft.resourcegraph/resources"))
    .then_some(("/options/$skipToken", "/$skipToken", "/data"))
}
#[cfg(test)]
mod media_tests {
    #[test]
    fn only_json_structured_media_types_are_accepted() {
        for media in [
            "application/json",
            "application/json-patch+json",
            "application/merge-patch+json",
            "application/vnd.api+json",
        ] {
            assert!(super::is_json_media_type(media), "{media}");
        }
        for media in [
            "application/xml",
            "text/json",
            "application/+json",
            "application/json; charset=utf-8",
            "Application/JSON",
            "application/a b+json",
            "application/x\r\n+json",
        ] {
            assert!(!super::is_json_media_type(media), "{media}");
        }
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn stable_names() {
        assert_eq!(
            super::canonical_component("VirtualMachines"),
            "virtual_machines"
        );
        assert_eq!(
            super::canonical_component("resource-groups"),
            "resource_groups"
        );
    }
}

pub mod cloud;
pub mod endpoint;
