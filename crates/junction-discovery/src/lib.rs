pub mod bundle;
mod continuation;
pub mod learn;
pub mod merge;
mod naming;
pub mod odata;
pub mod refresh;
use anyhow::{Result, bail};
use junction_core::*;
use junction_schema::CanonicalSchema;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// Normalize OpenAPI 3 and Swagger 2 without flattening or losing schema definitions.
/// Unresolved references remain explicit; execution must resolve them before validation.
pub fn ingest(
    spec: &Value,
    product: &str,
    service: &str,
    source: &str,
) -> Result<RegistryManifest> {
    if spec.get("openapi").is_none() && spec.get("swagger").is_none() {
        bail!("expected OpenAPI or Swagger document");
    }
    let paths = spec["paths"]
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("missing paths"))?;
    let extended_paths = spec
        .get("x-ms-paths")
        .map(|paths| {
            paths
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("invalid extended paths"))
        })
        .transpose()?;
    let document_server = server_endpoint(spec)?;
    let endpoint_template =
        if document_server.is_none() && spec.get("x-ms-parameterized-host").is_some() {
            Some(parameterized_swagger_template(spec)?)
        } else {
            server_template(spec)?.filter(|template| !template.variables.is_empty())
        };
    let base = document_server.or(swagger_endpoint(spec)?);
    let document_version = spec["info"]["version"].as_str().map(str::to_owned);
    let mut normalized = BTreeMap::new();
    for (prefix, definitions) in [
        ("#/definitions/", spec.get("definitions")),
        ("#/components/schemas/", spec.pointer("/components/schemas")),
    ] {
        if let Some(definitions) = definitions {
            for (name, schema) in definitions
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("schema definitions must be an object"))?
            {
                let escaped = name.replace('~', "~0").replace('/', "~1");
                normalized.insert(
                    format!("{prefix}{escaped}"),
                    CanonicalSchema::normalize(schema)?,
                );
            }
        }
    }
    let continuation_index =
        continuation::has_markers(spec).then(|| continuation::MarkerIndex::new(spec));
    let mut operations = Vec::new();
    for (raw_path, item, extended) in paths.iter().map(|(path, item)| (path, item, false)).chain(
        extended_paths
            .into_iter()
            .flatten()
            .map(|(path, item)| (path, item, true)),
    ) {
        // AutoRest query suffixes disambiguate overloads; declared parameters
        // still determine the actual request query.
        let path = if extended {
            raw_path.split('?').next().unwrap_or(raw_path).to_owned()
        } else {
            raw_path.clone()
        };
        for method in ["get", "post", "put", "patch", "delete", "head", "options"] {
            let Some(op) = item.get(method) else { continue };
            let upstream_id = op["operationId"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("missing operationId: {method} {path}"))?;
            let selected_template = server_template(op)?.or(server_template(item)?);
            let operation_server = selected_template
                .as_ref()
                .map(|template| template.resolve(&BTreeMap::new()))
                .transpose()?;
            let uses_document_endpoint = operation_server.is_none();
            let selected_template =
                selected_template.filter(|template| !template.variables.is_empty());
            let operation_base = operation_server
                .or_else(|| base.clone())
                .ok_or_else(|| anyhow::anyhow!("source requires an explicit service endpoint"))?;
            let (resource, action) = upstream_id
                .rsplit_once('_')
                .unwrap_or((upstream_id, method));
            let graph_name = if canonical_component(product) == "graph" {
                Some(naming::graph(&path, upstream_id)?)
            } else {
                None
            };
            let canonical_action = graph_name
                .as_ref()
                .map(|name| name.action.clone())
                .unwrap_or_else(|| canonical_component(action));
            let destructive_action = destructive_action(&canonical_action);
            let mut parameters = Vec::new();
            for parameter in item["parameters"]
                .as_array()
                .into_iter()
                .flatten()
                .chain(op["parameters"].as_array().into_iter().flatten())
            {
                let parameter = resolve_object(spec, parameter)?;
                let name = parameter["name"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("parameter missing name"))?;
                let location = parameter["in"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("parameter missing location"))?;
                if !["path", "query", "header", "cookie", "body", "formData"].contains(&location) {
                    bail!("unsupported parameter location");
                }
                if location == "path" && parameter["required"].as_bool() != Some(true) {
                    bail!("path parameter must be required");
                }
                // Operation parameters override path parameters by (name, location).
                parameters.retain(|old: &Parameter| old.name != name || old.location != location);
                parameters.push(Parameter {
                    name: name.into(),
                    location: location.into(),
                    required: parameter["required"].as_bool().unwrap_or(false),
                    serialization: ParameterSerialization {
                        style: parameter
                            .get("style")
                            .map(|v| {
                                v.as_str()
                                    .map(str::to_owned)
                                    .ok_or_else(|| anyhow::anyhow!("invalid parameter style"))
                            })
                            .transpose()?,
                        explode: parameter
                            .get("explode")
                            .map(|v| {
                                v.as_bool()
                                    .ok_or_else(|| anyhow::anyhow!("invalid parameter explode"))
                            })
                            .transpose()?,
                        collection_format: if spec.get("swagger").is_some() {
                            Some(
                                parameter
                                    .get("collectionFormat")
                                    .map(|v| {
                                        v.as_str().ok_or_else(|| {
                                            anyhow::anyhow!("invalid collection format")
                                        })
                                    })
                                    .transpose()?
                                    .unwrap_or("csv")
                                    .into(),
                            )
                        } else {
                            None
                        },
                        allow_reserved: parameter
                            .get("allowReserved")
                            .map(|v| {
                                v.as_bool()
                                    .ok_or_else(|| anyhow::anyhow!("invalid allowReserved"))
                            })
                            .transpose()?
                            .unwrap_or(false),
                    },
                    schema: parameter.get("schema").cloned().unwrap_or_else(|| {
                        let mut schema = parameter.clone();
                        // Swagger parameter requiredness is a boolean, while
                        // JSON Schema's required keyword lists object keys.
                        if let Some(object) = schema.as_object_mut() {
                            object.remove("required");
                        }
                        schema
                    }),
                });
            }
            // Azure DevOps publishes stable and preview operations in one document.
            // Its operation-level version is authoritative for the wire request.
            let version = match op.get("x-ms-docs-override-version") {
                Some(value) => {
                    let value = value
                        .as_str()
                        .filter(|value| {
                            !value.is_empty()
                                && value.len() <= 256
                                && value.bytes().all(|byte| {
                                    byte.is_ascii_alphanumeric() || b".-_".contains(&byte)
                                })
                        })
                        .ok_or_else(|| anyhow::anyhow!("invalid operation API version"))?;
                    Some(value.to_owned())
                }
                None => document_version.clone(),
            };
            let maturity_marker = |name: &str| -> Result<bool> {
                match op.get(name) {
                    None => Ok(false),
                    Some(value) => value
                        .as_bool()
                        .ok_or_else(|| anyhow::anyhow!("invalid operation maturity marker")),
                }
            };
            let declared_preview = maturity_marker("x-ms-preview")?;
            let deprecated = maturity_marker("deprecated")?;
            // Fabric also declares preview maturity in a leading Microsoft Learn note.
            let fabric_preview_note = product == "fabric"
                && op["description"].as_str().is_some_and(|description| {
                    let mut lines = description.trim_start().lines();
                    lines
                        .next()
                        .is_some_and(|line| line.trim().eq_ignore_ascii_case("> [!NOTE]"))
                        && lines
                            .flat_map(|line| {
                                line.trim_start().trim_start_matches('>').split_whitespace()
                            })
                            .take(8)
                            .collect::<Vec<_>>()
                            .join(" ")
                            .to_ascii_lowercase()
                            .eq("this api is part of a preview release")
                });
            let preview = fabric_preview_note
                || declared_preview
                || version.as_deref().is_some_and(|version| {
                    version.to_ascii_lowercase().contains("preview")
                        || version.eq_ignore_ascii_case("beta")
                });
            let mut request_body = op
                .get("requestBody")
                .map(|body| resolve_object(spec, body).cloned())
                .transpose()?;
            let body_parameters: Vec<_> =
                parameters.iter().filter(|p| p.location == "body").collect();
            if !body_parameters.is_empty() {
                if body_parameters.len() != 1 || request_body.is_some() {
                    bail!("conflicting request body definitions");
                }
                let parameter = body_parameters[0];
                let consumes = op.get("consumes").or(spec.get("consumes"));
                let media = match consumes {
                    None => "application/json",
                    Some(media) => {
                        let media = media.as_array().ok_or_else(|| {
                            anyhow::anyhow!("Swagger body requires a JSON media type")
                        })?;
                        // An empty list (Power BI) declares no restriction.
                        if media.is_empty() || media.iter().any(|m| m == "application/json") {
                            "application/json"
                        } else {
                            media
                                .iter()
                                .filter_map(Value::as_str)
                                .find(|m| junction_core::is_json_media_type(m))
                                .ok_or_else(|| {
                                    anyhow::anyhow!("Swagger body requires a JSON media type")
                                })?
                        }
                    }
                };
                request_body = Some(
                    json!({"required":parameter.required,"content":{media:{"schema":parameter.schema}}}),
                );
                parameters.retain(|p| p.location != "body");
            }
            let mut operation = JunctionOperation {
                id: graph_name
                    .as_ref()
                    .map(|name| name.id.clone())
                    .unwrap_or_else(|| {
                        format!(
                            "{}.{}.{}.{}",
                            canonical_component(product),
                            canonical_component(service),
                            canonical_component(resource),
                            canonical_component(action)
                        )
                    }),
                product: product.into(),
                service: graph_name
                    .as_ref()
                    .map(|name| name.service.clone())
                    .unwrap_or_else(|| service.into()),
                resource: graph_name
                    .as_ref()
                    .map(|name| name.resource.clone())
                    .unwrap_or_else(|| canonical_component(resource)),
                operation: graph_name
                    .as_ref()
                    .map(|name| name.action.clone())
                    .unwrap_or_else(|| canonical_component(action)),
                description: op["summary"]
                    .as_str()
                    .or(op["description"].as_str())
                    .unwrap_or("")
                    .into(),
                method: method.to_uppercase(),
                base_url: operation_base,
                endpoint_template: if uses_document_endpoint {
                    endpoint_template.clone()
                } else {
                    selected_template
                },
                path: path.clone(),
                pageable: pageable_metadata(op)?,
                query_continuation: continuation_index
                    .as_ref()
                    .map(|index| continuation::metadata(spec, item, op, index))
                    .transpose()?
                    .flatten(),
                api_version: version.clone(),
                parameters,
                request_body,
                responses: op["responses"].clone(),
                long_running: long_running_metadata(op)?,
                documentation_url: op
                    .get("externalDocs")
                    .or_else(|| spec.get("externalDocs"))
                    .and_then(|docs| docs.get("url"))
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                security: op
                    .get("security")
                    .or(spec.get("security"))
                    .cloned()
                    .unwrap_or(json!([])),
                risk: if path.to_lowercase().contains("conditionalaccess")
                    || (!matches!(method, "get" | "head" | "options")
                        && privileged_action(&canonical_action, &path))
                {
                    OperationRisk::Privileged
                } else {
                    match method {
                        "get" | "head" | "options" => OperationRisk::ReadOnly,
                        "delete" => OperationRisk::Destructive,
                        _ if destructive_action => OperationRisk::Destructive,
                        _ => OperationRisk::Write,
                    }
                },
                preview,
                maturity: if deprecated {
                    ApiMaturity::Deprecated
                } else if version.as_deref() == Some("beta") {
                    ApiMaturity::Beta
                } else if preview {
                    ApiMaturity::Preview
                } else {
                    ApiMaturity::Stable
                },
                source: SourceMetadata {
                    id: source.into(),
                    upstream: source.into(),
                    operation_id: upstream_id.into(),
                },
            };
            if operation.documentation().is_none() {
                operation.documentation_url = None;
            }
            if let Some(continuation) = &operation.query_continuation {
                continuation.validate(&operation)?;
            }
            operations.push(operation);
        }
    }
    operations.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(RegistryManifest {
        format_version: 1,
        operations,
        schemas: json!({"components":spec["components"], "definitions":spec["definitions"], "canonical": normalized,
            "x-junction-security-schemes": spec.get("securityDefinitions")
                .or_else(|| spec.pointer("/components/securitySchemes"))
                .cloned().unwrap_or_else(|| json!({}))}),
    })
}

/// OpenAPI servers override document defaults at path and operation level.
fn swagger_endpoint(spec: &Value) -> Result<Option<String>> {
    if spec.get("x-ms-parameterized-host").is_some() {
        let template = parameterized_swagger_template(spec)?;
        return if template
            .variables
            .values()
            .all(|variable| variable.default.is_some())
        {
            template.resolve(&BTreeMap::new()).map(Some)
        } else {
            Ok(Some(template.template.clone()))
        };
    }
    let Some(host) = spec.get("host") else {
        return Ok(None);
    };
    let host = host
        .as_str()
        .filter(|host| {
            !host.is_empty()
                && !host.contains(['/', '?', '#', '@', '\\', '{', '}'])
                && !host.chars().any(char::is_whitespace)
        })
        .ok_or_else(|| anyhow::anyhow!("invalid Swagger host"))?;
    let scheme = swagger_scheme(spec)?;
    let path = match spec.get("basePath") {
        None => "",
        Some(path) => path
            .as_str()
            .filter(|path| path.is_empty() || path.starts_with('/'))
            .ok_or_else(|| anyhow::anyhow!("invalid Swagger base path"))?,
    };
    server_endpoint(&json!({"servers":[{"url":format!("{scheme}://{host}{path}")}]}))
}

fn swagger_scheme(spec: &Value) -> Result<&'static str> {
    match spec.get("schemes") {
        None => Ok("https"),
        Some(schemes) => {
            let schemes = schemes
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("invalid Swagger schemes"))?;
            if schemes.iter().any(|scheme| scheme == "https") {
                Ok("https")
            } else if schemes.iter().any(|scheme| scheme == "http") {
                Ok("http")
            } else {
                bail!("unsupported Swagger scheme");
            }
        }
    }
}

fn parameterized_swagger_template(
    spec: &Value,
) -> Result<junction_core::endpoint::EndpointTemplate> {
    let extension = spec["x-ms-parameterized-host"]
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("invalid parameterized host"))?;
    let template = extension
        .get("hostTemplate")
        .and_then(Value::as_str)
        .filter(|template| !template.is_empty() && template.len() <= 16384)
        .ok_or_else(|| anyhow::anyhow!("invalid parameterized host template"))?;
    let prefix = match extension.get("useSchemePrefix") {
        None => true,
        Some(value) => value
            .as_bool()
            .ok_or_else(|| anyhow::anyhow!("invalid host scheme prefix"))?,
    };
    let parameters = extension
        .get("parameters")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("invalid host parameters"))?;
    let mut variables = BTreeMap::new();
    for parameter in parameters {
        let parameter = resolve_object(spec, parameter)?;
        let name = parameter["name"]
            .as_str()
            .filter(|name| !name.is_empty() && !name.contains(['{', '}']))
            .ok_or_else(|| anyhow::anyhow!("invalid host parameter name"))?;
        if parameter["in"] != "path" || parameter["type"] != "string" {
            bail!("host parameters must be path strings");
        }
        let default = parameter
            .get("default")
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow::anyhow!("host default must be a string"))
            })
            .transpose()?;
        let choices = parameter
            .get("enum")
            .map(|value| {
                serde_json::from_value::<Vec<String>>(value.clone())
                    .map_err(|_| anyhow::anyhow!("invalid host parameter choices"))
            })
            .transpose()?;
        let variable = junction_core::endpoint::EndpointVariable { default, choices };
        if variables.insert(name.into(), variable).is_some() {
            bail!("duplicate host parameter");
        }
    }
    let path = match spec.get("basePath") {
        None => "",
        Some(path) => path
            .as_str()
            .filter(|path| path.is_empty() || path.starts_with('/'))
            .ok_or_else(|| anyhow::anyhow!("invalid Swagger base path"))?,
    };
    // Reuse Swagger scheme selection and the common absolute-URL validator.
    let scheme = if prefix {
        format!("{}://", swagger_scheme(spec)?)
    } else {
        String::new()
    };
    let template = junction_core::endpoint::EndpointTemplate {
        template: format!("{scheme}{template}{path}"),
        variables,
    };
    template.validate()?;
    Ok(template)
}

fn server_endpoint(value: &Value) -> Result<Option<String>> {
    server_template(value)?
        .map(|template| template.resolve(&BTreeMap::new()))
        .transpose()
}

fn server_template(value: &Value) -> Result<Option<junction_core::endpoint::EndpointTemplate>> {
    let Some(servers) = value.get("servers") else {
        return Ok(None);
    };
    let servers = servers
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("invalid servers"))?;
    let Some(server) = servers.first() else {
        return Ok(None);
    };
    let template = server["url"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("invalid server URL"))?;
    let mut variables = BTreeMap::new();
    if let Some(declarations) = server.get("variables") {
        let declarations = declarations
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("invalid server variables"))?;
        for (name, declaration) in declarations {
            let default = declaration["default"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("server variable requires a string default"))?;
            let choices = declaration
                .get("enum")
                .map(|choices| {
                    serde_json::from_value::<Vec<String>>(choices.clone())
                        .map_err(|_| anyhow::anyhow!("invalid server variable choices"))
                })
                .transpose()?;
            variables.insert(
                name.clone(),
                junction_core::endpoint::EndpointVariable {
                    default: Some(default.into()),
                    choices,
                },
            );
        }
    }
    let template = junction_core::endpoint::EndpointTemplate {
        template: template.into(),
        variables,
    };
    template.validate()?;
    Ok(Some(template))
}

fn pageable_metadata(operation: &Value) -> Result<Option<junction_core::Pageable>> {
    let Some(metadata) = operation.get("x-ms-pageable") else {
        return Ok(None);
    };
    let metadata = metadata
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("invalid pageable metadata"))?;
    let item_name = match metadata.get("itemName") {
        None => "value",
        Some(value) => value
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("invalid pageable item field"))?,
    };
    let next_link_name = match metadata.get("nextLinkName") {
        Some(Value::Null) => None,
        Some(value) => Some(
            value
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("invalid pageable link field"))?
                .to_owned(),
        ),
        None => bail!("pageable metadata requires a next-link declaration"),
    };
    let operation_name = metadata
        .get("operationName")
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow::anyhow!("invalid pagination operation name"))
        })
        .transpose()?;
    let metadata = junction_core::Pageable {
        item_name: item_name.into(),
        next_link_name,
        operation_name,
    };
    metadata.validate()?;
    Ok(Some(metadata))
}

fn long_running_metadata(operation: &Value) -> Result<Option<junction_core::LongRunningOperation>> {
    let fabric = operation
        .get("x-ms-fabric-sdk-long-running-operation")
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| anyhow::anyhow!("invalid Fabric long-running marker"))
        })
        .transpose()?
        .unwrap_or(false);
    if fabric {
        if operation.get("x-ms-long-running-operation").is_some()
            || operation
                .get("x-ms-long-running-operation-options")
                .is_some()
        {
            bail!("conflicting long-running operation metadata");
        }
        return Ok(Some(junction_core::LongRunningOperation {
            protocol: Some(junction_core::LroProtocol::Fabric),
            ..Default::default()
        }));
    }
    let enabled = match operation.get("x-ms-long-running-operation") {
        None => false,
        Some(value) => value
            .as_bool()
            .ok_or_else(|| anyhow::anyhow!("invalid long-running operation marker"))?,
    };
    let options = operation.get("x-ms-long-running-operation-options");
    if !enabled {
        if options.is_some() {
            bail!("long-running options require an enabled operation marker");
        }
        return Ok(None);
    }
    let Some(options) = options else {
        return Ok(Some(Default::default()));
    };
    let options = options
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("invalid long-running operation options"))?;
    let final_state_via = options
        .get("final-state-via")
        .map(|value| {
            serde_json::from_value::<junction_core::LroFinalStateVia>(value.clone())
                .map_err(|_| anyhow::anyhow!("unsupported long-running final-state strategy"))
        })
        .transpose()?;
    let final_state_schema = options
        .get("final-state-schema")
        .map(|value| {
            let reference = value
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("invalid long-running final-state schema"))?;
            if !reference.starts_with("#/")
                || reference.len() > 4096
                || reference.chars().any(char::is_control)
            {
                bail!("long-running final-state schema must be a local reference");
            }
            Ok(reference.to_owned())
        })
        .transpose()?;
    Ok(Some(junction_core::LongRunningOperation {
        protocol: None,
        final_state_via,
        final_state_schema,
    }))
}

/// Resolve reference objects only. Schema references remain symbolic to support recursive types.
fn resolve_object<'a>(document: &'a Value, initial: &'a Value) -> Result<&'a Value> {
    let mut current = initial;
    let mut visited = BTreeSet::new();
    while let Some(reference) = current.get("$ref") {
        let reference = reference
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("reference must be string"))?;
        let pointer = reference
            .strip_prefix('#')
            .filter(|p| p.starts_with('/'))
            .ok_or_else(|| anyhow::anyhow!("external references require document loading"))?;
        if !visited.insert(reference) || visited.len() > 128 {
            bail!("reference cycle or depth limit");
        }
        current = document
            .pointer(pointer)
            .ok_or_else(|| anyhow::anyhow!("unresolved local reference"))?;
    }
    if !current.is_object() {
        bail!("reference object must resolve to object");
    }
    Ok(current)
}

pub mod sources;

/// Shared parser for fetched and local API definitions. JSON is also valid YAML,
/// but JSON-looking documents use serde_json's strict parser and recursion limit.
pub fn parse_document(bytes: &[u8]) -> Result<Value> {
    const MAX_DOCUMENT_BYTES: usize = 128 * 1024 * 1024;
    if bytes.len() > MAX_DOCUMENT_BYTES {
        bail!("API document exceeds size limit");
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| anyhow::anyhow!("API document must be UTF-8"))?;
    let text = text.trim_start_matches('\u{feff}');
    if text.trim_start().starts_with(['{', '[']) {
        serde_json::from_str(text).map_err(|_| anyhow::anyhow!("invalid JSON API document"))
    } else {
        let options = serde_saphyr::options! {
            strict_booleans: true,
            with_snippet: false,
            budget: serde_saphyr::budget! {
                max_nodes: 4_000_000,
                max_events: 8_000_000,
                max_total_scalar_bytes: MAX_DOCUMENT_BYTES,
                max_documents: 1,
            },
        };
        serde_saphyr::from_str_with_options(text, options)
            .map_err(|_| anyhow::anyhow!("invalid YAML API document or parser budget exceeded"))
    }
}

pub mod fetch;

/// Mutations that change security posture, run code on managed devices or
/// grant privileges. They require approval like destructive operations.
pub(crate) fn privileged_action(action: &str, path: &str) -> bool {
    let canonical = canonical_component(action);
    let canonical = canonical.strip_prefix("invoke_").unwrap_or(&canonical);
    let path = path.to_ascii_lowercase();
    [
        "isolate",
        "unisolate",
        "restrict_code_execution",
        "unrestrict_code_execution",
        "run_live_response",
        "runliveresponse",
        "stop_and_quarantine_file",
        "collect_investigation_package",
    ]
    .iter()
    .any(|verb| canonical == *verb || canonical.starts_with(&format!("{verb}_")))
        || [
            "roleassignment",
            "rolemanagement",
            "privilegedaccess",
            "roleeligibility",
        ]
        .iter()
        .any(|segment| path.contains(segment))
}

pub(crate) fn destructive_action(action: &str) -> bool {
    let canonical = canonical_component(action);
    let canonical = canonical.strip_prefix("invoke_").unwrap_or(&canonical);
    let mut words = canonical.split('_');
    let first = words.next().unwrap_or("");
    let verb = if first == "bulk" {
        words.next().unwrap_or("")
    } else {
        first
    };
    matches!(
        verb,
        "delete" | "remove" | "purge" | "erase" | "drop" | "truncate" | "offboard"
    )
}
