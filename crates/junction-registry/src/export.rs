//! Export the selected catalogue as one OpenAPI 3.1 document. Swagger 2
//! conventions retained by ingestion (`#/definitions/` references, response
//! `schema`) are converted; only schemas reachable from exported operations
//! are included.
use crate::Registry;
use anyhow::{Result, bail};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub struct ExportOptions<'a> {
    pub product: Option<&'a str>,
    pub service: Option<&'a str>,
    pub allow_preview: bool,
    pub max_operations: usize,
}

fn rewrite_references(value: &mut Value, found: &mut BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            if let Some(Value::String(reference)) = object.get_mut("$ref") {
                for prefix in ["#/definitions/", "#/components/schemas/"] {
                    if let Some(name) = reference.strip_prefix(prefix) {
                        let name = name.to_owned();
                        *reference = format!("#/components/schemas/{name}");
                        found.insert(name);
                        break;
                    }
                }
            }
            for child in object.values_mut() {
                rewrite_references(child, found);
            }
        }
        Value::Array(items) => {
            for child in items {
                rewrite_references(child, found);
            }
        }
        _ => {}
    }
}

fn response(value: &Value) -> Value {
    let mut out = Map::new();
    out.insert(
        "description".into(),
        value
            .get("description")
            .cloned()
            .unwrap_or_else(|| json!("Response")),
    );
    if let Some(content) = value.get("content") {
        out.insert("content".into(), content.clone());
    } else if let Some(schema) = value.get("schema") {
        out.insert(
            "content".into(),
            json!({"application/json": {"schema": schema}}),
        );
    }
    if let Some(headers) = value.get("headers") {
        out.insert("headers".into(), headers.clone());
    }
    Value::Object(out)
}

impl Registry {
    pub fn export_openapi(&self, options: &ExportOptions<'_>) -> Result<Value> {
        let selected: Vec<_> = self
            .operations
            .keys()
            .filter_map(|id| self.resolve(id, None, options.allow_preview).ok())
            .filter(|operation| {
                options
                    .product
                    .is_none_or(|product| operation.product == product)
                    && options
                        .service
                        .is_none_or(|service| operation.service == service)
            })
            .collect();
        if selected.is_empty() {
            bail!("no operations match the export filter");
        }
        if selected.len() > options.max_operations {
            bail!("export exceeds the operation limit; narrow it with --product or --service");
        }
        let mut paths: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
        let mut referenced = BTreeSet::new();
        let mut skipped = Vec::new();
        for operation in selected {
            let base = url::Url::parse(&operation.base_url).ok();
            let (origin, prefix) = match &base {
                Some(url) => (
                    url.origin().ascii_serialization(),
                    url.path().trim_end_matches('/').to_owned(),
                ),
                None => (operation.base_url.clone(), String::new()),
            };
            let path = format!("{prefix}{}", operation.path);
            let method = operation.method.to_ascii_lowercase();
            let entry = paths.entry(path).or_default();
            if entry.contains_key(&method) {
                skipped.push(json!(operation.id));
                continue;
            }
            let parameters: Vec<Value> = operation
                .parameters
                .iter()
                .map(|parameter| {
                    let mut value = json!({
                        "name": parameter.name,
                        "in": parameter.location,
                        "required": parameter.required,
                        "schema": parameter.schema,
                    });
                    if let Some(style) = &parameter.serialization.style {
                        value["style"] = json!(style);
                    }
                    if let Some(explode) = parameter.serialization.explode {
                        value["explode"] = json!(explode);
                    }
                    value
                })
                .collect();
            let mut value = json!({
                "operationId": operation.id,
                "summary": operation.description.chars().take(300).collect::<String>(),
                "tags": [format!("{}.{}", operation.product, operation.service)],
                "servers": [{"url": origin}],
                "parameters": parameters,
                "x-junction-risk": operation.risk,
                "x-junction-source": operation.source,
            });
            if let Some(version) = &operation.api_version {
                value["x-junction-api-version"] = json!(version);
            }
            if let Some(body) = &operation.request_body {
                value["requestBody"] = body.clone();
            }
            let responses: Map<String, Value> = operation
                .responses
                .as_object()
                .map(|responses| {
                    responses
                        .iter()
                        .map(|(code, value)| (code.clone(), response(value)))
                        .collect()
                })
                .unwrap_or_default();
            value["responses"] = if responses.is_empty() {
                json!({"default": {"description": "Response"}})
            } else {
                Value::Object(responses)
            };
            if let Some(security) = operation.security.as_array().filter(|s| !s.is_empty()) {
                value["security"] = json!(security);
            }
            if let Some(url) = operation.documentation() {
                value["externalDocs"] = json!({"url": url});
            }
            rewrite_references(&mut value, &mut referenced);
            entry.insert(method, value);
        }
        // Copy the transitive closure of referenced schemas.
        let mut available = Map::new();
        for section in [
            self.schemas.pointer("/components/schemas"),
            self.schemas.get("definitions"),
        ]
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        {
            for (name, schema) in section {
                available
                    .entry(name.clone())
                    .or_insert_with(|| schema.clone());
            }
        }
        let mut schemas = Map::new();
        let mut queue: VecDeque<String> = referenced.into_iter().collect();
        while let Some(name) = queue.pop_front() {
            if schemas.contains_key(&name) {
                continue;
            }
            let Some(mut schema) = available.get(&name).cloned() else {
                continue;
            };
            let mut nested = BTreeSet::new();
            rewrite_references(&mut schema, &mut nested);
            queue.extend(nested.into_iter().filter(|n| !schemas.contains_key(n)));
            schemas.insert(name, schema);
        }
        let mut security_schemes = self
            .schemas
            .pointer("/components/securitySchemes")
            .cloned()
            .unwrap_or_else(|| json!({}));
        rewrite_references(&mut security_schemes, &mut BTreeSet::new());
        Ok(json!({
            "openapi": "3.1.0",
            "info": {
                "title": "Junction catalogue export",
                "version": env!("CARGO_PKG_VERSION"),
                "description": "Generated by Junction from Microsoft's public API definitions and documentation. Junction is independent of Microsoft; use of these APIs is governed by Microsoft's terms of service. Operation IDs are Junction canonical IDs.",
            },
            "paths": paths,
            "components": {"schemas": schemas, "securitySchemes": security_schemes},
            "x-junction-skipped-duplicates": skipped,
        }))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    #[test]
    fn export_rewrites_swagger_references_and_keeps_only_reachable_schemas() {
        let operation = json!({"id":"azure.items.items.get","product":"azure","service":"items",
            "resource":"items","operation":"get","description":"Get item","method":"GET",
            "base_url":"https://management.azure.com","path":"/items/{id}",
            "api_version":"2025-01-01","parameters":[{"name":"id","location":"path","required":true,"schema":{"type":"string"}}],
            "request_body":null,"responses":{"200":{"description":"ok","schema":{"$ref":"#/definitions/Item"}}},
            "security":[],"risk":"read_only","preview":false,
            "source":{"id":"official","upstream":"official","operation_id":"Items_Get"}});
        let registry = crate::Registry::load(
            serde_json::from_value(json!({
                "format_version":1,"operations":[operation],
                "schemas":{"definitions":{
                    "Item":{"type":"object","properties":{"child":{"$ref":"#/definitions/Child"}}},
                    "Child":{"type":"string"},
                    "Unused":{"type":"integer"}
                }}
            }))
            .unwrap(),
        )
        .unwrap();
        let document = registry
            .export_openapi(&super::ExportOptions {
                product: Some("azure"),
                service: None,
                allow_preview: false,
                max_operations: 10,
            })
            .unwrap();
        let get = &document["paths"]["/items/{id}"]["get"];
        assert_eq!(get["operationId"], "azure.items.items.get");
        assert_eq!(get["servers"][0]["url"], "https://management.azure.com");
        assert_eq!(
            get["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/Item"
        );
        let schemas = document["components"]["schemas"].as_object().unwrap();
        assert!(schemas.contains_key("Item") && schemas.contains_key("Child"));
        assert!(!schemas.contains_key("Unused"));
        assert_eq!(
            schemas["Item"]["properties"]["child"]["$ref"],
            "#/components/schemas/Child"
        );
        assert!(
            registry
                .export_openapi(&super::ExportOptions {
                    product: Some("graph"),
                    service: None,
                    allow_preview: false,
                    max_operations: 10
                })
                .is_err()
        );
    }
}
