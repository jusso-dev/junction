use anyhow::{Result, bail};
use junction_core::JunctionOperation;
use serde_json::{Value, json};
use std::collections::BTreeSet;

/// Build the executor envelope and retain only its reachable local schema definitions.
pub fn build(operation: &JunctionOperation, definitions: &Value) -> Result<Value> {
    let mut properties = serde_json::Map::new();
    let mut required = BTreeSet::new();
    for parameter in &operation.parameters {
        let mut schema = junction_schema::adapt_openapi_schema(&parameter.schema)?;
        if parameter.name == "api-version" && parameter.location == "query" {
            let version = operation
                .api_version
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing API version"))?;
            schema = json!({"allOf":[schema,{"const":version}]});
        }
        if properties.contains_key(&parameter.name) {
            let previous = properties.remove(&parameter.name).unwrap();
            schema = json!({"allOf":[previous,schema]});
        }
        properties.insert(parameter.name.clone(), schema);
        if parameter.required && parameter.name != "api-version" {
            required.insert(parameter.name.clone());
        }
    }
    let parameters_required = !required.is_empty();
    let mut envelope = json!({"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"properties":{"parameters":{"type":"object","additionalProperties":false,"properties":properties,"required":required}},"required":[]});
    let mut required_envelope = Vec::new();
    if parameters_required {
        required_envelope.push("parameters");
    }
    if let Some(body) = &operation.request_body {
        let schema = body
            .pointer("/content/application~1json/schema")
            .ok_or_else(|| anyhow::anyhow!("unsupported request body schema"))?;
        envelope["properties"]["body"] = junction_schema::adapt_openapi_schema(schema)?;
        if body["required"].as_bool() == Some(true) {
            required_envelope.push("body");
        }
    }
    envelope["required"] = json!(required_envelope);
    let mut pending = BTreeSet::new();
    collect(&envelope, &mut pending, 0)?;
    let mut included = BTreeSet::new();
    while let Some(reference) = pending.pop_first() {
        let path = reference
            .strip_prefix('#')
            .ok_or_else(|| anyhow::anyhow!("external schema references unsupported"))?;
        if definitions.pointer(path).is_none() {
            bail!("missing schema reference");
        }
        let segments: Vec<_> = path.split('/').collect();
        let root = if segments.len() >= 3 && segments[1] == "definitions" {
            format!("/definitions/{}", segments[2])
        } else if segments.len() >= 4 && segments[1..3] == ["components", "schemas"] {
            format!("/components/schemas/{}", segments[3])
        } else {
            bail!("unsupported schema reference");
        };
        if !included.insert(root.clone()) {
            continue;
        }
        if included.len() > 4096 {
            bail!("schema reference limit exceeded");
        }
        let definition = definitions
            .pointer(&root)
            .ok_or_else(|| anyhow::anyhow!("missing schema reference"))?;
        let converted = junction_schema::adapt_openapi_schema(definition)?;
        collect(&converted, &mut pending, 0)?;
        let name = root
            .rsplit('/')
            .next()
            .unwrap()
            .replace("~1", "/")
            .replace("~0", "~");
        if root.starts_with("/definitions/") {
            if envelope.get("definitions").is_none() {
                envelope["definitions"] = json!({});
            }
            envelope["definitions"][name] = converted;
        } else {
            if envelope.get("components").is_none() {
                envelope["components"] = json!({"schemas":{}});
            }
            envelope["components"]["schemas"][name] = converted;
        }
    }
    Ok(envelope)
}
fn collect(value: &Value, references: &mut BTreeSet<String>, depth: usize) -> Result<()> {
    if depth > 128 {
        bail!("schema depth limit exceeded");
    }
    let Some(object) = value.as_object() else {
        return Ok(());
    };
    if let Some(reference) = object.get("$ref") {
        let reference = reference
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("invalid schema reference"))?;
        references.insert(reference.to_owned());
    }
    // Traverse schema positions, never annotation/example data or property names.
    for key in [
        "properties",
        "patternProperties",
        "$defs",
        "definitions",
        "dependentSchemas",
    ] {
        if let Some(children) = object.get(key).and_then(Value::as_object) {
            for child in children.values() {
                collect(child, references, depth + 1)?;
            }
        }
    }
    for key in [
        "items",
        "additionalItems",
        "additionalProperties",
        "contains",
        "not",
        "if",
        "then",
        "else",
        "propertyNames",
        "unevaluatedItems",
        "unevaluatedProperties",
    ] {
        if let Some(child) = object.get(key) {
            if let Some(children) = child.as_array() {
                for child in children {
                    collect(child, references, depth + 1)?;
                }
            } else {
                collect(child, references, depth + 1)?;
            }
        }
    }
    for key in ["allOf", "anyOf", "oneOf", "prefixItems"] {
        if let Some(children) = object.get(key).and_then(Value::as_array) {
            for child in children {
                collect(child, references, depth + 1)?;
            }
        }
    }
    Ok(())
}
