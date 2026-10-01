//! Combine independently imported documents without sharing their schema namespaces.
use anyhow::{Result, bail};
use junction_core::RegistryManifest;
use junction_schema::CanonicalSchema;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Identical imports are deduplicated; conflicting operation/version pairs fail.
/// Namespace identifiers are derived from document content, independent of input order.
pub fn merge(manifests: Vec<RegistryManifest>) -> Result<RegistryManifest> {
    if manifests.is_empty() || manifests.len() > 4096 {
        bail!("merge requires between one and 4096 manifests");
    }
    let mut documents = BTreeMap::new();
    for manifest in manifests {
        if manifest.format_version != 1 {
            bail!("unsupported manifest format");
        }
        let digest = format!("{:x}", Sha256::digest(serde_json::to_vec(&manifest)?));
        documents.entry(digest).or_insert(manifest);
    }
    let mut schemas = json!({"components":{},"definitions":{},"canonical":{}});
    let mut operations = Vec::new();
    let mut versions = BTreeSet::new();
    for (namespace, manifest) in documents {
        // Keep document-level provenance and extension metadata in its own
        // namespace. Metadata is literal data, so schema rewrites never touch it.
        let mut metadata = serde_json::Map::new();
        if let Some(root) = manifest.schemas.as_object() {
            for (name, value) in root {
                if name.starts_with("x-") {
                    metadata.insert(name.clone(), value.clone());
                }
            }
        }
        if let Some(components) = manifest
            .schemas
            .get("components")
            .and_then(Value::as_object)
        {
            let extensions: serde_json::Map<String, Value> = components
                .iter()
                .filter(|(name, _)| name.starts_with("x-"))
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect();
            if !extensions.is_empty() {
                metadata.insert("components".into(), Value::Object(extensions));
            }
        }
        if !metadata.is_empty() {
            if schemas.get("x-junction-import-metadata").is_none() {
                schemas["x-junction-import-metadata"] = json!({});
            }
            schemas["x-junction-import-metadata"][&namespace] = Value::Object(metadata);
        }
        let mut references = BTreeMap::new();
        let mut sections = Vec::new();
        if let Some(components) = manifest
            .schemas
            .get("components")
            .filter(|value| !value.is_null())
        {
            let components = components
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("invalid manifest components"))?;
            for (section, entries) in components {
                if section.starts_with("x-") {
                    continue;
                }
                let entries = entries
                    .as_object()
                    .ok_or_else(|| anyhow::anyhow!("invalid manifest component section"))?;
                sections.push((
                    format!("#/components/{}/", escape(section)),
                    section.clone(),
                    entries,
                ));
            }
        }
        if let Some(definitions) = manifest
            .schemas
            .get("definitions")
            .filter(|value| !value.is_null())
        {
            sections.push((
                "#/definitions/".into(),
                "definitions".into(),
                definitions
                    .as_object()
                    .ok_or_else(|| anyhow::anyhow!("invalid manifest definitions"))?,
            ));
        }
        for (prefix, _, entries) in &sections {
            for name in entries.keys() {
                references.insert(
                    format!("{prefix}{}", escape(name)),
                    format!("{prefix}{}", escape(&format!("{namespace}.{name}"))),
                );
            }
        }
        for (prefix, section, entries) in sections {
            for (name, schema) in entries {
                let mut schema = schema.clone();
                rewrite(&mut schema, &references);
                let name = format!("{namespace}.{name}");
                if section == "definitions" {
                    schemas["definitions"][&name] = schema.clone();
                } else {
                    if schemas["components"].get(&section).is_none() {
                        schemas["components"][&section] = json!({});
                    }
                    schemas["components"][&section][&name] = schema.clone();
                }
                if section == "schemas" || section == "definitions" {
                    schemas["canonical"][format!("{prefix}{}", escape(&name))] =
                        serde_json::to_value(CanonicalSchema::normalize(&schema)?)?;
                }
            }
        }
        for mut operation in manifest.operations {
            if !versions.insert((operation.id.clone(), operation.api_version.clone())) {
                bail!("duplicate operation/version in merged manifests");
            }
            if operations.len() >= 1_000_000 {
                bail!("merged operation limit exceeded");
            }
            for parameter in &mut operation.parameters {
                rewrite(&mut parameter.schema, &references);
            }
            if let Some(body) = &mut operation.request_body {
                rewrite(body, &references);
            }
            if let Some(responses) = operation.responses.as_object_mut() {
                for response in responses.values_mut() {
                    rewrite(response, &references);
                }
            }
            operations.push(operation);
        }
    }
    operations.sort_by(|a, b| {
        a.id.cmp(&b.id)
            .then_with(|| a.api_version.cmp(&b.api_version))
    });
    Ok(RegistryManifest {
        format_version: 1,
        operations,
        schemas,
    })
}
fn escape(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}
fn replacement(reference: &str, references: &BTreeMap<String, String>) -> Option<String> {
    if let Some(value) = references.get(reference) {
        return Some(value.clone());
    }
    references.iter().find_map(|(old, new)| {
        reference
            .strip_prefix(old)
            .filter(|suffix| suffix.starts_with('/'))
            .map(|suffix| format!("{new}{suffix}"))
    })
}
fn rewrite(value: &mut Value, references: &BTreeMap<String, String>) {
    match value {
        Value::Object(object) => {
            if let Some(reference) = object.get_mut("$ref")
                && let Some(replacement) = reference
                    .as_str()
                    .and_then(|value| replacement(value, references))
            {
                *reference = json!(replacement);
            }
            if let Some(mapping) = object
                .get_mut("discriminator")
                .and_then(|value| value.get_mut("mapping"))
                .and_then(Value::as_object_mut)
            {
                for target in mapping.values_mut() {
                    if let Some(replacement) = target
                        .as_str()
                        .and_then(|value| replacement(value, references))
                    {
                        *target = json!(replacement);
                    }
                }
            }
            for (key, value) in object {
                if matches!(
                    key.as_str(),
                    "example" | "examples" | "default" | "enum" | "const" | "$ref"
                ) || key.starts_with("x-")
                {
                    continue;
                }
                if matches!(
                    key.as_str(),
                    "properties"
                        | "patternProperties"
                        | "$defs"
                        | "definitions"
                        | "headers"
                        | "responses"
                ) {
                    if let Some(properties) = value.as_object_mut() {
                        for schema in properties.values_mut() {
                            rewrite(schema, references);
                        }
                    }
                } else {
                    rewrite(value, references);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                rewrite(value, references);
            }
        }
        _ => {}
    }
}
