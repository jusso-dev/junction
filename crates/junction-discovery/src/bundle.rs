//! Bundle repository-relative OpenAPI references from explicitly supplied documents.
//! This module never reads files or follows URLs.
use anyhow::{Result, bail};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Traversal bound sized for the largest official documents: Graph beta's
/// 2026 OpenAPI exceeds 1.4 million schema nodes. The 512 MiB byte limits
/// still bound memory independently.
const MAX_TRAVERSAL_NODES: usize = 8_000_000;

/// Convert references into local definitions while preserving recursive schemas.
/// Paths are repository-relative; referenced documents must already be supplied.
pub fn bundle(entry: &str, documents: &BTreeMap<String, Value>) -> Result<Value> {
    Ok(process(entry, documents, false)?.0)
}
/// Identify missing repository documents, following references through supplied
/// dependencies. Missing fragments in present documents remain errors.
pub fn missing_documents(
    entry: &str,
    documents: &BTreeMap<String, Value>,
) -> Result<BTreeSet<String>> {
    Ok(process(entry, documents, true)?.1)
}
fn process(
    entry: &str,
    documents: &BTreeMap<String, Value>,
    allow_missing: bool,
) -> Result<(Value, BTreeSet<String>)> {
    if documents.is_empty() || documents.len() > 4096 {
        bail!("invalid bundle document count");
    }
    let mut total = 0usize;
    for (path, document) in documents {
        crate::sources::validate_source_path(path)?;
        let bytes = serde_json::to_vec(document)?.len();
        total = total.saturating_add(bytes);
        if bytes > 128 * 1024 * 1024 || total > 512 * 1024 * 1024 {
            bail!("bundle document byte limit exceeded");
        }
    }
    let mut root = documents
        .get(entry)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("bundle entry document missing"))?;
    if !root.is_object() {
        bail!("bundle entry must be an object");
    }
    let mut state = State {
        entry,
        documents,
        targets: BTreeMap::new(),
        pending: VecDeque::new(),
        nodes: 0,
        allow_missing,
        missing: BTreeSet::new(),
    };
    state.rewrite(&mut root, entry, 0)?;
    let mut output_bytes = serde_json::to_vec(&root)?.len();
    while let Some((path, pointer, section, name)) = state.pending.pop_front() {
        let original = documents
            .get(&path)
            .and_then(|document| document.pointer(&pointer))
            .ok_or_else(|| anyhow::anyhow!("unresolved bundle reference"))?;
        output_bytes = output_bytes.saturating_add(serde_json::to_vec(original)?.len());
        if output_bytes > 512 * 1024 * 1024 {
            bail!("bundle output byte limit exceeded");
        }
        let mut value = documents
            .get(&path)
            .and_then(|document| document.pointer(&pointer))
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unresolved bundle reference"))?;
        state.rewrite(&mut value, &path, 0)?;
        if section == "definitions" {
            if root.get("definitions").is_none() {
                root["definitions"] = json!({});
            }
            insert(&mut root["definitions"], &name, value)?;
        } else {
            if root.get("components").is_none() {
                root["components"] = json!({});
            }
            if !root["components"].is_object() {
                bail!("invalid bundle components");
            }
            if root["components"].get(&section).is_none() {
                root["components"][&section] = json!({});
            }
            insert(&mut root["components"][&section], &name, value)?;
        }
    }
    Ok((root, state.missing))
}
fn insert(section: &mut Value, name: &str, value: Value) -> Result<()> {
    let section = section
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("invalid bundle component section"))?;
    if section.insert(name.into(), value).is_some() {
        bail!("bundle namespace collision");
    }
    Ok(())
}
struct State<'a> {
    entry: &'a str,
    documents: &'a BTreeMap<String, Value>,
    targets: BTreeMap<(String, String), String>,
    pending: VecDeque<(String, String, String, String)>,
    nodes: usize,
    allow_missing: bool,
    missing: BTreeSet<String>,
}
impl State<'_> {
    fn reference(&mut self, reference: &str, origin: &str) -> Result<String> {
        let (path, pointer) = target(origin, reference)?;
        if !self.documents.contains_key(&path) && self.allow_missing {
            if self.missing.len() >= 4096 {
                bail!("bundle dependency limit exceeded");
            }
            self.missing.insert(path);
            return Ok(reference.into());
        }
        if self
            .documents
            .get(&path)
            .and_then(|document| document.pointer(&pointer))
            .is_none()
        {
            bail!("unresolved bundle reference");
        }
        if path == self.entry {
            return Ok(format!("#{pointer}"));
        }
        let key = (path.clone(), pointer.clone());
        if let Some(reference) = self.targets.get(&key) {
            return Ok(reference.clone());
        }
        if self.targets.len() >= 100_000 {
            bail!("bundle reference limit exceeded");
        }
        let (section, prefix) = section(&pointer)?;
        let name = format!(
            "junction_external_{:x}",
            Sha256::digest(serde_json::to_vec(&key)?)
        );
        let reference = format!("{prefix}{name}");
        self.targets.insert(key, reference.clone());
        self.pending
            .push_back((path, pointer, section.into(), name));
        Ok(reference)
    }
    fn rewrite(&mut self, value: &mut Value, origin: &str, depth: usize) -> Result<()> {
        self.nodes += 1;
        if depth > 128 || self.nodes > MAX_TRAVERSAL_NODES {
            bail!("bundle traversal limit exceeded");
        }
        match value {
            Value::Object(object) => {
                if object.contains_key("$id")
                    || object.contains_key("$anchor")
                    || object.contains_key("$dynamicRef")
                    || object.contains_key("$dynamicAnchor")
                {
                    bail!("schema URI and anchor semantics are not supported by bundling");
                }
                if let Some(reference) = object.get_mut("$ref") {
                    let raw = reference
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("bundle reference must be a string"))?;
                    *reference = json!(self.reference(raw, origin)?);
                }
                if let Some(mapping) = object
                    .get_mut("discriminator")
                    .and_then(|value| value.get_mut("mapping"))
                    .and_then(Value::as_object_mut)
                {
                    for value in mapping.values_mut() {
                        let raw = value
                            .as_str()
                            .ok_or_else(|| anyhow::anyhow!("invalid discriminator mapping"))?;
                        if raw.contains('#') {
                            *value = json!(self.reference(raw, origin)?);
                        } else {
                            bail!("discriminator mapping requires explicit reference");
                        }
                    }
                }
                for (key, value) in object {
                    if matches!(
                        key.as_str(),
                        "$ref" | "example" | "examples" | "default" | "enum" | "const"
                    ) || (key.starts_with("x-") && key != "x-ms-paths")
                    {
                        // Extensions are opaque except Azure's x-ms-paths, which
                        // ingestion imports as ordinary path items.
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
                            | "schemas"
                            | "parameters"
                            | "requestBodies"
                            | "securitySchemes"
                            | "links"
                            | "callbacks"
                            | "pathItems"
                    ) {
                        if let Some(entries) = value.as_object_mut() {
                            for value in entries.values_mut() {
                                self.rewrite(value, origin, depth + 1)?;
                            }
                        } else {
                            self.rewrite(value, origin, depth + 1)?;
                        }
                    } else {
                        self.rewrite(value, origin, depth + 1)?;
                    }
                }
            }
            Value::Array(values) => {
                for value in values {
                    self.rewrite(value, origin, depth + 1)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}
fn section(pointer: &str) -> Result<(&'static str, String)> {
    if pointer.starts_with("/definitions/") {
        return Ok(("definitions", "#/definitions/".into()));
    }
    for section in [
        "schemas",
        "parameters",
        "responses",
        "requestBodies",
        "headers",
        "securitySchemes",
        "examples",
        "links",
        "callbacks",
        "pathItems",
    ] {
        if pointer.starts_with(&format!("/components/{section}/")) {
            return Ok((section, format!("#/components/{section}/")));
        }
    }
    for section in ["parameters", "responses"] {
        if pointer.starts_with(&format!("/{section}/")) {
            return Ok((section, format!("#/components/{section}/")));
        }
    }
    bail!("unsupported external reference target")
}
fn target(origin: &str, reference: &str) -> Result<(String, String)> {
    if reference.len() > 4096
        || reference.contains(['%', '\\', ':', '?'])
        || reference.chars().any(char::is_control)
    {
        bail!("invalid repository reference");
    }
    let (relative, pointer) = reference
        .split_once('#')
        .ok_or_else(|| anyhow::anyhow!("reference requires a JSON pointer fragment"))?;
    if !pointer.starts_with('/') || pointer.contains('#') {
        bail!("invalid reference fragment");
    }
    // Reject invalid JSON pointer escapes instead of interpreting them inconsistently.
    for segment in pointer.split('/').skip(1) {
        let mut chars = segment.chars();
        while let Some(character) = chars.next() {
            if character == '~' && !matches!(chars.next(), Some('0' | '1')) {
                bail!("invalid reference fragment");
            }
        }
    }
    if relative.is_empty() {
        return Ok((origin.into(), pointer.into()));
    }
    if relative.starts_with('/') {
        bail!("repository reference must be relative");
    }
    let mut segments: Vec<&str> = origin.split('/').collect();
    segments.pop();
    for segment in relative.split('/') {
        match segment {
            "." => {}
            ".." => {
                if segments.pop().is_none() {
                    bail!("reference escapes repository root");
                }
            }
            "" => bail!("invalid repository reference"),
            value => segments.push(value),
        }
    }
    let path = segments.join("/");
    crate::sources::validate_source_path(&path)?;
    Ok((path, pointer.into()))
}
