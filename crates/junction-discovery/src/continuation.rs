use anyhow::{Result, bail};
use junction_core::QueryContinuation;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const MARKER: &str = "x-ms-list-continuation-token";
pub(super) fn has_markers(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.contains_key(MARKER) || object.values().any(has_markers),
        Value::Array(values) => values.iter().any(has_markers),
        _ => false,
    }
}

// Compute reference reachability once per document. Reverse propagation handles
// recursive schemas without mistaking a cycle for an unmarked schema.
pub(super) struct MarkerIndex {
    references: BTreeSet<String>,
}
impl MarkerIndex {
    pub(super) fn new(spec: &Value) -> Self {
        let mut pending = references(spec);
        let mut seen = BTreeSet::new();
        let mut marked = BTreeSet::new();
        let mut parents: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        while let Some(reference) = pending.pop_first() {
            if !seen.insert(reference.clone()) {
                continue;
            }
            let Some(target) = reference
                .strip_prefix('#')
                .and_then(|path| spec.pointer(path))
            else {
                continue;
            };
            if has_markers(target) {
                marked.insert(reference.clone());
            }
            for child in references(target) {
                parents
                    .entry(child.clone())
                    .or_default()
                    .insert(reference.clone());
                if !seen.contains(&child) {
                    pending.insert(child);
                }
            }
        }
        let mut pending = marked.clone();
        while let Some(reference) = pending.pop_first() {
            for parent in parents.get(&reference).into_iter().flatten() {
                if marked.insert(parent.clone()) {
                    pending.insert(parent.clone());
                }
            }
        }
        Self { references: marked }
    }
    fn relevant(&self, schema: &Value) -> bool {
        has_markers(schema)
            || references(schema)
                .iter()
                .any(|reference| self.references.contains(reference))
    }
}
fn references(value: &Value) -> BTreeSet<String> {
    let mut result = BTreeSet::new();
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::Object(object) => {
                if let Some(reference) = object.get("$ref").and_then(Value::as_str)
                    && reference.starts_with("#/")
                {
                    result.insert(reference.to_owned());
                }
                pending.extend(object.values());
            }
            Value::Array(values) => pending.extend(values),
            _ => {}
        }
    }
    result
}

fn marked(value: &Value) -> Result<bool> {
    value
        .get(MARKER)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| anyhow::anyhow!("invalid continuation token marker"))
        })
        .transpose()
        .map(|value| value.unwrap_or(false))
}
fn string_schema(spec: &Value, schema: &Value) -> Result<bool> {
    let schema = super::resolve_object(spec, schema)?;
    Ok(schema["type"] == "string"
        || schema["type"].as_array().is_some_and(|types| {
            types.iter().any(|kind| kind == "string")
                && types.iter().all(|kind| kind == "string" || kind == "null")
        }))
}
pub(super) fn metadata(
    spec: &Value,
    item: &Value,
    operation: &Value,
    index: &MarkerIndex,
) -> Result<Option<QueryContinuation>> {
    let mut effective = BTreeMap::new();
    for parameter in item["parameters"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(operation["parameters"].as_array().into_iter().flatten())
    {
        let parameter = super::resolve_object(spec, parameter)?;
        effective.insert(
            (
                parameter["name"].as_str().unwrap_or(""),
                parameter["in"].as_str().unwrap_or(""),
            ),
            parameter,
        );
    }
    let mut requests = Vec::new();
    for ((name, location), parameter) in effective {
        if marked(parameter)? {
            if location != "query"
                || !string_schema(spec, parameter.get("schema").unwrap_or(parameter))?
            {
                bail!("continuation token requires a string query parameter");
            }
            requests.push(name.to_owned());
        }
    }
    let mut paths = BTreeSet::new();
    let mut nodes = 0usize;
    for (status, response) in operation["responses"].as_object().into_iter().flatten() {
        if status.len() != 3 || !status.starts_with('2') {
            continue;
        }
        let response = match super::resolve_object(spec, response) {
            Ok(response) => response,
            Err(error) if requests.is_empty() && !marked(response)? => {
                let _ = error;
                continue;
            }
            Err(error) => return Err(error),
        };
        if let Some(schema) = response
            .get("schema")
            .or_else(|| response.pointer("/content/application~1json/schema"))
        {
            if requests.is_empty() && !index.relevant(schema) {
                continue;
            }
            walk(
                spec,
                schema,
                "",
                &mut BTreeSet::new(),
                &mut paths,
                &mut nodes,
                0,
                !requests.is_empty(),
            )?;
        }
    }
    if requests.is_empty() && paths.is_empty() {
        return Ok(None);
    }
    if requests.len() != 1 || paths.len() != 1 {
        bail!("continuation token markers must identify one paired request and response");
    }
    Ok(Some(QueryContinuation {
        query_parameter: requests.remove(0),
        response_pointer: paths.into_iter().next().unwrap(),
    }))
}
#[allow(clippy::too_many_arguments)]
fn walk(
    spec: &Value,
    schema: &Value,
    path: &str,
    active: &mut BTreeSet<String>,
    paths: &mut BTreeSet<String>,
    nodes: &mut usize,
    depth: usize,
    strict: bool,
) -> Result<()> {
    if !schema.is_object() {
        return Ok(());
    }
    *nodes += 1;
    if *nodes > 4096 || depth > 32 {
        bail!("continuation schema traversal limit exceeded");
    }
    let reference = schema["$ref"].as_str();
    if reference.is_some_and(|reference| !reference.starts_with("#/")) {
        if strict || marked(schema)? {
            bail!("unresolved continuation schema reference");
        }
        return Ok(());
    }
    if reference.is_some_and(|reference| !active.insert(reference.to_owned())) {
        return Ok(());
    }
    let resolved = match super::resolve_object(spec, schema) {
        Ok(resolved) => resolved,
        Err(error) if !strict && !marked(schema)? => {
            let _ = error;
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    if marked(schema)? || marked(resolved)? {
        if path.is_empty() || !string_schema(spec, resolved)? {
            bail!("continuation response marker requires a string property");
        }
        paths.insert(path.to_owned());
    }
    for (name, property) in resolved["properties"].as_object().into_iter().flatten() {
        let segment = name.replace('~', "~0").replace('/', "~1");
        walk(
            spec,
            property,
            &format!("{path}/{segment}"),
            active,
            paths,
            nodes,
            depth + 1,
            strict,
        )?;
    }
    for composition in ["allOf", "oneOf", "anyOf"] {
        for branch in resolved[composition].as_array().into_iter().flatten() {
            walk(spec, branch, path, active, paths, nodes, depth + 1, strict)?;
        }
    }
    if let Some(reference) = reference {
        active.remove(reference);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn marker_reachability_propagates_through_aliases_and_cycles() {
        let spec = json!({"responses":[{"$ref":"#/definitions/Alias"},{"$ref":"#/definitions/Unrelated"}],"definitions":{
            "A":{"properties":{"b":{"$ref":"#/definitions/B"}}},
            "B":{"properties":{"a":{"$ref":"#/definitions/A"},"token":{
                "type":"string","x-ms-list-continuation-token":true}}},
            "Alias":{"$ref":"#/definitions/A"},
            "Unrelated":{"properties":{"value":{"type":"string"}}}
        }});
        let index = MarkerIndex::new(&spec);
        for name in ["A", "B", "Alias"] {
            assert!(index.relevant(&json!({"$ref":format!("#/definitions/{name}")})));
        }
        assert!(!index.relevant(&json!({"$ref":"#/definitions/Unrelated"})));
        assert!(!index.relevant(&json!({"$ref":"external.json#/Page"})));
    }
}
