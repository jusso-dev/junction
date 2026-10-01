//! Lossless schema metadata alongside a normalized type system for code generation.
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SchemaType {
    Any,
    Never,
    String {
        format: Option<StringFormat>,
    },
    Integer {
        format: Option<String>,
    },
    Number {
        format: Option<String>,
    },
    Boolean,
    Null,
    Enum {
        values: Vec<Value>,
        underlying: Box<SchemaType>,
    },
    Array {
        items: Box<SchemaType>,
    },
    Object {
        properties: BTreeMap<String, Property>,
        additional: Box<SchemaType>,
    },
    Union {
        variants: Vec<SchemaType>,
        exclusive: bool,
        discriminator: Option<Discriminator>,
    },
    Intersection {
        members: Vec<SchemaType>,
    },
    Nullable {
        value: Box<SchemaType>,
    },
    Reference {
        target: String,
    },
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StringFormat {
    Date,
    Timestamp,
    Duration,
    Uuid,
    Uri,
    Bytes,
    Binary,
    Other(String),
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Property {
    pub required: bool,
    pub schema: SchemaType,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Discriminator {
    pub property: String,
    pub mapping: BTreeMap<String, String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalSchema {
    pub schema_type: SchemaType,
    /// Original constraints and extensions are retained rather than silently dropped.
    pub original: Value,
}
impl CanonicalSchema {
    pub fn normalize(value: &Value) -> Result<Self> {
        Ok(Self {
            schema_type: normalize(value, 0)?,
            original: value.clone(),
        })
    }
}
const MAX_DEPTH: usize = 128;
fn normalize(value: &Value, depth: usize) -> Result<SchemaType> {
    if depth > MAX_DEPTH {
        bail!("schema nesting limit exceeded");
    }
    let recur = |v: &Value| normalize(v, depth + 1);
    if let Some(allowed) = value.as_bool() {
        return Ok(if allowed {
            SchemaType::Any
        } else {
            SchemaType::Never
        });
    }
    let Some(obj) = value.as_object() else {
        bail!("schema must be an object or boolean");
    };
    let mut members = Vec::new();
    if let Some(reference) = obj.get("$ref") {
        members.push(SchemaType::Reference {
            target: reference
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("reference must be a string"))?
                .into(),
        });
    }
    for (key, exclusive) in [("oneOf", true), ("anyOf", false)] {
        if let Some(variants) = obj.get(key) {
            let variants = variants
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("union must be an array"))?;
            if variants.is_empty() {
                bail!("empty union");
            }
            let discriminator = match obj.get("discriminator") {
                Some(Value::String(property)) => Some(Discriminator {
                    property: property.clone(),
                    mapping: BTreeMap::new(),
                }),
                Some(d) => Some(Discriminator {
                    property: d["propertyName"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("invalid discriminator"))?
                        .into(),
                    mapping: d
                        .get("mapping")
                        .map(|m| serde_json::from_value(m.clone()))
                        .transpose()?
                        .unwrap_or_default(),
                }),
                None => None,
            };
            members.push(SchemaType::Union {
                variants: variants.iter().map(recur).collect::<Result<_>>()?,
                exclusive,
                discriminator,
            });
        }
    }
    if let Some(all) = obj.get("allOf") {
        let all = all
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("intersection must be an array"))?;
        members.extend(all.iter().map(recur).collect::<Result<Vec<_>>>()?);
    }
    if let Some(types) = obj.get("type").and_then(Value::as_array) {
        if types.is_empty() {
            bail!("empty type array");
        }
        let variants = types
            .iter()
            .map(|t| {
                let mut branch = obj.clone();
                branch.insert("type".into(), t.clone());
                branch.remove("enum");
                branch.remove("nullable");
                branch.remove("oneOf");
                branch.remove("anyOf");
                branch.remove("allOf");
                branch.remove("$ref");
                recur(&Value::Object(branch))
            })
            .collect::<Result<Vec<_>>>()?;
        members.push(SchemaType::Union {
            variants,
            exclusive: false,
            discriminator: None,
        });
    } else {
        let kind = obj
            .get("type")
            .map(|t| {
                t.as_str()
                    .ok_or_else(|| anyhow::anyhow!("type must be string or array"))
            })
            .transpose()?;
        let kind = kind.or_else(|| {
            if obj.contains_key("properties") || obj.contains_key("additionalProperties") {
                Some("object")
            } else if obj.contains_key("items") {
                Some("array")
            } else {
                None
            }
        });
        if let Some(kind) = kind {
            let format = obj
                .get("format")
                .map(|f| {
                    f.as_str()
                        .ok_or_else(|| anyhow::anyhow!("format must be string"))
                })
                .transpose()?;
            let base = match kind {
                "string" => SchemaType::String {
                    format: format.map(|f| match f {
                        "date" => StringFormat::Date,
                        "date-time" => StringFormat::Timestamp,
                        "duration" => StringFormat::Duration,
                        "uuid" => StringFormat::Uuid,
                        "uri" | "url" => StringFormat::Uri,
                        "byte" => StringFormat::Bytes,
                        "binary" => StringFormat::Binary,
                        other => StringFormat::Other(other.into()),
                    }),
                },
                "integer" => SchemaType::Integer {
                    format: format.map(str::to_owned),
                },
                "number" => SchemaType::Number {
                    format: format.map(str::to_owned),
                },
                "boolean" => SchemaType::Boolean,
                "null" => SchemaType::Null,
                "array" => SchemaType::Array {
                    items: Box::new(
                        obj.get("items")
                            .map(recur)
                            .transpose()?
                            .unwrap_or(SchemaType::Any),
                    ),
                },
                "object" => {
                    let required: Vec<String> = obj
                        .get("required")
                        .map(|r| serde_json::from_value(r.clone()))
                        .transpose()?
                        .unwrap_or_default();
                    let mut properties = BTreeMap::new();
                    if let Some(props) = obj.get("properties") {
                        for (name, schema) in props
                            .as_object()
                            .ok_or_else(|| anyhow::anyhow!("properties must be object"))?
                        {
                            properties.insert(
                                name.clone(),
                                Property {
                                    required: required.contains(name),
                                    schema: recur(schema)?,
                                },
                            );
                        }
                    }
                    // Required fields may be defined by allOf; do not synthesize or discard them.
                    SchemaType::Object {
                        properties,
                        additional: Box::new(
                            obj.get("additionalProperties")
                                .map(recur)
                                .transpose()?
                                .unwrap_or(SchemaType::Any),
                        ),
                    }
                }
                _ => bail!("unsupported schema type"),
            };
            members.push(base);
        }
    }
    let mut result = match members.len() {
        0 => SchemaType::Any,
        1 => members.remove(0),
        _ => SchemaType::Intersection { members },
    };
    if let Some(values) = obj.get("enum") {
        let values = values
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("enum must be array"))?;
        result = SchemaType::Enum {
            values: values.clone(),
            underlying: Box::new(result),
        };
    }
    if obj
        .get("nullable")
        .or(obj.get("x-nullable"))
        .and_then(Value::as_bool)
        == Some(true)
    {
        result = SchemaType::Nullable {
            value: Box::new(result),
        };
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn microsoft_extensions_and_constraints_are_retained() {
        let value = json!({"type":"string","format":"uuid","nullable":true,"enum":["a"],"x-ms-enum":{"name":"Id"},"maxLength":32});
        let schema = CanonicalSchema::normalize(&value).unwrap();
        assert_eq!(schema.original, value);
        assert!(matches!(schema.schema_type, SchemaType::Nullable { .. }));
    }
    #[test]
    fn maps_arrays_required_and_references() {
        let schema = CanonicalSchema::normalize(&json!({"type":"object","required":["items"],"properties":{"items":{"type":"array","items":{"$ref":"#/components/schemas/Item"}}},"additionalProperties":{"type":"integer"}})).unwrap();
        let SchemaType::Object {
            properties,
            additional,
        } = schema.schema_type
        else {
            panic!()
        };
        assert!(properties["items"].required);
        assert!(matches!(*additional, SchemaType::Integer { .. }));
        let SchemaType::Array { items } = &properties["items"].schema else {
            panic!()
        };
        assert!(matches!(**items, SchemaType::Reference { .. }));
    }
    #[test]
    fn discriminated_union_and_reference_siblings() {
        let schema = CanonicalSchema::normalize(&json!({"oneOf":[{"$ref":"#/A"},{"$ref":"#/B"}],"discriminator":{"propertyName":"kind","mapping":{"a":"#/A"}}})).unwrap();
        let SchemaType::Union {
            exclusive,
            discriminator,
            ..
        } = schema.schema_type
        else {
            panic!()
        };
        assert!(exclusive);
        assert_eq!(discriminator.unwrap().mapping["a"], "#/A");
        assert!(matches!(
            CanonicalSchema::normalize(&json!({"$ref":"#/A","type":"object"}))
                .unwrap()
                .schema_type,
            SchemaType::Intersection { .. }
        ));
    }
    #[test]
    fn json_schema_null_union_and_boolean_schemas() {
        assert!(matches!(
            CanonicalSchema::normalize(&json!({"type":["string","null"]}))
                .unwrap()
                .schema_type,
            SchemaType::Union { .. }
        ));
        assert_eq!(
            CanonicalSchema::normalize(&json!(false))
                .unwrap()
                .schema_type,
            SchemaType::Never
        );
        assert!(CanonicalSchema::normalize(&json!({"type":"unknown"})).is_err());
        assert!(CanonicalSchema::normalize(&json!({"oneOf":[]})).is_err());
    }
}

/// Compile and validate local JSON Schema without network or filesystem resolvers.
/// OpenAPI dialect adaptation must run before this for nullable/exclusive keywords.
pub fn validate_json_schema(schema: &Value, instance: &Value) -> Result<()> {
    let validator = jsonschema::options()
        .should_validate_formats(true)
        .build(schema)
        .map_err(|_| anyhow::anyhow!("invalid or unresolved validation schema"))?;
    if !validator.is_valid(instance) {
        bail!("input_schema_violation");
    }
    Ok(())
}
#[cfg(test)]
mod validation_tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn constraints_and_local_references_are_enforced() {
        let schema = json!({"type":"object","required":["count","id"],"additionalProperties":false,"properties":{"count":{"type":"integer","minimum":1,"maximum":10},"id":{"$ref":"#/$defs/id"}},"$defs":{"id":{"type":"string","format":"uuid"}}});
        assert!(
            validate_json_schema(
                &schema,
                &json!({"count":2,"id":"550e8400-e29b-41d4-a716-446655440000"})
            )
            .is_ok()
        );
        for value in [
            json!({"count":0,"id":"bad"}),
            json!({"count":2}),
            json!({"count":2,"id":"sensitive"}),
            json!({"count":"2","id":"bad"}),
        ] {
            let error = validate_json_schema(&schema, &value)
                .unwrap_err()
                .to_string();
            assert_eq!(error, "input_schema_violation");
            assert!(!error.contains("sensitive"));
        }
    }
    #[test]
    fn external_references_are_not_fetched() {
        for reference in [
            "https://example.invalid/schema",
            "file:///tmp/credential.json",
        ] {
            assert!(validate_json_schema(&json!({"$ref":reference}), &json!({})).is_err());
        }
    }
}

/// Translate Swagger 2/OpenAPI 3.0 schema keywords to JSON Schema 2020-12.
/// Only schema-bearing keywords are traversed; examples/defaults remain literal data.
pub fn adapt_openapi_schema(schema: &Value) -> Result<Value> {
    fn adapt(schema: &Value, depth: usize) -> Result<Value> {
        if depth > MAX_DEPTH {
            bail!("schema nesting limit exceeded");
        }
        if schema.is_boolean() {
            return Ok(schema.clone());
        }
        let mut obj = schema
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("invalid schema"))?
            .clone();
        for key in ["properties", "patternProperties", "$defs", "definitions"] {
            if let Some(map) = obj.get_mut(key) {
                for value in map
                    .as_object_mut()
                    .ok_or_else(|| anyhow::anyhow!("invalid schema map"))?
                    .values_mut()
                {
                    *value = adapt(value, depth + 1)?;
                }
            }
        }
        for key in [
            "items",
            "additionalProperties",
            "not",
            "contains",
            "if",
            "then",
            "else",
            "propertyNames",
        ] {
            if let Some(value) = obj.get_mut(key) {
                *value = adapt(value, depth + 1)?;
            }
        }
        for key in ["allOf", "anyOf", "oneOf", "prefixItems"] {
            if let Some(values) = obj.get_mut(key) {
                for value in values
                    .as_array_mut()
                    .ok_or_else(|| anyhow::anyhow!("invalid schema list"))?
                {
                    *value = adapt(value, depth + 1)?;
                }
            }
        }
        for (exclusive, bound) in [
            ("exclusiveMinimum", "minimum"),
            ("exclusiveMaximum", "maximum"),
        ] {
            if let Some(flag) = obj.get(exclusive).and_then(Value::as_bool) {
                obj.remove(exclusive);
                if flag {
                    let value = obj
                        .remove(bound)
                        .ok_or_else(|| anyhow::anyhow!("exclusive bound missing value"))?;
                    if !value.is_number() {
                        bail!("exclusive bound must be numeric");
                    }
                    obj.insert(exclusive.into(), value);
                }
            }
        }
        let nullable = obj.remove("nullable").or_else(|| obj.remove("x-nullable"));
        if let Some(nullable) = nullable {
            let flag = nullable
                .as_bool()
                .ok_or_else(|| anyhow::anyhow!("nullable must be boolean"))?;
            if flag {
                return Ok(serde_json::json!({"anyOf":[obj,{"type":"null"}]}));
            }
        }
        Ok(Value::Object(obj))
    }
    adapt(schema, 0)
}
pub fn validate_openapi_schema(schema: &Value, instance: &Value) -> Result<()> {
    validate_json_schema(&adapt_openapi_schema(schema)?, instance)
}
#[cfg(test)]
mod dialect_tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn nullable_and_exclusive_bounds_work_recursively() {
        let schema = json!({"type":"object","properties":{"score":{"type":"number","minimum":0,"exclusiveMinimum":true,"maximum":10,"exclusiveMaximum":false,"nullable":true}}});
        for value in [
            json!({"score":null}),
            json!({"score":1}),
            json!({"score":10}),
        ] {
            assert!(validate_openapi_schema(&schema, &value).is_ok());
        }
        for value in [
            json!({"score":0}),
            json!({"score":11}),
            json!({"score":"1"}),
        ] {
            assert!(validate_openapi_schema(&schema, &value).is_err());
        }
    }
    #[test]
    fn annotations_are_data_and_numeric_exclusivity_is_preserved() {
        let schema = json!({"type":"number","exclusiveMinimum":2,"default":{"nullable":true},"example":{"exclusiveMinimum":true}});
        let adapted = adapt_openapi_schema(&schema).unwrap();
        assert_eq!(adapted["default"], schema["default"]);
        assert_eq!(adapted["example"], schema["example"]);
        assert!(validate_openapi_schema(&schema, &json!(2)).is_err());
        assert!(validate_openapi_schema(&schema, &json!(3)).is_ok());
        assert!(adapt_openapi_schema(&json!({"exclusiveMinimum":true})).is_err());
    }
}

/// Bind an operation schema to retained OpenAPI definitions without inlining cycles.
pub fn validate_with_definitions(
    schema: &Value,
    definitions: &Value,
    instance: &Value,
) -> Result<()> {
    let mut document = serde_json::json!({"allOf":[adapt_openapi_schema(schema)?]});
    if let Some(schemas) = definitions.get("definitions").filter(|v| !v.is_null()) {
        let map = schemas
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("invalid definitions"))?;
        let converted = map
            .iter()
            .map(|(name, value)| Ok((name.clone(), adapt_openapi_schema(value)?)))
            .collect::<Result<serde_json::Map<String, Value>>>()?;
        document["definitions"] = Value::Object(converted);
    }
    if let Some(schemas) = definitions
        .pointer("/components/schemas")
        .filter(|v| !v.is_null())
    {
        let map = schemas
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("invalid components schemas"))?;
        let converted = map
            .iter()
            .map(|(name, value)| Ok((name.clone(), adapt_openapi_schema(value)?)))
            .collect::<Result<serde_json::Map<String, Value>>>()?;
        document["components"] = serde_json::json!({"schemas":converted});
    }
    validate_json_schema(&document, instance)
}
#[cfg(test)]
mod definition_tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn recursive_registry_definitions_validate_without_inlining() {
        let definitions = json!({"components":{"schemas":{"Node":{"type":"object","required":["name"],"properties":{"name":{"type":"string"},"child":{"$ref":"#/components/schemas/Node"}}}}}});
        let schema = json!({"$ref":"#/components/schemas/Node"});
        assert!(
            validate_with_definitions(
                &schema,
                &definitions,
                &json!({"name":"root","child":{"name":"leaf"}})
            )
            .is_ok()
        );
        assert!(
            validate_with_definitions(&schema, &definitions, &json!({"name":"root","child":{}}))
                .is_err()
        );
        assert!(validate_with_definitions(&schema, &json!({}), &json!({"name":"root"})).is_err());
    }
    #[test]
    fn swagger_definitions_keep_nullable_semantics() {
        let definitions = json!({"definitions":{"Label":{"type":"string","x-nullable":true}}});
        assert!(
            validate_with_definitions(
                &json!({"$ref":"#/definitions/Label"}),
                &definitions,
                &Value::Null
            )
            .is_ok()
        );
        assert!(
            validate_with_definitions(
                &json!({"$ref":"#/definitions/Label"}),
                &definitions,
                &json!(42)
            )
            .is_err()
        );
    }
}
