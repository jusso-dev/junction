use anyhow::{Result, bail};
use junction_core::Parameter;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::Value;

pub(crate) fn scalar(value: &Value) -> Result<String> {
    match value {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Bool(b) => Ok(b.to_string()),
        _ => bail!("parameter requires a scalar value"),
    }
}
pub(crate) fn encode(value: &str) -> String {
    utf8_percent_encode(value, NON_ALPHANUMERIC).to_string()
}
/// Remove one omitted optional alias from the static function argument list.
pub(crate) fn omit_odata_alias(path: &str, parameter: &Parameter) -> Result<String> {
    let name = parameter
        .name
        .strip_prefix('@')
        .filter(|name| {
            !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
        .ok_or_else(|| anyhow::anyhow!("invalid OData alias name"))?;
    let (prefix, segment) = path
        .rsplit_once('/')
        .ok_or_else(|| anyhow::anyhow!("invalid OData function path"))?;
    let (function, arguments) = segment
        .split_once('(')
        .ok_or_else(|| anyhow::anyhow!("missing OData function arguments"))?;
    let arguments = arguments
        .strip_suffix(')')
        .ok_or_else(|| anyhow::anyhow!("invalid OData function arguments"))?;
    let omitted = format!("{name}=@{name}");
    let values = arguments.split(',').collect::<Vec<_>>();
    if values.iter().filter(|value| **value == omitted).count() != 1 {
        bail!("optional OData alias has no unique path argument");
    }
    Ok(format!(
        "{prefix}/{function}({})",
        values
            .into_iter()
            .filter(|value| *value != omitted)
            .collect::<Vec<_>>()
            .join(",")
    ))
}
/// Returns already encoded name/value pairs. Delimiters remain distinct from escaped data.
pub(crate) fn query(parameter: &Parameter, value: &Value) -> Result<Vec<(String, String)>> {
    let metadata = &parameter.serialization;
    if metadata.allow_reserved {
        bail!("allowReserved serialization not implemented");
    }
    let style = metadata.style.as_deref().unwrap_or("form");
    if style == "odata" {
        if metadata.explode == Some(true)
            || metadata.collection_format.is_some()
            || !parameter.name.starts_with('@')
        {
            bail!("invalid OData alias serialization metadata");
        }
        return Ok(vec![(
            encode(&parameter.name),
            encode(&odata_literal(
                value,
                parameter.schema["x-junction-odata-literal"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("OData literal type is missing"))?,
            )?),
        )]);
    }
    let explode = metadata.explode.unwrap_or(style == "form");
    let name = encode(&parameter.name);
    let array = match value {
        Value::Array(items) => Some(
            items
                .iter()
                .map(|item| scalar(item).map(|v| encode(&v)))
                .collect::<Result<Vec<_>>>()?,
        ),
        _ => None,
    };
    if let Some(format) = metadata.collection_format.as_deref() {
        if let Some(values) = array {
            let delimiter = match format {
                "csv" => ",",
                "ssv" => "%20",
                "tsv" => "%09",
                "pipes" => "|",
                "multi" => return Ok(values.into_iter().map(|v| (name.clone(), v)).collect()),
                _ => bail!("unsupported collection format"),
            };
            return Ok(vec![(name, values.join(delimiter))]);
        }
        return Ok(vec![(name, encode(&scalar(value)?))]);
    }
    match (style, value) {
        ("form", Value::Array(_)) if explode => Ok(array
            .unwrap()
            .into_iter()
            .map(|v| (name.clone(), v))
            .collect()),
        ("form", Value::Array(_)) => Ok(vec![(name, array.unwrap().join(","))]),
        ("spaceDelimited", Value::Array(_)) if !explode => {
            Ok(vec![(name, array.unwrap().join("%20"))])
        }
        ("pipeDelimited", Value::Array(_)) if !explode => {
            Ok(vec![(name, array.unwrap().join("|"))])
        }
        ("form", Value::Object(properties)) => {
            let entries = properties
                .iter()
                .map(|(k, v)| scalar(v).map(|v| (encode(k), encode(&v))))
                .collect::<Result<Vec<_>>>()?;
            if explode {
                Ok(entries)
            } else {
                Ok(vec![(
                    name,
                    entries
                        .into_iter()
                        .flat_map(|(k, v)| [k, v])
                        .collect::<Vec<_>>()
                        .join(","),
                )])
            }
        }
        ("deepObject", Value::Object(properties)) if explode => properties
            .iter()
            .map(|(key, value)| {
                Ok((
                    format!("{name}%5B{}%5D", encode(key)),
                    encode(&scalar(value)?),
                ))
            })
            .collect(),
        ("form", _) => Ok(vec![(name, encode(&scalar(value)?))]),
        _ => bail!("unsupported query serialization"),
    }
}
/// Quote data before URI encoding; caller values never become OData expressions.
fn odata_literal(value: &Value, kind: &str) -> Result<String> {
    if value.is_null() {
        return Ok("null".into());
    }
    let quoted = |value: &str| format!("'{}'", value.replace('\'', "''"));
    match (kind, value) {
        ("Edm.String", Value::String(value)) => Ok(quoted(value)),
        ("Edm.Boolean", Value::Bool(value)) => Ok(value.to_string()),
        (
            "Edm.Byte" | "Edm.SByte" | "Edm.Int16" | "Edm.Int32" | "Edm.Int64" | "Edm.Decimal"
            | "Edm.Single" | "Edm.Double",
            Value::Number(value),
        ) => Ok(value.to_string()),
        ("Edm.Int64" | "Edm.Decimal", Value::String(value))
            if !value.is_empty()
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b"-.".contains(&b)) =>
        {
            Ok(value.clone())
        }
        ("Edm.Single" | "Edm.Double", Value::String(value))
            if ["INF", "-INF", "NaN"].contains(&value.as_str()) =>
        {
            Ok(value.clone())
        }
        (
            "Edm.Guid" | "Edm.Date" | "Edm.DateTimeOffset" | "Edm.TimeOfDay",
            Value::String(value),
        ) if !value.is_empty()
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || b"abcdefABCDEF-.:+TZ".contains(&b)) =>
        {
            Ok(value.clone())
        }
        ("Edm.Binary", Value::String(value))
            if value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_=".contains(&b)) =>
        {
            Ok(format!("binary{}", quoted(value)))
        }
        ("Edm.Duration", Value::String(value)) => Ok(format!("duration{}", quoted(value))),
        ("json", Value::Array(_) | Value::Object(_)) => Ok(serde_json::to_string(value)?),
        (kind, Value::String(value)) if kind.starts_with("enum:") => {
            let name = &kind[5..];
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._".contains(&b))
            {
                bail!("invalid OData enum literal metadata");
            }
            Ok(format!("{name}{}", quoted(value)))
        }
        _ => bail!("unsupported OData literal type or value"),
    }
}
pub(crate) fn header(parameter: &Parameter, value: &Value) -> Result<String> {
    if parameter
        .serialization
        .style
        .as_deref()
        .is_some_and(|style| style != "simple")
    {
        bail!("unsupported header style");
    }
    if parameter
        .serialization
        .collection_format
        .as_deref()
        .is_some_and(|format| format != "csv")
    {
        bail!("unsupported header collection format");
    }
    match value {
        Value::Array(values) => values
            .iter()
            .map(scalar)
            .collect::<Result<Vec<_>>>()
            .map(|v| v.join(",")),
        Value::Object(_) => bail!("object header serialization not implemented"),
        _ => scalar(value),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn parameter(serialization: Value) -> Parameter {
        serde_json::from_value(json!({"name":"$select","location":"query","required":false,"schema":{},"serialization":serialization})).unwrap()
    }
    #[test]
    fn delimiters_cannot_be_injected_through_array_values() {
        assert_eq!(
            query(
                &parameter(json!({"explode":false})),
                &json!(["a,b", "c&x=1"])
            )
            .unwrap(),
            [("%24select".into(), "a%2Cb,c%26x%3D1".into())]
        );
        assert_eq!(
            query(&parameter(json!({})), &json!(["a", "b"])).unwrap(),
            [
                ("%24select".into(), "a".into()),
                ("%24select".into(), "b".into())
            ]
        );
        assert_eq!(
            query(
                &parameter(json!({"collection_format":"pipes"})),
                &json!(["a|b", "c"])
            )
            .unwrap()[0]
                .1,
            "a%7Cb|c"
        );
    }
    #[test]
    fn flat_object_styles_and_unsupported_nested_values() {
        assert_eq!(
            query(
                &parameter(json!({"style":"deepObject","explode":true})),
                &json!({"x":"a&b"})
            )
            .unwrap(),
            [("%24select%5Bx%5D".into(), "a%26b".into())]
        );
        assert!(
            query(
                &parameter(json!({"style":"deepObject","explode":true})),
                &json!({"x":[1,2]})
            )
            .is_err()
        );
        assert!(
            query(
                &parameter(json!({"allow_reserved":true})),
                &json!("x&admin=true")
            )
            .is_err()
        );
    }
    #[test]
    fn csdl_count_and_search_queries_encode_data_without_adding_query_fields() {
        let registry = junction_registry::Registry::load(
            junction_discovery::odata::ingest(
                include_bytes!("../../junction-discovery/tests/fixtures/odata.xml"),
                "graph",
                "directory",
                "official",
                "https://graph.microsoft.com/v1.0",
                "v1.0",
            )
            .unwrap(),
        )
        .unwrap();
        let operation = registry.resolve("graph.users.list", None, false).unwrap();
        let policy = junction_policy::Policy::default();
        let plan = |input: &Value| {
            crate::prepare_with_schemas(
                operation,
                input,
                "tenant-a",
                "https://graph.microsoft.com/v1.0",
                &policy,
                registry.schemas(),
            )
        };
        for count in [true, false] {
            let request = plan(
                &json!({"parameters":{"$count":count,"$search":"\"quoted phrase\" &admin=true"}}),
            )
            .unwrap();
            let pairs = request
                .url
                .query_pairs()
                .collect::<std::collections::BTreeMap<_, _>>();
            assert_eq!(pairs.len(), 2);
            assert_eq!(pairs["$count"], count.to_string());
            assert_eq!(pairs["$search"], "\"quoted phrase\" &admin=true");
        }
        for value in [json!("true"), json!(1), json!(null)] {
            assert!(plan(&json!({"parameters":{"$count":value}})).is_err());
        }
    }

    #[test]
    fn csdl_query_capabilities_reject_unsupported_and_missing_options_before_transport() {
        let xml = std::str::from_utf8(include_bytes!("../../junction-discovery/tests/fixtures/odata.xml")).unwrap().replace(r#"<EntitySet Name="users" EntityType="self.User"/>"#, r#"<EntitySet Name="users" EntityType="self.User"><Annotation Term="Caps.TopSupported" Bool="false"/><Annotation Term="Caps.FilterRestrictions"><Record><PropertyValue Property="RequiresFilter" Bool="true"/></Record></Annotation></EntitySet>"#);
        let registry = junction_registry::Registry::load(
            junction_discovery::odata::ingest(
                xml.as_bytes(),
                "graph",
                "directory",
                "official",
                "https://graph.microsoft.com/v1.0",
                "v1.0",
            )
            .unwrap(),
        )
        .unwrap();
        let operation = registry.resolve("graph.users.list", None, false).unwrap();
        let policy = junction_policy::Policy::default();
        let plan = |input: &Value| {
            crate::prepare_with_schemas(
                operation,
                input,
                "tenant-a",
                "https://graph.microsoft.com/v1.0",
                &policy,
                registry.schemas(),
            )
        };
        for input in [
            json!({}),
            json!({"parameters":{"$filter":""}}),
            json!({"parameters":{"$filter":"name eq 'a'","$top":2}}),
        ] {
            assert!(plan(&input).is_err());
        }
        let request = plan(&json!({"parameters":{"$filter":"name eq 'a'"}})).unwrap();
        assert_eq!(
            request.url.query_pairs().collect::<Vec<_>>(),
            vec![("$filter".into(), "name eq 'a'".into())]
        );
    }

    #[test]
    fn csdl_key_reads_use_validated_literals_and_static_paths() {
        let xml = std::str::from_utf8(include_bytes!(
            "../../junction-discovery/tests/fixtures/odata.xml"
        ))
        .unwrap()
        .replace(
            "Type=\"Edm.Guid\" Nullable=\"false\"",
            "Type=\"Edm.String\" Nullable=\"false\" MaxLength=\"40\"",
        );
        let manifest = junction_discovery::odata::ingest(
            xml.as_bytes(),
            "graph",
            "directory",
            "official",
            "https://graph.microsoft.com/v1.0",
            "v1.0",
        )
        .unwrap();
        let registry = junction_registry::Registry::load(manifest).unwrap();
        let operation = registry.resolve("graph.users.get", None, false).unwrap();
        let policy = junction_policy::Policy::default();
        let plan = |input: &Value| {
            crate::prepare_with_schemas(
                operation,
                input,
                "tenant-a",
                "https://graph.microsoft.com/v1.0",
                &policy,
                registry.schemas(),
            )
        };
        let request =
            plan(&json!({"parameters":{"@id":"O'Brien/&admin=true","$select":"name"}})).unwrap();
        assert_eq!(request.url.path(), "/v1.0/users(@id)");
        let pairs = request
            .url
            .query_pairs()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(pairs["@id"], "'O''Brien/&admin=true'");
        assert_eq!(pairs["$select"], "name");
        assert_eq!(pairs.len(), 2);
        let reports = registry
            .resolve("graph.users.reports.list", None, false)
            .unwrap();
        let request = crate::prepare_with_schemas(
            reports,
            &json!({"parameters":{"@id":"O'Brien/&admin=true","$top":2}}),
            "tenant-a",
            "https://graph.microsoft.com/v1.0",
            &policy,
            registry.schemas(),
        )
        .unwrap();
        assert_eq!(request.url.path(), "/v1.0/users(@id)/reports");
        let pairs = request
            .url
            .query_pairs()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(pairs["@id"], "'O''Brien/&admin=true'");
        assert_eq!(pairs["$top"], "2");
        assert_eq!(pairs.len(), 2);
        assert!(
            crate::prepare_with_schemas(
                reports,
                &json!({"parameters":{"$top":2}}),
                "tenant-a",
                "https://graph.microsoft.com/v1.0",
                &policy,
                registry.schemas()
            )
            .is_err()
        );
        for input in [
            json!({}),
            json!({"parameters":{"@id":null}}),
            json!({"parameters":{"@id":1}}),
            json!({"parameters":{"@id":"x".repeat(41)}}),
        ] {
            assert!(plan(&input).is_err());
        }
    }

    #[test]
    fn imported_functions_use_typed_aliases_without_expression_or_query_injection() {
        let xml = include_str!("../../junction-discovery/tests/fixtures/odata.xml").replace(
            "<EntityContainer Name=\"Service\">",
            r#"
              <Function Name="Find">
                <Parameter Name="term" Type="Edm.String" Nullable="false"/>
                <Parameter Name="count" Type="Edm.Int32" Nullable="false"/>
                <Parameter Name="tags" Type="Collection(Edm.String)" Nullable="false"/>
                <Parameter Name="address" Type="self.Address" Nullable="false"/>
                <Parameter Name="state" Type="self.State" Nullable="false"/>
                <ReturnType Type="Collection(self.User)" Nullable="false"/>
              </Function>
              <Function Name="Version"><ReturnType Type="Edm.String" Nullable="false"/></Function>
              <EntityContainer Name="Service">
                <FunctionImport Name="find" Function="self.Find"/>
                <FunctionImport Name="version" Function="self.Version"/>
            "#,
        );
        let manifest = junction_discovery::odata::ingest(
            xml.as_bytes(),
            "graph",
            "directory",
            "official",
            "https://graph.microsoft.com/v1.0",
            "v1.0",
        )
        .unwrap();
        let registry = junction_registry::Registry::load(manifest).unwrap();
        let operation = registry
            .resolve(
                "graph.find.invoke_by_address_count_state_tags_term",
                None,
                false,
            )
            .unwrap();
        let input = json!({"parameters":{"@term":"O'Brien'&admin=true","@count":2,"@tags":["red","O'Brien","x&y"],"@address":{"city":"Canberra"},"@state":"healthy"}});
        let request = crate::prepare_with_schemas(
            operation,
            &input,
            "tenant-a",
            "https://graph.microsoft.com/v1.0",
            &junction_policy::Policy::default(),
            registry.schemas(),
        )
        .unwrap();
        let pairs = request
            .url
            .query_pairs()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(pairs.len(), 5);
        assert_eq!(pairs["@term"], "'O''Brien''&admin=true'");
        assert_eq!(pairs["@count"], "2");
        assert_eq!(pairs["@tags"], r#"["red","O'Brien","x&y"]"#);
        assert_eq!(pairs["@address"], r#"{"city":"Canberra"}"#);
        assert_eq!(pairs["@state"], "Demo.State'healthy'");
        assert_eq!(
            request.url.path(),
            "/v1.0/find(address=@address,count=@count,state=@state,tags=@tags,term=@term)"
        );
        let mut invalid = input.clone();
        invalid["parameters"]["@count"] = json!("1 or true");
        assert!(
            crate::prepare_with_schemas(
                operation,
                &invalid,
                "tenant-a",
                "https://graph.microsoft.com/v1.0",
                &junction_policy::Policy::default(),
                registry.schemas()
            )
            .is_err()
        );
        let version = registry
            .resolve("graph.version.invoke", None, false)
            .unwrap();
        assert_eq!(
            crate::prepare(
                version,
                &json!({}),
                "tenant-a",
                "https://graph.microsoft.com/v1.0",
                &junction_policy::Policy::default()
            )
            .unwrap()
            .url
            .path(),
            "/v1.0/version()"
        );
    }
    #[test]
    fn odata_literals_reject_unsupported_values_and_escape_quoted_values() {
        assert_eq!(odata_literal(&json!(true), "Edm.Boolean").unwrap(), "true");
        assert_eq!(odata_literal(&json!(null), "Edm.String").unwrap(), "null");
        assert_eq!(
            odata_literal(&json!("9223372036854775807"), "Edm.Int64").unwrap(),
            "9223372036854775807"
        );
        assert_eq!(
            odata_literal(&json!("P1D'&x=1"), "Edm.Duration").unwrap(),
            "duration'P1D''&x=1'"
        );
        assert!(odata_literal(&json!("true or false"), "Edm.Boolean").is_err());
        assert!(odata_literal(&json!("1&admin=true"), "Edm.Decimal").is_err());
        assert!(odata_literal(&json!("guid' or true"), "Edm.Guid").is_err());
        assert!(odata_literal(&json!("x"), "enum:private'bad").is_err());
        assert!(odata_literal(&json!("x"), "unknown").is_err());
    }
    #[test]
    fn optional_csdl_parameters_preserve_omission_null_and_service_defaults() {
        let xml = include_str!("../../junction-discovery/tests/fixtures/odata.xml")
            .replace("<edmx:Include Namespace=\"Org.OData.Capabilities.V1\" Alias=\"Caps\" />",r#"<edmx:Include Namespace="Org.OData.Capabilities.V1" Alias="Caps"/><edmx:Include Namespace="Org.OData.Core.V1" Alias="Core"/>"#)
            .replace("<EntityContainer Name=\"Service\">",r#"
                <Function Name="OptionalFind">
                  <Parameter Name="term" Type="Edm.String" Nullable="false"/>
                  <Parameter Name="limit" Type="Edm.Int32" Nullable="false"><Annotation Term="Core.OptionalParameter"><Record><PropertyValue Property="DefaultValue" String="10"/></Record></Annotation></Parameter>
                  <Parameter Name="suffix" Type="Edm.String"><Annotation Term="Core.OptionalParameter"><Record/></Annotation></Parameter>
                  <ReturnType Type="Collection(self.User)" Nullable="false"/>
                </Function>
                <Action Name="OptionalReset">
                  <Parameter Name="term" Type="Edm.String" Nullable="false"/>
                  <Parameter Name="limit" Type="Edm.Int32" Nullable="false"><Annotation Term="Core.OptionalParameter"><Record><PropertyValue Property="DefaultValue"><String>10</String></PropertyValue></Record></Annotation></Parameter>
                </Action>
                <EntityContainer Name="Service">
                  <FunctionImport Name="findOptional" Function="self.OptionalFind"/>
                  <ActionImport Name="resetOptional" Action="self.OptionalReset"/>
            "#);
        let manifest = junction_discovery::odata::ingest(
            xml.as_bytes(),
            "graph",
            "directory",
            "official",
            "https://graph.microsoft.com/v1.0",
            "v1.0",
        )
        .unwrap();
        let registry = junction_registry::Registry::load(manifest).unwrap();
        let operation = registry
            .resolve(
                "graph.find_optional.invoke_by_limit_suffix_term",
                None,
                false,
            )
            .unwrap();
        let policy = junction_policy::Policy::default();
        let plan = |input: &Value| {
            crate::prepare_with_schemas(
                operation,
                input,
                "tenant-a",
                "https://graph.microsoft.com/v1.0",
                &policy,
                registry.schemas(),
            )
        };
        let request = plan(&json!({"parameters":{"@term":"actual"}})).unwrap();
        assert_eq!(request.url.path(), "/v1.0/findOptional(term=@term)");
        assert_eq!(request.url.query_pairs().count(), 1);
        assert!(!request.url.as_str().contains("10"));
        let request =
            plan(&json!({"parameters":{"@term":"actual","@suffix":null,"@limit":0}})).unwrap();
        let pairs = request
            .url
            .query_pairs()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(pairs["@suffix"], "null");
        assert_eq!(pairs["@limit"], "0");
        assert!(plan(&json!({"parameters":{"@term":"actual","@limit":null}})).is_err());
        assert!(plan(&json!({"parameters":{}})).is_err());
        let schema = registry.input_schema(&operation.id, None, false).unwrap();
        junction_schema::validate_json_schema(&schema, &json!({"parameters":{"@term":"actual"}}))
            .unwrap();
        assert_eq!(
            operation
                .parameters
                .iter()
                .find(|parameter| parameter.name == "@limit")
                .unwrap()
                .schema["x-odata-optional-parameter"]["default_value_literal"],
            "10"
        );
        let reset = registry
            .resolve("graph.reset_optional.invoke", None, false)
            .unwrap();
        let write_policy = junction_policy::Policy::parse("[agent]\nmode='safe-write'\n").unwrap();
        let reset_input = json!({"body":{"term":"actual"}});
        let reset_request = crate::prepare_with_schemas(
            reset,
            &reset_input,
            "tenant-a",
            "https://graph.microsoft.com/v1.0",
            &write_policy,
            registry.schemas(),
        )
        .unwrap();
        assert_eq!(reset_request.body, Some(reset_input["body"].clone()));
        let reset_schema = registry.input_schema(&reset.id, None, false).unwrap();
        junction_schema::validate_json_schema(&reset_schema, &reset_input).unwrap();
        assert!(
            crate::prepare_with_schemas(
                reset,
                &reset_input,
                "tenant-a",
                "https://graph.microsoft.com/v1.0",
                &policy,
                registry.schemas()
            )
            .is_err()
        );
    }
}
