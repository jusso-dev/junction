//! Native OData 4.x CSDL XML ingestion. External references are never fetched.
use anyhow::{Result, bail};
use junction_core::RegistryManifest;
use quick_xml::{
    NsReader, XmlVersion,
    events::{BytesStart, Event},
    name::ResolveResult,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

const EDM: &str = "http://docs.oasis-open.org/odata/ns/edm";
const EDMX: &str = "http://docs.oasis-open.org/odata/ns/edmx";
const MAX_BYTES: usize = 128 * 1024 * 1024;
fn invalid_xml_character(character: char) -> bool {
    matches!(character as u32, 0..=8 | 11..=12 | 14..=31 | 0xfffe | 0xffff)
}

struct Node {
    namespace: String,
    name: String,
    attributes: BTreeMap<String, String>,
    children: Vec<Node>,
    text: String,
}
impl Node {
    fn attr(&self, name: &str) -> Result<&str> {
        self.attributes
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| anyhow::anyhow!("CSDL required attribute is missing"))
    }
    fn children(&self, name: &str) -> impl Iterator<Item = &Node> {
        self.children
            .iter()
            .filter(move |node| node.namespace == EDM && node.name == name)
    }
    fn boolean(&self, name: &str, default: bool) -> Result<bool> {
        match self.attributes.get(name).map(String::as_str) {
            None => Ok(default),
            Some("true") => Ok(true),
            Some("false") => Ok(false),
            _ => bail!("invalid CSDL boolean attribute"),
        }
    }
}
fn node(start: &BytesStart<'_>, namespace: ResolveResult<'_>) -> Result<Node> {
    let namespace = match namespace {
        ResolveResult::Bound(namespace) if matches!(namespace.0, EDM | EDMX) => {
            namespace.0.to_owned()
        }
        _ => bail!("unsupported or missing CSDL XML namespace"),
    };
    let mut attributes = BTreeMap::new();
    for attribute in start.attributes() {
        let attribute = attribute.map_err(|_| anyhow::anyhow!("invalid CSDL XML attribute"))?;
        let key = attribute.key.0;
        if key == "xmlns" || key.starts_with("xmlns:") {
            continue;
        }
        if key.contains(':') {
            bail!("unsupported namespaced CSDL attribute");
        }
        let value = attribute
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|_| anyhow::anyhow!("invalid CSDL attribute encoding"))?
            .into_owned();
        if attributes.insert(key.to_owned(), value).is_some() || attributes.len() > 64 {
            bail!("duplicate or excessive CSDL attributes");
        }
    }
    Ok(Node {
        namespace,
        name: start.local_name().as_ref().to_owned(),
        attributes,
        children: vec![],
        text: String::new(),
    })
}
fn tree(bytes: &[u8]) -> Result<Node> {
    if bytes.len() > MAX_BYTES {
        bail!("CSDL document exceeds byte limit");
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| anyhow::anyhow!("CSDL requires UTF-8 XML"))?;
    if text.chars().any(invalid_xml_character) {
        bail!("invalid XML character");
    }
    let mut reader = NsReader::from_str(text);
    let mut stack: Vec<Node> = vec![];
    let mut root = None;
    let mut nodes = 0usize;
    loop {
        let (namespace, event) = reader
            .read_resolved_event()
            .map_err(|_| anyhow::anyhow!("malformed CSDL XML"))?;
        let empty = matches!(&event, Event::Empty(_));
        match event {
            Event::Start(start) | Event::Empty(start) => {
                let child = node(&start, namespace)?;
                nodes += 1;
                if nodes > 200_000 || stack.len() >= 128 {
                    bail!("CSDL document exceeds structural limit");
                }
                if empty {
                    if let Some(parent) = stack.last_mut() {
                        parent.children.push(child);
                    } else if root.replace(child).is_some() {
                        bail!("multiple CSDL XML roots");
                    }
                } else {
                    stack.push(child);
                }
            }
            Event::End(_) => {
                let child = stack
                    .pop()
                    .ok_or_else(|| anyhow::anyhow!("unbalanced CSDL XML"))?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(child);
                } else if root.replace(child).is_some() {
                    bail!("multiple CSDL XML roots");
                }
            }
            Event::Text(text) => {
                if let Some(parent) = stack.last_mut() {
                    parent.text.push_str(&text.xml10_content());
                } else if !text.trim().is_empty() {
                    bail!("text outside CSDL XML root");
                }
            }
            Event::CData(text) => {
                stack
                    .last_mut()
                    .ok_or_else(|| anyhow::anyhow!("CDATA outside CSDL XML root"))?
                    .text
                    .push_str(&text.xml10_content());
            }
            Event::GeneralRef(reference) => {
                let character = reference
                    .resolve_char_ref()
                    .map_err(|_| anyhow::anyhow!("invalid XML character reference"))?
                    .or_else(|| match reference.as_ref() {
                        "amp" => Some('&'),
                        "lt" => Some('<'),
                        "gt" => Some('>'),
                        "quot" => Some('"'),
                        "apos" => Some('\''),
                        _ => None,
                    })
                    .ok_or_else(|| anyhow::anyhow!("custom XML entities are not supported"))?;
                if invalid_xml_character(character) {
                    bail!("invalid XML character reference");
                }
                stack
                    .last_mut()
                    .ok_or_else(|| anyhow::anyhow!("XML reference outside CSDL root"))?
                    .text
                    .push(character);
            }
            Event::DocType(_) => bail!("XML document type declarations are not supported"),
            Event::Eof => break,
            Event::Decl(declaration) => {
                if declaration
                    .version()
                    .map_err(|_| anyhow::anyhow!("invalid XML declaration"))?
                    .as_ref()
                    != "1.0"
                {
                    bail!("CSDL importer requires XML 1.0");
                }
                if let Some(encoding) = declaration.encoding()
                    && !encoding
                        .map_err(|_| anyhow::anyhow!("invalid XML encoding declaration"))?
                        .eq_ignore_ascii_case("utf-8")
                {
                    bail!("CSDL requires UTF-8 XML");
                }
            }
            Event::Comment(_) => {}
            _ => bail!("unsupported CSDL XML construct"),
        }
    }
    if !stack.is_empty() {
        bail!("unclosed CSDL XML elements");
    }
    root.ok_or_else(|| anyhow::anyhow!("empty CSDL XML document"))
}
/// Validate bounded XML framing and the OData document envelope without fetching references.
pub fn validate_document(bytes: &[u8]) -> Result<()> {
    let root = tree(bytes)?;
    if root.namespace != EDMX
        || root.name != "Edmx"
        || !matches!(root.attr("Version")?, "4.0" | "4.01")
    {
        bail!("expected OData 4.x EDMX document");
    }
    let services = root
        .children
        .iter()
        .filter(|n| n.namespace == EDMX && n.name == "DataServices")
        .collect::<Vec<_>>();
    if services.len() != 1 || services[0].children("Schema").next().is_none() {
        bail!("CSDL requires DataServices with schemas");
    }
    Ok(())
}
fn identifier(value: &str) -> Result<&str> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        || value.as_bytes()[0].is_ascii_digit()
    {
        bail!("unsupported CSDL identifier");
    }
    Ok(value)
}
fn qualified(value: &str, aliases: &BTreeMap<String, String>) -> Result<String> {
    for part in value.split('.') {
        identifier(part)?;
    }
    if let Some((prefix, suffix)) = value.split_once('.') {
        if let Some(namespace) = aliases.get(prefix) {
            return Ok(format!("{namespace}.{suffix}"));
        }
        return Ok(value.to_owned());
    }
    bail!("CSDL type name must be qualified")
}
fn reference(value: &str) -> Value {
    json!({"$ref":format!("#/components/schemas/{value}")})
}
fn data_type(value: &str, aliases: &BTreeMap<String, String>) -> Result<Value> {
    if let Some(inner) = value
        .strip_prefix("Collection(")
        .and_then(|v| v.strip_suffix(')'))
    {
        if inner.starts_with("Collection(") {
            bail!("nested CSDL collections are unsupported");
        }
        return Ok(json!({"type":"array","items":data_type(inner,aliases)?}));
    }
    Ok(match value {
        "Edm.String" => json!({"type":"string"}),
        "Edm.Boolean" => json!({"type":"boolean"}),
        "Edm.Byte" => json!({"type":"integer","minimum":0,"maximum":255}),
        "Edm.SByte" => json!({"type":"integer","minimum":-128,"maximum":127}),
        "Edm.Int16" => json!({"type":"integer","minimum":-32768,"maximum":32767}),
        "Edm.Int32" => json!({"type":"integer","minimum":-2147483648_i64,"maximum":2147483647_i64}),
        "Edm.Int64" => {
            json!({"anyOf":[{"type":"integer"},{"type":"string","pattern":"^-?[0-9]+$"}],"x-odata-type":"Edm.Int64"})
        }
        "Edm.Decimal" => {
            json!({"anyOf":[{"type":"number"},{"type":"string","pattern":"^-?[0-9]+(\\.[0-9]+)?$"}],"x-odata-type":"Edm.Decimal"})
        }
        "Edm.Single" | "Edm.Double" => {
            json!({"anyOf":[{"type":"number"},{"enum":["INF","-INF","NaN"]}]})
        }
        "Edm.Guid" => json!({"type":"string","format":"uuid"}),
        "Edm.Date" => json!({"type":"string","format":"date"}),
        "Edm.DateTimeOffset" => json!({"type":"string","format":"date-time"}),
        "Edm.Duration" => json!({"type":"string","format":"duration"}),
        "Edm.TimeOfDay" => {
            json!({"type":"string","pattern":"^[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?$"})
        }
        "Edm.Binary" => json!({"type":"string","contentEncoding":"base64url"}),
        "Edm.Stream" | "Edm.Untyped" | "Edm.PrimitiveType" => json!({"x-odata-type":value}),
        value if value.starts_with("Edm.Geography") || value.starts_with("Edm.Geometry") => {
            json!({"type":"object","x-odata-type":value})
        }
        value if value.starts_with("Edm.") => bail!("unsupported CSDL primitive type"),
        value => reference(&qualified(value, aliases)?),
    })
}
fn typed(node: &Node, aliases: &BTreeMap<String, String>) -> Result<Value> {
    let type_name = node.attr("Type")?;
    let collection = type_name
        .strip_prefix("Collection(")
        .and_then(|v| v.strip_suffix(')'));
    let mut schema = data_type(collection.unwrap_or(type_name), aliases)?;
    if let Some(length) = node
        .attributes
        .get("MaxLength")
        .filter(|value| *value != "max")
    {
        let length = length
            .parse::<u64>()
            .map_err(|_| anyhow::anyhow!("invalid CSDL MaxLength"))?;
        if length == 0 {
            bail!("CSDL MaxLength must be positive");
        }
        // CSDL binary length counts decoded octets, unlike JSON string length.
        // Preserve that facet instead of applying an incorrect character bound.
        if collection.unwrap_or(type_name) == "Edm.String" {
            schema["maxLength"] = json!(length);
        }
    }
    // Preserve CSDL facets which cannot be expressed faithfully as JSON Schema.
    schema["x-odata-facets"] = json!(node.attributes);
    let nullable = node.boolean("Nullable", true)?;
    if collection.is_some() && node.name != "Parameter" {
        if nullable && node.name != "NavigationProperty" {
            schema = json!({"anyOf":[schema,{"type":"null"}]});
        }
        return Ok(json!({"type":"array","items":schema}));
    }
    if collection.is_some() {
        schema = json!({"type":"array","items":schema});
    }
    if nullable {
        schema = json!({"anyOf":[schema,{"type":"null"}]});
    }
    Ok(schema)
}
fn capability_bool(node: &Node, default: Option<bool>) -> Result<bool> {
    let children = node.children("Bool").collect::<Vec<_>>();
    let attribute = node.attributes.get("Bool");
    if children.len() > 1
        || node.children.len() != children.len()
        || node
            .attributes
            .keys()
            .any(|key| !matches!(key.as_str(), "Term" | "Property" | "Bool"))
        || children
            .iter()
            .any(|node| !node.attributes.is_empty() || !node.children.is_empty())
        || (attribute.is_some() && !node.children.is_empty())
    {
        bail!("ambiguous CSDL capability boolean");
    }
    let value = attribute
        .map(String::as_str)
        .or_else(|| children.first().map(|node| node.text.trim()));
    match value {
        Some("true") => Ok(true),
        Some("false") => Ok(false),
        None if node.children.is_empty()
            && !node
                .attributes
                .keys()
                .any(|key| !matches!(key.as_str(), "Term" | "Property")) =>
        {
            default.ok_or_else(|| anyhow::anyhow!("missing CSDL capability boolean"))
        }
        _ => bail!("unsupported CSDL capability boolean expression"),
    }
}

fn query_parameters(
    nodes: &[&Node],
    aliases: &BTreeMap<String, String>,
    collection: bool,
) -> Result<Vec<Value>> {
    let mappings = [
        ("SelectSupport", Some("Supported"), "$select"),
        ("ExpandRestrictions", Some("Expandable"), "$expand"),
        ("FilterRestrictions", Some("Filterable"), "$filter"),
        ("SortRestrictions", Some("Sortable"), "$orderby"),
        ("TopSupported", None, "$top"),
        ("SkipSupported", None, "$skip"),
        ("CountRestrictions", Some("Countable"), "$count"),
        ("SearchRestrictions", Some("Searchable"), "$search"),
    ];
    let mut enabled = BTreeMap::from_iter(mappings.iter().map(|(_, _, option)| (*option, true)));
    let mut requires_filter = false;
    for node in nodes {
        for annotation in node
            .children("Annotation")
            .filter(|node| !node.attributes.contains_key("Qualifier"))
        {
            let Some(term) = annotation.attributes.get("Term") else {
                continue;
            };
            let term = qualified(term, aliases)?;
            let Some(term) = term.strip_prefix("Org.OData.Capabilities.V1.") else {
                continue;
            };
            let Some((_, property_name, option)) =
                mappings.iter().find(|(name, _, _)| *name == term)
            else {
                continue;
            };
            if !collection && !matches!(*option, "$select" | "$expand") {
                continue;
            }
            if let Some(property_name) = property_name {
                let records = annotation.children("Record").collect::<Vec<_>>();
                if records.len() != 1 {
                    bail!("CSDL query capability requires one record");
                }
                let mut seen = std::collections::BTreeSet::new();
                for property in records[0].children("PropertyValue") {
                    let name = property.attr("Property")?;
                    if name != *property_name
                        && !(term == "FilterRestrictions" && name == "RequiresFilter")
                    {
                        continue;
                    }
                    if !seen.insert(name) {
                        bail!("duplicate CSDL query capability property");
                    }
                    let value = capability_bool(property, None)?;
                    if name == "RequiresFilter" {
                        requires_filter |= value;
                    } else {
                        *enabled.get_mut(option).expect("known option") &= value;
                    }
                }
            } else {
                *enabled.get_mut(option).expect("known option") &=
                    capability_bool(annotation, Some(true))?;
            }
        }
    }
    if requires_filter && !enabled["$filter"] {
        bail!("contradictory CSDL filter capabilities");
    }
    Ok(mappings
        .into_iter()
        .filter(|(_, _, option)| {
            enabled[option] && (collection || matches!(*option, "$select" | "$expand"))
        })
        .map(|(_, _, option)| {
            let required = option == "$filter" && requires_filter;
            let schema = if matches!(option, "$top" | "$skip") {
                json!({"type":"integer","minimum":0})
            } else if option == "$count" {
                json!({"type":"boolean"})
            } else if required {
                json!({"type":"string","minLength":1})
            } else {
                json!({"type":"string"})
            };
            json!({"name":option,"in":"query","required":required,"schema":schema})
        })
        .collect())
}

fn readable(node: &Node, aliases: &BTreeMap<String, String>, by_key: bool) -> Result<bool> {
    let bool_value = |property: &Node| -> Result<bool> {
        let value = property
            .attributes
            .get("Bool")
            .map(String::as_str)
            .or_else(|| property.children("Bool").next().map(|n| n.text.trim()));
        match value {
            Some("false") => Ok(false),
            Some("true") => Ok(true),
            _ => bail!("unsupported CSDL Readable restriction expression"),
        }
    };
    let mut allowed = true;
    if by_key {
        for annotation in node.children("Annotation").filter(|n| {
            !n.attributes.contains_key("Qualifier")
                && n.attributes.get("Term").is_some_and(|term| {
                    qualified(term, aliases)
                        .is_ok_and(|term| term == "Org.OData.Capabilities.V1.IndexableByKey")
                })
        }) {
            // Core.Tag defaults to true when no value is specified.
            if annotation.attributes.contains_key("Bool") || !annotation.children.is_empty() {
                allowed &= bool_value(annotation)?;
            }
        }
    }
    for annotation in node.children("Annotation").filter(|n| {
        !n.attributes.contains_key("Qualifier")
            && n.attributes.get("Term").is_some_and(|t| {
                qualified(t, aliases)
                    .is_ok_and(|term| term == "Org.OData.Capabilities.V1.ReadRestrictions")
            })
    }) {
        for record in annotation.children("Record") {
            let mut readable = true;
            for property in record.children("PropertyValue").filter(|n| {
                n.attributes
                    .get("Property")
                    .is_some_and(|p| p == "Readable")
            }) {
                readable &= bool_value(property)?;
            }
            if by_key {
                let mut overrides = Vec::new();
                for nested in record.children("PropertyValue").filter(|n| {
                    n.attributes
                        .get("Property")
                        .is_some_and(|p| p == "ReadByKeyRestrictions")
                }) {
                    for property in nested
                        .children("Record")
                        .flat_map(|n| n.children("PropertyValue"))
                        .filter(|n| {
                            n.attributes
                                .get("Property")
                                .is_some_and(|p| p == "Readable")
                        })
                    {
                        overrides.push(bool_value(property)?);
                    }
                }
                if !overrides.is_empty() {
                    readable = overrides.into_iter().all(|value| value);
                }
            }
            allowed &= readable;
        }
    }
    Ok(allowed)
}
fn description(node: &Node) -> Option<String> {
    node.children("Annotation")
        .find(|n| {
            n.attributes
                .get("Term")
                .is_some_and(|t| t.ends_with(".Description"))
        })
        .and_then(|n| {
            n.attributes
                .get("String")
                .cloned()
                .or_else(|| n.children("String").next().map(|n| n.text.clone()))
        })
}
fn literal_kind(
    value: &str,
    aliases: &BTreeMap<String, String>,
    types: &BTreeMap<String, &Node>,
) -> Result<String> {
    let mut value = value.to_owned();
    let mut seen = std::collections::BTreeSet::new();
    loop {
        if value.starts_with("Collection(") {
            return Ok("json".into());
        }
        if value.starts_with("Edm.") {
            return Ok(value);
        }
        let name = qualified(&value, aliases)?;
        if !seen.insert(name.clone()) || seen.len() > 128 {
            bail!("cyclic CSDL underlying type");
        }
        let node = types.get(&name).ok_or_else(|| {
            anyhow::anyhow!("CSDL function parameter type has no local definition")
        })?;
        match node.name.as_str() {
            "EnumType" => return Ok(format!("enum:{name}")),
            "EntityType" | "ComplexType" => return Ok("json".into()),
            "TypeDefinition" => value = node.attr("UnderlyingType")?.to_owned(),
            _ => bail!("unsupported CSDL function parameter type"),
        }
    }
}
fn entity_hierarchy<'a>(
    type_name: &str,
    aliases: &BTreeMap<String, String>,
    types: &BTreeMap<String, &'a Node>,
) -> Result<Vec<(String, &'a Node)>> {
    let mut hierarchy = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut name = qualified(type_name, aliases)?;
    loop {
        if !seen.insert(name.clone()) || seen.len() > 128 {
            bail!("cyclic CSDL entity inheritance");
        }
        let node = types
            .get(&name)
            .ok_or_else(|| anyhow::anyhow!("CSDL entity type has no local definition"))?;
        if node.name != "EntityType" {
            bail!("CSDL entity set requires an entity type");
        }
        hierarchy.push((name.clone(), *node));
        if let Some(base) = node.attributes.get("BaseType") {
            name = qualified(base, aliases)?;
        } else {
            break;
        }
    }
    Ok(hierarchy)
}

fn entity_keys(
    type_name: &str,
    aliases: &BTreeMap<String, String>,
    types: &BTreeMap<String, &Node>,
) -> Result<Vec<(String, Value)>> {
    let hierarchy = entity_hierarchy(type_name, aliases, types)?;
    let keys = hierarchy
        .iter()
        .flat_map(|(_, node)| node.children("Key"))
        .collect::<Vec<_>>();
    if keys.len() > 1 {
        bail!("multiple CSDL entity keys");
    }
    let Some(key) = keys.first() else {
        return Ok(Vec::new());
    };
    let mut result = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    for property_ref in key.children("PropertyRef") {
        let name = identifier(property_ref.attr("Name")?)?;
        if property_ref.attributes.contains_key("Alias") {
            bail!("CSDL complex property key aliases are not yet supported");
        }
        if !names.insert(name) {
            bail!("duplicate CSDL key property");
        }
        let properties = hierarchy
            .iter()
            .flat_map(|(_, node)| node.children("Property"))
            .filter(|property| {
                property
                    .attributes
                    .get("Name")
                    .is_some_and(|value| value == name)
            })
            .collect::<Vec<_>>();
        if properties.len() != 1 {
            bail!("CSDL key requires one declared structural property");
        }
        let property = properties[0];
        if property.boolean("Nullable", true)? {
            bail!("CSDL key property must be non-nullable");
        }
        let kind = literal_kind(property.attr("Type")?, aliases, types)?;
        if kind == "json"
            || kind == "Edm.Stream"
            || kind == "Edm.Untyped"
            || kind.starts_with("Edm.Geography")
            || kind.starts_with("Edm.Geometry")
        {
            bail!("unsupported CSDL key type");
        }
        let mut schema = typed(property, aliases)?;
        schema["x-junction-odata-literal"] = json!(kind);
        result.push((name.to_owned(), schema));
    }
    if result.is_empty() {
        bail!("CSDL entity key requires properties");
    }
    Ok(result)
}

fn optional_parameter(node: &Node, aliases: &BTreeMap<String, String>) -> Result<Option<Value>> {
    let mut annotations = node.children("Annotation").filter(|annotation| {
        !annotation.attributes.contains_key("Qualifier")
            && annotation.attributes.get("Term").is_some_and(|term| {
                qualified(term, aliases)
                    .is_ok_and(|name| name == "Org.OData.Core.V1.OptionalParameter")
            })
    });
    let Some(annotation) = annotations.next() else {
        return Ok(None);
    };
    if annotations.next().is_some() {
        bail!("duplicate CSDL optional parameter annotation");
    }
    let records = annotation.children("Record").collect::<Vec<_>>();
    if records.len() > 1
        || annotation.attributes.keys().any(|key| key != "Term")
        || annotation.children.iter().any(|node| node.name != "Record")
    {
        bail!("unsupported CSDL optional parameter annotation");
    }
    let mut metadata = json!({});
    if let Some(record) = records.first() {
        let defaults = record
            .children("PropertyValue")
            .filter(|node| {
                node.attributes
                    .get("Property")
                    .is_some_and(|value| value == "DefaultValue")
            })
            .collect::<Vec<_>>();
        if defaults.len() > 1 {
            bail!("duplicate CSDL optional parameter default");
        }
        if let Some(default) = defaults.first() {
            metadata["default_value_literal"] =
                if let Some(value) = default.attributes.get("String") {
                    if !default.children.is_empty() {
                        bail!("ambiguous CSDL optional parameter default");
                    }
                    json!(value)
                } else if default.children.len() == 1 && default.children[0].name == "String" {
                    json!(default.children[0].text)
                } else if default.children.len() == 1 && default.children[0].name == "Null" {
                    Value::Null
                } else {
                    bail!("unsupported CSDL optional parameter default expression");
                };
        }
    }
    Ok(Some(metadata))
}
fn operation_responses(
    operation: &Node,
    aliases: &BTreeMap<String, String>,
    primitive_types: &std::collections::BTreeSet<String>,
) -> Result<Value> {
    let mut returns = operation.children("ReturnType");
    let return_type = returns.next();
    if returns.next().is_some() {
        bail!("multiple CSDL operation return types");
    }
    if let Some(node) = return_type {
        let mut result = typed(node, aliases)?;
        let type_name = node.attr("Type")?;
        if type_name.starts_with("Edm.")
            || type_name.starts_with("Collection(")
            || primitive_types.contains(&qualified(type_name, aliases)?)
        {
            result = json!({"type":"object","properties":{"value":result},"required":["value"]});
        }
        let mut responses = json!({"200":{"description":"OData operation response","content":{"application/json":{"schema":result}}}});
        if node.boolean("Nullable", true)? && !type_name.starts_with("Collection(") {
            responses["204"] = json!({"description":"Null operation result"});
        }
        Ok(responses)
    } else {
        Ok(json!({"204":{"description":"Operation completed without a result"}}))
    }
}

/// Normalize local CSDL into the same canonical manifest as OpenAPI ingestion.
/// Endpoint and version are trusted source configuration, never taken from XML links.
pub(crate) fn validate_endpoint(endpoint: &str, version: &str) -> Result<()> {
    let url = url::Url::parse(endpoint).map_err(|_| anyhow::anyhow!("invalid CSDL endpoint"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("CSDL endpoint must be a plain HTTPS service root");
    }
    if version.is_empty() || version.len() > 256 {
        bail!("CSDL API version is required");
    }
    Ok(())
}

pub fn ingest(
    bytes: &[u8],
    product: &str,
    service: &str,
    source: &str,
    endpoint: &str,
    version: &str,
) -> Result<RegistryManifest> {
    validate_endpoint(endpoint, version)?;
    let root = tree(bytes)?;
    if root.namespace != EDMX
        || root.name != "Edmx"
        || !matches!(root.attr("Version")?, "4.0" | "4.01")
    {
        bail!("expected OData 4.x EDMX document");
    }
    let services = root
        .children
        .iter()
        .filter(|n| n.namespace == EDMX && n.name == "DataServices")
        .collect::<Vec<_>>();
    if services.len() != 1 {
        bail!("CSDL requires one DataServices element");
    }
    let schemas = services[0].children("Schema").collect::<Vec<_>>();
    if schemas.is_empty() {
        bail!("CSDL requires schemas");
    }
    let mut aliases = BTreeMap::new();
    for reference in root
        .children
        .iter()
        .filter(|n| n.namespace == EDMX && n.name == "Reference")
    {
        for include in reference
            .children
            .iter()
            .filter(|n| n.namespace == EDMX && n.name == "Include")
        {
            if let Some(alias) = include.attributes.get("Alias") {
                identifier(alias)?;
                let namespace = include.attr("Namespace")?;
                for part in namespace.split('.') {
                    identifier(part)?;
                }
                if aliases
                    .insert(alias.clone(), namespace.to_owned())
                    .is_some_and(|previous| previous != namespace)
                {
                    bail!("duplicate CSDL namespace alias");
                }
            }
        }
    }
    let mut namespaces = std::collections::BTreeSet::new();
    for schema in &schemas {
        let namespace = schema.attr("Namespace")?;
        for part in namespace.split('.') {
            identifier(part)?;
        }
        if matches!(namespace, "Edm" | "odata" | "System" | "Transient")
            || !namespaces.insert(namespace)
        {
            bail!("duplicate or reserved CSDL namespace");
        }
        if let Some(alias) = schema.attributes.get("Alias") {
            identifier(alias)?;
            if aliases
                .insert(alias.clone(), namespace.to_owned())
                .is_some_and(|previous| previous != namespace)
            {
                bail!("duplicate CSDL namespace alias");
            }
        }
    }
    let mut external_annotations: BTreeMap<String, Vec<&Node>> = BTreeMap::new();
    for schema in &schemas {
        for annotations in schema.children("Annotations") {
            if annotations.attributes.contains_key("Qualifier") {
                continue;
            }
            if let Some((container, resource)) = annotations.attr("Target")?.split_once('/')
                && !resource.contains('/')
            {
                identifier(resource)?;
                external_annotations
                    .entry(format!("{}/{}", qualified(container, &aliases)?, resource))
                    .or_default()
                    .push(annotations);
            }
        }
    }
    let mut definitions = json!({});
    let mut primitive_types = std::collections::BTreeSet::new();
    let mut actions: BTreeMap<String, &Node> = BTreeMap::new();
    let mut functions: BTreeMap<String, Vec<&Node>> = BTreeMap::new();
    let mut types: BTreeMap<String, &Node> = BTreeMap::new();
    let mut containers = 0usize;
    for schema in &schemas {
        let namespace = schema.attr("Namespace")?;
        for node in &schema.children {
            if node.namespace != EDM {
                bail!("invalid CSDL schema child namespace");
            }
            if !matches!(
                node.name.as_str(),
                "EntityType"
                    | "ComplexType"
                    | "EnumType"
                    | "TypeDefinition"
                    | "Action"
                    | "Function"
            ) {
                continue;
            }
            let name = format!("{namespace}.{}", identifier(node.attr("Name")?)?);
            if node.name == "Function" {
                if !node.boolean("IsBound", false)? {
                    functions.entry(name).or_default().push(node);
                }
                continue;
            }
            if matches!(node.name.as_str(), "EnumType" | "TypeDefinition") {
                primitive_types.insert(name.clone());
            }
            if node.name == "Action" {
                if !node.boolean("IsBound", false)? && actions.insert(name, node).is_some() {
                    bail!("overloaded unbound CSDL actions are unsupported");
                }
                continue;
            }
            types.insert(name.clone(), node);
            let mut definition = match node.name.as_str() {
                "EntityType" | "ComplexType" => {
                    let mut properties = json!({});
                    for property in node
                        .children("Property")
                        .chain(node.children("NavigationProperty"))
                    {
                        let key = identifier(property.attr("Name")?)?;
                        if properties.get(key).is_some() {
                            bail!("duplicate CSDL property");
                        }
                        properties[key] = typed(property, &aliases)?;
                    }
                    let own = json!({"type":"object","properties":properties,"x-odata-open-type":node.boolean("OpenType",false)?});
                    if let Some(base) = node.attributes.get("BaseType") {
                        json!({"allOf":[reference(&qualified(base,&aliases)?),own]})
                    } else {
                        own
                    }
                }
                "EnumType" => {
                    let members = node
                        .children("Member")
                        .map(|member| Ok(identifier(member.attr("Name")?)?.to_owned()))
                        .collect::<Result<Vec<_>>>()?;
                    if members.is_empty() {
                        bail!("CSDL enum requires members");
                    }
                    if node.boolean("IsFlags", false)? {
                        json!({"type":"string","x-odata-enum-members":members,"x-odata-flags":true})
                    } else {
                        json!({"type":"string","enum":members})
                    }
                }
                "TypeDefinition" => data_type(node.attr("UnderlyingType")?, &aliases)?,
                _ => unreachable!(),
            };
            if let Some(text) = description(node) {
                definition["description"] = json!(text);
            }
            if definitions.get(&name).is_some() {
                bail!("duplicate CSDL type");
            }
            definitions[&name] = definition;
        }
    }
    let mut paths = json!({});
    let mut destructive_paths = std::collections::BTreeSet::new();
    let mut function_names = BTreeMap::new();
    let mut key_names = BTreeMap::new();
    let mut navigation_names = BTreeMap::new();
    for schema in schemas {
        for container in schema.children("EntityContainer") {
            containers += 1;
            identifier(container.attr("Name")?)?;
            if container.attributes.contains_key("Extends") {
                bail!("CSDL container inheritance is not yet supported");
            }
            for resource in container
                .children("EntitySet")
                .chain(container.children("Singleton"))
            {
                let name = identifier(resource.attr("Name")?)?;
                let target = format!(
                    "{}.{}/{name}",
                    schema.attr("Namespace")?,
                    container.attr("Name")?
                );
                let mut capability_nodes = vec![resource];
                if let Some(annotations) = external_annotations.get(&target) {
                    capability_nodes.extend(annotations.iter().copied());
                }
                let mut allowed = readable(resource, &aliases, false)?;
                let mut key_allowed = readable(resource, &aliases, true)?;
                if let Some(annotations) = external_annotations.get(&target) {
                    for annotation in annotations {
                        allowed &= readable(annotation, &aliases, false)?;
                        key_allowed &= readable(annotation, &aliases, true)?;
                    }
                }
                if !allowed && (!key_allowed || resource.name != "EntitySet") {
                    continue;
                }
                let schema = reference(&qualified(
                    resource.attr(if resource.name == "EntitySet" {
                        "EntityType"
                    } else {
                        "Type"
                    })?,
                    &aliases,
                )?);
                let (action, result) = if resource.name == "EntitySet" {
                    (
                        "List",
                        json!({"type":"object","properties":{"value":{"type":"array","items":schema},"@odata.nextLink":{"type":"string","format":"uri"},"@odata.count":{"anyOf":[{"type":"integer","minimum":0},{"type":"string","pattern":"^[0-9]+$"}],"x-odata-type":"Edm.Int64"}}}),
                    )
                } else {
                    ("Get", schema)
                };
                let path = format!("/{name}");
                if paths.get(&path).is_some() {
                    bail!("duplicate CSDL service route");
                }
                if allowed {
                    paths[&path] = json!({"get":{"operationId":format!("{name}_{action}"),"description":description(resource).unwrap_or_else(||format!("{action} {name}")),
                    "parameters":query_parameters(&capability_nodes, &aliases, resource.name == "EntitySet")?,
                    "responses":{"200":{"description":"OData response","content":{"application/json":{"schema":result}}}}}});
                }
                let mut navigation_base = if resource.name == "Singleton" && allowed {
                    Some((path.clone(), Vec::new()))
                } else {
                    None
                };
                if resource.name == "EntitySet" && key_allowed {
                    let keys = entity_keys(resource.attr("EntityType")?, &aliases, &types)?;
                    if !keys.is_empty() {
                        let predicate = if keys.len() == 1 {
                            format!("@{}", keys[0].0)
                        } else {
                            keys.iter()
                                .map(|(key, _)| format!("{key}=@{key}"))
                                .collect::<Vec<_>>()
                                .join(",")
                        };
                        let key_path = format!("/{name}({predicate})");
                        if paths.get(&key_path).is_some() {
                            bail!("duplicate CSDL service route");
                        }
                        let mut parameters = keys.into_iter().map(|(key, schema)| json!({"name":format!("@{key}"),"in":"query","required":true,"style":"odata","explode":false,"schema":schema})).collect::<Vec<_>>();
                        parameters.extend(query_parameters(&capability_nodes, &aliases, false)?);
                        navigation_base = Some((key_path.clone(), parameters.clone()));
                        key_names
                            .insert(key_path.clone(), junction_core::canonical_component(name));
                        paths[&key_path] = json!({"get":{"operationId":format!("{name}_Get"),"description":format!("Get {name} by key"),"parameters":parameters,"responses":{"200":{"description":"OData entity","content":{"application/json":{"schema":reference(&qualified(resource.attr("EntityType")?, &aliases)?)}}}}}});
                    }
                }
                if let Some((base_path, base_parameters)) = navigation_base {
                    let type_name = resource.attr(if resource.name == "EntitySet" {
                        "EntityType"
                    } else {
                        "Type"
                    })?;
                    let mut navigation = BTreeMap::new();
                    for (entity_name, entity) in entity_hierarchy(type_name, &aliases, &types)? {
                        for property in entity.children("NavigationProperty") {
                            let property_name = identifier(property.attr("Name")?)?;
                            if navigation
                                .insert(
                                    property_name,
                                    (format!("{entity_name}/{property_name}"), property),
                                )
                                .is_some()
                            {
                                bail!("duplicate inherited CSDL navigation property");
                            }
                        }
                    }
                    for (property_name, (annotation_target, property)) in navigation {
                        let mut allowed = readable(property, &aliases, false)?;
                        if let Some(annotations) = external_annotations.get(&annotation_target) {
                            for annotation in annotations {
                                allowed &= readable(annotation, &aliases, false)?;
                            }
                        }
                        if !allowed {
                            continue;
                        }
                        let property_type = property.attr("Type")?;
                        let collection = property_type
                            .strip_prefix("Collection(")
                            .and_then(|value| value.strip_suffix(')'));
                        let target = qualified(collection.unwrap_or(property_type), &aliases)?;
                        if types
                            .get(&target)
                            .is_none_or(|node| node.name != "EntityType")
                        {
                            bail!("CSDL navigation target requires a local entity type");
                        }
                        let navigation_path = format!("{base_path}/{property_name}");
                        if paths.get(&navigation_path).is_some() {
                            bail!("duplicate CSDL service route");
                        }
                        let mut capability_nodes = vec![property];
                        if let Some(annotations) = external_annotations.get(&annotation_target) {
                            capability_nodes.extend(annotations.iter().copied());
                        }
                        let mut parameters = base_parameters
                            .iter()
                            .filter(|parameter| {
                                parameter["name"]
                                    .as_str()
                                    .is_some_and(|name| name.starts_with('@'))
                            })
                            .cloned()
                            .collect::<Vec<_>>();
                        parameters.extend(query_parameters(
                            &capability_nodes,
                            &aliases,
                            collection.is_some(),
                        )?);
                        let (action, result) = if collection.is_some() {
                            (
                                "list",
                                json!({"type":"object","properties":{"value":{"type":"array","items":reference(&target)},"@odata.nextLink":{"type":"string","format":"uri"},"@odata.count":{"anyOf":[{"type":"integer","minimum":0},{"type":"string","pattern":"^[0-9]+$"}],"x-odata-type":"Edm.Int64"}}}),
                            )
                        } else {
                            ("get", reference(&target))
                        };
                        let mut responses = json!({"200":{"description":"OData navigation response","content":{"application/json":{"schema":result}}}});
                        if collection.is_none() && property.boolean("Nullable", true)? {
                            responses["204"] = json!({"description":"No related entity"});
                        }
                        navigation_names.insert(
                            navigation_path.clone(),
                            (
                                format!(
                                    "{}.{}",
                                    junction_core::canonical_component(name),
                                    junction_core::canonical_component(property_name)
                                ),
                                action.to_owned(),
                            ),
                        );
                        paths[&navigation_path] = json!({"get":{"operationId":format!("{name}_{property_name}_{action}"),"description":description(property).unwrap_or_else(||format!("{action} {name} {property_name}")),"parameters":parameters,"responses":responses}});
                    }
                }
            }
            for import in container.children("ActionImport") {
                let name = identifier(import.attr("Name")?)?;
                let action = actions
                    .get(&qualified(import.attr("Action")?, &aliases)?)
                    .ok_or_else(|| anyhow::anyhow!("CSDL action import has no local definition"))?;
                let mut properties = json!({});
                let mut required = vec![];
                let mut optional_seen = false;
                for parameter in action.children("Parameter") {
                    let key = identifier(parameter.attr("Name")?)?;
                    if properties.get(key).is_some() {
                        bail!("duplicate CSDL action parameter");
                    }
                    let optional = optional_parameter(parameter, &aliases)?;
                    let mut schema = typed(parameter, &aliases)?;
                    if let Some(metadata) = optional {
                        optional_seen = true;
                        schema["x-odata-optional-parameter"] = metadata;
                    } else {
                        if optional_seen {
                            bail!("required CSDL parameters must precede optional parameters");
                        }
                        required.push(key);
                    }
                    properties[key] = schema;
                }
                let responses = operation_responses(action, &aliases, &primitive_types)?;
                let path = format!("/{name}");
                if paths.get(&path).is_some() {
                    bail!("duplicate CSDL service route");
                }
                if crate::destructive_action(action.attr("Name")?) {
                    destructive_paths.insert(path.clone());
                }
                paths[&path] = json!({"post":{"operationId":format!("{name}_Invoke"),"description":description(action).unwrap_or_else(||format!("Invoke {name}")),
                    "requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","properties":properties,"required":required,"additionalProperties":false}}}},
                    "responses":responses}});
            }
            for import in container.children("FunctionImport") {
                let name = identifier(import.attr("Name")?)?;
                let overloads = functions
                    .get(&qualified(import.attr("Function")?, &aliases)?)
                    .ok_or_else(|| {
                        anyhow::anyhow!("CSDL function import has no local definition")
                    })?;
                for function in overloads {
                    if function.children("ReturnType").next().is_none() {
                        bail!("CSDL functions require a return type");
                    }
                    let mut parameters = BTreeMap::new();
                    let mut optional_seen = false;
                    for parameter in function.children("Parameter") {
                        let key = identifier(parameter.attr("Name")?)?;
                        let mut schema = typed(parameter, &aliases)?;
                        let optional = optional_parameter(parameter, &aliases)?;
                        let required = optional.is_none();
                        if let Some(metadata) = optional {
                            optional_seen = true;
                            schema["x-odata-optional-parameter"] = metadata;
                        } else if optional_seen {
                            bail!("required CSDL parameters must precede optional parameters");
                        }
                        schema["x-junction-odata-literal"] =
                            json!(literal_kind(parameter.attr("Type")?, &aliases, &types)?);
                        if parameters.insert(key,json!({"name":format!("@{key}"),"in":"query","required":required,"style":"odata","explode":false,"schema":schema})).is_some() { bail!("duplicate CSDL function parameter"); }
                    }
                    let arguments = parameters
                        .keys()
                        .map(|key| format!("{key}=@{key}"))
                        .collect::<Vec<_>>()
                        .join(",");
                    let path = format!("/{name}({arguments})");
                    if paths.get(&path).is_some() {
                        bail!(
                            "CSDL function overloads with identical parameter names are unsupported"
                        );
                    }
                    let signature = parameters.keys().copied().collect::<Vec<_>>().join("_");
                    let action = if parameters.is_empty() {
                        "invoke".into()
                    } else {
                        format!(
                            "invoke_by_{}",
                            parameters
                                .keys()
                                .map(|key| junction_core::canonical_component(key))
                                .collect::<Vec<_>>()
                                .join("_")
                        )
                    };
                    function_names.insert(
                        path.clone(),
                        (junction_core::canonical_component(name), action),
                    );
                    paths[&path] = json!({"get":{"operationId":format!("{name}_InvokeBy{signature}"),"description":description(function).unwrap_or_else(||format!("Invoke {name}")),
                        "parameters":parameters.into_values().collect::<Vec<_>>(),"responses":operation_responses(function,&aliases,&primitive_types)?}});
                }
            }
        }
    }
    if containers != 1 {
        bail!("CSDL service requires one entity container");
    }
    let mut manifest = crate::ingest(
        &json!({"openapi":"3.1.0","info":{"version":version},"servers":[{"url":endpoint}],"paths":paths,"components":{"schemas":definitions}}),
        product,
        service,
        source,
    )?;
    for operation in &mut manifest.operations {
        if destructive_paths.contains(&operation.path)
            && operation.risk != junction_core::OperationRisk::Privileged
        {
            operation.risk = junction_core::OperationRisk::Destructive;
        }
        if let Some((resource, action)) = navigation_names.get(&operation.path) {
            operation.resource = resource.clone();
            operation.operation = action.clone();
            operation.id = if operation.product == "graph" {
                format!("graph.{resource}.{action}")
            } else {
                format!(
                    "{}.{}.{resource}.{action}",
                    operation.product, operation.service
                )
            };
        }
        if let Some(resource) = key_names.get(&operation.path) {
            operation.resource = resource.clone();
            operation.operation = "get".into();
            operation.id = if operation.product == "graph" {
                format!("graph.{resource}.get")
            } else {
                format!("{}.{}.{resource}.get", operation.product, operation.service)
            };
        }
        if operation.product != "graph"
            && let Some((resource, action)) = function_names.get(&operation.path)
        {
            operation.resource = resource.clone();
            operation.operation = action.clone();
            operation.id = format!(
                "{}.{}.{}.{}",
                operation.product, operation.service, resource, action
            );
        }
    }
    manifest.operations.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(manifest)
}
