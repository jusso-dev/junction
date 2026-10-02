//! Structured Microsoft Learn documentation adapter.
//!
//! Some Microsoft APIs (Defender for Endpoint, Defender XDR, Defender for Cloud
//! Apps, Power Platform, Office 365 Management Activity) publish no official
//! OpenAPI document. Microsoft Learn serves their reference pages as Markdown
//! (`Accept: text/markdown`) with a machine-readable `toc.json`. This adapter
//! extracts documented request templates, parameters, permissions and request
//! body tables, synthesizes an OpenAPI 3 document per service and API version,
//! and hands it to the ordinary [`crate::ingest`] pipeline so naming, risk
//! classification and schema validation stay identical to other sources.
//!
//! This is the specification's last-resort "documented endpoint extraction":
//! only pages listed in the official table of contents under a configured
//! prefix are read, nothing is executed, and every page is recorded with a
//! SHA-256 receipt.
use crate::sources::{ApiSource, SourceType};
use anyhow::{Result, bail};
use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const MAX_PAGES: usize = 2048;
const MAX_PAGE_BYTES: usize = 4 * 1024 * 1024;
const MAX_TOC_BYTES: usize = 16 * 1024 * 1024;
const METHODS: [&str; 5] = ["GET", "POST", "PUT", "PATCH", "DELETE"];
const ODATA_QUERY: [&str; 6] = ["$filter", "$top", "$skip", "$select", "$expand", "$orderby"];

/// One Learn page as retrieved, keyed by its TOC href.
pub struct LearnPage {
    pub href: String,
    pub url: String,
    pub markdown: String,
}

#[derive(Debug, Serialize)]
pub struct PageReceipt {
    pub source: String,
    pub upstream: String,
    pub path: String,
    pub sha256: String,
    pub bytes: usize,
}

/// Collect relative TOC hrefs under the configured prefixes. A prefix ending in
/// `-` is a plain string prefix (`api-` matches `api-list-incidents`); any
/// other prefix is a path scope (`api` matches `api/get-alerts`).
pub fn toc_hrefs(toc: &Value, prefixes: &[String]) -> Result<Vec<String>> {
    fn walk(node: &Value, out: &mut BTreeSet<String>, depth: usize) -> Result<()> {
        if depth > 64 {
            bail!("documentation table of contents is too deep");
        }
        let children = node
            .get("items")
            .or_else(|| node.get("children"))
            .and_then(Value::as_array);
        for child in children.into_iter().flatten() {
            if let Some(href) = child.get("href").and_then(Value::as_str) {
                out.insert(href.to_owned());
            }
            walk(child, out, depth + 1)?;
        }
        Ok(())
    }
    let mut all = BTreeSet::new();
    walk(toc, &mut all, 0)?;
    let selected: Vec<String> = all
        .into_iter()
        .map(|href| href.split(['?', '#']).next().unwrap_or_default().to_owned())
        .filter(|href| {
            !href.is_empty()
                && !href.starts_with('/')
                && !href.contains("://")
                && !href.ends_with(".yml")
                && crate::sources::validate_source_path(href).is_ok()
                && prefixes.iter().any(|prefix| {
                    if prefix.ends_with('-') {
                        href.starts_with(prefix.as_str())
                    } else {
                        href.strip_prefix(prefix.as_str())
                            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
                    }
                })
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if selected.len() > MAX_PAGES {
        bail!("documentation page limit exceeded");
    }
    Ok(selected)
}

#[derive(Debug, Clone)]
struct BodyField {
    name: String,
    schema: Value,
    required: bool,
    /// Documented type text, resolved against page definitions later.
    kind: String,
}
/// A documented definition: object properties (name, type text) or enum values.
#[derive(Debug, Clone)]
enum Definition {
    Object(Vec<(String, String)>),
    Enum(Vec<String>),
}

#[derive(Debug, Clone)]
struct DocOperation {
    method: String,
    base: String,
    base_variables: Vec<String>,
    path: String,
    query: Vec<(String, bool)>,
    title: String,
    summary: String,
    permissions: Vec<(String, String)>,
    scopes: Vec<String>,
    body: Option<Vec<BodyField>>,
    api_version: Option<String>,
    odata: bool,
    pageable: bool,
    named: Option<(String, String)>,
    page: String,
    responses: Vec<(String, Option<String>)>,
    definitions: BTreeMap<String, Definition>,
}

struct Section {
    level: usize,
    heading: String,
    lines: Vec<String>,
}

fn strip_front_matter(markdown: &str) -> &str {
    if let Some(rest) = markdown.strip_prefix("---\n")
        && let Some(end) = rest.find("\n---\n")
    {
        return &rest[end + 5..];
    }
    markdown
}

fn sections(markdown: &str) -> Vec<Section> {
    let mut out = vec![Section {
        level: 0,
        heading: String::new(),
        lines: Vec::new(),
    }];
    let mut fenced = false;
    for line in strip_front_matter(markdown).lines() {
        let trimmed = line.trim_end();
        if trimmed.trim_start().starts_with("```") {
            fenced = !fenced;
        }
        if !fenced {
            let hashes = trimmed.chars().take_while(|c| *c == '#').count();
            if (1..=6).contains(&hashes) && trimmed[hashes..].starts_with(' ') {
                out.push(Section {
                    level: hashes,
                    heading: trimmed[hashes..].trim().to_owned(),
                    lines: Vec::new(),
                });
                continue;
            }
        }
        out.last_mut()
            .expect("root section")
            .lines
            .push(trimmed.to_owned());
    }
    out
}

/// Fenced code blocks inside a section, as (language, lines).
fn code_blocks(lines: &[String]) -> Vec<(String, Vec<String>)> {
    let mut blocks = Vec::new();
    let mut current: Option<(String, Vec<String>)> = None;
    for line in lines {
        let trimmed = line.trim();
        if let Some(language) = trimmed.strip_prefix("```") {
            match current.take() {
                Some(block) => blocks.push(block),
                None => current = Some((language.trim().to_ascii_lowercase(), Vec::new())),
            }
        } else if let Some((_, body)) = current.as_mut() {
            body.push(trimmed.to_owned());
        }
    }
    blocks
}

/// Markdown table rows (header excluded) as trimmed cells.
fn tables(lines: &[String]) -> Vec<(Vec<String>, Vec<Vec<String>>)> {
    let mut tables = Vec::new();
    let mut index = 0;
    while index + 1 < lines.len() {
        let header = lines[index].trim();
        let divider = lines[index + 1].trim();
        if header.starts_with('|') && divider.starts_with('|') && divider.contains("---") {
            let cells = |line: &str| {
                line.trim()
                    .trim_matches('|')
                    .split('|')
                    .map(|cell| clean_cell(cell.trim()))
                    .collect::<Vec<_>>()
            };
            let header = cells(header);
            let mut rows = Vec::new();
            index += 2;
            while index < lines.len() && lines[index].trim().starts_with('|') {
                rows.push(cells(&lines[index]));
                index += 1;
            }
            tables.push((header, rows));
        } else {
            index += 1;
        }
    }
    tables
}

fn clean_cell(cell: &str) -> String {
    let mut text = strip_links(cell).replace(['`', '*'], "");
    text = text.replace("<br>", " ").replace("<br/>", " ");
    text.trim().to_owned()
}

/// Replace `[text](url)` with `text`.
fn strip_links(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(open) = rest.find('[') {
        let after = &rest[open + 1..];
        match after.find("](") {
            Some(close) if !after[..close].contains('[') => {
                let tail = &after[close + 2..];
                match tail.find(')') {
                    Some(end) => {
                        out.push_str(&rest[..open]);
                        out.push_str(&after[..close]);
                        rest = &tail[end + 1..];
                    }
                    None => break,
                }
            }
            _ => {
                out.push_str(&rest[..=open]);
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

fn title(markdown: &str) -> String {
    let heading = sections(markdown)
        .into_iter()
        .find(|section| section.level == 1)
        .map(|section| section.heading)
        .unwrap_or_default();
    let heading = heading
        .split(" | Microsoft Learn")
        .next()
        .unwrap_or_default();
    // "List alerts API - Microsoft Defender for Endpoint" keeps "List alerts API".
    match heading.rsplit_once(" - Microsoft ") {
        Some((head, _)) => head.trim().to_owned(),
        None => heading.trim().to_owned(),
    }
}

fn description(markdown: &str) -> String {
    let markdown = markdown.strip_prefix("---\n").unwrap_or(markdown);
    markdown
        .lines()
        .take_while(|line| *line != "---")
        .find_map(|line| line.strip_prefix("description: "))
        .unwrap_or_default()
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(1024)
        .collect()
}

fn is_identifier(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'$' | b'@'))
}

/// Normalize documented placeholders: `<pk>` and `{machine action id}` become
/// `{pk}` and `{machine_action_id}`. Returns None for unbalanced templates.
fn normalize_placeholders(text: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        let close = match c {
            '{' => '}',
            '<' => '>',
            _ => {
                out.push(c);
                continue;
            }
        };
        let mut name = String::new();
        loop {
            match chars.next() {
                Some(next) if next == close => break,
                Some(next) if next == '{' || next == '<' || next == '/' => return None,
                Some(next) => name.push(next),
                None => return None,
            }
        }
        let name: String = name
            .trim()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect::<String>()
            .trim_matches('_')
            .to_owned();
        if name.is_empty() || name.len() > 64 {
            return None;
        }
        out.push('{');
        out.push_str(&name);
        out.push('}');
    }
    Some(out)
}

/// A documented request line split into method, optional absolute base and path.
struct RequestLine {
    method: String,
    base: Option<String>,
    path: String,
    query: Vec<(String, bool)>,
    api_version: Option<String>,
}

fn parse_request_line(line: &str, root: Option<&str>) -> Option<RequestLine> {
    let line = strip_links(line.trim());
    let (method, target) = line.split_once(char::is_whitespace)?;
    let method = method.to_ascii_uppercase();
    if !METHODS.contains(&method.as_str()) {
        return None;
    }
    // The target ends at whitespace outside placeholders, so documented
    // names such as `{machine action id}` stay intact.
    let mut depth = 0usize;
    let target: String = target
        .trim()
        .chars()
        .take_while(|c| {
            match c {
                '{' | '<' => depth += 1,
                '}' | '>' => depth = depth.saturating_sub(1),
                _ => {}
            }
            depth > 0 || !c.is_whitespace()
        })
        .collect();
    let mut target = target;
    if target.starts_with("{root}") || target.starts_with("<root>") {
        let root = root?;
        target = format!("{root}{}", &target[6..]);
    }
    let target = target.trim_start_matches("...");
    let (location, query) = match target.split_once('?') {
        Some((location, query)) => (location, Some(query)),
        None => (target, None),
    };
    let location = normalize_placeholders(location)?;
    let (base, path) = if let Some(rest) = location.strip_prefix("https://") {
        let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
        if host.is_empty() || host.contains(['@', ':']) || !microsoft_api_host(host) {
            return None;
        }
        (Some(format!("https://{host}")), format!("/{path}"))
    } else if location.starts_with("http://") || location.contains("://") {
        return None;
    } else if location.starts_with('/') {
        (None, location.clone())
    } else if location.to_ascii_lowercase().starts_with("api/") {
        (None, format!("/{location}"))
    } else {
        return None;
    };
    let path = if path.len() > 1 {
        path.trim_end_matches('/').to_owned()
    } else {
        path
    };
    if path.contains(['\\', '"', '\'', '`', ' ', '#', '%', '|'])
        || path
            .split('/')
            .skip(1)
            .any(|segment| segment.is_empty() || segment == "..")
        || path.len() > 2048
    {
        return None;
    }
    let mut query_parameters = Vec::new();
    let mut api_version = None;
    for pair in query.into_iter().flat_map(|query| query.split('&')) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if !is_identifier(name) {
            continue;
        }
        if name == "api-version" {
            if !value.is_empty() && !value.contains(['{', '<']) {
                api_version = Some(value.to_owned());
            }
            continue;
        }
        let required = value.starts_with('{') || value.starts_with('<');
        if !query_parameters
            .iter()
            .any(|(existing, _)| existing == name)
        {
            query_parameters.push((name.to_owned(), required));
        }
    }
    Some(RequestLine {
        method,
        base,
        path,
        query: query_parameters,
        api_version,
    })
}

/// Documentation samples also mention placeholder tenants such as contoso;
/// only Microsoft-operated API domains may become an operation endpoint.
fn microsoft_api_host(host: &str) -> bool {
    const SUFFIXES: [&str; 11] = [
        ".microsoft.com",
        ".microsoft.us",
        ".office.com",
        ".office365.us",
        ".apps.mil",
        ".powerplatform.com",
        ".powerbi.com",
        ".powerbigov.us",
        ".cloudappsecurity.com",
        ".loganalytics.io",
        ".azure.com",
    ];
    let host = host.to_ascii_lowercase();
    !host.contains("contoso")
        && !host.starts_with("learn.")
        && !host.starts_with("docs.")
        && !host.starts_with("login.")
        && SUFFIXES.iter().any(|suffix| host.ends_with(suffix))
}

fn path_parameters(path: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = path;
    while let Some(start) = rest.find('{') {
        let Some(end) = rest[start..].find('}') else {
            break;
        };
        let name = &rest[start + 1..start + end];
        if !names.iter().any(|existing| existing == name) {
            names.push(name.to_owned());
        }
        rest = &rest[start + end + 1..];
    }
    names
}

/// Resolve documented type text: definition names become component
/// references, `X[]` becomes an array, anything else a primitive.
fn schema_for(kind: &str, definitions: &BTreeSet<String>) -> Value {
    let trimmed = kind.trim();
    if let Some(item) = trimmed.strip_suffix("[]") {
        return json!({"type":"array","items": schema_for(item, definitions)});
    }
    let name = trimmed.split_once(' ').map_or(trimmed, |(name, _)| name);
    if definitions.contains(name) {
        return json!({"$ref": format!("#/components/schemas/{name}")});
    }
    primitive_schema(trimmed)
}

/// `## Definitions` subsections on REST reference pages.
fn definitions(sections: &[Section]) -> BTreeMap<String, Definition> {
    let mut out = BTreeMap::new();
    let mut inside = false;
    for section in sections {
        if section.level <= 2 {
            inside = section.level == 2 && section.heading.eq_ignore_ascii_case("definitions");
            continue;
        }
        if !inside || section.level != 3 {
            continue;
        }
        let name = section.heading.trim().to_owned();
        if !is_identifier(&name) || name.contains('.') {
            continue;
        }
        for (header, rows) in tables(&section.lines) {
            let first = header.first().map(|cell| cell.to_ascii_lowercase());
            if first.as_deref() == Some("value") {
                let values = rows
                    .iter()
                    .filter_map(|row| row.first().cloned())
                    .filter(|value| !value.is_empty() && value.len() <= 256)
                    .collect();
                out.insert(name.clone(), Definition::Enum(values));
                break;
            }
            let lower: Vec<String> = header
                .iter()
                .map(|cell| cell.to_ascii_lowercase())
                .collect();
            let (Some(name_column), Some(type_column)) = (
                lower.iter().position(|cell| cell == "name"),
                lower.iter().position(|cell| cell == "type"),
            ) else {
                continue;
            };
            let properties = rows
                .iter()
                .filter_map(|row| {
                    Some((row.get(name_column)?.clone(), row.get(type_column)?.clone()))
                })
                .filter(|(property, _)| is_identifier(property) || property.starts_with('@'))
                .collect();
            out.insert(name.clone(), Definition::Object(properties));
            break;
        }
    }
    out
}

/// `## Responses` rows: ("200", Some("TypeName")).
fn response_rows(sections: &[Section]) -> Vec<(String, Option<String>)> {
    sections
        .iter()
        .filter(|section| section.level == 2 && section.heading.eq_ignore_ascii_case("responses"))
        .flat_map(|section| tables(&section.lines))
        .flat_map(|(_, rows)| rows)
        .filter_map(|row| {
            let code = row.first()?.split_whitespace().next()?.to_owned();
            if !(code.len() == 3 && code.bytes().all(|b| b.is_ascii_digit())) && code != "Other" {
                return None;
            }
            let code = if code == "Other" {
                "default".to_owned()
            } else {
                code
            };
            let kind = row
                .get(1)
                .map(|kind| kind.trim().to_owned())
                .filter(|kind| !kind.is_empty());
            Some((code, kind))
        })
        .collect()
}

fn primitive_schema(kind: &str) -> Value {
    let kind = kind.trim().to_ascii_lowercase();
    let (kind, format) = match kind.split_once('(') {
        Some((kind, format)) => (
            kind.trim().to_owned(),
            Some(format.trim_end_matches(')').trim().to_owned()),
        ),
        None => (kind, None),
    };
    if let Some(item) = kind.strip_suffix("[]") {
        return json!({"type":"array","items":primitive_schema(item)});
    }
    let mut schema = match kind.as_str() {
        "string" | "datetime" | "datetimeoffset" | "guid" | "uuid" | "enum" => {
            json!({"type":"string"})
        }
        "int" | "int32" | "int64" | "integer" | "long" => json!({"type":"integer"}),
        "number" | "double" | "float" | "decimal" => json!({"type":"number"}),
        "bool" | "boolean" => json!({"type":"boolean"}),
        _ => json!({}),
    };
    if let (Some(format), Some(object)) = (format, schema.as_object_mut())
        && object.get("type") == Some(&json!("string"))
        && matches!(format.as_str(), "date-time" | "uuid" | "date" | "uri")
    {
        object.insert("format".into(), json!(format));
    }
    schema
}

/// Body tables: REST reference `Name | Required | Type | Description` or
/// Defender `Property | Type | Description` with "Required" in the text.
fn body_fields(lines: &[String]) -> Vec<BodyField> {
    let mut fields = Vec::new();
    for (header, rows) in tables(lines) {
        let column = |names: &[&str]| {
            header
                .iter()
                .position(|cell| names.contains(&cell.to_ascii_lowercase().as_str()))
        };
        let Some(name_column) = column(&["name", "property", "parameter"]) else {
            continue;
        };
        let type_column = column(&["type"]);
        let required_column = column(&["required"]);
        let description_column = column(&["description"]);
        for row in rows {
            let Some(name) = row.get(name_column) else {
                continue;
            };
            let name = name.trim().to_owned();
            if !is_identifier(&name) || name.contains('.') {
                continue;
            }
            let required = required_column
                .and_then(|index| row.get(index))
                .map(|cell| cell.eq_ignore_ascii_case("true") || cell.eq_ignore_ascii_case("yes"))
                .unwrap_or_else(|| {
                    description_column
                        .and_then(|index| row.get(index))
                        .is_some_and(|text| {
                            let lower = text.to_ascii_lowercase();
                            lower.contains("required") && !lower.contains("not required")
                        })
                });
            let schema = type_column
                .and_then(|index| row.get(index))
                .map(|kind| primitive_schema(kind))
                .unwrap_or_else(|| json!({}));
            let kind = type_column
                .and_then(|index| row.get(index))
                .cloned()
                .unwrap_or_default();
            if !fields.iter().any(|field: &BodyField| field.name == name) {
                fields.push(BodyField {
                    name,
                    schema,
                    required,
                    kind,
                });
            }
        }
    }
    fields
}

/// Permission rows (`Application` / `Delegated`) as (kind, scope).
fn permission_rows(lines: &[String]) -> Vec<(String, String)> {
    let mut permissions = Vec::new();
    for (header, rows) in tables(lines) {
        let lower: Vec<String> = header
            .iter()
            .map(|cell| cell.to_ascii_lowercase())
            .collect();
        let Some(kind_column) = lower
            .iter()
            .position(|cell| cell.contains("permission type"))
        else {
            continue;
        };
        let Some(scope_column) = lower
            .iter()
            .position(|cell| cell == "permission" || cell == "permissions")
        else {
            continue;
        };
        for row in rows {
            let (Some(kind), Some(scopes)) = (row.get(kind_column), row.get(scope_column)) else {
                continue;
            };
            let kind = if kind.to_ascii_lowercase().starts_with("application") {
                "application"
            } else if kind.to_ascii_lowercase().starts_with("delegated") {
                "delegated"
            } else {
                continue;
            };
            for scope in scopes.split([',', ' ', ';']) {
                let scope = scope.trim().trim_matches('\'');
                if scope.contains('.')
                    && scope.len() <= 128
                    && scope
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'.')
                {
                    permissions.push((kind.to_owned(), scope.to_owned()));
                }
            }
        }
    }
    permissions
}

fn heading_kind(heading: &str) -> &'static str {
    let lower = heading.to_ascii_lowercase();
    let lower = lower.trim_start_matches(|c: char| c.is_ascii_digit() || c == '.' || c == ' ');
    if lower.contains("example") || lower.contains("sample") || lower == "request" {
        "example"
    } else if lower.contains("http request") || lower == "url" || lower.ends_with(" url") {
        "request"
    } else if lower.contains("request body") || lower.contains("body parameters") {
        "body"
    } else if lower.contains("permission") {
        "permissions"
    } else if lower.contains("uri parameters") || lower.contains("query parameters") {
        "parameters"
    } else if lower == "scopes" {
        "scopes"
    } else {
        "other"
    }
}

/// Extract documented operations from one Learn page.
fn parse_page(page: &LearnPage) -> Vec<DocOperation> {
    let markdown = &page.markdown;
    let sections = sections(markdown);
    let page_title = title(markdown);
    let summary = description(markdown);
    let lower_text = markdown.to_ascii_lowercase();
    let odata = lower_text.contains("odata");
    let pageable = lower_text.contains("@odata.nextlink") || lower_text.contains("\"nextlink\"");
    // `{root}` templates resolve against the page's documented absolute root.
    let root = sections
        .iter()
        .flat_map(|section| code_blocks(&section.lines))
        .flat_map(|(_, lines)| lines)
        .find_map(|line| {
            let line = line.trim();
            line.starts_with("https://")
                .then(|| line.strip_suffix("/{operation}"))
                .flatten()
                .map(str::to_owned)
        });
    // REST reference pages: "# Environment Groups - List Environment Groups".
    let reference_name = (lower_text.contains("## uri parameters")
        || lower_text.contains("## responses"))
    .then(|| page_title.split_once(" - "))
    .flatten()
    .map(|(group, action)| (group.trim().to_owned(), action.trim().to_owned()));
    // Sections that document a request belong to the block opened by their
    // parent heading: the whole page for "## HTTP request", or one numbered
    // "## 1. ..." block for "### 1.3 URL" on multi-operation pages.
    let block = |index: usize| {
        let parent = sections[index].level.saturating_sub(1).max(1);
        let start = (0..=index)
            .rev()
            .find(|candidate| {
                *candidate < index
                    && sections[*candidate].level <= parent
                    && sections[*candidate].level > 0
            })
            .unwrap_or(0);
        let end = sections[index + 1..]
            .iter()
            .position(|next| next.level <= parent && next.level > 0)
            .map(|offset| index + 1 + offset)
            .unwrap_or(sections.len());
        start..end
    };
    let block_lines = |index: usize, wanted: &str| -> Vec<String> {
        sections[block(index)]
            .iter()
            .filter(|candidate| heading_kind(&candidate.heading) == wanted)
            .flat_map(|candidate| candidate.lines.clone())
            .collect()
    };
    let scopes: Vec<String> = sections
        .iter()
        .filter(|section| heading_kind(&section.heading) == "scopes")
        .flat_map(|section| tables(&section.lines))
        .flat_map(|(_, rows)| rows)
        .filter_map(|row| row.first().cloned())
        .filter(|scope| !scope.is_empty() && scope.len() <= 256 && !scope.contains(' '))
        .collect();
    let page_definitions = definitions(&sections);
    let page_responses = response_rows(&sections);
    let uri_parameters: Vec<(String, String, bool, String)> = sections
        .iter()
        .filter(|section| heading_kind(&section.heading) == "parameters")
        .flat_map(|section| tables(&section.lines))
        .flat_map(|(header, rows)| {
            let lower: Vec<String> = header.iter().map(|c| c.to_ascii_lowercase()).collect();
            let at = |name: &str| lower.iter().position(|c| c == name);
            let (name, location, required, kind) =
                (at("name"), at("in"), at("required"), at("type"));
            rows.into_iter().filter_map(move |row| {
                let name = row.get(name?)?.clone();
                let location = row.get(location?)?.to_ascii_lowercase();
                let required = required
                    .and_then(|index| row.get(index))
                    .is_some_and(|cell| cell.eq_ignore_ascii_case("true"));
                let kind = kind
                    .and_then(|index| row.get(index))
                    .cloned()
                    .unwrap_or_default();
                Some((name, location, required, kind))
            })
        })
        .collect();

    let mut operations: Vec<DocOperation> = Vec::new();
    let has_template_section = sections
        .iter()
        .any(|section| heading_kind(&section.heading) == "request")
        || reference_name.is_some();
    for (index, section) in sections.iter().enumerate() {
        let kind = heading_kind(&section.heading);
        let template = kind == "request" || (reference_name.is_some() && section.level == 1);
        // Pages without a template section may still document `{root}` requests
        // in their samples (Office 365 Management Activity API).
        let rooted_samples = !has_template_section && kind == "example" && root.is_some();
        if !template && !rooted_samples {
            continue;
        }
        for (language, lines) in code_blocks(&section.lines) {
            if !matches!(
                language.as_str(),
                "http" | "" | "rest" | "console" | "json" | "https"
            ) {
                continue;
            }
            for line in lines {
                if rooted_samples && !line.contains("{root}") {
                    continue;
                }
                let Some(request) = parse_request_line(&line, root.as_deref()) else {
                    continue;
                };
                let body_lines = block_lines(index, "body");
                let body_text = body_lines.join("\n").to_ascii_lowercase();
                let no_body = body_text.contains("empty")
                    || body_text.contains("don't supply")
                    || body_text.contains("do not supply")
                    || body_text.contains("not required");
                let fields = body_fields(&body_lines);
                let writes = matches!(request.method.as_str(), "POST" | "PUT" | "PATCH");
                let body = ((writes && !(no_body && fields.is_empty()))
                    || (!fields.is_empty() && request.method != "GET"))
                    .then_some(fields);
                let mut query = request.query.clone();
                for (name, location, required, _) in &uri_parameters {
                    if location == "query"
                        && name != "api-version"
                        && is_identifier(name)
                        && !query.iter().any(|(existing, _)| existing == name)
                    {
                        query.push((name.clone(), *required));
                    }
                }
                let base = request.base.clone().unwrap_or_default();
                operations.push(DocOperation {
                    method: request.method.clone(),
                    base_variables: Vec::new(),
                    base,
                    path: request.path.clone(),
                    query,
                    title: page_title.clone(),
                    summary: summary.clone(),
                    permissions: permission_rows(&block_lines(index, "permissions")),
                    scopes: scopes.clone(),
                    body,
                    api_version: request.api_version.clone(),
                    odata,
                    pageable,
                    named: reference_name.clone(),
                    page: page.url.clone(),
                    responses: page_responses.clone(),
                    definitions: page_definitions.clone(),
                });
            }
        }
    }
    // A request without a host borrows one from the page's own absolute examples.
    let absolute: Vec<(String, String)> = sections
        .iter()
        .flat_map(|section| code_blocks(&section.lines))
        .flat_map(|(_, lines)| lines)
        .flat_map(|line| {
            // URLs appear as request lines or inside curl/PowerShell samples.
            line.match_indices("https://")
                .map(|(start, _)| {
                    line[start..]
                        .split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ')' | ','))
                        .next()
                        .unwrap_or_default()
                        .to_owned()
                })
                .collect::<Vec<_>>()
        })
        .filter_map(|url| {
            parse_request_line(&format!("GET {url}"), root.as_deref())
                .and_then(|request| request.base.map(|base| (base, request.path)))
        })
        .collect();
    for operation in operations
        .iter_mut()
        .filter(|operation| operation.base.is_empty())
    {
        let wanted = operation.path.to_ascii_lowercase();
        if let Some((base, _)) = absolute.iter().find(|(_, path)| {
            let path = path.to_ascii_lowercase();
            path == wanted || path.ends_with(&wanted) || wanted.ends_with(&path)
        }) {
            operation.base = base.clone();
        }
    }
    let mut seen = BTreeSet::new();
    operations.retain(|operation| {
        seen.insert((
            operation.method.clone(),
            operation.path.to_ascii_lowercase(),
        ))
    });
    operations
}

fn words(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut previous_lower = false;
    for c in text.chars() {
        if !c.is_ascii_alphanumeric() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            previous_lower = false;
            continue;
        }
        if c.is_ascii_uppercase() && previous_lower && !current.is_empty() {
            words.push(std::mem::take(&mut current));
        }
        previous_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        current.push(c.to_ascii_lowercase());
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

fn camel(words: &[String]) -> String {
    words
        .iter()
        .map(|word| {
            let mut chars = word.chars();
            chars
                .next()
                .map(|first| first.to_ascii_uppercase().to_string() + chars.as_str())
                .unwrap_or_default()
        })
        .collect()
}

/// Deterministic `Resource_Action` name for an extracted operation.
fn operation_name(operation: &DocOperation) -> (String, String) {
    if let Some((group, action)) = &operation.named {
        let group = camel(&words(group));
        let action = camel(&words(action));
        if !group.is_empty() && !action.is_empty() {
            return (group, action);
        }
    }
    // Segments without placeholders; "find(timestamp={time})" keeps "find".
    let segments: Vec<(&str, bool)> = operation
        .path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            if segment.starts_with('{')
                && segment.ends_with('}')
                && segment.matches('{').count() == 1
            {
                (segment, true)
            } else {
                (
                    segment.split(['(', '{', '?']).next().unwrap_or(segment),
                    false,
                )
            }
        })
        .filter(|(segment, parameter)| {
            *parameter
                || !(segment.eq_ignore_ascii_case("api")
                    || (segment.len() <= 4
                        && segment.starts_with(['v', 'V'])
                        && segment[1..].chars().all(|c| c.is_ascii_digit() || c == '.')))
        })
        .filter(|(segment, _)| !segment.is_empty())
        .collect();
    let statics: Vec<&str> = segments
        .iter()
        .filter(|(_, parameter)| !parameter)
        .map(|(segment, _)| *segment)
        .collect();
    let ends_with_parameter = segments.last().is_some_and(|(_, parameter)| *parameter);
    let parameter_before_last = segments.len() >= 2 && segments[segments.len() - 2].1;
    let verb_like = |segment: &str| {
        let lower = segment.to_ascii_lowercase();
        [
            "get",
            "find",
            "run",
            "set",
            "add",
            "cancel",
            "start",
            "stop",
            "retrieve",
            "close",
            "create",
            "update",
            "delete",
            "remove",
            "import",
            "export",
            "list",
            "mark",
            "batch",
            "restrict",
            "unrestrict",
            "isolate",
            "unisolate",
            "offboard",
            "collect",
            "read",
            "unread",
            "done",
            "initiate",
            "perform",
            "finalize",
        ]
        .iter()
        .any(|verb| lower.starts_with(verb))
    };
    let join = |parts: &[&str]| {
        camel(
            &parts
                .iter()
                .flat_map(|part| words(part))
                .collect::<Vec<_>>(),
        )
    };
    let (resource, action) = match (operation.method.as_str(), statics.as_slice()) {
        (_, []) => (
            "Root".to_owned(),
            camel(&words(&operation.method.to_ascii_lowercase())),
        ),
        ("GET", parts) if ends_with_parameter => (join(parts), "Get".to_owned()),
        ("GET", [only]) => (join(&[only]), "List".to_owned()),
        ("GET", [head @ .., last]) if verb_like(last) => (join(head), join(&[last])),
        ("GET", [head @ .., last]) if parameter_before_last => {
            (join(head), format!("List{}", join(&[last])))
        }
        ("GET", [head @ .., last]) => (join(head), format!("List{}", join(&[last]))),
        ("DELETE", parts) if ends_with_parameter || parts.len() == 1 => {
            (join(parts), "Delete".to_owned())
        }
        ("DELETE", [head @ .., last]) => (join(head), format!("Delete{}", join(&[last]))),
        ("PATCH" | "PUT", parts) if ends_with_parameter || parts.len() == 1 => {
            (join(parts), "Update".to_owned())
        }
        ("PATCH" | "PUT", [head @ .., last]) => (join(head), join(&[last])),
        (_, [only]) => (join(&[only]), "Create".to_owned()),
        (_, parts) if ends_with_parameter => (join(parts), "Create".to_owned()),
        (_, [head @ .., last]) => (join(head), join(&[last])),
    };
    (resource, action)
}

fn openapi_operation(
    operation: &DocOperation,
    operation_id: &str,
    known: &BTreeSet<String>,
) -> Value {
    let mut parameters = Vec::new();
    for name in path_parameters(&operation.path) {
        parameters
            .push(json!({"name":name,"in":"path","required":true,"schema":{"type":"string"}}));
    }
    for (name, required) in &operation.query {
        parameters
            .push(json!({"name":name,"in":"query","required":required,"schema":{"type":"string"}}));
    }
    if operation.api_version.is_some() {
        parameters.push(
            json!({"name":"api-version","in":"query","required":true,"schema":{"type":"string"}}),
        );
    }
    let collection = operation.method == "GET" && !operation.path.ends_with('}');
    if collection && operation.odata {
        for name in ODATA_QUERY {
            if !operation.query.iter().any(|(existing, _)| existing == name) {
                parameters.push(
                    json!({"name":name,"in":"query","required":false,"schema":{"type":"string"}}),
                );
            }
        }
    }
    let mut value = json!({
        "operationId": operation_id,
        "summary": if operation.title.is_empty() { operation.summary.clone() } else { operation.title.clone() },
        "description": operation.summary,
        "externalDocs": {"url": operation.page},
        "parameters": parameters,
        "responses": responses(operation, known),
    });
    if let Some(fields) = &operation.body {
        let mut properties = Map::new();
        let mut required = Vec::new();
        for field in fields {
            let schema = if field.kind.is_empty() {
                field.schema.clone()
            } else {
                schema_for(&field.kind, known)
            };
            properties.insert(field.name.clone(), schema);
            if field.required {
                required.push(json!(field.name));
            }
        }
        let schema = if fields.is_empty() {
            json!({"type":"object"})
        } else {
            json!({"type":"object","properties":properties,"required":required})
        };
        value["requestBody"] = json!({
            "required": !fields.is_empty() && fields.iter().any(|field| field.required),
            "content": {"application/json": {"schema": schema}},
        });
    }
    let mut security = Vec::new();
    for kind in ["application", "delegated"] {
        let scopes: BTreeSet<&str> = operation
            .permissions
            .iter()
            .filter(|(candidate, _)| candidate == kind)
            .map(|(_, scope)| scope.as_str())
            .collect();
        // Learn permission tables list alternatives: any one scope suffices.
        for scope in scopes {
            security.push(json!({kind: [scope]}));
        }
    }
    if security.is_empty() && !operation.scopes.is_empty() {
        security.push(json!({"oauth2": operation.scopes}));
    }
    value["security"] = json!(security);
    if collection && operation.pageable {
        value["x-ms-pageable"] = json!({"nextLinkName":"@odata.nextLink"});
    }
    value
}

fn responses(operation: &DocOperation, known: &BTreeSet<String>) -> Value {
    if operation.responses.is_empty() {
        return json!({"200": {"description": "Success", "content": {"application/json": {"schema": {}}}}});
    }
    let mut out = Map::new();
    for (code, kind) in &operation.responses {
        let mut response = json!({"description": "Documented response"});
        if let Some(kind) = kind {
            response["content"] = json!({"application/json": {"schema": schema_for(kind, known)}});
        }
        out.entry(code.clone()).or_insert(response);
    }
    Value::Object(out)
}

fn component_schemas(definitions: &BTreeMap<String, Definition>) -> Map<String, Value> {
    let known: BTreeSet<String> = definitions.keys().cloned().collect();
    definitions
        .iter()
        .map(|(name, definition)| {
            let schema = match definition {
                Definition::Enum(values) => json!({"type":"string","enum":values}),
                Definition::Object(properties) => {
                    let properties: Map<String, Value> = properties
                        .iter()
                        .map(|(property, kind)| (property.clone(), schema_for(kind, &known)))
                        .collect();
                    json!({"type":"object","properties":properties})
                }
            };
            (name.clone(), schema)
        })
        .collect()
}

/// Synthesize one OpenAPI 3 document per (service, base, API version).
pub fn synthesize(source: &ApiSource, pages: &[LearnPage]) -> Result<Vec<(String, Value)>> {
    // "defender-endpoint" under product "defender" is service "endpoint"; a
    // source named after its product uses its Learn directory ("defender-xdr").
    let prefix = format!("{}-", source.product);
    let name = if source.id == source.product {
        source
            .upstream
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or(&source.id)
            .to_owned()
    } else {
        source.id.clone()
    };
    let default_service = name
        .strip_prefix(&prefix)
        .unwrap_or(&name)
        .replace('-', "_");
    let mut extracted = Vec::new();
    let mut seen = BTreeSet::new();
    for page in pages {
        for operation in parse_page(page) {
            // Several pages may document one endpoint, sometimes with different
            // letter case; the first page in TOC order wins.
            if seen.insert((
                operation.method.clone(),
                operation.path.to_ascii_lowercase(),
            )) {
                extracted.push((page.href.clone(), operation));
            }
        }
    }
    // Hostless requests fall back to the most common documented base.
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for (_, operation) in &extracted {
        if !operation.base.is_empty() {
            *counts.entry(operation.base.clone()).or_default() += 1;
        }
    }
    let common = counts
        .iter()
        .max_by_key(|(base, count)| (**count, std::cmp::Reverse((*base).clone())))
        .map(|(base, _)| base.clone());
    let mut groups: BTreeMap<(String, String, String), Vec<DocOperation>> = BTreeMap::new();
    for (href, mut operation) in extracted {
        if operation.base.is_empty() {
            match &common {
                Some(base) => operation.base = base.clone(),
                None => continue,
            }
        }
        let Some(base) = normalize_placeholders(&operation.base) else {
            continue;
        };
        operation.base_variables = path_parameters(&base);
        operation.base = base;
        let relative = source
            .paths
            .iter()
            .find_map(|prefix| {
                if prefix.ends_with('-') {
                    None
                } else {
                    href.strip_prefix(prefix.as_str())
                        .map(|rest| rest.trim_start_matches('/'))
                }
            })
            .unwrap_or(&href);
        let service = match relative.split_once('/') {
            Some((namespace, _)) => namespace.replace('-', "_"),
            None => default_service.clone(),
        };
        let version = operation
            .api_version
            .clone()
            .unwrap_or_else(|| "documented".into());
        groups
            .entry((service, operation.base.clone(), version))
            .or_default()
            .push(operation);
    }
    let mut documents = Vec::new();
    for ((service, base, version), mut operations) in groups {
        operations.sort_by(|a, b| (&a.path, &a.method).cmp(&(&b.path, &b.method)));
        let mut paths = Map::new();
        let mut used = BTreeSet::new();
        let mut definitions = BTreeMap::new();
        for operation in &operations {
            for (name, definition) in &operation.definitions {
                definitions
                    .entry(name.clone())
                    .or_insert_with(|| definition.clone());
            }
        }
        let known: BTreeSet<String> = definitions.keys().cloned().collect();
        for operation in &operations {
            let (resource, action) = operation_name(operation);
            let mut operation_id = format!("{resource}_{action}");
            let mut suffix = 2;
            while !used.insert(operation_id.to_ascii_lowercase()) {
                operation_id = format!("{resource}_{action}{suffix}");
                suffix += 1;
            }
            let entry = paths
                .entry(operation.path.clone())
                .or_insert_with(|| json!({}));
            let method = operation.method.to_ascii_lowercase();
            if entry.get(&method).is_none() {
                entry[&method] = openapi_operation(operation, &operation_id, &known);
            }
        }
        if paths.is_empty() {
            continue;
        }
        let variables: Map<String, Value> = operations[0]
            .base_variables
            .iter()
            .map(|name| (name.clone(), json!({"default": name.replace('_', "-")})))
            .collect();
        let mut server = json!({"url": base});
        if !variables.is_empty() {
            server["variables"] = Value::Object(variables);
        }
        documents.push((
            service,
            json!({
                "openapi": "3.0.3",
                "info": {"title": source.id, "version": version},
                "servers": [server],
                "paths": paths,
                "components": {"schemas": component_schemas(&definitions), "securitySchemes": {
                    "application": {"type":"oauth2","flows":{"clientCredentials":{"tokenUrl":"https://login.microsoftonline.com/common/oauth2/v2.0/token","scopes":{}}}},
                    "delegated": {"type":"oauth2","flows":{"authorizationCode":{"authorizationUrl":"https://login.microsoftonline.com/common/oauth2/v2.0/authorize","tokenUrl":"https://login.microsoftonline.com/common/oauth2/v2.0/token","scopes":{}}}},
                }},
            }),
        ));
    }
    Ok(documents)
}

/// Import already retrieved pages into one manifest with page receipts.
pub fn import(
    source: &ApiSource,
    pages: &[LearnPage],
    receipts: Vec<PageReceipt>,
    toc_sha256: &str,
) -> Result<junction_core::RegistryManifest> {
    let mut manifests = Vec::new();
    for (service, document) in synthesize(source, pages)? {
        // "documented" means the page declares no API version.
        let mut document = document;
        let documented = document["info"]["version"] == "documented";
        if documented {
            document["info"]["version"] = json!(null);
        }
        let mut manifest = crate::ingest(&document, &source.product, &service, &source.upstream)?;
        if documented {
            for operation in &mut manifest.operations {
                operation.api_version = None;
            }
        }
        manifests.push(manifest);
    }
    if manifests.is_empty() {
        bail!("documentation source produced no operations");
    }
    let mut manifest = if manifests.len() == 1 {
        manifests.pop().expect("one manifest")
    } else {
        crate::merge::merge(manifests)?
    };
    manifest
        .operations
        .sort_by(|a, b| (&a.id, &a.api_version).cmp(&(&b.id, &b.api_version)));
    if !manifest.schemas.is_object() {
        manifest.schemas = json!({});
    }
    manifest.schemas["x-junction-refresh"] = json!({
        "imported": receipts.len(),
        "kind": "documentation",
        "revision": toc_sha256,
        "documents": receipts.iter().map(|receipt| json!({"receipt": receipt, "status": "imported"})).collect::<Vec<_>>(),
    });
    Ok(manifest)
}

fn page_url(source: &ApiSource, href: &str) -> Result<url::Url> {
    let base = url::Url::parse(&source.upstream)?;
    if base.host_str() != Some("learn.microsoft.com") || !base.path().ends_with('/') {
        bail!("documentation source must be a Microsoft Learn directory URL");
    }
    let url = base.join(href)?;
    if url.host_str() != Some("learn.microsoft.com")
        || !url.path().starts_with(base.path())
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("documentation page outside configured source");
    }
    Ok(url)
}

async fn download(
    client: &reqwest::Client,
    url: url::Url,
    accept: &str,
    limit: usize,
) -> Result<Vec<u8>> {
    // Learn throttles bursts with 429; honour a bounded Retry-After.
    let mut attempt = 0u32;
    let mut response = loop {
        let response = client
            .get(url.clone())
            .header(reqwest::header::ACCEPT, accept)
            .send()
            .await;
        let retryable = match &response {
            Ok(response) => {
                response.status().as_u16() == 429 || response.status().is_server_error()
            }
            Err(error) => error.is_timeout() || error.is_connect(),
        };
        if !retryable || attempt >= 6 {
            break response.map_err(|_| anyhow::anyhow!("documentation download failed"))?;
        }
        let delay = response
            .ok()
            .and_then(|response| {
                response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)?
                    .to_str()
                    .ok()?
                    .parse::<u64>()
                    .ok()
            })
            .unwrap_or(2u64 << attempt)
            .clamp(1, 60);
        tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
        attempt += 1;
    };
    if !response.status().is_success() {
        return Err(crate::fetch::FetchFailure {
            kind: crate::fetch::FetchFailureKind::HttpStatus,
            http_status: Some(response.status().as_u16()),
        }
        .into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow::anyhow!("documentation download failed"))?
    {
        if bytes.len() + chunk.len() > limit {
            bail!("documentation page exceeds size limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// Retrieve the configured Learn table of contents and pages, then import them.
pub async fn refresh(
    source: &ApiSource,
    timeout_seconds: u64,
) -> Result<junction_core::RegistryManifest> {
    source.validate()?;
    if !source.enabled || !matches!(source.source_type, SourceType::Documentation) {
        bail!("documentation source is disabled or not a documentation source");
    }
    let client = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            // Learn moves pages; follow only HTTPS redirects that stay on Learn.
            if attempt.previous().len() < 5
                && attempt.url().scheme() == "https"
                && attempt.url().host_str() == Some("learn.microsoft.com")
            {
                attempt.follow()
            } else {
                attempt.stop()
            }
        }))
        .timeout(std::time::Duration::from_secs(60))
        .user_agent(concat!("junction/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|_| anyhow::anyhow!("documentation transport initialization failed"))?;
    let work = async {
        let toc_bytes = download(
            &client,
            page_url(source, "toc.json")?,
            "application/json",
            MAX_TOC_BYTES,
        )
        .await?;
        let toc: Value = serde_json::from_slice(&toc_bytes)
            .map_err(|_| anyhow::anyhow!("invalid documentation table of contents"))?;
        let hrefs = toc_hrefs(&toc, &source.paths)?;
        if hrefs.is_empty() {
            bail!("documentation table of contents has no matching pages");
        }
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(3));
        let mut tasks = tokio::task::JoinSet::new();
        for href in hrefs {
            let url = page_url(source, &href)?;
            let client = client.clone();
            let semaphore = semaphore.clone();
            tasks.spawn(async move {
                let _permit = semaphore.acquire_owned().await;
                let bytes = download(&client, url.clone(), "text/markdown", MAX_PAGE_BYTES).await;
                // Pace requests: Learn throttles bursts from one client.
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                (href, url, bytes)
            });
        }
        let mut pages = Vec::new();
        let mut receipts = Vec::new();
        let mut missing = 0usize;
        let mut total = 0usize;
        while let Some(result) = tasks.join_next().await {
            let (href, url, bytes) =
                result.map_err(|_| anyhow::anyhow!("documentation download failed"))?;
            total += 1;
            // Stale TOC entries (404/410) are skipped; anything else aborts.
            let bytes = match bytes {
                Ok(bytes) => bytes,
                Err(error)
                    if error
                        .downcast_ref::<crate::fetch::FetchFailure>()
                        .is_some_and(|failure| matches!(failure.http_status, Some(404 | 410))) =>
                {
                    missing += 1;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let markdown = String::from_utf8(bytes.clone())
                .map_err(|_| anyhow::anyhow!("documentation page is not UTF-8"))?;
            receipts.push(PageReceipt {
                source: source.id.clone(),
                upstream: url.to_string(),
                path: href.clone(),
                sha256: format!("{:x}", Sha256::digest(&bytes)),
                bytes: bytes.len(),
            });
            pages.push(LearnPage {
                href,
                url: url.to_string(),
                markdown,
            });
        }
        if missing * 4 > total {
            bail!("too many documentation pages are unavailable");
        }
        pages.sort_by(|a, b| a.href.cmp(&b.href));
        receipts.sort_by(|a, b| a.path.cmp(&b.path));
        import(
            source,
            &pages,
            receipts,
            &format!("{:x}", Sha256::digest(&toc_bytes)),
        )
    };
    tokio::time::timeout(std::time::Duration::from_secs(timeout_seconds), work)
        .await
        .map_err(|_| anyhow::anyhow!("documentation refresh deadline exceeded"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    fn source(id: &str, product: &str, upstream: &str, paths: &[&str]) -> ApiSource {
        serde_json::from_value(json!({"id":id,"product":product,"source_type":"documentation","upstream":upstream,"paths":paths,"authority":"microsoft","clouds":["public"],"enabled":true})).unwrap()
    }
    fn page(href: &str, markdown: &str) -> LearnPage {
        LearnPage {
            href: href.into(),
            url: format!("https://learn.microsoft.com/en-us/x/{href}"),
            markdown: markdown.into(),
        }
    }
    const DEFENDER: &str = "---\ntitle: List alerts API - Microsoft Defender for Endpoint | Microsoft Learn\ndescription: Retrieve alerts.\n---\n# List alerts API - Microsoft Defender for Endpoint | Microsoft Learn\n\nSupports OData V4 queries.\n\n## Permissions\n\n| Permission type | Permission | Permission display name |\n| --- | --- | --- |\n| Application | Alert.Read.All | `Read all alerts` |\n| Delegated (work or school account) | Alert.Read | `Read alerts` |\n\n## HTTP request\n\n```http\nGET /api/alerts\n```\n\n## Example\n\n### Request\n\n```http\nGET https://api.security.microsoft.com/api/alerts?$top=10\n```\n\nResponse has @odata.nextLink.\n";
    const ISOLATE: &str = "# Isolate machine API - Microsoft Defender for Endpoint | Microsoft Learn\n\n## Permissions\n\n| Permission type | Permission | Permission display name |\n| --- | --- | --- |\n| Application | Machine.Isolate | `Isolate` |\n\n## HTTP request\n\n```http\nPOST [https://api.security.microsoft.com/api/machines/{id}/isolate](https://api.security.microsoft.com/api/machines/%7Bid%7D/isolate)\n```\n\n## Request body\n\n| Parameter | Type | Description |\n| --- | --- | --- |\n| Comment | String | Comment to associate with the action. **Required**. |\n| IsolationType | String | Type of the isolation. |\n";
    const REFERENCE: &str = "# Environment Groups - List Environment Groups\n\n```http\nGET https://api.powerplatform.com/environmentmanagement/environmentGroups?api-version=2024-10-01\n```\n\n## URI Parameters\n\n| Name | In | Required | Type | Description |\n| --- | --- | --- | --- | --- |\n| api-version | query | True | string | The API version. |\n| $top | query | False | integer | Limit. |\n\n## Responses\n\n| Name | Type | Description |\n| --- | --- | --- |\n| 200 OK | GroupList | Success |\n\n## Security\n\n### oauth2\n\n#### Scopes\n\n| Name | Description |\n| --- | --- |\n| .default | .default |\n\n## Definitions\n\n| Name | Description |\n| --- | --- |\n| GroupList | |\n\n### GroupList\n\nObject\n\n| Name | Type | Description |\n| --- | --- | --- |\n| value | Group[] | |\n| @odata.nextLink | string | |\n\n### Group\n\nObject\n\n| Name | Type | Description |\n| --- | --- | --- |\n| id | string (uuid) | |\n| kind | GroupKind | |\n\n### GroupKind\n\n| Value | Description |\n| --- | --- |\n| Standard | |\n| Developer | |\n";
    const ROOTED: &str = "# Office 365 Management Activity API reference | Microsoft Learn\n\n## Activity API operations\n\n```http\nhttps://manage.office.com/api/v1.0/{tenant_id}/activity/feed/{operation}\n```\n\n## Start a subscription\n\n#### Sample request\n\n```json\nPOST {root}/subscriptions/start?contentType=Audit.SharePoint&PublisherIdentifier=46b4\nContent-Type: application/json; utf-8\n```\n\n## Webhook validation\n\n### Sample request\n\n```json\nPOST {webhook address}\n```\n";
    #[test]
    fn defender_pages_become_named_permissioned_operations() {
        let source = source(
            "defender-endpoint",
            "defender",
            "https://learn.microsoft.com/en-us/defender-endpoint/",
            &["api"],
        );
        let pages = [
            page("api/get-alerts", DEFENDER),
            page("api/isolate-machine", ISOLATE),
        ];
        let manifest = import(&source, &pages, Vec::new(), &"a".repeat(64)).unwrap();
        let ids: Vec<_> = manifest
            .operations
            .iter()
            .map(|op| op.id.as_str())
            .collect();
        assert_eq!(
            ids,
            [
                "defender.endpoint.alerts.list",
                "defender.endpoint.machines.isolate"
            ]
        );
        let list = &manifest.operations[0];
        assert_eq!(list.base_url, "https://api.security.microsoft.com");
        assert_eq!(list.path, "/api/alerts");
        assert!(list.parameters.iter().any(|p| p.name == "$filter"));
        assert!(list.pageable.is_some());
        assert_eq!(
            list.required_permissions().unwrap(),
            vec![
                vec!["Alert.Read.All".to_owned()],
                vec!["Alert.Read".to_owned()]
            ]
        );
        let isolate = &manifest.operations[1];
        assert_eq!(isolate.method, "POST");
        let body = isolate.request_body.as_ref().unwrap();
        assert_eq!(body["required"], true);
        assert_eq!(
            body.pointer("/content/application~1json/schema/required/0")
                .unwrap(),
            "Comment"
        );
        assert!(manifest.schemas["x-junction-refresh"]["kind"] == "documentation");
    }
    #[test]
    fn rest_reference_and_rooted_pages_use_documented_names_and_versions() {
        let platform = source(
            "power-platform",
            "power-platform",
            "https://learn.microsoft.com/en-us/rest/api/",
            &["power-platform"],
        );
        let manifest = import(
            &platform,
            &[page(
                "power-platform/environmentmanagement/environment-groups/list-environment-groups",
                REFERENCE,
            )],
            Vec::new(),
            &"a".repeat(64),
        )
        .unwrap();
        let operation = &manifest.operations[0];
        assert_eq!(
            operation.id,
            "power_platform.environmentmanagement.environment_groups.list_environment_groups"
        );
        assert_eq!(operation.api_version.as_deref(), Some("2024-10-01"));
        assert!(operation.parameters.iter().any(|p| p.name == "$top"));
        let reference = operation.responses["200"]
            .pointer("/content/application~1json/schema/$ref")
            .and_then(Value::as_str)
            .unwrap();
        assert!(reference.ends_with("GroupList"), "{reference}");
        let canonical = manifest.schemas["canonical"].as_object().unwrap();
        assert!(canonical.keys().any(|name| name.ends_with("GroupKind")));
        let office = source(
            "office-365-management",
            "m365",
            "https://learn.microsoft.com/en-us/office/office-365-management-api/",
            &["office-365-management-activity-api-reference"],
        );
        let manifest = import(
            &office,
            &[page("office-365-management-activity-api-reference", ROOTED)],
            Vec::new(),
            &"a".repeat(64),
        )
        .unwrap();
        assert_eq!(manifest.operations.len(), 1);
        let start = &manifest.operations[0];
        assert_eq!(
            start.id,
            "m365.office_365_management.activity_feed_subscriptions.start"
        );
        assert_eq!(start.base_url, "https://manage.office.com");
        assert!(
            start
                .parameters
                .iter()
                .any(|p| p.name == "tenant_id" && p.location == "path")
        );
        assert!(start.parameters.iter().any(|p| p.name == "contentType"));
    }
    #[test]
    fn toc_selection_is_scoped_and_relative() {
        let toc = json!({"items":[{"href":"api/get-alerts","children":[{"href":"api/isolate-machine?x=1"},{"href":"/defender-endpoint/api/apis-intro"},{"href":"https://evil.example/api/x"},{"href":"apiary"},{"href":"api-list-incidents"}]}]});
        assert_eq!(
            toc_hrefs(&toc, &["api".into()]).unwrap(),
            ["api/get-alerts", "api/isolate-machine"]
        );
        assert_eq!(
            toc_hrefs(&toc, &["api-".into()]).unwrap(),
            ["api-list-incidents"]
        );
    }
    #[test]
    fn request_lines_reject_unsafe_or_ambiguous_targets() {
        for line in [
            "GET http://insecure/api/x",
            "GET /api/{unbalanced",
            "GET https://user@host/api",
            "FETCH /api/x",
            "GET relative/path",
            "GET /api/../x",
        ] {
            assert!(parse_request_line(line, None).is_none(), "{line}");
        }
        let line = parse_request_line("DELETE /api/v1/subnet/<ip_range_id>/", None).unwrap();
        assert_eq!(line.path, "/api/v1/subnet/{ip_range_id}");
        let line = parse_request_line(
            "GET /api/machineactions/{machine action id}/getPackageUri",
            None,
        )
        .unwrap();
        assert_eq!(
            line.path,
            "/api/machineactions/{machine_action_id}/getPackageUri"
        );
    }
}
