//! Native MCP JSON-RPC lifecycle and small stable tool surface.
//! Hosts supply execution using their shared registry, context and policy runtime.
use serde_json::{Value, json};
mod driver;
pub use driver::{Incoming, serve_messages};
use std::{
    future::Future,
    io::{BufRead, Write},
};

pub const PROTOCOL_VERSION: &str = "2025-11-25";
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

pub fn tools() -> Value {
    let selection = json!({"operation":{"type":"string","minLength":1,"maxLength":512},
        "api_version":{"type":"string","maxLength":256},"allow_preview":{"type":"boolean"}});
    let schema = |properties: Value, required: Value| {
        json!({"type":"object","properties":properties,
        "required":required,"additionalProperties":false})
    };
    let mut execute = selection.clone();
    execute["input"] = json!({"type":"object"});
    execute["wait"] = json!({"type":"boolean"});
    execute["timeout_seconds"] = json!({"type":"integer","minimum":1,"maximum":3600});
    execute["all"] = json!({"type":"boolean"});
    execute["max_items"] = json!({"type":"integer","minimum":1,"maximum":10000});
    execute["max_pages"] = json!({"type":"integer","minimum":1,"maximum":10000});
    execute["continuation"] = json!({"type":"string","pattern":"^[0-9a-f]{64}$"});
    // Single-use approval an operator recorded with `junction approvals issue`.
    execute["approval_id"] = json!({"type":"string","pattern":"^[0-9a-f]{32}$"});
    let definitions = [
        (
            "junction_search",
            "Find a bounded set of canonical operations.",
            schema(
                json!({
            "query":{"type":"string","maxLength":1024},"limit":{"type":"integer","minimum":1,"maximum":100},
            "product":{"type":"string","maxLength":128},"service":{"type":"string","maxLength":128},
            "allow_preview":{"type":"boolean"}}),
                json!(["query"]),
            ),
            true,
        ),
        (
            "junction_describe",
            "Describe one operation and its exact input schema.",
            schema(selection.clone(), json!(["operation"])),
            true,
        ),
        (
            "junction_execute",
            "Execute one operation under the configured host policy and context.",
            schema(execute, json!(["operation", "input"])),
            false,
        ),
        (
            "junction_batch",
            "Execute a bounded dependency-aware batch under the configured host policy.",
            schema(
                json!({
            "operations":{"type":"array","minItems":1,"maxItems":100,"items":{"type":"object"}},
            "max_parallel":{"type":"integer","minimum":1,"maximum":10},"fail_fast":{"type":"boolean"},"timeout_seconds":{"type":"integer","minimum":1,"maximum":3600}}),
                json!(["operations"]),
            ),
            false,
        ),
        (
            "junction_permissions",
            "Inspect authoritative imported permission requirements.",
            schema(selection, json!(["operation"])),
            true,
        ),
        (
            "junction_context",
            "List or inspect operator-configured secret-free contexts.",
            schema(
                json!({
            "action":{"type":"string","enum":["list","show"]},"name":{"type":"string","minLength":1,"maxLength":80}}),
                json!(["action"]),
            ),
            true,
        ),
    ];
    Value::Array(
        definitions
            .into_iter()
            .map(|(name, description, input, read)| {
                json!({
                    "name":name,"description":description,"inputSchema":input,
                    "annotations":{"readOnlyHint":read,"destructiveHint":!read,"openWorldHint":true}
                })
            })
            .collect(),
    )
}

/// Host errors must already be safe structured values, never raw exception strings.
pub struct ToolResult {
    pub value: Value,
    pub is_error: bool,
}
impl ToolResult {
    pub fn success(value: Value) -> Self {
        Self {
            value,
            is_error: false,
        }
    }
    pub fn error(value: Value) -> Self {
        Self {
            value,
            is_error: true,
        }
    }
    pub fn into_value(self) -> Value {
        let structured = if self.value.is_object() {
            self.value
        } else {
            json!({"result":self.value})
        };
        json!({"content":[{"type":"text","text":structured.to_string()}],
            "structuredContent":structured,"isError":self.is_error})
    }
}

#[derive(Debug)]
pub struct ResponseTooLarge;
impl std::fmt::Display for ResponseTooLarge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MCP tool result exceeds response size limit")
    }
}
impl std::error::Error for ResponseTooLarge {}

/// Includes both text and structuredContent, reserving space for the JSON-RPC
/// envelope and a maximally escaped 256-byte request ID.
pub fn tool_result_fits(value: &Value) -> anyhow::Result<bool> {
    let result = ToolResult::success(value.clone()).into_value();
    Ok(bounded_encoding(&result)?.is_some_and(|bytes| bytes.len() <= MAX_MESSAGE_BYTES - 2048))
}
#[derive(Default, PartialEq, Eq)]
enum Phase {
    #[default]
    New,
    Initializing,
    Ready,
}
#[derive(Default)]
pub struct Session {
    phase: Phase,
}

pub struct ToolCall {
    pub id: Value,
    pub name: String,
    pub arguments: Value,
}
impl ToolCall {
    pub fn complete(self, result: ToolResult) -> Value {
        json!({"jsonrpc":"2.0","id":self.id,"result":result.into_value()})
    }
}

fn error(id: Value, code: i32, message: &'static str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}
impl Session {
    /// A host callback cannot change initialization, schemas or the advertised surface.
    pub async fn handle<F, Fut>(&mut self, message: Value, mut call: F) -> Option<Value>
    where
        F: FnMut(String, Value) -> Fut,
        Fut: Future<Output = ToolResult>,
    {
        match self.prepare(message) {
            Err(response) => response,
            Ok(mut tool) => {
                let result = call(
                    std::mem::take(&mut tool.name),
                    std::mem::take(&mut tool.arguments),
                )
                .await;
                Some(tool.complete(result))
            }
        }
    }
    /// Validate and route without borrowing session state during host execution.
    pub fn prepare(&mut self, message: Value) -> std::result::Result<ToolCall, Option<Value>> {
        let Some(object) = message.as_object() else {
            return Err(Some(error(Value::Null, -32600, "Invalid Request")));
        };
        let id = object.get("id").cloned();
        let valid_id = id.as_ref().is_none_or(|id| {
            id.as_str().is_some_and(|value| value.len() <= 256)
                || id.as_i64().is_some()
                || id.as_u64().is_some()
        });
        if object.get("jsonrpc") != Some(&json!("2.0"))
            || !valid_id
            || !object.get("method").is_some_and(Value::is_string)
        {
            return Err(Some(error(Value::Null, -32600, "Invalid Request")));
        }
        let method = object["method"].as_str().expect("validated method");
        let params = object.get("params").cloned().unwrap_or_else(|| json!({}));
        let Some(id) = id else {
            if method == "notifications/initialized"
                && params.is_object()
                && self.phase == Phase::Initializing
            {
                self.phase = Phase::Ready;
            }
            return Err(None);
        };
        if !params.is_object() {
            return Err(Some(error(id, -32602, "Invalid params")));
        }
        let result = match method {
            "ping" => json!({}),
            "initialize" if self.phase == Phase::New => {
                if !params.get("protocolVersion").is_some_and(Value::is_string)
                    || !params.get("capabilities").is_some_and(Value::is_object)
                    || !params
                        .pointer("/clientInfo/name")
                        .is_some_and(Value::is_string)
                    || !params
                        .pointer("/clientInfo/version")
                        .is_some_and(Value::is_string)
                {
                    return Err(Some(error(id, -32602, "Invalid initialize params")));
                }
                self.phase = Phase::Initializing;
                json!({"protocolVersion":PROTOCOL_VERSION,"capabilities":{"tools":{"listChanged":false}},
                    "serverInfo":{"name":"junction","version":env!("CARGO_PKG_VERSION")}})
            }
            "initialize" => return Err(Some(error(id, -32600, "Already initialized"))),
            _ if self.phase != Phase::Ready => {
                return Err(Some(error(id, -32002, "Server not initialized")));
            }
            "tools/list" => {
                if params.get("cursor").is_some() {
                    return Err(Some(error(id, -32602, "Invalid cursor")));
                }
                json!({"tools":tools()})
            }
            "tools/call" => {
                let Some(name) = params.get("name").and_then(Value::as_str) else {
                    return Err(Some(error(id, -32602, "Invalid tool name")));
                };
                let definitions = tools();
                let Some(tool) = definitions
                    .as_array()
                    .expect("tools array")
                    .iter()
                    .find(|tool| tool["name"] == name)
                else {
                    return Err(Some(error(id, -32602, "Unknown tool")));
                };
                let arguments = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                if junction_schema::validate_json_schema(&tool["inputSchema"], &arguments).is_err()
                {
                    return Err(Some(error(id, -32602, "Invalid tool arguments")));
                }
                return Ok(ToolCall {
                    id,
                    name: name.to_owned(),
                    arguments,
                });
            }
            _ => return Err(Some(error(id, -32601, "Method not found"))),
        };
        Err(Some(json!({"jsonrpc":"2.0","id":id,"result":result})))
    }
    pub fn parse_error() -> Value {
        error(Value::Null, -32700, "Parse error")
    }
}

/// Read one bounded newline-delimited UTF-8 JSON frame without an unbounded allocation.
pub fn read_frame(reader: &mut impl BufRead) -> anyhow::Result<Option<Vec<u8>>> {
    let mut frame = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(if frame.is_empty() { None } else { Some(frame) });
        }
        let count = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if frame.len() + count > MAX_MESSAGE_BYTES {
            anyhow::bail!("MCP message size limit exceeded");
        }
        frame.extend_from_slice(&available[..count]);
        let complete = available[count - 1] == b'\n';
        reader.consume(count);
        if complete {
            return Ok(Some(frame));
        }
    }
}
pub fn write_frame(writer: &mut impl Write, message: &Value) -> anyhow::Result<()> {
    let bytes = bounded_encoding(message)?
        .ok_or_else(|| anyhow::anyhow!("MCP response size limit exceeded"))?;
    writer.write_all(&bytes)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

struct FrameBuffer {
    bytes: Vec<u8>,
    overflow: bool,
}
impl Write for FrameBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > (MAX_MESSAGE_BYTES - 1) - self.bytes.len() {
            self.overflow = true;
            return Err(std::io::Error::other("MCP response size limit exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn bounded_encoding(message: &Value) -> anyhow::Result<Option<Vec<u8>>> {
    let mut buffer = FrameBuffer {
        bytes: Vec::new(),
        overflow: false,
    };
    let result = serde_json::to_writer(&mut buffer, message);
    if buffer.overflow {
        return Ok(None);
    }
    result?;
    Ok(Some(buffer.bytes))
}

/// Reject an oversized result with a small correlated error, preserving the session.
/// Output I/O failures remain errors and are never followed by another partial frame.
pub fn write_response(writer: &mut impl Write, message: &Value) -> anyhow::Result<()> {
    let bytes = match bounded_encoding(message)? {
        Some(bytes) => bytes,
        None => {
            let id = message
                .get("id")
                .filter(|id| {
                    id.as_str().is_some_and(|value| value.len() <= 256)
                        || id.as_i64().is_some()
                        || id.as_u64().is_some()
                })
                .cloned()
                .unwrap_or(Value::Null);
            let mut rejected = error(id, -32000, "Response exceeds host size limit");
            rejected["error"]["data"] = json!({"status":"response_too_large",
                "max_message_bytes":MAX_MESSAGE_BYTES,"execution_may_have_completed":true});
            serde_json::to_vec(&rejected)?
        }
    };
    writer.write_all(&bytes)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}
