use serde_json::{Value, json};

pub struct HttpError {
    pub status: u16,
    pub body: Value,
}
fn error(status: u16, reason: &'static str) -> HttpError {
    HttpError {
        status,
        body: json!({"status":"invalid_request","reason":reason}),
    }
}
/// Sensitive request inputs deliberately have no Debug or Serialize implementation.
pub enum Route {
    Health,
    Openapi,
    Tool {
        name: &'static str,
        arguments: Value,
    },
    Operations {
        offset: usize,
        limit: usize,
        product: Option<String>,
        service: Option<String>,
        allow_preview: bool,
    },
}
fn decoded(value: &str) -> Result<String, HttpError> {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1..=index + 2]
                    .iter()
                    .all(u8::is_ascii_hexdigit)
            {
                return Err(error(400, "Malformed URL encoding"));
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    percent_encoding::percent_decode_str(value)
        .decode_utf8()
        .map(|value| value.into_owned())
        .map_err(|_| error(400, "Invalid UTF-8 target"))
}
pub fn route(method: &str, target: &str, body: &[u8]) -> Result<Route, HttpError> {
    if target.len() > 8192
        || target.chars().any(char::is_control)
        || !target.starts_with('/')
        || target.starts_with("//")
        || target.contains(['#', '\\'])
    {
        return Err(error(400, "Invalid request target"));
    }
    if body.len() > 16 * 1024 * 1024 {
        return Err(error(413, "Request body limit exceeded"));
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let path = decoded(path)?;
    let (template, expected, tool, id) = match path.as_str() {
        "/health" => ("/health", "GET", None, None),
        "/openapi.json" => ("/openapi.json", "GET", None, None),
        "/v1/search" => ("/v1/search", "GET", Some("junction_search"), None),
        "/v1/operations" => ("/v1/operations", "GET", None, None),
        "/v1/contexts" => ("/v1/contexts", "GET", Some("junction_context"), None),
        "/v1/batch" => ("/v1/batch", "POST", Some("junction_batch"), None),
        "/v1/checks" => ("/v1/checks", "GET", Some("junction_check_list"), None),
        "/v1/checks/run" => ("/v1/checks/run", "POST", Some("junction_check_run"), None),
        // Reading pending answers is GET; submitting one (host flag permitting) is POST.
        "/v1/checks/attestations" => (
            "/v1/checks/attestations",
            if method == "POST" { "POST" } else { "GET" },
            Some("junction_check_attestations"),
            None,
        ),
        _ => {
            let (template, expected, tool, id) =
                if let Some(id) = path.strip_prefix("/v1/operations/") {
                    ("/v1/operations/{id}", "GET", "junction_describe", id)
                } else if let Some(id) = path.strip_prefix("/v1/execute/") {
                    ("/v1/execute/{id}", "POST", "junction_execute", id)
                } else if let Some(id) = path.strip_prefix("/v1/permissions/") {
                    ("/v1/permissions/{id}", "GET", "junction_permissions", id)
                } else if let Some(id) = path.strip_prefix("/v1/checks/runs/") {
                    ("/v1/checks/runs/{id}", "GET", "junction_check_run_status", id)
                } else {
                    return Err(error(404, "Route not found"));
                };
            if id.is_empty()
                || id.len() > 512
                || !id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._".contains(&byte))
            {
                return Err(error(400, "Invalid operation identifier"));
            }
            (template, expected, Some(tool), Some(id))
        }
    };
    if method != expected {
        return Err(error(405, "Method not allowed"));
    }
    let contract = crate::openapi();
    let operation = &contract["paths"][template][if expected == "GET" { "get" } else { "post" }];
    let mut args = json!({});
    if expected == "GET" {
        if !body.is_empty() {
            return Err(error(400, "GET requests must not contain a body"));
        }
        let mut properties = json!({});
        let mut required = vec![];
        for parameter in operation["parameters"]
            .as_array()
            .expect("contract parameters")
        {
            if parameter["in"] == "query" {
                let name = parameter["name"].as_str().expect("parameter name");
                properties[name] = parameter["schema"].clone();
                if parameter["required"] == true {
                    required.push(name);
                }
            }
        }
        for pair in query.split('&').filter(|pair| !pair.is_empty()) {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            let name = decoded(&name.replace('+', " "))?;
            let value = decoded(&value.replace('+', " "))?;
            if args.get(&name).is_some() || properties.get(&name).is_none() {
                return Err(error(400, "Unknown or duplicate query parameter"));
            }
            args[&name] = match properties[&name]["type"].as_str() {
                Some("boolean") => match value.as_str() {
                    "true" => json!(true),
                    "false" => json!(false),
                    _ => return Err(error(400, "Invalid boolean query parameter")),
                },
                Some("integer") => json!(
                    value
                        .parse::<u64>()
                        .map_err(|_| error(400, "Invalid integer query parameter"))?
                ),
                _ => json!(value),
            };
        }
        junction_schema::validate_json_schema(&json!({"type":"object","properties":properties,"required":required,"additionalProperties":false}),&args)
            .map_err(|_|error(400,"Invalid query parameters"))?;
    } else {
        if !query.is_empty() {
            return Err(error(400, "POST options belong in the JSON body"));
        }
        args = serde_json::from_slice(body).map_err(|_| error(400, "Invalid JSON request body"))?;
        let schema = &contract["components"]["schemas"][match tool {
            Some("junction_execute") => "ExecuteRequest",
            Some("junction_check_attestations") => "CheckAttestationRequest",
            Some(other) => other,
            None => "junction_batch",
        }];
        junction_schema::validate_json_schema(schema, &args)
            .map_err(|_| error(400, "Invalid request body"))?;
    }
    if let Some(id) = id {
        args[if template == "/v1/checks/runs/{id}" {
            "run_id"
        } else {
            "operation"
        }] = json!(id);
    }
    match template {
        "/health" => Ok(Route::Health),
        "/openapi.json" => Ok(Route::Openapi),
        "/v1/operations" => Ok(Route::Operations {
            offset: usize::try_from(args["offset"].as_u64().unwrap_or(0))
                .map_err(|_| error(400, "Offset exceeds platform limit"))?,
            limit: args["limit"].as_u64().unwrap_or(20) as usize,
            product: args["product"].as_str().map(str::to_owned),
            service: args["service"].as_str().map(str::to_owned),
            allow_preview: args["allow_preview"].as_bool().unwrap_or(false),
        }),
        "/v1/contexts" => Ok(Route::Tool {
            name: "junction_context",
            arguments: json!({"action":"list"}),
        }),
        "/v1/checks" | "/v1/checks/attestations" => {
            // Comma-separated query values become the tool's arrays.
            let list = |name: &str| -> Option<Value> {
                args[name].as_str().map(|value| {
                    json!(value.split(',').filter(|v| !v.is_empty()).collect::<Vec<_>>())
                })
            };
            let mut arguments = json!({});
            if template == "/v1/checks" {
                for (from, to) in [("pack", "packs"), ("tag", "tags"), ("check", "checks")] {
                    if let Some(values) = list(from) {
                        arguments[to] = values;
                    }
                }
            } else {
                arguments = args.clone();
                arguments["action"] = json!(if expected == "POST" { "submit" } else { "pending" });
            }
            let name = tool.expect("check route");
            let schema = &contract["components"]["schemas"][name];
            junction_schema::validate_json_schema(schema, &arguments)
                .map_err(|_| error(400, "Invalid check request"))?;
            Ok(Route::Tool { name, arguments })
        }
        _ => Ok(Route::Tool {
            name: tool.expect("tool route"),
            arguments: args,
        }),
    }
}
