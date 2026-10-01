//! Junction's local HTTP contract. Listening and runtime adapters are separate.
use serde_json::{Value, json};
mod routing;
pub use routing::{HttpError, Route, route};
mod dispatch;
pub use dispatch::{HttpResponse, dispatch};
mod transport;
pub use transport::{HttpHost, ServerConfig, ServerError, router, serve};

pub fn openapi() -> Value {
    let mut paths = json!({});
    let mut schemas = json!({});
    for tool in junction_mcp::tools().as_array().expect("stable tool array") {
        let name = tool["name"].as_str().expect("tool name");
        schemas[name] = tool["inputSchema"].clone();
    }
    let parameter = |name: &str, location: &str, required: bool, schema: Value| {
        json!({
        "name":name,"in":location,"required":required,"schema":schema})
    };
    let id = parameter(
        "id",
        "path",
        true,
        json!({"type":"string","minLength":1,"maxLength":512}),
    );
    let version = parameter(
        "api_version",
        "query",
        false,
        json!({"type":"string","maxLength":256}),
    );
    let preview = parameter(
        "allow_preview",
        "query",
        false,
        json!({"type":"boolean","default":false}),
    );
    let response = |schema: Value| json!({"description":"Successful JSON result","content":{"application/json":{"schema":schema}}});
    let errors = json!({"description":"Structured, secret-safe host or policy error","content":{"application/json":{"schema":{"type":"object","properties":{"status":{"type":"string"},"reason":{"type":"string"},"error":{"type":"string"},"message":{"type":"string"},"retryable":{"type":"boolean"}},"required":["status"]}}}});
    let make = |operation: &str, parameters: Value, body: Option<Value>, result: Value| {
        let mut endpoint = json!({"operationId":operation,"parameters":parameters,
            "responses":{"200":response(result),"400":errors,"401":errors,"403":errors,"404":errors,"405":errors,"408":errors,"413":errors,"415":errors,"429":errors,"504":errors,"default":errors}});
        if let Some(body) = body {
            endpoint["requestBody"] =
                json!({"required":true,"content":{"application/json":{"schema":body}}});
        }
        endpoint
    };
    paths["/health"]["get"] = make(
        "junction_health",
        json!([]),
        None,
        json!({"type":"object","properties":{"status":{"const":"ok"}},"required":["status"],"additionalProperties":false}),
    );
    let search = &schemas["junction_search"];
    let search_parameters: Vec<_> = search["properties"]
        .as_object()
        .expect("search properties")
        .iter()
        .map(|(name, schema)| parameter(name, "query", name == "query", schema.clone()))
        .collect();
    paths["/v1/search"]["get"] = make(
        "junction_search",
        json!(search_parameters),
        None,
        json!({"type":"object","properties":{"matches":{"type":"array","items":{"type":"object"}}},"required":["matches"]}),
    );
    paths["/v1/operations"]["get"] = make(
        "junction_operations",
        json!([
            parameter(
                "offset",
                "query",
                false,
                json!({"type":"integer","minimum":0,"default":0})
            ),
            parameter(
                "limit",
                "query",
                false,
                json!({"type":"integer","minimum":1,"maximum":100,"default":20})
            ),
            parameter(
                "product",
                "query",
                false,
                json!({"type":"string","maxLength":128})
            ),
            parameter(
                "service",
                "query",
                false,
                json!({"type":"string","maxLength":128})
            ),
            preview.clone()
        ]),
        None,
        json!({"type":"object","properties":{"operations":{"type":"array","items":{"type":"object"}},"next_offset":{"type":["integer","null"]}},"required":["operations","next_offset"]}),
    );
    paths["/v1/operations/{id}"]["get"] = make(
        "junction_describe",
        json!([id.clone(), version.clone(), preview.clone()]),
        None,
        json!({"type":"object","properties":{"input_schema":{"type":"object"}},"required":["input_schema"]}),
    );
    let mut execute = schemas["junction_execute"].clone();
    execute["properties"]
        .as_object_mut()
        .expect("execute properties")
        .remove("operation");
    execute["required"] = json!(["input"]);
    schemas["ExecuteRequest"] = execute;
    paths["/v1/execute/{id}"]["post"] = make(
        "junction_execute",
        json!([id.clone()]),
        Some(json!({"$ref":"#/components/schemas/ExecuteRequest"})),
        json!({"type":"object"}),
    );
    paths["/v1/batch"]["post"] = make(
        "junction_batch",
        json!([]),
        Some(json!({"$ref":"#/components/schemas/junction_batch"})),
        json!({"type":"object"}),
    );
    paths["/v1/contexts"]["get"] = make(
        "junction_contexts",
        json!([]),
        None,
        json!({"type":"object","properties":{"contexts":{"type":"array","items":{"type":"string"}}},"required":["contexts"]}),
    );
    paths["/v1/permissions/{id}"]["get"] = make(
        "junction_permissions",
        json!([id, version, preview]),
        None,
        json!({"type":"object","properties":{"operation":{"type":"string"},"required_permissions":{}},"required":["operation","required_permissions"]}),
    );
    paths["/openapi.json"]["get"] = make(
        "junction_openapi",
        json!([]),
        None,
        json!({"type":"object"}),
    );
    json!({"openapi":"3.1.1","info":{"title":"Junction local API","version":env!("CARGO_PKG_VERSION"),
        "description":"Operator-configured Microsoft API runtime. Context, credentials and policy are fixed by the host, never request input. All routes require the host's server bearer token."},
        "servers":[{"url":"http://127.0.0.1:8080"}],"security":[{"JunctionBearer":[]}],"paths":paths,
        "components":{"schemas":schemas,"securitySchemes":{"JunctionBearer":{"type":"http","scheme":"bearer","description":"Local Junction server token configured through an environment variable; separate from Microsoft credentials."}}}})
}
