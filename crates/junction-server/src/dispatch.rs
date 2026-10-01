use junction_mcp::ToolResult;
use junction_registry::{Registry, SearchOptions};
use serde_json::{Value, json};
use std::future::Future;

/// Transport-neutral response; sensitive API data is deliberately not Debug.
pub struct HttpResponse {
    pub status: u16,
    pub body: Value,
}

/// Dispatch validated HTTP requests through the host's shared tool runtime.
/// The callback owns credential, context and policy enforcement.
pub async fn dispatch<F, Fut>(
    registry: &Registry,
    method: &str,
    target: &str,
    body: &[u8],
    mut call: F,
) -> HttpResponse
where
    F: FnMut(String, Value) -> Fut,
    Fut: Future<Output = ToolResult>,
{
    let route = match crate::route(method, target, body) {
        Ok(route) => route,
        Err(error) => {
            return HttpResponse {
                status: error.status,
                body: error.body,
            };
        }
    };
    match route {
        crate::Route::Health => HttpResponse {
            status: 200,
            body: json!({"status":"ok"}),
        },
        crate::Route::Openapi => HttpResponse {
            status: 200,
            body: crate::openapi(),
        },
        crate::Route::Operations {
            offset,
            limit,
            product,
            service,
            allow_preview,
        } => {
            let options = SearchOptions {
                product: product.as_deref(),
                service: service.as_deref(),
                allow_preview,
            };
            match registry.list_filtered(offset, limit, &options) {
                Ok((operations, next)) => HttpResponse {
                    status: 200,
                    body: json!({
                        "operations":operations.into_iter().map(|op| json!({
                            "operation":op.id,"description":op.description.chars().take(1024).collect::<String>(),
                            "product":op.product,"service":op.service,"risk":op.risk,
                            "api_version":op.api_version,"required_permissions":op.required_permissions()
                        })).collect::<Vec<_>>(),"next_offset":next
                    }),
                },
                Err(_) => HttpResponse {
                    status: 400,
                    body: json!({"status":"invalid_request","reason":"Invalid operation listing bounds"}),
                },
            }
        }
        crate::Route::Tool { name, arguments } => {
            let result = call(name.to_owned(), arguments).await;
            let status = if !result.is_error {
                200
            } else {
                match result.value["status"].as_str() {
                    Some("policy_rejected" | "approval_required") => 403,
                    Some("server_busy" | "credential_busy") => 429,
                    Some("response_too_large") => 413,
                    Some("operation_wait_timed_out") => 504,
                    Some("authorization_failed") => match result.value["http_status"].as_u64() {
                        Some(401) => 401,
                        _ => 403,
                    },
                    _ => 400,
                }
            };
            HttpResponse {
                status,
                body: result.value,
            }
        }
    }
}
