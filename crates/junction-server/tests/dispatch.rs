use junction_mcp::ToolResult;
use junction_registry::Registry;
use serde_json::json;

#[tokio::test]
async fn metadata_is_bounded_and_execution_uses_the_shared_host() {
    let registry = Registry::load(
        junction_discovery::ingest(
            &junction_server::openapi(),
            "junction",
            "local",
            "junction-local",
        )
        .unwrap(),
    )
    .unwrap();
    let never =
        |_: String, _: serde_json::Value| async { panic!("metadata must not acquire credentials") };
    let first =
        junction_server::dispatch(&registry, "GET", "/v1/operations?limit=2", &[], never).await;
    assert_eq!(first.status, 200);
    assert_eq!(first.body["operations"].as_array().unwrap().len(), 2);
    assert_eq!(first.body["next_offset"], 2);
    assert!(first.body["operations"][0].get("parameters").is_none());
    let second = junction_server::dispatch(
        &registry,
        "GET",
        "/v1/operations?limit=2&offset=2",
        &[],
        never,
    )
    .await;
    assert_ne!(
        first.body["operations"][0]["operation"],
        second.body["operations"][0]["operation"]
    );
    let end =
        junction_server::dispatch(&registry, "GET", "/v1/operations?offset=999", &[], never).await;
    assert_eq!(end.body, json!({"operations":[],"next_offset":null}));
    let denied = junction_server::dispatch(
        &registry,
        "POST",
        "/v1/execute/graph.users.create",
        br#"{"input":{}}"#,
        |name, arguments| async move {
            assert_eq!(name, "junction_execute");
            assert_eq!(
                arguments,
                json!({"operation":"graph.users.create","input":{}})
            );
            ToolResult::error(json!({"status":"policy_rejected"}))
        },
    )
    .await;
    assert_eq!(denied.status, 403);
    let invalid = junction_server::dispatch(
        &registry,
        "POST",
        "/v1/execute/graph.users.create",
        br#"{"input":{},"policy":"full"}"#,
        never,
    )
    .await;
    assert_eq!(invalid.status, 400);
    assert!(!invalid.body.to_string().contains("full"));
    for (failure, expected) in [
        (json!({"status":"approval_required"}), 403),
        (
            json!({"status":"authorization_failed","http_status":401}),
            401,
        ),
        (
            json!({"status":"authorization_failed","http_status":403}),
            403,
        ),
        (json!({"status":"response_too_large"}), 413),
        (json!({"status":"operation_wait_timed_out"}), 504),
    ] {
        let response = junction_server::dispatch(
            &registry,
            "GET",
            "/v1/permissions/graph.users.list",
            &[],
            |_, _| std::future::ready(ToolResult::error(failure.clone())),
        )
        .await;
        assert_eq!(response.status, expected);
        assert_eq!(response.body, failure);
    }
}
