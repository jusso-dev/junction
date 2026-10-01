use junction_mcp::{
    MAX_MESSAGE_BYTES, PROTOCOL_VERSION, Session, ToolResult, read_frame, write_frame,
};
use serde_json::{Value, json};
use std::io::{BufReader, Cursor};
fn request(method: &str, params: Value) -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":method,"params":params})
}
async fn unused(_: String, _: Value) -> ToolResult {
    panic!("unexpected host execution")
}

#[tokio::test]
async fn lifecycle_and_tool_schema_validation_guard_host_execution() {
    let mut session = Session::default();
    assert_eq!(
        session
            .handle(request("tools/list", json!({})), unused)
            .await
            .unwrap()["error"]["code"],
        -32002
    );
    assert_eq!(
        session
            .handle(request("ping", json!({})), unused)
            .await
            .unwrap()["result"],
        json!({})
    );
    assert_eq!(
        session
            .handle(request("initialize", json!({})), unused)
            .await
            .unwrap()["error"]["code"],
        -32602
    );
    let init = session
        .handle(
            request(
                "initialize",
                json!({"protocolVersion":"unsupported-version","capabilities":{},
        "clientInfo":{"name":"test","version":"1"}}),
            ),
            unused,
        )
        .await
        .unwrap();
    assert_eq!(init["result"]["protocolVersion"], PROTOCOL_VERSION);
    assert_eq!(
        session
            .handle(request("tools/list", json!({})), unused)
            .await
            .unwrap()["error"]["code"],
        -32002
    );
    assert!(
        session
            .handle(
                json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
                unused
            )
            .await
            .is_none()
    );
    let list = session
        .handle(request("tools/list", json!({})), unused)
        .await
        .unwrap();
    let tools = list["result"]["tools"].as_array().unwrap();
    let names: Vec<_> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "junction_search",
            "junction_describe",
            "junction_execute",
            "junction_batch",
            "junction_permissions",
            "junction_context"
        ]
    );
    assert_eq!(tools[0]["annotations"]["readOnlyHint"], true);
    assert_eq!(tools[2]["annotations"]["destructiveHint"], true);
    assert_eq!(
        session
            .handle(request("initialize", json!({})), unused)
            .await
            .unwrap()["error"]["code"],
        -32600
    );
    for (name, arguments) in [
        (
            "junction_search",
            json!({"query":"private-query","limit":101}),
        ),
        (
            "junction_execute",
            json!({"operation":"graph.users.list","input":{},"policy":"full","token":"private-token"}),
        ),
        (
            "junction_execute",
            json!({"operation":"graph.users.list","input":{},"timeout_seconds":0}),
        ),
        (
            "junction_context",
            json!({"action":"add","name":"private-name"}),
        ),
        ("junction_batch", json!({"operations":[]})),
        (
            "junction_execute",
            json!({"operation":"graph.users.list","input":{},"all":true,"max_items":0}),
        ),
        (
            "junction_execute",
            json!({"operation":"graph.users.list","input":{},"all":true,"max_pages":10001}),
        ),
        (
            "junction_execute",
            json!({"operation":"graph.users.list","input":{},"all":true,"continuation":"https://private.invalid/?secret=token"}),
        ),
        ("untrusted-private-tool", json!({})),
    ] {
        let error = session
            .handle(
                request("tools/call", json!({"name":name,"arguments":arguments})),
                unused,
            )
            .await
            .unwrap();
        assert_eq!(error["error"]["code"], -32602);
        assert!(!error.to_string().contains("private"));
    }
    assert_eq!(
        session
            .handle(request("tools/list", json!({"cursor":"private"})), unused)
            .await
            .unwrap()["error"]["code"],
        -32602
    );
    assert_eq!(
        session
            .handle(request("unknown", json!({})), unused)
            .await
            .unwrap()["error"]["code"],
        -32601
    );
    for message in [
        json!([]),
        json!({"jsonrpc":"2.0","id":null,"method":"ping"}),
    ] {
        assert_eq!(
            session.handle(message, unused).await.unwrap()["error"]["code"],
            -32600
        );
    }
    let result = session.handle(request("tools/call",json!({"name":"junction_execute","arguments":{"operation":"graph.users.list","input":{}}})),
        |name, args| async move {
            assert_eq!(name,"junction_execute"); assert_eq!(args["operation"],"graph.users.list");
            ToolResult::error(json!({"status":"policy_rejected","reason":"operator policy"}))
        }).await.unwrap();
    assert_eq!(result["result"]["isError"], true);
    let text: Value =
        serde_json::from_str(result["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(text, result["result"]["structuredContent"]);
    let success = session
        .handle(
            request(
                "tools/call",
                json!({"name":"junction_permissions","arguments":{"operation":"graph.users.list"}}),
            ),
            |_, _| async { ToolResult::success(json!({"required_permissions":null})) },
        )
        .await
        .unwrap();
    assert_eq!(success["result"]["isError"], false);
}

#[test]
fn stdio_frames_are_bounded_json_and_never_write_partial_oversized_messages() {
    let mut bytes = Vec::new();
    write_frame(
        &mut bytes,
        &json!({"jsonrpc":"2.0","id":1,"result":{"text":"line\nbreak"}}),
    )
    .unwrap();
    assert_eq!(bytes.iter().filter(|byte| **byte == b'\n').count(), 1);
    let mut reader = BufReader::with_capacity(7, Cursor::new(bytes.clone()));
    assert_eq!(read_frame(&mut reader).unwrap().unwrap(), bytes);
    assert!(read_frame(&mut reader).unwrap().is_none());
    let mut huge = BufReader::new(Cursor::new(vec![b'x'; MAX_MESSAGE_BYTES + 1]));
    assert!(read_frame(&mut huge).is_err());
    let mut output = Vec::new();
    assert!(
        write_frame(
            &mut output,
            &json!({"result":"x".repeat(MAX_MESSAGE_BYTES)})
        )
        .is_err()
    );
    assert!(output.is_empty());
    assert_eq!(Session::parse_error()["error"]["code"], -32700);
    assert_eq!(Session::parse_error()["id"], Value::Null);
}

#[test]
fn oversized_response_is_correlated_and_followed_by_a_normal_frame() {
    let mut output = Vec::new();
    junction_mcp::write_response(
        &mut output,
        &json!({"jsonrpc":"2.0","id":"request-1",
        "result":{"private":"private-response-value".repeat(MAX_MESSAGE_BYTES/20)}}),
    )
    .unwrap();
    junction_mcp::write_response(&mut output, &json!({"jsonrpc":"2.0","id":2,"result":{}}))
        .unwrap();
    let text = String::from_utf8(output).unwrap();
    assert!(!text.contains("private-response-value"));
    let frames: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0]["id"], "request-1");
    assert_eq!(frames[0]["error"]["data"]["status"], "response_too_large");
    assert_eq!(frames[1]["result"], json!({}));
}
