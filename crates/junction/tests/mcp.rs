use serde_json::{Value, json};
use std::{
    io::Write,
    process::{Command, Stdio},
};

#[test]
fn oversized_description_keeps_stdio_session_usable_without_partial_output() {
    let directory = tempfile::tempdir().unwrap();
    let registry = directory.path().join("large.json");
    std::fs::write(&registry,serde_json::to_vec(&json!({"format_version":1,"schemas":{},"operations":[{
        "id":"graph.users.list","product":"graph","service":"users","resource":"users","operation":"list",
        "description":"private-description".repeat(500000),"method":"GET","base_url":"https://example.invalid","path":"/users",
        "parameters":[],"responses":{},"security":[],"risk":"read_only","preview":false,
        "source":{"id":"official","upstream":"official","operation_id":"Users_List"}
    }]})).unwrap()).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_junction"))
        .arg("--registry")
        .arg(&registry)
        .args(["mcp", "serve"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    for message in [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"junction_describe","arguments":{"operation":"graph.users.list"}}}),
        json!({"jsonrpc":"2.0","id":3,"method":"ping"}),
    ] {
        writeln!(stdin, "{message}").unwrap();
    }
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains("private-description"));
    let frames: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(frames.len(), 3);
    assert_eq!(frames[1]["id"], 2);
    assert_eq!(frames[1]["error"]["data"]["status"], "response_too_large");
    assert_eq!(frames[2]["result"], json!({}));
}

#[test]
fn stdio_mcp_uses_registry_and_enforces_policy_before_credentials() {
    let directory = tempfile::tempdir().unwrap();
    let registry = directory.path().join("registry.json");
    let context = directory.path().join("context.json");
    std::fs::write(&context,serde_json::to_vec(&json!({"endpoint":"https://example.invalid","token_request":{
        "tenant":"tenant-a","authority":"https://login.example.invalid","audience":"https://example.invalid",
        "scopes":[],"credential_profile":"environment","flow":"client_credentials"}})).unwrap()).unwrap();
    let operations: Vec<_> = [("list","GET"),("create","POST"),("delete","DELETE")].into_iter().map(|(action,method)|json!({
        "id":format!("graph.users.{action}"),"product":"graph","service":"users","resource":"users",
        "operation":action,"description":"User operation","method":method,"base_url":"https://example.invalid",
        "path":"/users","parameters":[],"responses":{},"security":[],"risk":"read_only","preview":false,
        "source":{"id":"official","upstream":"official","operation_id":format!("Users_{action}")}
    })).collect();
    std::fs::write(
        &registry,
        serde_json::to_vec(&json!({"format_version":1,"schemas":{},"operations":operations}))
            .unwrap(),
    )
    .unwrap();
    for (mode, operation, status) in [
        ("read-only", "graph.users.create", "policy_rejected"),
        ("full", "graph.users.delete", "approval_required"),
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_junction"))
            .arg("--registry")
            .arg(&registry)
            .arg("--contexts-directory")
            .arg(directory.path().join("contexts"))
            .args(["mcp", "serve", "--policy", mode, "--context-file"])
            .arg(&context)
            .env_remove("AZURE_CLIENT_SECRET")
            .env_remove("AZURE_CLIENT_ID")
            .env_remove("AZURE_TENANT_ID")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let messages = [
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
            json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"junction_search","arguments":{"query":"list users"}}}),
            json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"junction_describe","arguments":{"operation":"graph.users.list"}}}),
            json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"junction_permissions","arguments":{"operation":"graph.users.list"}}}),
            json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"junction_execute","arguments":{"operation":operation,"input":{"body":"private-request-body"}}}}),
            json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"junction_batch","arguments":{"operations":[{"id":"write","operation":operation,"input":{}}]}}}),
            json!({"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"junction_context","arguments":{"action":"list"}}}),
            json!({"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"junction_execute","arguments":{"operation":operation,"input":{},"policy":"full","token":"private-token"}}}),
        ];
        let mut stdin = child.stdin.take().unwrap();
        for message in messages {
            writeln!(stdin, "{message}").unwrap();
        }
        writeln!(stdin, "private-malformed-frame").unwrap();
        writeln!(
            stdin,
            "{}",
            json!({"jsonrpc":"2.0","id":10,"method":"ping"})
        )
        .unwrap();
        drop(stdin);
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(!text.contains("private-"));
        let responses: Vec<Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(responses.len(), 11);
        assert_eq!(responses[1]["result"]["tools"].as_array().unwrap().len(), 6);
        assert_eq!(
            responses[2]["result"]["structuredContent"]["matches"][0]["operation"],
            "graph.users.list"
        );
        assert!(responses[3]["result"]["structuredContent"]["input_schema"].is_object());
        assert_eq!(
            responses[4]["result"]["structuredContent"]["metadata_status"],
            "unavailable"
        );
        for response in &responses[5..7] {
            assert_eq!(response["result"]["isError"], true);
            assert_eq!(response["result"]["structuredContent"]["status"], status);
        }
        assert_eq!(
            responses[7]["result"]["structuredContent"]["contexts"],
            json!([])
        );
        assert_eq!(responses[8]["error"]["code"], -32602);
        assert_eq!(responses[9]["error"]["code"], -32700);
        assert_eq!(responses[10]["result"], json!({}));
    }
}
