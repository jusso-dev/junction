use serde_json::{Value, json};
use std::process::Command;

#[test]
fn permissions_and_describe_share_selected_version_requirements() {
    let directory = tempfile::tempdir().unwrap();
    let manifest = directory.path().join("registry.json");
    let operation = |version: &str, preview: bool, security: Value| {
        json!({
            "id":"graph.users.list", "product":"graph", "service":"users",
            "resource":"users", "operation":"list", "description":"List users",
            "method":"GET", "base_url":"https://graph.microsoft.com", "path":"/users",
            "api_version":version, "parameters":[], "responses":{}, "security":security,
        "risk":"read_only", "preview":preview,
        "documentation_url": if preview { "https://learn.microsoft.com/graph?token=private-doc-token" } else { "https://learn.microsoft.com/graph/api/user-list" },
            "source":{"id":"official","upstream":"official","operation_id":"Users_List"}
        })
    };
    std::fs::write(
        &manifest,
        serde_json::to_vec(&json!({
            "format_version":1, "schemas":{}, "operations":[
                operation("v1.0", false, json!([{"oauth":["Users.Read.All"]}])),
                operation("beta", true, json!([]))
            ]
        }))
        .unwrap(),
    )
    .unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_junction"))
            .env_remove("AZURE_TENANT_ID")
            .env_remove("AZURE_CLIENT_ID")
            .env_remove("AZURE_CLIENT_SECRET")
            .arg("--registry")
            .arg(&manifest)
            .args(args)
            .output()
            .unwrap()
    };
    let result = run(&["permissions", "graph.users.list", "--json"]);
    assert!(result.status.success());
    let summary: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(summary["required_permissions"], json!([["Users.Read.All"]]));
    assert_eq!(summary["api_version"], "v1.0");
    assert_eq!(summary["metadata_status"], "imported_scope_requirements");
    assert_eq!(
        summary["documentation_url"],
        "https://learn.microsoft.com/graph/api/user-list"
    );
    assert!(summary.get("parameters").is_none());
    let description = run(&["describe", "graph.users.list"]);
    assert!(description.status.success());
    let description: Value = serde_json::from_slice(&description.stdout).unwrap();
    assert_eq!(
        description["required_permissions"],
        summary["required_permissions"]
    );
    assert!(
        !run(&["permissions", "graph.users.list", "--api-version", "beta"])
            .status
            .success()
    );
    let preview = run(&[
        "permissions",
        "graph.users.list",
        "--api-version",
        "beta",
        "--allow-preview",
    ]);
    assert!(preview.status.success());
    let preview: Value = serde_json::from_slice(&preview.stdout).unwrap();
    assert_eq!(preview["required_permissions"], Value::Null);
    assert_eq!(preview["metadata_status"], "unavailable");
    assert_eq!(preview["documentation_url"], Value::Null);
    let description = run(&[
        "describe",
        "graph.users.list",
        "--api-version",
        "beta",
        "--allow-preview",
    ]);
    assert!(description.status.success());
    assert!(!String::from_utf8_lossy(&description.stdout).contains("private-doc-token"));
    assert!(!run(&["permissions", "graph.missing.list"]).status.success());
}
