use serde_json::json;
use std::process::Command;
fn manifest(version: &str, kind: &str) -> junction_core::RegistryManifest {
    junction_discovery::ingest(&json!({"openapi":"3.1.0","info":{"version":version},"servers":[{"url":"https://example.invalid"}],"components":{"schemas":{"Item":{"type":kind}}},"paths":{"/items":{"post":{"operationId":"Items_Create","requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Item"}}}},"responses":{"204":{"description":"ok"}}}}}}), "azure","compute","official").unwrap()
}
#[test]
fn merge_cli_combines_versions_and_preserves_prior_output_on_conflicts() {
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("first.json");
    let second = directory.path().join("second.json");
    let output = directory.path().join("merged.json");
    std::fs::write(
        &first,
        serde_json::to_vec(&manifest("2025-01-01", "integer")).unwrap(),
    )
    .unwrap();
    std::fs::write(
        &second,
        serde_json::to_vec(&manifest("2026-01-01", "string")).unwrap(),
    )
    .unwrap();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_junction"))
            .args(["--registry", "missing.json", "merge"])
            .arg(&first)
            .arg(&second)
            .arg("--output")
            .arg(&output)
            .output()
            .unwrap()
    };
    let result = run();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let merged: junction_core::RegistryManifest =
        serde_json::from_slice(&std::fs::read(&output).unwrap()).unwrap();
    assert_eq!(merged.operations.len(), 2);
    let registry = junction_registry::Registry::load(merged).unwrap();
    let schema = registry
        .input_schema("azure.compute.items.create", None, false)
        .unwrap();
    junction_schema::validate_json_schema(&schema, &json!({"body":"item"})).unwrap();
    assert!(junction_schema::validate_json_schema(&schema, &json!({"body":3})).is_err());
    let previous = std::fs::read(&output).unwrap();
    std::fs::write(
        &second,
        serde_json::to_vec(&manifest("2025-01-01", "string")).unwrap(),
    )
    .unwrap();
    assert!(!run().status.success());
    assert_eq!(std::fs::read(&output).unwrap(), previous);
    std::fs::write(&second, b"private-invalid-input").unwrap();
    let result = run();
    assert!(!result.status.success());
    assert!(!String::from_utf8_lossy(&result.stderr).contains("private-invalid-input"));
    assert_eq!(std::fs::read(&output).unwrap(), previous);
}
