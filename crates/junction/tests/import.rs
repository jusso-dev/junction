use serde_json::json;
use std::process::Command;
#[test]
fn invalid_catalog_import_preserves_existing_output() {
    let directory = tempfile::tempdir().unwrap();
    let spec = directory.path().join("spec.json");
    let output = directory.path().join("registry.json");
    std::fs::write(&output, b"previous-registry").unwrap();
    std::fs::write(&spec, serde_json::to_vec(&json!({"openapi":"3.0.0","paths":{"/users":{"get":{"description":"hidden-input","responses":{}}}}})).unwrap()).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_junction"))
        .arg("import")
        .arg(&spec)
        .args([
            "--product",
            "graph",
            "--service",
            "users",
            "--source",
            "official",
            "--output",
        ])
        .arg(&output)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!String::from_utf8_lossy(&result.stderr).contains("hidden-input"));
    assert_eq!(std::fs::read(&output).unwrap(), b"previous-registry");
}
