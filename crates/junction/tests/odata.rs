use serde_json::Value;
use std::process::Command;

#[test]
fn odata_cli_imports_and_describes_without_credentials_or_existing_registry() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("metadata.xml");
    let output = directory.path().join("registry.json");
    std::fs::write(
        &source,
        include_bytes!("../../junction-discovery/tests/fixtures/odata.xml"),
    )
    .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_junction"))
        .args(["--registry", "missing.json", "import"])
        .arg(&source)
        .args([
            "--format",
            "odata",
            "--product",
            "graph",
            "--service",
            "directory",
            "--source",
            "official-csdl",
            "--endpoint",
            "https://graph.microsoft.com/v1.0",
            "--api-version",
            "v1.0",
            "--output",
        ])
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let description = Command::new(env!("CARGO_BIN_EXE_junction"))
        .arg("--registry")
        .arg(output)
        .args(["describe", "graph.reset.invoke", "--json"])
        .output()
        .unwrap();
    assert!(description.status.success());
    let description: Value = serde_json::from_slice(&description.stdout).unwrap();
    assert_eq!(description["method"], "POST");
    assert!(description["input_schema"].is_object());
    assert_eq!(description["required_permissions"], Value::Null);
    let invalid = Command::new(env!("CARGO_BIN_EXE_junction"))
        .arg("import")
        .arg(source)
        .args([
            "--format",
            "odata",
            "--product",
            "graph",
            "--service",
            "directory",
            "--source",
            "official-csdl",
            "--output",
        ])
        .arg(directory.path().join("missing.json"))
        .output()
        .unwrap();
    assert!(!invalid.status.success());
}
