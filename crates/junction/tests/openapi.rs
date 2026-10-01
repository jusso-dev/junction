use serde_json::Value;
use std::process::Command;
#[test]
fn local_openapi_export_needs_no_registry_and_supports_atomic_file_output() {
    let directory = tempfile::tempdir().unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_junction"))
        .arg("--registry")
        .arg(directory.path().join("missing"))
        .args(["openapi", "--json"])
        .output()
        .unwrap();
    assert!(result.status.success());
    let contract: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(contract["openapi"], "3.1.1");
    let path = directory.path().join("openapi.json");
    std::fs::write(&path, "old-content").unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_junction"))
        .arg("--registry")
        .arg(directory.path().join("missing"))
        .args(["openapi", "--output"])
        .arg(&path)
        .arg("--quiet")
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(result.stdout.is_empty());
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(path).unwrap()).unwrap(),
        contract
    );
}
