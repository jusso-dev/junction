use serde_json::json;
use std::process::Command;

#[test]
fn cli_generates_selected_types_atomically_and_preserves_output_on_error() {
    let directory = tempfile::tempdir().unwrap();
    let registry = directory.path().join("registry.json");
    let output = directory.path().join("types.rs");
    let schema = json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"],"additionalProperties":false});
    let canonical = junction_schema::CanonicalSchema::normalize(&schema).unwrap();
    std::fs::write(&registry, serde_json::to_vec(&json!({"format_version":1,"operations":[],"schemas":{"components":{"schemas":{"User":schema}},"canonical":{"#/components/schemas/User":canonical}}})).unwrap()).unwrap();
    let invoke = |reference: &str| {
        Command::new(env!("CARGO_BIN_EXE_junction"))
            .arg("--registry")
            .arg(&registry)
            .args(["generate-rust", "--schema", reference, "--output"])
            .arg(&output)
            .output()
            .unwrap()
    };
    let result = invoke("#/components/schemas/User");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let emitted = std::fs::read(&output).unwrap();
    assert!(String::from_utf8_lossy(&emitted).contains("pub struct User"));
    let result = invoke("#/missing");
    assert!(!result.status.success());
    assert_eq!(std::fs::read(&output).unwrap(), emitted);
}
