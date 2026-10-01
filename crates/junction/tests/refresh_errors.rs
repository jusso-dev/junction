use std::process::Command;

#[test]
fn refresh_configuration_errors_expose_only_safe_stage_metadata() {
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("private-credential-value.json");
    let sources = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sources");
    let output = Command::new(env!("CARGO_BIN_EXE_junction"))
        .args([
            "refresh",
            "azure-resources",
            "--max-documents",
            "0",
            "--sources-directory",
        ])
        .arg(sources)
        .arg("--output")
        .arg(&destination)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!destination.exists());
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(
        error,
        serde_json::json!({"error":"source_refresh_failed","stage":"configuration"})
    );
    assert!(
        !String::from_utf8(output.stderr)
            .unwrap()
            .contains("private-credential-value")
    );
}
