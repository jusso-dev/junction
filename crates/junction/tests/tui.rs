use std::process::Command;

#[test]
fn tui_is_a_native_subcommand_and_refuses_piped_terminal_control() {
    let help = Command::new(env!("CARGO_BIN_EXE_junction"))
        .args(["tui", "--help"])
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(
        String::from_utf8(help.stdout)
            .unwrap()
            .contains("--allow-preview")
    );
    let directory = tempfile::tempdir().unwrap();
    let registry = directory.path().join("registry.json");
    std::fs::write(
        &registry,
        r#"{"format_version":1,"schemas":{},"operations":[]}"#,
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_junction"))
        .arg("--registry")
        .arg(registry)
        .arg("tui")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.contains(&0x1b));
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"], "command_failed");
}
