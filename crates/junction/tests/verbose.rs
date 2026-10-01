use std::process::Command;

#[test]
fn verbose_keeps_json_stdout_and_omits_private_arguments_from_diagnostics() {
    let output = Command::new(env!("CARGO_BIN_EXE_junction"))
        .args(["openapi", "--verbose", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let contract: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(contract["openapi"], "3.1.1");
    let diagnostics: Vec<serde_json::Value> = String::from_utf8(output.stderr)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(diagnostics.len(), 2);
    assert_eq!(
        diagnostics[0],
        serde_json::json!({"event":"command_started"})
    );
    assert_eq!(diagnostics[1]["event"], "command_finished");
    assert!(diagnostics[1]["elapsed_ms"].is_number());

    let output = Command::new(env!("CARGO_BIN_EXE_junction"))
        .args([
            "--registry",
            "/missing/private-credential-value.json",
            "--verbose",
            "api",
            "stats",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.contains("private-credential-value"));
    assert!(stderr.contains("command_finished"));
    assert!(stderr.contains("command_failed"));
}
