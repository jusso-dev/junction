use serde_json::{Value, json};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[test]
fn token_info_needs_no_registry_and_never_outputs_injected_token() {
    let directory = tempfile::tempdir().unwrap();
    let context = directory.path().join("context.json");
    let contexts = directory.path().join("contexts");
    std::fs::write(
        &context,
        serde_json::to_vec(&json!({
            "cloud":"public", "tenant":"tenant-a", "service":"graph",
            "credential_profile":"injected", "flow":"external_bearer"
        }))
        .unwrap(),
    )
    .unwrap();
    let expires = (SystemTime::now() + Duration::from_secs(3600))
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();
    let call = |arguments: &[&str], tenant: &str| {
        Command::new(env!("CARGO_BIN_EXE_junction"))
            .arg("--registry")
            .arg(directory.path().join("missing-registry"))
            .arg("--contexts-directory")
            .arg(&contexts)
            .env("JUNCTION_ACCESS_TOKEN", "private-injected-token")
            .env("JUNCTION_TOKEN_TENANT", tenant)
            .env("JUNCTION_TOKEN_AUDIENCE", "https://graph.microsoft.com")
            .env("JUNCTION_TOKEN_EXPIRES_AT", &expires)
            .args(arguments)
            .output()
            .unwrap()
    };
    let result = call(
        &[
            "auth",
            "token-info",
            "--context-file",
            context.to_str().unwrap(),
            "--json",
        ],
        "tenant-a",
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let info: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(info["tenant"], "tenant-a");
    assert_eq!(info["audience"], "https://graph.microsoft.com");
    assert_eq!(info["scopes"], json!([]));
    assert_eq!(info["roles"], json!([]));
    assert_eq!(info["account"], Value::Null);
    assert!(info.get("expires_at").is_some());
    assert!(!String::from_utf8_lossy(&result.stdout).contains("private-injected-token"));
    assert!(!String::from_utf8_lossy(&result.stderr).contains("private-injected-token"));
    assert!(
        call(
            &[
                "context",
                "add",
                "customer-a",
                "--file",
                context.to_str().unwrap()
            ],
            "tenant-a"
        )
        .status
        .success()
    );
    let quiet = call(
        &["--context", "customer-a", "auth", "token-info", "--quiet"],
        "tenant-a",
    );
    assert!(quiet.status.success());
    assert!(quiet.stdout.is_empty());
    let rejected = call(
        &["--context", "customer-a", "auth", "token-info"],
        "tenant-b",
    );
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&rejected.stderr).contains("private-injected-token"));
    assert!(
        !call(
            &[
                "--context",
                "customer-a",
                "auth",
                "token-info",
                "--context-file",
                context.to_str().unwrap()
            ],
            "tenant-a"
        )
        .status
        .success()
    );
}

#[test]
fn auth_commands_validate_contexts_and_report_environment_status_without_acquisition() {
    let directory = tempfile::tempdir().unwrap();
    let context = directory.path().join("context.json");
    std::fs::write(
        &context,
        serde_json::to_vec(&json!({
            "cloud":"us_government", "tenant":"tenant-a", "service":"graph",
            "credential_profile":"injected", "flow":"external_bearer"
        }))
        .unwrap(),
    )
    .unwrap();
    let call = |arguments: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_junction"))
            .arg("--registry")
            .arg(directory.path().join("missing-registry"))
            .arg("--contexts-directory")
            .arg(directory.path().join("empty-contexts"))
            .env("JUNCTION_ACCESS_TOKEN", "private-injected-token")
            .args(arguments)
            .output()
            .unwrap()
    };
    let result = call(&[
        "auth",
        "status",
        "--context-file",
        context.to_str().unwrap(),
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let status: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(status["status"], "environment_credential");
    assert_eq!(status["audience"], "https://graph.microsoft.us");
    assert!(status["metadata"].is_null());
    assert!(!String::from_utf8_lossy(&result.stdout).contains("private-injected-token"));
    let accounts = call(&["auth", "accounts"]);
    assert!(accounts.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&accounts.stdout).unwrap(),
        json!({"accounts": []})
    );
    for args in [
        vec!["auth", "status"],
        vec!["auth", "logout"],
        vec![
            "auth",
            "login",
            "--client-id",
            "client-a",
            "--context-file",
            context.to_str().unwrap(),
        ],
        vec![
            "auth",
            "login",
            "--client-id",
            "client-a",
            "--timeout-seconds",
            "0",
        ],
        vec![
            "auth",
            "login",
            "--client-id",
            "client-a",
            "--timeout-seconds",
            "3601",
        ],
    ] {
        let rejected = call(&args);
        assert!(!rejected.status.success());
        assert!(rejected.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&rejected.stderr).contains("private-injected-token"));
    }
    let help = call(&["auth", "--help"]);
    assert!(help.status.success());
    let help = String::from_utf8_lossy(&help.stdout);
    for command in ["login", "logout", "status", "accounts", "token-info"] {
        assert!(help.contains(command));
    }
}
