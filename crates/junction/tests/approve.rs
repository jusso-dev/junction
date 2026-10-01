use serde_json::json;
use std::process::Command;

fn fixture(directory: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let manifest = directory.join("registry.json");
    let context = directory.join("context.json");
    std::fs::write(
        &context,
        serde_json::to_vec(&json!({
            "endpoint":"https://example.invalid", "token_request":{
                "tenant":"customer-a", "authority":"https://login.example.invalid",
                "audience":"https://example.invalid", "scopes":[],
                "credential_profile":"environment", "flow":"client_credentials"
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let operation = |id: &str, method: &str, risk: &str| {
        json!({
            "id":id, "product":"graph", "service":"users", "resource":"users",
            "operation":id.rsplit('.').next().unwrap(), "description":"",
            "method":method, "base_url":"https://example.invalid", "path":"/users",
            "parameters":[], "responses":{}, "security":[], "risk":risk,
            "preview":false, "source":{"id":"official", "upstream":"official", "operation_id":id}
        })
    };
    std::fs::write(
        &manifest,
        serde_json::to_vec(&json!({
            "format_version":1, "schemas":{}, "operations":[
                operation("graph.users.delete", "DELETE", "destructive"),
                operation("graph.users.list", "GET", "read_only"),
            ]
        }))
        .unwrap(),
    )
    .unwrap();
    (manifest, context)
}

/// Run without a controlling terminal, as an agent or pipeline would.
fn detached(
    manifest: &std::path::Path,
    context: &std::path::Path,
    policy: &std::path::Path,
) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_junction"));
    command
        .env_remove("AZURE_TENANT_ID")
        .env_remove("AZURE_CLIENT_ID")
        .env_remove("AZURE_CLIENT_SECRET")
        .stdin(std::process::Stdio::null())
        .arg("--registry")
        .arg(manifest)
        .arg("execute")
        .arg("--context-file")
        .arg(context)
        .arg("--policy")
        .arg(policy);
    #[cfg(unix)]
    unsafe {
        use std::os::unix::process::CommandExt;
        command.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    command
}

#[test]
fn approval_requires_operator_terminal_and_never_bypasses_policy() {
    let directory = tempfile::tempdir().unwrap();
    let (manifest, context) = fixture(directory.path());
    let full = directory.path().join("full.toml");
    std::fs::write(&full, "[agent]\nmode = 'full'\n").unwrap();
    let deny = directory.path().join("deny.toml");
    std::fs::write(
        &deny,
        "[agent]\nmode = 'full'\n[deny]\noperations = ['*.delete']\n",
    )
    .unwrap();
    let read_only = directory.path().join("read-only.toml");
    std::fs::write(&read_only, "[agent]\nmode = 'read-only'\n").unwrap();

    let run = |policy: &std::path::Path, operation: &str, input: &str| {
        let output = detached(&manifest, &context, policy)
            .args([operation, "--approve", "--input", input])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let text = String::from_utf8(output.stderr).unwrap();
        assert!(!text.contains("secret-value"), "{text}");
        text
    };

    // Without a terminal the request is validated, then refused before any
    // credential acquisition; piped stdin cannot answer the prompt.
    #[cfg(unix)]
    assert!(run(&full, "graph.users.delete", "{}").contains("operator_terminal_unavailable"));
    // Invalid input fails validation before a human is asked to review it.
    assert!(
        !run(
            &full,
            "graph.users.delete",
            "{\"invalid\":\"secret-value\"}"
        )
        .contains("operator_terminal_unavailable")
    );
    // Deny rules and read-only mode cannot be overridden by approval.
    for policy in [&deny, &read_only] {
        let text = run(policy, "graph.users.delete", "{}");
        let denial: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(denial["status"], "policy_rejected");
    }
    // Approval is only meaningful for approval-required requests.
    assert!(run(&full, "graph.users.list", "{}").contains("approval_not_required"));
    // Bounded pagination cannot be combined with an approval.
    let output = detached(&manifest, &context, &full)
        .args(["graph.users.delete", "--approve", "--all", "--input", "{}"])
        .output()
        .unwrap();
    assert!(!output.status.success());
}
