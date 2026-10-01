use serde_json::json;
use std::process::Command;

#[test]
fn execution_policy_precedes_credentials_and_schema_validation() {
    let directory = tempfile::tempdir().unwrap();
    let manifest = directory.path().join("registry.json");
    let context = directory.path().join("context.json");
    let policy = directory.path().join("policy.toml");
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
    std::fs::write(&policy, "[agent]\nmode = 'full'\n").unwrap();
    let contexts = directory.path().join("contexts");
    let added = Command::new(env!("CARGO_BIN_EXE_junction"))
        .arg("--contexts-directory")
        .arg(&contexts)
        .args(["context", "add", "customer-a", "--file"])
        .arg(&context)
        .output()
        .unwrap();
    assert!(
        added.status.success(),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );

    for (method, full, expected) in [
        ("POST", false, "policy_rejected"),
        ("DELETE", true, "approval_required"),
    ] {
        // Even incorrect read-only metadata cannot downgrade the HTTP method's risk.
        std::fs::write(&manifest, serde_json::to_vec(&json!({
            "format_version":1, "schemas":{}, "operations":[{
                "id":"graph.users.action", "product":"graph", "service":"users",
                "resource":"users", "operation":"action", "description":"",
                "method":method, "base_url":"https://example.invalid", "path":"/users",
                "parameters":[], "responses":{}, "security":[], "risk":"read_only",
                "long_running":{"final_state_via":null,"final_state_schema":null},
                "preview":false, "source":{"id":"official", "upstream":"official", "operation_id":"Users_Action"}
            }]
        })).unwrap()).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_junction"));
        command
            .env_remove("AZURE_TENANT_ID")
            .env_remove("AZURE_CLIENT_ID")
            .env_remove("AZURE_CLIENT_SECRET")
            .arg("--registry")
            .arg(&manifest)
            .args(["execute", "graph.users.action", "--context-file"])
            .arg(&context)
            .args(["--input", "{\"invalid-secret-field\":\"secret-value\"}"]);
        if full {
            command.arg("--policy").arg(&policy);
        }
        // Select stored context for one branch, explicit file for the other.
        if !full {
            command = Command::new(env!("CARGO_BIN_EXE_junction"));
            command
                .env_remove("AZURE_TENANT_ID")
                .env_remove("AZURE_CLIENT_ID")
                .env_remove("AZURE_CLIENT_SECRET")
                .arg("--registry")
                .arg(&manifest)
                .arg("--contexts-directory")
                .arg(&contexts)
                .args([
                    "--context",
                    "customer-a",
                    "execute",
                    "graph.users.action",
                    "--input",
                    "{\"invalid-secret-field\":\"secret-value\"}",
                ]);
        }
        let output = command.output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let text = String::from_utf8(output.stderr).unwrap();
        assert!(!text.contains("secret-value"));
        let denial: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(denial["status"], expected);
        assert_eq!(denial["operation"], "graph.users.action");
        let mut batch = Command::new(env!("CARGO_BIN_EXE_junction"));
        batch.env_remove("AZURE_TENANT_ID").env_remove("AZURE_CLIENT_ID").env_remove("AZURE_CLIENT_SECRET")
            .arg("--registry").arg(&manifest).args(["batch", "--context-file"]).arg(&context)
            .arg("--input").arg(json!({"operations":[{"id":"one","operation":"graph.users.action","input":{"invalid-secret-field":"secret-value"}}]}).to_string());
        if full {
            batch.arg("--policy").arg(&policy);
        }
        let output = batch.output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let denial: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(denial["status"], expected);
        assert!(!String::from_utf8_lossy(&output.stderr).contains("secret-value"));

        // An explicit operator downgrade must agree across preview and execution.
        let overrides = directory.path().join("risks.toml");
        std::fs::write(&overrides, "[[operations]]\noperation='graph.users.action'\nrisk='read_only'\nreason='Regression fixture'\n").unwrap();
        let preview_policy = directory.path().join("preview-policy.toml");
        std::fs::write(
            &preview_policy,
            if full {
                "[agent]\nmode='full'\n"
            } else {
                "[agent]\nmode='read-only'\n"
            },
        )
        .unwrap();
        let preview = Command::new(env!("CARGO_BIN_EXE_junction"))
            .arg("--registry")
            .arg(&manifest)
            .arg("--risk-overrides")
            .arg(&overrides)
            .args([
                "policy-check",
                "graph.users.action",
                "--tenant",
                "customer-a",
                "--policy",
            ])
            .arg(&preview_policy)
            .output()
            .unwrap();
        assert!(
            preview.status.success(),
            "{}",
            String::from_utf8_lossy(&preview.stderr)
        );
        let decision: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
        assert_eq!(decision["status"], expected);
        let hierarchical = Command::new(env!("CARGO_BIN_EXE_junction"))
            .env_remove("AZURE_TENANT_ID")
            .env_remove("AZURE_CLIENT_ID")
            .env_remove("AZURE_CLIENT_SECRET")
            .arg("--registry")
            .arg(&manifest)
            .arg("--risk-overrides")
            .arg(&overrides)
            .args(["graph", "users", "action", "--context-file"])
            .arg(&context)
            .arg("--policy")
            .arg(&preview_policy)
            .arg("--quiet")
            .output()
            .unwrap();
        assert!(!hierarchical.status.success());
        assert!(hierarchical.stdout.is_empty());
        let hierarchy_decision: serde_json::Value =
            serde_json::from_slice(&hierarchical.stderr).unwrap();
        assert_eq!(hierarchy_decision["status"], expected);
        assert_eq!(hierarchy_decision["operation"], "graph.users.action");
        let waited = Command::new(env!("CARGO_BIN_EXE_junction"))
            .env_remove("AZURE_TENANT_ID")
            .env_remove("AZURE_CLIENT_ID")
            .env_remove("AZURE_CLIENT_SECRET")
            .arg("--registry")
            .arg(&manifest)
            .args(["graph", "users", "action", "--context-file"])
            .arg(&context)
            .arg("--policy")
            .arg(&preview_policy)
            .args(["--wait", "--timeout-seconds", "1", "--max-polls", "1"])
            .output()
            .unwrap();
        assert!(!waited.status.success());
        let denial: serde_json::Value = serde_json::from_slice(&waited.stderr).unwrap();
        assert_eq!(denial["status"], expected);
        let input_file = directory.path().join("private-input.json");
        let payload = b"{\"invalid-secret-field\":\"secret-value\"}";
        std::fs::write(&input_file, payload).unwrap();
        for stdin in [false, true] {
            let mut command = Command::new(env!("CARGO_BIN_EXE_junction"));
            command
                .arg("--registry")
                .arg(&manifest)
                .args(["graph", "users", "action", "--context-file"])
                .arg(&context)
                .arg("--policy")
                .arg(&preview_policy)
                .arg("--input-file");
            if stdin {
                command.arg("-");
            } else {
                command.arg(&input_file);
            }
            command
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            let mut child = command.spawn().unwrap();
            if stdin {
                use std::io::Write;
                child.stdin.take().unwrap().write_all(payload).unwrap();
            }
            let output = child.wait_with_output().unwrap();
            assert!(!output.status.success());
            assert!(output.stdout.is_empty());
            assert!(!String::from_utf8_lossy(&output.stderr).contains("secret-value"));
            let denial: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
            assert_eq!(denial["status"], expected);
        }
        let overridden_execution = Command::new(env!("CARGO_BIN_EXE_junction"))
            .env_remove("AZURE_TENANT_ID")
            .env_remove("AZURE_CLIENT_ID")
            .env_remove("AZURE_CLIENT_SECRET")
            .arg("--registry")
            .arg(&manifest)
            .arg("--risk-overrides")
            .arg(&overrides)
            .args(["execute", "graph.users.action", "--context-file"])
            .arg(&context)
            .arg("--policy")
            .arg(&preview_policy)
            .output()
            .unwrap();
        assert!(!overridden_execution.status.success());
        let decision: serde_json::Value =
            serde_json::from_slice(&overridden_execution.stderr).unwrap();
        assert_eq!(decision["status"], expected);
    }
}

#[test]
fn context_management_works_without_a_registry() {
    let directory = tempfile::tempdir().unwrap();
    let contexts = directory.path().join("contexts");
    let source = directory.path().join("source.json");
    std::fs::write(&source, serde_json::to_vec(&json!({"cloud":"china","tenant":"customer-a","service":"graph","credential_profile":"environment"})).unwrap()).unwrap();
    let call = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_junction"))
            .arg("--contexts-directory")
            .arg(&contexts)
            .args(args)
            .output()
            .unwrap()
    };
    let source_arg = source.to_str().unwrap();
    assert!(
        call(&["context", "add", "customer-a", "--file", source_arg])
            .status
            .success()
    );
    assert!(
        !call(&["context", "add", "customer-a", "--file", source_arg])
            .status
            .success()
    );
    let list = call(&["context", "list"]);
    assert!(list.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&list.stdout).unwrap()["contexts"],
        json!(["customer-a"])
    );
    let show = call(&["context", "show", "customer-a"]);
    assert!(show.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&show.stdout).unwrap()["cloud"],
        "china"
    );
    assert!(call(&["context", "remove", "customer-a"]).status.success());
    std::fs::write(&source, serde_json::to_vec(&json!({"cloud":"public","tenant":"customer-a","service":"graph","credential_profile":"environment-obo","flow":"on_behalf_of","scopes":["https://graph.microsoft.com/User.Read.All"]})).unwrap()).unwrap();
    let added = call(&["context", "add", "obo-user", "--file", source_arg]);
    assert!(
        added.status.success(),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );
    let shown = call(&["context", "show", "obo-user"]);
    assert!(shown.status.success());
    let shown: serde_json::Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_eq!(shown["flow"], "on_behalf_of");
    assert_eq!(
        shown["scopes"],
        json!(["https://graph.microsoft.com/User.Read.All"])
    );
    std::fs::write(&source, br#"{"cloud":"public","tenant":"customer-a","service":"graph","credential_profile":"environment","client_secret":"hidden-secret"}"#).unwrap();
    let rejected = call(&["context", "add", "bad-context", "--file", source_arg]);
    assert!(!rejected.status.success());
    assert!(!String::from_utf8_lossy(&rejected.stderr).contains("hidden-secret"));
    assert!(!contexts.join("bad-context.json").exists());
}

#[test]
fn pagination_cli_requires_private_checkpoint_destination() {
    let binary = env!("CARGO_BIN_EXE_junction");
    let missing = Command::new(binary)
        .args(["execute", "graph.users.list", "--all"])
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("--continuation-file"));
    let help = Command::new(binary)
        .args(["execute", "--help"])
        .output()
        .unwrap();
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    for flag in [
        "--all",
        "--max-items",
        "--max-pages",
        "--resume",
        "--continuation-file",
    ] {
        assert!(help.contains(flag));
    }
}

#[test]
fn output_flags_are_global_and_quiet_preserves_failures() {
    let directory = tempfile::tempdir().unwrap();
    let binary = env!("CARGO_BIN_EXE_junction");
    let json_output = Command::new(binary)
        .arg("--contexts-directory")
        .arg(directory.path())
        .args(["context", "list", "--json"])
        .output()
        .unwrap();
    assert!(json_output.status.success());
    assert_eq!(json_output.stdout, b"{\"contexts\":[]}\n");
    let quiet = Command::new(binary)
        .arg("--contexts-directory")
        .arg(directory.path())
        .args(["--quiet", "context", "list"])
        .output()
        .unwrap();
    assert!(quiet.status.success());
    assert!(quiet.stdout.is_empty());
    let failed = Command::new(binary)
        .arg("--contexts-directory")
        .arg(directory.path())
        .args(["context", "show", "missing", "--quiet"])
        .output()
        .unwrap();
    assert!(!failed.status.success());
    assert!(failed.stdout.is_empty());
    assert!(!failed.stderr.is_empty());
}

#[test]
fn yaml_output_roundtrips_the_json_data_and_conflicts_with_json() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("context.json");
    let context =
        json!({"cloud":"public","tenant":"true","service":"graph","credential_profile":"0123"});
    std::fs::write(&source, serde_json::to_vec(&context).unwrap()).unwrap();
    let binary = env!("CARGO_BIN_EXE_junction");
    let run = |arguments: &[&str]| {
        Command::new(binary)
            .arg("--contexts-directory")
            .arg(directory.path().join("contexts"))
            .args(arguments)
            .output()
            .unwrap()
    };
    assert!(
        run(&[
            "context",
            "add",
            "customer",
            "--file",
            source.to_str().unwrap()
        ])
        .status
        .success()
    );
    let output = run(&["context", "show", "customer", "--yaml"]);
    assert!(output.status.success());
    let parsed: serde_json::Value =
        serde_saphyr::from_str(std::str::from_utf8(&output.stdout).unwrap()).unwrap();
    assert_eq!(parsed["tenant"], context["tenant"]);
    assert_eq!(parsed["credential_profile"], context["credential_profile"]);
    let json_output = run(&["context", "show", "customer", "--json"]);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&json_output.stdout).unwrap(),
        parsed
    );
    assert!(
        !run(&["context", "list", "--yaml", "--json"])
            .status
            .success()
    );
    let quiet = run(&["context", "list", "--yaml", "--quiet"]);
    assert!(quiet.status.success());
    assert!(quiet.stdout.is_empty());
}
