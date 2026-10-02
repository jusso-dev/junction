use serde_json::json;
use std::process::Command;

fn detached() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_junction"));
    command
        .env_remove("JUNCTION_API_KEY_MDCA")
        .stdin(std::process::Stdio::null());
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
fn api_key_contexts_require_out_of_band_keys_and_never_echo_them() {
    let directory = tempfile::tempdir().unwrap();
    let manifest = directory.path().join("registry.json");
    let context = directory.path().join("context.json");
    std::fs::write(
        &manifest,
        serde_json::to_vec(&json!({
            "format_version":1, "schemas":{}, "operations":[{
                "id":"defender.cloud_apps.alerts.list", "product":"defender", "service":"cloud_apps",
                "resource":"alerts", "operation":"list", "description":"",
                "method":"GET", "base_url":"https://contoso.us3.portal.cloudappsecurity.invalid",
                "path":"/api/v1/alerts", "parameters":[], "responses":{}, "security":[],
                "risk":"read_only", "preview":false,
                "source":{"id":"official","upstream":"official","operation_id":"Alerts_List"}
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(
        &context,
        serde_json::to_vec(&json!({
            "endpoint":"https://contoso.us3.portal.cloudappsecurity.invalid",
            "token_request":{
                "tenant":"contoso-tenant", "authority":"https://login.microsoftonline.com",
                "audience":"https://contoso.us3.portal.cloudappsecurity.invalid", "scopes":[],
                "credential_profile":"mdca", "flow":"api_key",
                "api_key":{"header":"authorization","prefix":"Token"}
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let execute = |command: &mut Command| {
        command
            .arg("--registry")
            .arg(&manifest)
            .args([
                "execute",
                "defender.cloud_apps.alerts.list",
                "--context-file",
            ])
            .arg(&context)
            .args(["--input", "{}"])
            .output()
            .unwrap()
    };

    // Headless runs cannot be prompted: they get structured remediation.
    #[cfg(unix)]
    {
        let output = execute(&mut detached());
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["error"], "credential_required");
        assert_eq!(error["flow"], "api_key");
        assert_eq!(error["environment_variable"], "JUNCTION_API_KEY_MDCA");
    }

    // An environment-supplied key is used without prompting and never printed.
    let mut command = detached();
    command.env("JUNCTION_API_KEY_MDCA", "private-mdca-key");
    let output = execute(&mut command);
    assert!(!output.status.success(), "unreachable test host must fail");
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(!text.contains("private-mdca-key"));
    assert!(!text.contains("credential_required"), "{text}");

    let status = |key: Option<&str>| {
        let mut command = detached();
        if let Some(key) = key {
            command.env("JUNCTION_API_KEY_MDCA", key);
        }
        let output = command
            .args(["auth", "status", "--context-file"])
            .arg(&context)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("private-mdca-key"));
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    assert_eq!(
        status(Some("private-mdca-key"))["status"],
        "api_key_environment"
    );

    // Placements must be valid and tied to the api_key flow.
    for token_request in [
        json!({"tenant":"t","authority":"https://login.microsoftonline.com","audience":"a","scopes":[],"credential_profile":"p","flow":"api_key"}),
        json!({"tenant":"t","authority":"https://login.microsoftonline.com","audience":"a","scopes":[],"credential_profile":"p","flow":"api_key","api_key":{"header":"cookie"}}),
        json!({"tenant":"t","authority":"https://login.microsoftonline.com","audience":"a","scopes":[],"credential_profile":"p","flow":"client_credentials","api_key":{"header":"x-api-key"}}),
    ] {
        let invalid = directory.path().join("invalid.json");
        std::fs::write(
            &invalid,
            serde_json::to_vec(
                &json!({"endpoint":"https://x.example","token_request":token_request}),
            )
            .unwrap(),
        )
        .unwrap();
        let output = detached()
            .args(["auth", "status", "--context-file"])
            .arg(&invalid)
            .output()
            .unwrap();
        assert!(!output.status.success());
    }
}
