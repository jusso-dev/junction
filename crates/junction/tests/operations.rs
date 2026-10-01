use serde_json::{Value, json};
use std::{
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
const ID: &str = "00000000-0000-4000-8000-000000000001";

#[test]
fn saved_operations_resume_privately_with_policy_context_and_lock_checks() {
    let directory = tempfile::tempdir().unwrap();
    let checkpoint = directory.path().join(format!("{ID}.json"));
    let registry = directory.path().join("registry.json");
    let context = directory.path().join("context.json");
    let policy = directory.path().join("policy.toml");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut state = json!({
        "format_version":1, "operation_id":ID,"operation":"graph.users.action",
        "version":null,"allow_preview":false,"tenant":"tenant-a",
        "audience":"https://example.invalid","endpoint":"https://example.invalid",
        "poll_url":"https://example.invalid/status?private-query=secret-value",
        "protocol":"resource", "progress":{"state":"succeeded","polls":2},
        "max_polls":100,"not_before":now + 60
    });
    let save = |state: &Value| {
        std::fs::write(&checkpoint, serde_json::to_vec(state).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&checkpoint, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    };
    save(&state);
    std::fs::write(
        &registry,
        serde_json::to_vec(&json!({
            "format_version":1,"schemas":{},"operations":[{
                "id":"graph.users.action","product":"graph","service":"users",
                "resource":"users","operation":"action","description":"",
                "method":"PUT","base_url":"https://example.invalid","path":"/users",
                "parameters":[],"responses":{},"security":[],"risk":"write",
                "long_running":{},"preview":false,
                "source":{"id":"official","upstream":"official","operation_id":"Users_Action"}
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    let write_context = |tenant: &str| {
        std::fs::write(
            &context,
            serde_json::to_vec(&json!({
                "endpoint":"https://example.invalid","token_request":{
                    "tenant":tenant,"authority":"https://login.example.invalid",
                    "audience":"https://example.invalid","scopes":[],
                    "credential_profile":"injected","flow":"external_bearer"
                }
            }))
            .unwrap(),
        )
        .unwrap();
    };
    write_context("tenant-a");
    std::fs::write(&policy, "[agent]\nmode = 'safe-write'\n").unwrap();
    let call = |action: &str, id: &str, credentials: bool, allow: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_junction"));
        command
            .arg("--registry")
            .arg(if action == "get" {
                directory.path().join("missing")
            } else {
                registry.clone()
            })
            .arg("--operations-directory")
            .arg(directory.path())
            .args([
                "operations",
                if action == "wait-result" {
                    "wait"
                } else {
                    action
                },
                id,
                "--json",
            ])
            .env_remove("JUNCTION_ACCESS_TOKEN")
            .env_remove("AZURE_CLIENT_SECRET");
        if action.starts_with("wait") {
            command
                .arg("--context-file")
                .arg(&context)
                .args(["--timeout-seconds", "1"]);
            if allow {
                command.arg("--policy").arg(&policy);
            }
            if action == "wait-result" {
                command.arg("--result");
            }
        }
        if credentials {
            command
                .env("JUNCTION_ACCESS_TOKEN", "private-access-token")
                .env("JUNCTION_TOKEN_TENANT", "tenant-a")
                .env("JUNCTION_TOKEN_AUDIENCE", "https://example.invalid")
                .env("JUNCTION_TOKEN_EXPIRES_AT", (now + 3600).to_string());
        }
        let output = command.output().unwrap();
        for bytes in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(bytes);
            assert!(!text.contains("secret-value"));
            assert!(!text.contains("private-access-token"));
            assert!(!text.contains("poll_url"));
        }
        output
    };
    let get = call("get", ID, false, false);
    assert!(get.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&get.stdout).unwrap()["state"],
        "succeeded"
    );
    assert!(!call("get", "../escape", false, false).status.success());
    let denied = call("wait", ID, false, false);
    assert_eq!(
        serde_json::from_slice::<Value>(&denied.stderr).unwrap()["status"],
        "policy_rejected"
    );
    write_context("tenant-b");
    assert!(!call("wait", ID, false, true).status.success());
    write_context("tenant-a");
    let resumed = call("wait", ID, true, true);
    assert!(
        resumed.status.success(),
        "{}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&resumed.stdout).unwrap()["polls"],
        2
    );
    assert!(!directory.path().join(format!("{ID}.lock")).exists());
    let unavailable = call("wait-result", ID, true, true);
    assert!(!unavailable.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&unavailable.stderr).unwrap()["status"],
        "operation_result_unavailable"
    );
    assert!(!directory.path().join(format!("{ID}.lock")).exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&checkpoint).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    state["progress"]["state"] = json!("running");
    save(&state);
    let timeout = call("wait", ID, true, true);
    assert!(!timeout.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&timeout.stderr).unwrap()["status"],
        "operation_wait_timed_out"
    );
    let persisted: Value = serde_json::from_slice(&std::fs::read(&checkpoint).unwrap()).unwrap();
    assert_eq!(persisted["progress"]["polls"], 2);
    assert_eq!(persisted["progress"]["state"], "running");
    let lock = directory.path().join(format!("{ID}.lock"));
    std::fs::write(&lock, "").unwrap();
    assert!(!call("wait", ID, true, true).status.success());
    assert!(
        lock.exists(),
        "a competing process cannot delete an existing lock"
    );
    assert!(call("get", ID, false, false).status.success());
    std::fs::remove_file(lock).unwrap();
    state["operation_id"] = json!("00000000-0000-4000-8000-000000000002");
    save(&state);
    assert!(!call("get", ID, false, false).status.success());
    assert!(!call("wait", ID, true, true).status.success());
    assert!(!directory.path().join(format!("{ID}.lock")).exists());
}
