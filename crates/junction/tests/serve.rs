use std::process::Command;

#[test]
fn serve_validates_connection_configuration_without_network_or_registry() {
    let token = "synthetic-junction-server-token-123456789";
    for (args, credential, expected) in [
        (vec![], None, "server token environment variable is missing"),
        (
            vec![],
            Some("short-private-value"),
            "server token must contain",
        ),
        (
            vec!["--listen", "0.0.0.0:8080"],
            Some(token),
            "external listening requires --allow-external",
        ),
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_junction"));
        command
            .args(["--registry", "missing-private-registry.json", "serve"])
            .args(args)
            .env_remove("JUNCTION_SERVER_TOKEN");
        if let Some(credential) = credential {
            command.env("JUNCTION_SERVER_TOKEN", credential);
        }
        let output = command.output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains(expected));
        assert!(!error.contains("short-private-value"));
        assert!(!error.contains(token));
        assert!(!error.contains("missing-private-registry"));
    }
    let help = Command::new(env!("CARGO_BIN_EXE_junction"))
        .args(["serve", "--help"])
        .output()
        .unwrap();
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("127.0.0.1:8080"));
    assert!(help.contains("--allow-external"));
    assert!(help.contains("JUNCTION_SERVER_TOKEN"));
    assert!(help.contains("read-only"));
}

#[cfg(test)]
mod transport_tests {
    use serde_json::{Value, json};
    use std::{
        io::{BufRead, BufReader, Read, Write},
        net::TcpStream,
        process::{Child, Command, Stdio},
        time::Duration,
    };
    struct Running(Child);
    impl Drop for Running {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn request(
        address: &str,
        method: &str,
        target: &str,
        body: &str,
        authenticated: bool,
    ) -> (u16, Value) {
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let authorization = if authenticated {
            "Authorization: Bearer synthetic-junction-server-token-123456789\r\n"
        } else {
            ""
        };
        write!(stream,"{method} {target} HTTP/1.1\r\nHost: {address}\r\n{authorization}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
        let mut bytes = Vec::new();
        stream
            .take(20 * 1024 * 1024)
            .read_to_end(&mut bytes)
            .unwrap();
        let separator = bytes
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .unwrap();
        let headers = std::str::from_utf8(&bytes[..separator]).unwrap();
        let status = headers.split_whitespace().nth(1).unwrap().parse().unwrap();
        (
            status,
            serde_json::from_slice(&bytes[separator + 4..]).unwrap(),
        )
    }
    #[test]
    fn real_http_cli_serves_all_routes_and_enforces_fixed_policy() {
        let directory = tempfile::tempdir().unwrap();
        let registry = directory.path().join("registry.json");
        let context = directory.path().join("context.json");
        let operations = [("list","GET"),("create","POST")].into_iter().map(|(action,method)|json!({
            "id":format!("graph.users.{action}"),"product":"graph","service":"users","resource":"users",
            "operation":action,"description":"User operation","method":method,"base_url":"https://example.invalid",
            "path":"/users","parameters":[],"responses":{},"security":[],"risk":"read_only","preview":false,
            "source":{"id":"official","upstream":"official","operation_id":format!("Users_{action}")}
        })).collect::<Vec<_>>();
        std::fs::write(
            &registry,
            serde_json::to_vec(&json!({"format_version":1,"schemas":{},"operations":operations}))
                .unwrap(),
        )
        .unwrap();
        std::fs::write(&context,serde_json::to_vec(&json!({"endpoint":"https://example.invalid","token_request":{
            "tenant":"tenant-a","authority":"https://login.example.invalid","audience":"https://example.invalid",
            "scopes":[],"credential_profile":"environment","flow":"client_credentials"}})).unwrap()).unwrap();
        let mut child = Running(
            Command::new(env!("CARGO_BIN_EXE_junction"))
                .arg("--registry")
                .arg(registry)
                .arg("--contexts-directory")
                .arg(directory.path().join("contexts"))
                .arg("--operations-directory")
                .arg(directory.path().join("operations"))
                .args(["serve", "--listen", "127.0.0.1:0", "--context-file"])
                .arg(context)
                .env(
                    "JUNCTION_SERVER_TOKEN",
                    "synthetic-junction-server-token-123456789",
                )
                .env_remove("AZURE_CLIENT_ID")
                .env_remove("AZURE_CLIENT_SECRET")
                .env_remove("AZURE_TENANT_ID")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let stderr = child.0.stderr.take().unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = BufReader::new(stderr).read_line(&mut line);
            let _ = send.send(line);
        });
        let line = receive
            .recv_timeout(Duration::from_secs(10))
            .expect("listener startup deadline");
        let address = line
            .trim()
            .strip_prefix("Junction HTTP listening on ")
            .expect("listener started");
        assert_eq!(request(address, "GET", "/health", "", false).0, 401);
        for target in [
            "/health",
            "/openapi.json",
            "/v1/search?query=users",
            "/v1/operations?limit=1",
            "/v1/operations/graph.users.list",
            "/v1/permissions/graph.users.list",
            "/v1/contexts",
        ] {
            assert_eq!(request(address, "GET", target, "", true).0, 200, "{target}");
        }
        let (status, body) = request(
            address,
            "POST",
            "/v1/execute/graph.users.create",
            r#"{"input":{}}"#,
            true,
        );
        assert_eq!(status, 403);
        assert_eq!(body["status"], "policy_rejected");
        let (status, body) = request(
            address,
            "POST",
            "/v1/batch",
            r#"{"operations":[{"id":"one","operation":"graph.users.create","input":{}}]}"#,
            true,
        );
        assert_eq!(status, 403);
        assert_eq!(body["status"], "policy_rejected");
        assert_eq!(request(address, "GET", "/unknown", "", true).0, 404);
        assert!(child.0.try_wait().unwrap().is_none());
    }
}
