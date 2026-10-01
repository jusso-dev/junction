use std::process::Command;

#[test]
fn refresh_rejects_invalid_scope_and_options_without_replacing_output() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("graph.toml"),
        include_str!("../../../sources/graph.toml"),
    )
    .unwrap();
    std::fs::write(
        directory.path().join("graph-odata.toml"),
        include_str!("../../../sources/graph-odata.toml"),
    )
    .unwrap();
    let output = directory.path().join("manifest.json");
    std::fs::write(&output, b"previous-manifest").unwrap();
    for args in [
        vec!["graph", "--path", "openapi/v1.0/openapi.yaml-extra"],
        vec!["graph", "--path", "../private"],
        vec!["graph", "--max-documents", "0"],
        vec!["graph", "--timeout-seconds", "0"],
        vec!["graph", "--timeout-seconds", "3601"],
        vec!["graph", "--service", "Invalid service"],
        vec![
            "graph-odata",
            "--endpoint",
            "https://example.invalid?secret=value",
            "--api-version",
            "v1.0",
        ],
        vec![
            "graph-odata",
            "--endpoint",
            "https://example.invalid",
            "--api-version",
            "",
        ],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_junction"))
            .args(["--registry", "missing-registry.json", "refresh"])
            .args(args)
            .arg("--sources-directory")
            .arg(directory.path())
            .arg("--output")
            .arg(&output)
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert_eq!(std::fs::read(&output).unwrap(), b"previous-manifest");
        let error = String::from_utf8_lossy(&result.stderr);
        assert!(!error.contains("missing-registry"));
        assert!(!error.contains("secret=value"));
    }
}
