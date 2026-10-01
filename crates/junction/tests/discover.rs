use std::process::Command;

#[test]
fn discovery_cli_validates_before_network_and_preserves_existing_output() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("graph.toml"),
        include_str!("../../../sources/graph.toml"),
    )
    .unwrap();
    let output = directory.path().join("inventory.json");
    std::fs::write(&output, b"previous-inventory").unwrap();
    for (source, revision) in [
        ("graph", "main"),
        ("missing", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_junction"))
            .args([
                "--registry",
                "missing-registry.json",
                "discover",
                source,
                "--revision",
                revision,
                "--sources-directory",
            ])
            .arg(directory.path())
            .arg("--output")
            .arg(&output)
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert_eq!(std::fs::read(&output).unwrap(), b"previous-inventory");
        assert!(!String::from_utf8_lossy(&result.stderr).contains("missing-registry"));
    }
    let help = Command::new(env!("CARGO_BIN_EXE_junction"))
        .args(["discover", "--help"])
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("--revision"));
}
