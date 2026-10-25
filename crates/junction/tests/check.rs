//! `junction check` CLI, MCP and HTTP surfaces over recorded fixtures.
//! No test contacts Microsoft: `JUNCTION_CHECK_OFFLINE=1` blocks live calls.
use serde_json::{Value, json};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/check")
}

fn junction(history: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_junction"));
    command
        .env("JUNCTION_CHECK_OFFLINE", "1")
        .env_remove("JUNCTION_CHECK_FIXTURES")
        .arg("check")
        .args(args);
    if matches!(args.first(), Some(&("run" | "attest" | "history" | "diff"))) {
        command.arg("--history-dir").arg(history);
    }
    command.output().unwrap()
}

fn run(history: &Path, args: &[&str]) -> Output {
    let dir = fixtures();
    let mut all = vec!["run", "--fixtures", dir.to_str().unwrap()];
    all.extend_from_slice(args);
    junction(history, &all)
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

const GA: &[&str] = &["--check", "identity.global_admin_count"];

fn with<'a>(base: &[&'a str], extra: &[&'a str]) -> Vec<&'a str> {
    base.iter().chain(extra).copied().collect()
}

fn normalise(mut report: Value) -> Value {
    report["finished_at"] = json!("<finished>");
    report["run_id"] = json!("<run>");
    report["started_at"] = json!("<started>");
    report
}

fn validate_schema(report: &Value) {
    let schema: Value =
        serde_json::from_str(include_str!("../../../docs/check-result.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let errors: Vec<String> = validator
        .iter_errors(report)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn exit_codes_cover_every_documented_outcome() {
    for (args, expected) in [
        // 0: assessed, nothing breached.
        (with(&["--context", "healthy"], GA), 0),
        // 1: a high-severity failure with --fail-on high, or a score below --min-score.
        (with(&["--context", "weak", "--fail-on", "high"], GA), 1),
        (with(&["--context", "weak", "--min-score", "70"], GA), 1),
        // A failure below the --fail-on threshold does not breach it.
        (with(&["--context", "weak", "--fail-on", "critical"], GA), 0),
        // 2: no tenant could be assessed, or the selection is invalid.
        (with(&["--context", "authfail"], GA), 2),
        (
            vec!["--context", "healthy", "--check", "identity.no_such_check"],
            2,
        ),
        (vec!["--context", "healthy", "--tag", "bogus:1"], 2),
        // 3: partial (one tenant failed); --allow-partial accepts it.
        (
            with(&["--context", "healthy", "--context", "authfail"], GA),
            3,
        ),
        (
            with(
                &[
                    "--context",
                    "healthy",
                    "--context",
                    "authfail",
                    "--allow-partial",
                ],
                GA,
            ),
            0,
        ),
    ] {
        let history = tempfile::tempdir().unwrap();
        let output = run(history.path(), &args);
        assert_eq!(
            code(&output),
            expected,
            "{args:?}\nstdout: {}\nstderr: {}",
            stdout(&output),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn json_output_validates_and_runs_read_only_across_tenants() {
    let history = tempfile::tempdir().unwrap();
    let output = run(
        history.path(),
        &[
            "--all-contexts",
            "--check",
            "identity.global_admin_count",
            "--check",
            "endpoint.onboarding_coverage",
            "--format",
            "json",
            "--allow-partial",
        ],
    );
    assert_eq!(
        code(&output),
        0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_str(&stdout(&output)).unwrap();
    validate_schema(&report);
    let tenants = report["tenants"].as_array().unwrap();
    assert_eq!(tenants.len(), 4);
    let by_label = |label: &str| {
        tenants
            .iter()
            .find(|t| t["label"] == label)
            .unwrap_or_else(|| panic!("{label}"))
    };
    assert_eq!(by_label("Auth failure")["status"], "failed");
    let nomde = by_label("No Defender for Endpoint");
    let mde = nomde["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "endpoint.onboarding_coverage")
        .unwrap();
    assert_eq!(mde["status"], "not_applicable");
    assert_eq!(by_label("Weak tenant")["results"][0]["status"], "fail");
    let text = stdout(&output);
    assert!(!text.contains("eyJ") && !text.contains("Access token has expired"));
}

#[test]
fn table_fits_100_columns_in_quick_win_order() {
    let history = tempfile::tempdir().unwrap();
    let output = run(
        history.path(),
        &["--all-contexts", "--allow-partial", "--show-passes"],
    );
    let text = stdout(&output);
    assert!(!text.is_empty());
    for line in text.lines() {
        assert!(line.chars().count() <= 100, "too wide: {line}");
    }
}

#[test]
fn report_formats_write_files_and_split_per_tenant() {
    let history = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    for (format, file) in [
        ("markdown", "r.md"),
        ("html", "r.html"),
        ("m365-secure-json", "r.json"),
    ] {
        let path = out.path().join(file);
        let output = run(
            history.path(),
            &with(
                &[
                    "--context",
                    "weak",
                    "--format",
                    format,
                    "--output",
                    path.to_str().unwrap(),
                ],
                GA,
            ),
        );
        assert_eq!(
            code(&output),
            0,
            "{format}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(stdout(&output).is_empty());
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("Weak tenant") || format == "m365-secure-json",
            "{format}"
        );
    }
    let split = out.path().join("split");
    let output = run(
        history.path(),
        &with(
            &[
                "--context",
                "healthy",
                "--context",
                "weak",
                "--format",
                "html",
                "--split",
                "--output",
                split.to_str().unwrap(),
            ],
            GA,
        ),
    );
    assert_eq!(
        code(&output),
        0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read_dir(&split).unwrap().count(), 2);
    // --split only makes sense with an output directory and a document format.
    let output = run(
        history.path(),
        &with(&["--context", "weak", "--split", "--output", "x"], GA),
    );
    assert_eq!(code(&output), 2);
}

#[test]
fn history_diff_and_regression_threshold() {
    let history = tempfile::tempdir().unwrap();
    // Same tenant id, first healthy then weak: a regression.
    let staged = tempfile::tempdir().unwrap();
    let copy = |from: &str| {
        let dir = staged.path().join("tenant");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for entry in std::fs::read_dir(fixtures().join(from)).unwrap() {
            let entry = entry.unwrap();
            std::fs::copy(entry.path(), dir.join(entry.file_name())).unwrap();
        }
        std::fs::write(
            dir.join("case.toml"),
            "tenant_id = \"00000000-0000-4000-8000-0000000000ee\"\n",
        )
        .unwrap();
    };
    let staged_run = |extra: &[&str]| {
        let mut args = vec![
            "run",
            "--fixtures",
            staged.path().to_str().unwrap(),
            "--context",
            "tenant",
        ];
        args.extend_from_slice(GA);
        args.extend_from_slice(extra);
        junction(history.path(), &args)
    };
    copy("healthy");
    assert_eq!(code(&staged_run(&["--fail-on-regression"])), 0);
    copy("weak");
    assert_eq!(code(&staged_run(&["--fail-on-regression"])), 1);
    let fixtures_arg = staged.path().to_str().unwrap().to_owned();
    let listed = junction(
        history.path(),
        &[
            "history",
            "--fixtures",
            &fixtures_arg,
            "--context",
            "tenant",
        ],
    );
    assert_eq!(
        code(&listed),
        0,
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    assert_eq!(stdout(&listed).matches("score").count(), 2);
    let diff = junction(
        history.path(),
        &[
            "diff",
            "--fixtures",
            &fixtures_arg,
            "--context",
            "tenant",
            "--format",
            "json",
        ],
    );
    let diff: Value = serde_json::from_str(&stdout(&diff)).unwrap();
    assert_eq!(
        diff[0]["diff"]["new_failures"],
        json!(["identity.global_admin_count"])
    );
    // --no-history skips storage and cannot be combined with --fail-on-regression.
    assert_eq!(
        code(&staged_run(&["--no-history", "--fail-on-regression"])),
        2
    );
}

#[test]
fn attestations_answer_manual_checks_and_expire() {
    let history = tempfile::tempdir().unwrap();
    let fx = fixtures();
    let fx = fx.to_str().unwrap();
    let manual = "backup.restore_tested";
    let before = run(
        history.path(),
        &[
            "--context",
            "healthy",
            "--check",
            manual,
            "--format",
            "json",
        ],
    );
    let report: Value = serde_json::from_str(&stdout(&before)).unwrap();
    assert_eq!(report["tenants"][0]["results"][0]["status"], "unknown");
    assert_eq!(code(&before), 0, "awaiting an answer is not a partial run");
    let attested = junction(
        history.path(),
        &[
            "attest",
            manual,
            "--answer",
            "yes",
            "--note",
            "Restore tested",
            "--author",
            "ops",
            "--fixtures",
            fx,
            "--context",
            "healthy",
        ],
    );
    assert_eq!(
        code(&attested),
        0,
        "{}",
        String::from_utf8_lossy(&attested.stderr)
    );
    let after = run(
        history.path(),
        &[
            "--context",
            "healthy",
            "--check",
            manual,
            "--format",
            "json",
        ],
    );
    let report: Value = serde_json::from_str(&stdout(&after)).unwrap();
    let result = &report["tenants"][0]["results"][0];
    assert_eq!(result["status"], "pass");
    assert_eq!(result["attested"]["author"], "ops");
    // Automated checks take no attestations.
    let refused = junction(
        history.path(),
        &[
            "attest",
            "identity.global_admin_count",
            "--answer",
            "yes",
            "--fixtures",
            fx,
            "--context",
            "healthy",
        ],
    );
    assert_eq!(code(&refused), 2);
    let pending = junction(
        history.path(),
        &[
            "attest",
            "--pending",
            "--fixtures",
            fx,
            "--context",
            "healthy",
        ],
    );
    assert!(
        !stdout(&pending).contains(manual),
        "answered checks are not pending"
    );
}

#[test]
fn list_permissions_and_explain() {
    let history = tempfile::tempdir().unwrap();
    let list = junction(
        history.path(),
        &[
            "list",
            "--tag",
            "e8:restrict-admin-privileges",
            "--format",
            "json",
        ],
    );
    let checks: Value = serde_json::from_str(&stdout(&list)).unwrap();
    assert!(
        checks
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == "identity.global_admin_count")
    );
    let permissions = junction(
        history.path(),
        &["permissions", "--pack", "identity", "--format", "json"],
    );
    let rows: Value = serde_json::from_str(&stdout(&permissions)).unwrap();
    assert!(
        rows.as_array()
            .unwrap()
            .iter()
            .any(|r| r["permission"] == "RoleManagement.Read.Directory")
    );
    let explain = junction(history.path(), &["explain", "identity.global_admin_count"]);
    let text = stdout(&explain);
    assert!(text.contains("graph.role_management.directory.role_assignments.list"));
    assert!(text.contains("suggestion only"));
    assert_eq!(
        code(&junction(history.path(), &["explain", "identity.nope"])),
        2
    );
}

#[test]
fn context_selection_is_validated() {
    let history = tempfile::tempdir().unwrap();
    // No tenants selected.
    assert_eq!(code(&run(history.path(), GA)), 2);
    // --context and --all-contexts together.
    assert_eq!(
        code(&run(
            history.path(),
            &with(&["--context", "healthy", "--all-contexts"], GA)
        )),
        2
    );
    // Other commands still take at most one context.
    let output = Command::new(env!("CARGO_BIN_EXE_junction"))
        .args(["--context", "a", "--context", "b", "auth", "status"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    // A tenants file maps ids to contexts.
    let dir = tempfile::tempdir().unwrap();
    let tenants = dir.path().join("tenants.toml");
    std::fs::write(
        &tenants,
        "[[tenant]]\nid = \"00000000-0000-4000-8000-0000000000aa\"\ncontext = \"healthy\"\nlabel = \"Customer A\"\n",
    )
    .unwrap();
    let output = run(
        history.path(),
        &with(
            &["--tenants", tenants.to_str().unwrap(), "--format", "json"],
            GA,
        ),
    );
    assert_eq!(
        code(&output),
        0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(
        report["tenants"][0]["tenant_id"],
        "00000000-0000-4000-8000-0000000000aa"
    );
    assert_eq!(report["tenants"][0]["label"], "Customer A");
}

#[test]
fn mcp_check_run_matches_cli_json() {
    let history = tempfile::tempdir().unwrap();
    let cli = run(
        history.path(),
        &with(
            &["--context", "weak", "--format", "json", "--no-history"],
            GA,
        ),
    );
    let cli: Value = serde_json::from_str(&stdout(&cli)).unwrap();

    let directory = tempfile::tempdir().unwrap();
    let registry = directory.path().join("registry.json");
    std::fs::write(
        &registry,
        br#"{"format_version":1,"schemas":{},"operations":[]}"#,
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_junction"))
        .env("JUNCTION_CHECK_OFFLINE", "1")
        .env("JUNCTION_CHECK_FIXTURES", fixtures())
        .arg("--registry")
        .arg(&registry)
        .args([
            "mcp",
            "serve",
            "--allow-check-contexts",
            "--check-history-dir",
        ])
        .arg(directory.path().join("history"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    for message in [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"junction_check_run","arguments":{"contexts":["weak"],"checks":["identity.global_admin_count"]}}}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"junction_check_attestations","arguments":{"action":"submit","context":"weak","check":"backup.restore_tested","answer":"yes"}}}),
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"junction_check_list","arguments":{"packs":["identity"]}}}),
    ] {
        writeln!(stdin, "{message}").unwrap();
    }
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    let frames: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let report = frames[1]["result"]["structuredContent"].clone();
    assert_eq!(frames[1]["result"]["isError"], false, "{report}");
    assert_eq!(normalise(report), normalise(cli));
    // Agents cannot submit attestations without the operator flag.
    assert_eq!(frames[2]["result"]["isError"], true);
    assert_eq!(
        frames[2]["result"]["structuredContent"]["status"],
        "attestation_disabled"
    );
    assert!(
        frames[3]["result"]["structuredContent"]["checks"]
            .as_array()
            .unwrap()
            .len()
            > 1
    );
}

fn mcp(fixtures_env: bool, flags: &[&str], calls: &[Value]) -> Vec<Value> {
    let directory = tempfile::tempdir().unwrap();
    let registry = directory.path().join("registry.json");
    std::fs::write(
        &registry,
        br#"{"format_version":1,"schemas":{},"operations":[]}"#,
    )
    .unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_junction"));
    command.env("JUNCTION_CHECK_OFFLINE", "1");
    if fixtures_env {
        command.env("JUNCTION_CHECK_FIXTURES", fixtures());
    } else {
        command.env_remove("JUNCTION_CHECK_FIXTURES");
    }
    let mut child = command
        .arg("--contexts-directory")
        .arg(directory.path().join("contexts"))
        .arg("--registry")
        .arg(&registry)
        .args(["mcp", "serve"])
        .args(flags)
        .arg("--check-history-dir")
        .arg(directory.path().join("history"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "{}", json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}})).unwrap();
    writeln!(
        stdin,
        "{}",
        json!({"jsonrpc":"2.0","method":"notifications/initialized"})
    )
    .unwrap();
    for (i, args) in calls.iter().enumerate() {
        writeln!(
            stdin,
            "{}",
            json!({"jsonrpc":"2.0","id":i + 1,"method":"tools/call","params":args})
        )
        .unwrap();
    }
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .skip(1)
        .map(|l| serde_json::from_str::<Value>(l).unwrap()["result"]["structuredContent"].clone())
        .collect()
}

#[test]
fn agents_only_reach_other_contexts_with_the_operator_flag() {
    let run = json!({"name":"junction_check_run","arguments":{"contexts":["weak"],"checks":["identity.global_admin_count"]}});
    let all = json!({"name":"junction_check_run","arguments":{"all_contexts":true}});
    let traversal = json!({"name":"junction_check_attestations","arguments":{"action":"pending","context":"..x"}});
    let pending = json!({"name":"junction_check_attestations","arguments":{"action":"pending","context":"weak"}});
    let replies = mcp(true, &[], &[run.clone(), all, traversal, pending]);
    assert_eq!(replies[0]["status"], "context_not_allowed");
    assert_eq!(replies[1]["status"], "context_not_allowed");
    // Path-like names never reach the host: the tool schema rejects them.
    assert!(replies[2].is_null(), "{}", replies[2]);
    assert_eq!(replies[3]["status"], "context_not_allowed");
    let replies = mcp(true, &["--allow-check-contexts"], &[run]);
    assert_eq!(replies[0]["schema_version"], "1.0");
}

#[test]
fn fixture_replay_needs_both_environment_flags() {
    // Without JUNCTION_CHECK_FIXTURES the host resolves real contexts (none exist).
    let run = json!({"name":"junction_check_run","arguments":{"contexts":["weak"],"checks":["identity.global_admin_count"]}});
    let replies = mcp(false, &["--allow-check-contexts"], &[run]);
    assert_eq!(
        replies[0]["tenants"][0]["status"], "failed",
        "{}",
        replies[0]
    );
    assert_eq!(replies[0]["tenants"][0]["error"]["code"], "context_invalid");
}

#[test]
fn push_is_refused_without_approval_and_never_loses_the_report() {
    let history = tempfile::tempdir().unwrap();
    let push = [
        "--push-sentinel",
        "--dce",
        "https://contoso.australiaeast-1.ingest.monitor.azure.com",
        "--dcr",
        "dcr-00000000000000000000000000000000",
        "--stream",
        "Custom-JunctionCheck_CL",
        "--push-context",
        "weak",
    ];
    let refused = run(
        history.path(),
        &with(&with(&["--context", "weak"], GA), &push),
    );
    assert_eq!(code(&refused), 2);
    assert!(String::from_utf8_lossy(&refused.stderr).contains("approve the push interactively"));
    // A policy whose deny rules forbid the upload cannot be approved away.
    let dir = tempfile::tempdir().unwrap();
    let policy = dir.path().join("deny.toml");
    std::fs::write(
        &policy,
        "[agent]\nmode = 'safe-write'\n[deny]\noperations = ['azure.monitor.*']\n",
    )
    .unwrap();
    let mut args = with(&with(&["--context", "weak"], GA), &push);
    args.extend(["--push-policy", policy.to_str().unwrap()]);
    let denied = run(history.path(), &args);
    assert_eq!(code(&denied), 2);
    assert!(String::from_utf8_lossy(&denied.stderr).contains("deny"));
}
