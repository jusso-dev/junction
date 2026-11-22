//! `junction apps` CLI over the synthetic governance fixtures in
//! `crates/junction-check/tests/fixtures/governance`. No test contacts
//! Microsoft: `JUNCTION_CHECK_OFFLINE=1` blocks live calls.
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../junction-check/tests/fixtures/governance")
}

/// `junction --context <context> apps <args...> --fixtures <dir>`.
fn apps(context: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_junction"))
        .env("JUNCTION_CHECK_OFFLINE", "1")
        .args(["--context", context, "apps"])
        .args(args)
        .arg("--fixtures")
        .arg(fixtures())
        .output()
        .unwrap()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap()
}

fn text(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

#[test]
fn inventory_table_json_and_fail_on() {
    let table = apps("tenant", &["inventory"]);
    assert_eq!(
        code(&table),
        0,
        "{}",
        String::from_utf8_lossy(&table.stderr)
    );
    let out = text(&table);
    assert!(
        out.contains("Flagged: 3 critical, 2 high, 2 medium"),
        "{out}"
    );
    // Microsoft first-party apps without flags are hidden from the table by default.
    assert!(!out.contains("Office 365 Exchange Online"));

    let json = apps("tenant", &["inventory", "--format", "json"]);
    let inv: Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(inv["schema_version"], 1);
    assert_eq!(inv["apps"].as_array().unwrap().len(), 13);

    assert_eq!(
        code(&apps("tenant", &["inventory", "--fail-on", "critical"])),
        1
    );
    let flagged = apps(
        "tenant",
        &["inventory", "--flagged-only", "--min-severity", "critical"],
    );
    assert_eq!(text(&flagged).matches("critical_permission").count(), 3);
}

#[test]
fn baseline_diff_and_export_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("baseline.json");
    let saved = apps(
        "tenant",
        &["baseline", "save", "--output", base.to_str().unwrap()],
    );
    assert_eq!(
        code(&saved),
        0,
        "{}",
        String::from_utf8_lossy(&saved.stderr)
    );

    let b = base.to_str().unwrap();
    let unchanged = apps("tenant", &["diff", "--baseline", b, "--fail-on-drift"]);
    assert_eq!(code(&unchanged), 0);
    assert!(text(&unchanged).contains("No changes since the baseline."));

    let drifted = apps("later", &["diff", "--baseline", b, "--fail-on-drift"]);
    assert_eq!(
        code(&drifted),
        1,
        "added apps and widened permissions breach --fail-on-drift"
    );
    assert!(text(&drifted).contains("Northwind Inbox Analytics"));

    let pack = dir.path().join("evidence");
    let exported = apps(
        "later",
        &[
            "export",
            "--baseline",
            b,
            "--output",
            pack.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code(&exported),
        0,
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    for file in [
        "README.md",
        "inventory.json",
        "apps.csv",
        "permissions.csv",
        "grants.csv",
        "flags.csv",
        "drift.json",
        "drift.md",
        "manifest.json",
    ] {
        assert!(pack.join(file).is_file(), "{file} missing");
    }
}

#[test]
fn a_baseline_from_another_tenant_or_with_edits_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("baseline.json");
    apps(
        "tenant",
        &["baseline", "save", "--output", base.to_str().unwrap()],
    );
    let text = std::fs::read_to_string(&base).unwrap();
    std::fs::write(&base, text.replace("Mail.Read", "Mail.Send")).unwrap();
    let refused = apps("tenant", &["diff", "--baseline", base.to_str().unwrap()]);
    assert_eq!(code(&refused), 2);
    assert!(String::from_utf8_lossy(&refused.stderr).contains("digest"));
}

#[test]
fn flags_and_permissions_need_no_tenant() {
    for args in [
        ["flags", "--format", "json"],
        ["permissions", "--format", "json"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_junction"))
            .env("JUNCTION_CHECK_OFFLINE", "1")
            .arg("apps")
            .args(args)
            .output()
            .unwrap();
        assert_eq!(code(&output), 0);
        let rows: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(!rows.as_array().unwrap().is_empty());
    }
}

#[test]
fn markdown_and_html_reports_render_from_fixtures() {
    let md = text(&apps("tenant", &["inventory", "--format", "markdown"]));
    assert!(md.starts_with("# Connected apps"));
    assert!(md.contains("### Free PDF Helper"));
    assert!(md.contains("Suggested fix:"));
    let html = text(&apps("tenant", &["inventory", "--format", "html"]));
    assert!(html.starts_with("<!doctype html>"));
    assert!(html.contains("default-src 'none'"));
    assert!(!html.contains("<script"));
    assert!(
        !html.contains("http://") && !html.contains("https://"),
        "no external assets"
    );
    for out in [&md, &html] {
        assert!(!out.contains('\u{2014}'), "no em dashes");
    }
}

/// MCP host over the governance fixtures; returns each call's structured content.
fn mcp(flags: &[&str], calls: &[Value]) -> Vec<Value> {
    use std::io::Write;
    use std::process::Stdio;
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
    let init = serde_json::json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}});
    writeln!(stdin, "{init}").unwrap();
    writeln!(
        stdin,
        "{}",
        serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"})
    )
    .unwrap();
    for (i, params) in calls.iter().enumerate() {
        writeln!(
            stdin,
            "{}",
            serde_json::json!({"jsonrpc":"2.0","id":i + 1,"method":"tools/call","params":params})
        )
        .unwrap();
    }
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .skip(1)
        .map(|l| serde_json::from_str::<Value>(l).unwrap()["result"].clone())
        .collect()
}

#[test]
fn mcp_inventory_matches_the_cli_and_needs_the_context_flag() {
    let cli: Value =
        serde_json::from_slice(&apps("tenant", &["inventory", "--format", "json"]).stdout).unwrap();
    let call =
        serde_json::json!({"name":"junction_apps_inventory","arguments":{"context":"tenant"}});
    let replies = mcp(&["--allow-check-contexts"], std::slice::from_ref(&call));
    assert_eq!(replies[0]["isError"], false, "{}", replies[0]);
    assert_eq!(replies[0]["structuredContent"], cli);

    // Without the operator flag agents cannot name another context.
    let refused = mcp(&[], &[call]);
    assert_eq!(
        refused[0]["structuredContent"]["status"],
        "context_not_allowed"
    );

    // No write tool exists to call.
    let apply = serde_json::json!({"name":"junction_apps_apply","arguments":{}});
    let reply = mcp(&["--allow-check-contexts"], &[apply]);
    assert_ne!(reply[0]["isError"], false);
}
