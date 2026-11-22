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
