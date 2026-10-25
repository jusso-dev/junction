//! History and attestation store: schema, runs, retention, tenant binding,
//! attestations with a fake clock, drift from stored runs and concurrency.
use junction_check::attest::{self, DEFAULT_EXPIRY_DAYS, PendingStatus};
use junction_check::check::{CheckMeta, ManualCheck, ManualSpec};
use junction_check::history;
use junction_check::model::{
    Affected, Answer, CheckKind, CheckResult, Evidence, Level, Pack, Remediation, Severity, Status,
    TenantReport, TenantStatus,
};
use junction_check::registry::CheckRegistry;
use junction_check::store::Store;
use junction_watch::clock::Instant;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

const T1: &str = "11111111-1111-4111-8111-111111111111";
const T2: &str = "22222222-2222-4222-8222-222222222222";
const DAY: Duration = Duration::from_secs(86_400);

fn at(value: &str) -> Instant {
    Instant::parse(value).unwrap()
}

fn report(tenant: &str, results: &[(&str, Status)]) -> TenantReport {
    let results: Vec<CheckResult> = results
        .iter()
        .map(|(id, status)| CheckResult {
            id: (*id).into(),
            title: (*id).into(),
            pack: Pack::Identity,
            kind: CheckKind::Automated,
            status: *status,
            severity: Severity::High,
            effort: Level::Low,
            impact: Level::High,
            evidence: Evidence {
                summary: "Synthetic.".into(),
                data: serde_json::json!({"count": 1}),
            },
            affected: Affected::from_items(vec!["admin@contoso.example".into()]),
            remediation: Remediation {
                text: "Fix it.".into(),
                links: vec![],
            },
            references: vec![],
            tags: Default::default(),
            reason: None,
            attested: None,
        })
        .collect();
    TenantReport {
        tenant_id: tenant.into(),
        label: Some("Contoso".into()),
        status: TenantStatus::Complete,
        error: None,
        licences: None,
        score: junction_check::score::score(&results),
        packs: junction_check::score::pack_scores(&results),
        quick_wins: vec![],
        results,
        diff: None,
    }
}

fn simple(tenant: &str, status: Status) -> TenantReport {
    report(tenant, &[("identity.a", status)])
}

fn save(store: &Store, run_id: &str, finished_at: &str, report: &TenantReport) {
    store
        .save_run(run_id, finished_at, finished_at, report)
        .unwrap();
}

fn ids(store: &Store) -> Vec<String> {
    store
        .runs(100)
        .unwrap()
        .into_iter()
        .map(|r| r.run_id)
        .collect()
}

#[test]
fn schema_is_created_from_empty() {
    let store = Store::in_memory(T1).unwrap();
    assert_eq!(store.schema_version().unwrap(), 1);
    assert_eq!(store.tenant_id(), T1);
    assert!(store.runs(10).unwrap().is_empty());
    assert!(store.latest().unwrap().is_none());
    assert!(store.attestations().unwrap().is_empty());
    assert_eq!(store.verify_audit_trail().unwrap(), None);

    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("state").join("history");
    let store = Store::open(&nested, T1).unwrap();
    assert_eq!(store.schema_version().unwrap(), 1);
    save(
        &store,
        "run-1",
        "2026-10-01T00:00:00Z",
        &simple(T1, Status::Pass),
    );
    drop(store);
    let path = Store::path_for(&nested, T1).unwrap();
    assert_eq!(
        path.file_name().unwrap(),
        "11111111-1111-4111-8111-111111111111.sqlite"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&nested), 0o700);
    }
    // Reopening keeps the data and does not migrate again.
    let store = Store::open(&nested, &T1.to_uppercase()).unwrap();
    assert_eq!(ids(&store), ["run-1"]);
    drop(store);

    // A store written by a newer version is refused.
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA user_version = 99").unwrap();
    drop(conn);
    let error = Store::open(&nested, T1).err().unwrap().to_string();
    assert!(error.contains("newer version"), "{error}");
}

#[test]
fn saves_loads_and_lists_newest_first() {
    let store = Store::in_memory(T1).unwrap();
    let mixed = report(
        T1,
        &[
            ("identity.a", Status::Pass),
            ("identity.b", Status::Fail),
            ("identity.c", Status::Unknown),
        ],
    );
    save(&store, "run-2", "2026-10-02T00:00:00Z", &mixed);
    save(
        &store,
        "run-1",
        "2026-10-01T00:00:00Z",
        &simple(T1, Status::Pass),
    );
    // Offsets are normalised to UTC so ordering is by time, not text.
    save(
        &store,
        "run-3",
        "2026-10-03T09:00:00+10:00",
        &simple(T1, Status::Fail),
    );
    save(
        &store,
        "run-4",
        "2026-10-03T00:30:00Z",
        &simple(T1, Status::Fail),
    );
    assert_eq!(ids(&store), ["run-4", "run-3", "run-2", "run-1"]);
    assert_eq!(store.runs(2).unwrap().len(), 2);

    let summary = store
        .runs(10)
        .unwrap()
        .into_iter()
        .find(|r| r.run_id == "run-2")
        .unwrap();
    assert_eq!(summary.finished_at, "2026-10-02T00:00:00.000Z");
    assert_eq!(summary.score, Some(50.0));
    assert_eq!(
        (
            summary.statuses.pass,
            summary.statuses.fail,
            summary.statuses.unknown
        ),
        (1, 1, 1)
    );
    assert_eq!(summary.status, TenantStatus::Complete);

    let loaded = store.load_run("run-2").unwrap().unwrap();
    assert_eq!(loaded.report, mixed, "the full report round-trips");
    assert_eq!(loaded.finished_at, "2026-10-02T00:00:00.000Z");
    assert!(store.load_run("missing").unwrap().is_none());
    assert_eq!(store.latest().unwrap().unwrap().run_id, "run-4");

    // Idempotent on run id: saving again replaces, never duplicates.
    save(&store, "run-2", "2026-10-02T00:00:00Z", &mixed);
    save(&store, "run-2", "2026-10-02T00:00:00Z", &mixed);
    assert_eq!(ids(&store).len(), 4);

    // Wrong tenant, bad timestamps and bad ids are refused.
    assert!(
        store
            .save_run(
                "run-x",
                "2026-10-04T00:00:00Z",
                "2026-10-04T00:00:00Z",
                &simple(T2, Status::Pass)
            )
            .is_err()
    );
    assert!(
        store
            .save_run(
                "run-x",
                "yesterday",
                "2026-10-04T00:00:00Z",
                &simple(T1, Status::Pass)
            )
            .is_err()
    );
    assert!(
        store
            .save_run(
                "run x;",
                "2026-10-04T00:00:00Z",
                "2026-10-04T00:00:00Z",
                &simple(T1, Status::Pass)
            )
            .is_err()
    );
    assert_eq!(ids(&store).len(), 4);
    assert_eq!(store.verify_audit_trail().unwrap(), None);
}

#[test]
fn finds_the_previous_run_and_runs_by_date() {
    let store = Store::in_memory(T1).unwrap();
    assert!(
        store
            .latest_before("2026-10-01T00:00:00Z")
            .unwrap()
            .is_none()
    );
    save(
        &store,
        "a",
        "2026-10-01T08:00:00Z",
        &simple(T1, Status::Pass),
    );
    save(
        &store,
        "b",
        "2026-10-01T23:59:59.999Z",
        &simple(T1, Status::Pass),
    );
    save(
        &store,
        "c",
        "2026-10-02T00:00:00Z",
        &simple(T1, Status::Fail),
    );
    save(
        &store,
        "d",
        "2026-10-05T12:00:00Z",
        &simple(T1, Status::Fail),
    );

    let before = |t: &str| store.latest_before(t).unwrap().map(|r| r.run_id);
    assert_eq!(before("2026-10-05T12:00:00Z").as_deref(), Some("c"));
    assert_eq!(
        before("2026-10-02T00:00:00Z").as_deref(),
        Some("b"),
        "strictly before"
    );
    assert_eq!(before("2026-10-01T08:00:00Z"), None);
    assert!(store.latest_before("not a time").is_err());

    let on = |d: &str| store.run_at_or_before_date(d).unwrap().map(|r| r.run_id);
    assert_eq!(
        on("2026-10-01").as_deref(),
        Some("b"),
        "latest run that day"
    );
    assert_eq!(on("2026-10-02").as_deref(), Some("c"));
    assert_eq!(
        on("2026-10-04").as_deref(),
        Some("c"),
        "falls back to an earlier day"
    );
    assert_eq!(on("2027-01-01").as_deref(), Some("d"));
    assert_eq!(on("2026-09-30"), None);
    for bad in [
        "2026-02-30",
        "20261001",
        "2026-10-1",
        "2026-10-01T00:00:00Z",
        "",
    ] {
        assert!(store.run_at_or_before_date(bad).is_err(), "{bad}");
    }
}

#[test]
fn prune_applies_retention_but_keeps_the_latest_run() {
    let store = Store::in_memory(T1).unwrap();
    let now = at("2026-10-25T00:00:00Z");
    save(
        &store,
        "old",
        &now.minus(DAY * 100).to_rfc3339(),
        &simple(T1, Status::Pass),
    );
    save(
        &store,
        "older",
        &now.minus(DAY * 200).to_rfc3339(),
        &simple(T1, Status::Pass),
    );
    save(
        &store,
        "recent",
        &now.minus(DAY * 10).to_rfc3339(),
        &simple(T1, Status::Pass),
    );
    save(
        &store,
        "latest",
        &now.minus(DAY * 40).to_rfc3339(),
        &simple(T1, Status::Fail),
    );
    // "recent" is the newest by finish time, whatever the insertion order.
    assert_eq!(store.prune(30, now).unwrap(), 3);
    assert_eq!(ids(&store), ["recent"]);
    assert_eq!(store.prune(30, now).unwrap(), 0);

    // Even when everything is past retention, the newest run stays.
    assert_eq!(store.prune(0, now.plus(DAY * 365)).unwrap(), 0);
    assert_eq!(ids(&store), ["recent"]);
    let audit = store.audit_entries(10).unwrap();
    assert_eq!(audit[0].action, "runs.prune");
    assert!(audit[0].detail.contains("removed=3"), "{}", audit[0].detail);
    assert_eq!(store.verify_audit_trail().unwrap(), None);
}

#[test]
fn a_store_is_bound_to_one_tenant() {
    let dir = tempfile::tempdir().unwrap();
    let a = Store::open(dir.path(), T1).unwrap();
    save(
        &a,
        "run-1",
        "2026-10-01T00:00:00Z",
        &simple(T1, Status::Pass),
    );
    drop(a);
    // Each tenant gets its own file, so T2 never sees T1's runs.
    let b = Store::open(dir.path(), T2).unwrap();
    assert!(b.runs(10).unwrap().is_empty());
    drop(b);
    // A mis-pointed file (T1's data under T2's name) is refused.
    std::fs::copy(
        Store::path_for(dir.path(), T1).unwrap(),
        Store::path_for(dir.path(), T2).unwrap(),
    )
    .unwrap();
    let error = Store::open(dir.path(), T2).err().unwrap().to_string();
    assert!(error.contains("different tenant"), "{error}");
    for bad in [
        "contoso.example",
        "../11111111-1111-4111-8111-111111111111",
        "",
    ] {
        assert!(Store::open(dir.path(), bad).is_err(), "{bad}");
        assert!(Store::in_memory(bad).is_err(), "{bad}");
    }
}

#[test]
fn audit_trail_detects_tampering() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), T1).unwrap();
    let now = at("2026-10-25T00:00:00Z");
    save(
        &store,
        "run-1",
        "2026-10-01T00:00:00Z",
        &simple(T1, Status::Pass),
    );
    let a = attest::new(Answer::Yes, "Ticket 42", "ops@contoso.example", now, 30).unwrap();
    store
        .put_attestation("identity.break_glass_monitored", &a)
        .unwrap();
    store
        .audit("history.export", "run-1", "format=json", now)
        .unwrap();
    assert_eq!(store.verify_audit_trail().unwrap(), None);
    let actions: Vec<_> = store
        .audit_entries(10)
        .unwrap()
        .into_iter()
        .map(|e| e.action)
        .collect();
    assert_eq!(actions, ["history.export", "attestation.put", "run.save"]);
    drop(store);

    let conn = rusqlite::Connection::open(Store::path_for(dir.path(), T1).unwrap()).unwrap();
    conn.execute(
        "UPDATE audit_trail SET detail = 'answer=no' WHERE action = 'attestation.put'",
        [],
    )
    .unwrap();
    drop(conn);
    let store = Store::open(dir.path(), T1).unwrap();
    assert_eq!(store.verify_audit_trail().unwrap(), Some(2));
}

#[test]
fn attestations_are_append_only_survive_reopen_and_are_per_tenant() {
    let dir = tempfile::tempdir().unwrap();
    let t0 = at("2026-01-01T00:00:00Z");
    let first = attest::new(Answer::No, "Not yet.", "ops@contoso.example", t0, 180).unwrap();
    let second = attest::new(
        Answer::Yes,
        "Alerts go to the SOC.\nTicket SEC-12.",
        "lead@contoso.example",
        t0.plus(DAY),
        90,
    )
    .unwrap();
    let other = attest::new(Answer::Partial, "", "ops@contoso.example", t0, 30).unwrap();
    {
        let store = Store::open(dir.path(), T1).unwrap();
        store
            .put_attestation("identity.break_glass", &first)
            .unwrap();
        store
            .put_attestation("identity.break_glass", &second)
            .unwrap();
        store
            .put_attestation("backup.offline_copy", &other)
            .unwrap();
    }
    let store = Store::open(dir.path(), T1).unwrap();
    let latest = store.attestations().unwrap();
    assert_eq!(latest.len(), 2);
    assert_eq!(
        latest["identity.break_glass"], second,
        "the latest answer wins"
    );
    assert_eq!(latest["backup.offline_copy"], other);
    assert_eq!(
        store.attestation_history("identity.break_glass").unwrap(),
        [second.clone(), first.clone()],
        "history is kept, newest first"
    );
    assert!(
        store
            .attestation_history("identity.unknown")
            .unwrap()
            .is_empty()
    );

    let t2 = Store::open(dir.path(), T2).unwrap();
    assert!(
        t2.attestations().unwrap().is_empty(),
        "answers are per tenant"
    );

    // The store re-validates what it is given.
    let mut bad = second.clone();
    bad.note = "bell\u{7}".into();
    assert!(store.put_attestation("identity.break_glass", &bad).is_err());
    let mut bad = second.clone();
    bad.expires_at = bad.attested_at.clone();
    assert!(store.put_attestation("identity.break_glass", &bad).is_err());
    assert!(store.put_attestation("not an id", &second).is_err());
    assert_eq!(
        store
            .attestation_history("identity.break_glass")
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn attestation_validation_and_expiry_use_the_given_clock() {
    let t0 = at("2026-03-01T10:00:00Z");
    let a = attest::new(
        Answer::Yes,
        "  Ticket 7  ",
        " ops@contoso.example ",
        t0,
        DEFAULT_EXPIRY_DAYS,
    )
    .unwrap();
    assert_eq!(a.note, "Ticket 7");
    assert_eq!(a.author, "ops@contoso.example");
    assert_eq!(a.attested_at, "2026-03-01T10:00:00.000Z");
    assert_eq!(a.expires_at, t0.plus(DAY * 180).to_rfc3339());
    assert!(attest::is_current(&a, t0));
    assert!(attest::is_current(
        &a,
        t0.plus(DAY * 180).minus(Duration::from_millis(1))
    ));
    assert!(
        !attest::is_current(&a, t0.plus(DAY * 180)),
        "expired answers are not current"
    );
    let mut unreadable = a.clone();
    unreadable.expires_at = "never".into();
    assert!(!attest::is_current(&unreadable, t0));

    let ok = |note: &str, author: &str, days: u32| attest::new(Answer::No, note, author, t0, days);
    assert!(ok(&"x".repeat(2000), "a", 1).is_ok());
    assert!(
        ok(&"é".repeat(2000), "a", 730).is_ok(),
        "limits count characters"
    );
    assert!(ok(&"x".repeat(2001), "a", 180).is_err());
    assert!(ok("tab\there", "a", 180).is_err());
    assert!(ok("escape \u{1b}[31m", "a", 180).is_err());
    assert!(ok("line one\nline two", "a", 180).is_ok());
    assert!(ok("", "   ", 180).is_err());
    assert!(ok("", &"a".repeat(201), 180).is_err());
    assert!(ok("", "ops\nadmin", 180).is_err());
    assert!(ok("", "a", 0).is_err());
    assert!(ok("", "a", 731).is_err());
}

const SPEC: ManualSpec = ManualSpec {
    question: "Is the account monitored?",
    guidance: "Alert on every sign-in.",
    why_manual: "No API reports alert routing.",
};
const MISSING: CheckMeta =
    CheckMeta::manual("identity.manual_missing", "Missing", Pack::Identity, SPEC);
const EXPIRED: CheckMeta =
    CheckMeta::manual("identity.manual_expired", "Expired", Pack::Identity, SPEC);
const EXPIRING: CheckMeta =
    CheckMeta::manual("identity.manual_expiring", "Expiring", Pack::Identity, SPEC);
const CURRENT: CheckMeta =
    CheckMeta::manual("identity.manual_current", "Current", Pack::Identity, SPEC);

#[test]
fn pending_lists_missing_expired_and_expiring_answers() {
    let tags: String = [&MISSING, &EXPIRED, &EXPIRING, &CURRENT]
        .iter()
        .map(|m| format!("{}:\n  mitre: [T1078]\n", m.id))
        .collect();
    let registry = CheckRegistry::new(
        vec![
            Arc::new(ManualCheck(&MISSING)),
            Arc::new(ManualCheck(&EXPIRED)),
            Arc::new(ManualCheck(&EXPIRING)),
            Arc::new(ManualCheck(&CURRENT)),
        ],
        &[("test", tags.as_str())],
    )
    .unwrap();
    let now = at("2026-10-25T00:00:00Z");
    let made = |days_ago: u32, expiry: u32| {
        attest::new(
            Answer::Yes,
            "",
            "ops@contoso.example",
            now.minus(DAY * days_ago),
            expiry,
        )
        .unwrap()
    };
    let store = Store::in_memory(T1).unwrap();
    store.put_attestation(EXPIRED.id, &made(200, 180)).unwrap();
    store.put_attestation(EXPIRING.id, &made(160, 180)).unwrap();
    store.put_attestation(CURRENT.id, &made(10, 180)).unwrap();
    let stored = store.attestations().unwrap();

    let pending = attest::pending(&registry, &stored, now);
    let got: Vec<_> = pending
        .iter()
        .map(|p| (p.check_id.as_str(), p.status, p.expires_at.is_some()))
        .collect();
    assert_eq!(
        got,
        [
            ("identity.manual_missing", PendingStatus::Missing, false),
            ("identity.manual_expired", PendingStatus::Expired, true),
            ("identity.manual_expiring", PendingStatus::Expiring, true),
        ]
    );
    let p = &pending[0];
    assert_eq!(
        (
            p.title.as_str(),
            p.question.as_str(),
            p.guidance.as_str(),
            p.why_manual.as_str()
        ),
        ("Missing", SPEC.question, SPEC.guidance, SPEC.why_manual)
    );
    assert_eq!(
        serde_json::to_value(&pending[1]).unwrap()["status"],
        "expired"
    );

    // Expired answers are excluded by `is_current`, so the runner sees only current ones.
    let current: BTreeMap<_, _> = stored
        .into_iter()
        .filter(|(_, a)| attest::is_current(a, now))
        .collect();
    assert_eq!(
        current.keys().map(String::as_str).collect::<Vec<_>>(),
        ["identity.manual_current", "identity.manual_expiring"]
    );
    // Thirty days on, the expiring answer has expired and the current one is fine.
    let later = attest::pending(
        &registry,
        &store.attestations().unwrap(),
        now.plus(DAY * 30),
    );
    assert_eq!(later[2].status, PendingStatus::Expired);
    assert_eq!(later.len(), 3);
    assert!(
        attest::pending(&registry, &BTreeMap::new(), now)
            .iter()
            .all(|p| p.status == PendingStatus::Missing)
    );
}

#[test]
fn drift_against_the_previous_stored_run() {
    let store = Store::in_memory(T1).unwrap();
    let v1 = report(
        T1,
        &[
            ("identity.a", Status::Fail),
            ("identity.b", Status::Pass),
            ("identity.retired", Status::Fail),
        ],
    );
    let v2 = report(
        T1,
        &[
            ("identity.a", Status::Pass),
            ("identity.b", Status::Warn),
            ("identity.added", Status::Fail),
        ],
    );
    save(&store, "run-1", "2026-10-01T00:00:00Z", &v1);
    save(&store, "run-2", "2026-10-08T00:00:00Z", &v2);

    let current = store.latest().unwrap().unwrap();
    let previous = store.latest_before(&current.finished_at).unwrap().unwrap();
    let d = history::diff(
        &previous.run_id,
        &previous.finished_at,
        &previous.report,
        &current.report,
    );
    assert_eq!(d.previous_run_id, "run-1");
    assert_eq!(d.previous_finished_at, "2026-10-01T00:00:00.000Z");
    assert_eq!(d.new_failures, ["identity.added"]);
    assert_eq!(d.fixed, ["identity.a"]);
    assert_eq!(d.changed.len(), 1);
    assert_eq!(
        (d.changed[0].before, d.changed[0].after),
        (Status::Pass, Status::Warn)
    );
    assert_eq!(d.added, ["identity.added"]);
    assert_eq!(d.removed, ["identity.retired"]);
    // Equal weights: v1 is one pass in three (33.3), v2 a pass, a warn and a fail (50).
    assert_eq!(current.report.score.score, Some(50.0));
    assert_eq!(previous.report.score.score, Some(33.3));
    assert_eq!(d.score_delta, Some(16.7));
    assert!(d.regressed());

    // A diff can be stored with the run and read back.
    let mut with_diff = current.report.clone();
    with_diff.diff = Some(d.clone());
    save(&store, "run-2", "2026-10-08T00:00:00Z", &with_diff);
    assert_eq!(
        store.load_run("run-2").unwrap().unwrap().report.diff,
        Some(d)
    );
}

#[test]
fn concurrent_runs_for_different_tenants_do_not_corrupt_the_store() {
    let dir = tempfile::tempdir().unwrap();
    // The directory does not exist yet: every thread races to create it.
    let root = dir.path().join("history");
    const TENANTS: usize = 8;
    const RUNS: usize = 20;
    let tenant = |i: usize| format!("{i:08x}-0000-4000-8000-000000000000");
    let base = at("2026-10-01T00:00:00Z");
    std::thread::scope(|scope| {
        for i in 0..TENANTS {
            let (root, tenant) = (&root, tenant(i));
            scope.spawn(move || {
                let store = Store::open(root, &tenant).unwrap();
                for r in 0..RUNS {
                    let finished = base.plus(Duration::from_secs(60 * r as u64)).to_rfc3339();
                    let status = if r % 2 == 0 {
                        Status::Pass
                    } else {
                        Status::Fail
                    };
                    store
                        .save_run(
                            &format!("run-{r}"),
                            &finished,
                            &finished,
                            &simple(&tenant, status),
                        )
                        .unwrap();
                    let a = attest::new(
                        Answer::Yes,
                        &format!("run {r}"),
                        "ops@contoso.example",
                        base,
                        30,
                    )
                    .unwrap();
                    store.put_attestation("identity.break_glass", &a).unwrap();
                }
            });
        }
    });
    for i in 0..TENANTS {
        let store = Store::open(&root, &tenant(i)).unwrap();
        assert_eq!(store.runs(1000).unwrap().len(), RUNS, "tenant {i}");
        assert_eq!(
            store.latest().unwrap().unwrap().run_id,
            format!("run-{}", RUNS - 1)
        );
        assert!(
            store.runs(1000).unwrap().iter().all(|r| store
                .load_run(&r.run_id)
                .unwrap()
                .unwrap()
                .report
                .tenant_id
                == tenant(i))
        );
        assert_eq!(
            store
                .attestation_history("identity.break_glass")
                .unwrap()
                .len(),
            RUNS
        );
        assert_eq!(store.verify_audit_trail().unwrap(), None);
        assert_eq!(store.audit_entries(500).unwrap().len(), RUNS * 2);
    }
}

#[test]
fn concurrent_writers_to_one_tenant_wait_instead_of_failing() {
    let dir = tempfile::tempdir().unwrap();
    let base = at("2026-10-01T00:00:00Z");
    std::thread::scope(|scope| {
        for w in 0..4 {
            let dir = dir.path();
            scope.spawn(move || {
                // Separate handles (as separate processes would have) on the same file.
                let store = Store::open(dir, T1).unwrap();
                for r in 0..15 {
                    let finished = base
                        .plus(Duration::from_secs((w * 100 + r) as u64))
                        .to_rfc3339();
                    store
                        .save_run(
                            &format!("w{w}-r{r}"),
                            &finished,
                            &finished,
                            &simple(T1, Status::Pass),
                        )
                        .unwrap();
                }
            });
        }
    });
    let store = Store::open(dir.path(), T1).unwrap();
    assert_eq!(store.runs(1000).unwrap().len(), 60);
    assert_eq!(store.verify_audit_trail().unwrap(), None);
}
