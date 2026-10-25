//! Report renderers: snapshots, HTML lint, accessibility, escaping and secrets.
use junction_check::check::{
    ApiRequirement, Check, CheckMeta, Evaluation, Finding, ManualSpec, Requirements,
};
use junction_check::context::CheckContext;
use junction_check::gateway::BoxFut;
use junction_check::history::{Diff, StatusChange};
use junction_check::model::*;
use junction_check::registry::CheckRegistry;
use junction_check::report::{ReportOptions, coverage, html, markdown, maturity, table};
use junction_check::score;
use junction_check::tags::{E8Tag, Tags};
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;

const SECRETS: [&str; 3] = [
    "Hunter2-not-for-print",
    "tok-SECRET-0001",
    "k3y-SECRET-0002",
];

struct R {
    id: &'static str,
    title: &'static str,
    status: Status,
    severity: Severity,
    effort: Level,
    impact: Level,
    e8: &'static [(&'static str, &'static [u8])],
    ism: &'static [&'static str],
    summary: &'static str,
}

fn result(r: R) -> CheckResult {
    let pack = Pack::parse(r.id.split('.').next().unwrap()).unwrap();
    CheckResult {
        id: r.id.into(),
        title: r.title.into(),
        pack,
        kind: CheckKind::Automated,
        status: r.status,
        severity: r.severity,
        effort: r.effort,
        impact: r.impact,
        evidence: Evidence {
            summary: r.summary.into(),
            data: json!({ "count": 1 }),
        },
        affected: Affected::default(),
        remediation: Remediation {
            text: format!("Suggested fix for {}.", r.title),
            links: vec!["https://learn.microsoft.com/entra/identity/".into()],
        },
        references: vec![],
        tags: Tags {
            essential_eight: r
                .e8
                .iter()
                .map(|(s, l)| E8Tag {
                    strategy: (*s).into(),
                    levels: l.to_vec(),
                })
                .collect(),
            ism: r.ism.iter().map(|s| (*s).into()).collect(),
            cis_v8: vec!["5.4".into()],
            ..Tags::default()
        },
        reason: None,
        attested: None,
    }
}

fn tenant(id: &str, label: Option<&str>, mut results: Vec<CheckResult>) -> TenantReport {
    score::quick_win_order(&mut results);
    let quick_wins = results
        .iter()
        .filter(|r| matches!(r.status, Status::Fail | Status::Warn))
        .map(|r| r.id.clone())
        .collect();
    let status = if results.iter().any(|r| r.status == Status::Unknown) {
        TenantStatus::Partial
    } else {
        TenantStatus::Complete
    };
    TenantReport {
        tenant_id: id.into(),
        label: label.map(Into::into),
        status,
        error: None,
        licences: Some(LicenceSnapshot {
            features: vec!["entra_id_p1".into(), "intune".into()],
            skus: vec!["SPE_E3".into()],
        }),
        score: score::score(&results),
        packs: score::pack_scores(&results),
        quick_wins,
        results,
        diff: None,
    }
}

fn sample_results() -> Vec<CheckResult> {
    use Level::{High, Low, Medium};
    let mut mfa = result(R {
        id: "identity.mfa_admins",
        title: "Administrators register phishing-resistant MFA",
        status: Status::Fail,
        severity: Severity::Critical,
        effort: Low,
        impact: High,
        e8: &[("mfa", &[1, 2, 3])],
        ism: &["ISM-1504"],
        summary: "25 of 30 administrators have no phishing-resistant method registered.",
    });
    mfa.affected = Affected::from_items(
        (1..=25)
            .map(|i| format!("admin{i:02}@contoso.example"))
            .collect(),
    );
    mfa.evidence.data = json!({
        "without_mfa": 25,
        "password": SECRETS[0],
        "access_token": SECRETS[1],
        "nested": { "key": SECRETS[2] },
    });
    mfa.references = vec!["CIS M365 1.1.1".into()];
    let mut patch = result(R {
        id: "intune.os_update_rings",
        title: "Windows quality updates install within two weeks",
        status: Status::Unknown,
        severity: Severity::High,
        effort: Medium,
        impact: High,
        e8: &[("patch-operating-systems", &[1, 2, 3])],
        ism: &["ISM-1877"],
        summary: "Could not read Windows update rings.",
    });
    patch.reason = Some(Reason {
        code: "missing_permission".into(),
        detail: "Microsoft Graph returned 403 for update rings.".into(),
        missing_permissions: vec!["DeviceManagementConfiguration.Read.All".into()],
    });
    let mut backup = result(R {
        id: "backup.m365_backup",
        title: "Microsoft 365 Backup protects mailboxes and sites",
        status: Status::NotApplicable,
        severity: Severity::Medium,
        effort: Medium,
        impact: Medium,
        e8: &[("regular-backups", &[1, 2, 3])],
        ism: &[],
        summary: "Microsoft 365 Backup is not licensed.",
    });
    backup.reason = Some(Reason::new(
        "missing_licence",
        "Microsoft 365 Backup is not licensed.",
    ));
    let mut glass = result(R {
        id: "identity.break_glass_monitored",
        title: "Break-glass sign-ins raise an alert",
        status: Status::Pass,
        severity: Severity::Medium,
        effort: Low,
        impact: Medium,
        e8: &[("restrict-admin-privileges", &[2, 3])],
        ism: &[],
        summary: "Attested 'yes' by secops@contoso.example on 2026-10-01.",
    });
    glass.kind = CheckKind::Manual;
    glass.attested = Some(Attestation {
        answer: Answer::Yes,
        note: "Sentinel rule BG-01 alerts the on-call engineer.".into(),
        author: "secops@contoso.example".into(),
        attested_at: "2026-10-01T00:00:00Z".into(),
        expires_at: "2027-04-01T00:00:00Z".into(),
    });
    let mut dmarc = result(R {
        id: "email.dmarc_reject",
        title: "DMARC policy is reject or quarantine",
        status: Status::Pass,
        severity: Severity::Low,
        effort: Low,
        impact: Medium,
        e8: &[],
        ism: &[],
        summary: "contoso.example publishes p=reject.",
    });
    dmarc.evidence.data = json!({ "password": SECRETS[0] });
    vec![
        mfa,
        patch,
        backup,
        glass,
        dmarc,
        result(R {
            id: "identity.global_admin_count",
            title: "Between two and four Global Administrators",
            status: Status::Pass,
            severity: Severity::High,
            effort: Low,
            impact: High,
            e8: &[("restrict-admin-privileges", &[1, 2, 3])],
            ism: &["ISM-1507"],
            summary: "3 Global Administrators.",
        }),
        result(R {
            id: "endpoint.asr_office_macros",
            title: "ASR blocks Office macros from creating executables",
            status: Status::Warn,
            severity: Severity::Medium,
            effort: Low,
            impact: Medium,
            e8: &[("office-macros", &[1, 2, 3])],
            ism: &[],
            summary: "The rule is in audit mode on 12 devices.",
        }),
        result(R {
            id: "intune.app_update_policy",
            title: "Microsoft 365 Apps update automatically",
            status: Status::Pass,
            severity: Severity::Medium,
            effort: Low,
            impact: Medium,
            e8: &[("patch-applications", &[1])],
            ism: &[],
            summary: "Monthly Enterprise Channel with automatic updates.",
        }),
        result(R {
            id: "endpoint.app_vulnerabilities",
            title: "No critical application vulnerabilities older than two weeks",
            status: Status::Fail,
            severity: Severity::High,
            effort: High,
            impact: High,
            e8: &[("patch-applications", &[2, 3])],
            ism: &[],
            summary: "4 devices run applications with critical vulnerabilities.",
        }),
    ]
}

fn sample_report() -> RunReport {
    let mut contoso = tenant(
        "00000000-0000-4000-8000-000000000001",
        Some("Contoso"),
        sample_results(),
    );
    contoso.diff = Some(Diff {
        previous_run_id: "run-20260918".into(),
        previous_finished_at: "2026-09-18T01:00:00Z".into(),
        new_failures: vec!["endpoint.app_vulnerabilities".into()],
        fixed: vec!["identity.global_admin_count".into()],
        changed: vec![StatusChange {
            id: "endpoint.asr_office_macros".into(),
            before: Status::Pass,
            after: Status::Warn,
        }],
        added: vec!["backup.m365_backup".into()],
        removed: vec!["identity.legacy_check".into()],
        score_delta: Some(-4.2),
    });
    let fabrikam = TenantReport {
        tenant_id: "00000000-0000-4000-8000-000000000002".into(),
        label: Some("Fabrikam".into()),
        status: TenantStatus::Failed,
        error: Some(Reason::new(
            "authentication_failed",
            "The app registration has no consent in this tenant.",
        )),
        licences: None,
        score: score::score(&[]),
        packs: vec![],
        quick_wins: vec![],
        results: vec![],
        diff: None,
    };
    RunReport {
        schema_version: SCHEMA_VERSION.into(),
        run_id: "run-20261025".into(),
        tool: Tool {
            name: "junction".into(),
            version: "0.0.0-test".into(),
        },
        started_at: "2026-10-25T01:00:00Z".into(),
        finished_at: "2026-10-25T01:02:00Z".into(),
        selection: json!({}),
        tenants: vec![contoso, fabrikam],
    }
}

fn options() -> ReportOptions {
    ReportOptions {
        title: Some("Security posture report".into()),
        organisation: Some("Contoso Group".into()),
        logo: Some(("image/png".into(), b"Ma".to_vec())),
    }
}

fn assert_snapshot(name: &str, actual: &str) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots")
        .join(name);
    if std::env::var_os("UPDATE_SNAPSHOTS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, actual).expect("write snapshot");
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "missing snapshot {}; run with UPDATE_SNAPSHOTS=1",
            path.display()
        )
    });
    assert_eq!(expected, actual, "snapshot {} differs", path.display());
}

#[test]
fn markdown_snapshot() {
    let text = markdown::render(&sample_report(), &options());
    assert_snapshot("report.md", &text);
    assert!(text.contains("## Tenants"));
    assert!(text.contains("### Changes since last run"));
    assert!(text.contains("and 5 more"));
    assert!(text.contains("missing_permission"));
    assert!(text.contains("authentication_failed"));
}

#[test]
fn html_snapshot() {
    let text = html::render(&sample_report(), &options());
    assert_snapshot("report.html", &text);
}

#[test]
fn table_snapshot() {
    let report = sample_report();
    assert_snapshot("report.txt", &table::render(&report, false));
    let all = table::render(&report, true);
    assert!(all.contains("identity.global_admin_count"));
    assert!(!table::render(&report, false).contains("identity.global_admin_count"));
}

#[test]
fn table_lines_fit_in_100_columns_without_escapes() {
    let mut report = sample_report();
    let t = &mut report.tenants[0];
    t.label = Some(format!(
        "Contoso \u{1b}[31m{}",
        "very long name ".repeat(12)
    ));
    t.results[0].id = format!("identity.{}", "x".repeat(80));
    t.results[0].evidence.summary = format!("{}\n\u{1b}[2J", "word ".repeat(40));
    report.tenants[1].error.as_mut().unwrap().detail = "detail ".repeat(30);
    for show in [false, true] {
        let text = table::render(&report, show);
        assert!(!text.contains('\u{1b}'), "terminal escape leaked");
        for line in text.lines() {
            assert!(line.chars().count() <= table::WIDTH, "too wide: {line:?}");
        }
        assert!(text.contains('…'));
        assert!(text.contains("[missing_permission]"));
        assert!(text.contains("[missing_licence]"));
        assert!(text.contains("error: authentication_failed"));
    }
}

#[test]
fn secrets_in_evidence_data_are_never_rendered() {
    let report = sample_report();
    for (name, text) in [
        ("markdown", markdown::render(&report, &options())),
        ("html", html::render(&report, &options())),
        ("table", table::render(&report, true)),
    ] {
        for secret in SECRETS {
            assert!(!text.contains(secret), "{name} rendered {secret}");
        }
        assert!(!text.contains("access_token"), "{name} rendered raw data");
    }
}

#[test]
fn html_escapes_tenant_data() {
    let mut report = sample_report();
    let payload = "<script>alert(\"x\")</script>";
    report.tenants[0].label = Some(format!("Contoso {payload}"));
    report.tenants[0].results[0].evidence.summary = format!("Summary {payload}");
    report.tenants[0].results[0].affected.items[0] = format!("{payload}@contoso.example");
    report.tenants[0].results[0].remediation.links = vec![
        "javascript:alert(1)".into(),
        "https://learn.microsoft.com/\"onmouseover=\"x".into(),
    ];
    report.tenants[1].error.as_mut().unwrap().detail = payload.into();
    let options = ReportOptions {
        title: Some(format!("Title {payload}")),
        organisation: Some("O'Brien & Co".into()),
        logo: None,
    };
    let text = html::render(&report, &options);
    assert!(!text.contains("<script"), "unescaped script tag");
    assert!(!text.contains("href=\"javascript"));
    assert!(!text.contains("onmouseover=\"x"));
    assert!(text.contains("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;"));
    assert!(text.contains("O&#39;Brien &amp; Co"));
    let md = markdown::render(&report, &options);
    assert!(
        !md.replace("\\<", "").contains("<script"),
        "unescaped in Markdown"
    );
    assert!(md.contains("\\<script\\>"));
}

/// Light HTML lint: balanced tags, a single h1, no heading level skipped,
/// table headers with scope, no scripts and no external assets.
#[test]
fn html_lint() {
    let text = html::render(&sample_report(), &options());
    assert!(text.starts_with("<!DOCTYPE html>\n<html lang=\"en-AU\">"));
    assert!(!text.to_ascii_lowercase().contains("<script"));
    let handler = regex::Regex::new(r"\son[a-z]+\s*=").unwrap();
    let void = ["meta", "img", "br", "hr", "link", "input"];
    let mut stack: Vec<String> = vec![];
    let mut headings = vec![];
    let mut tables = 0;
    let mut rest = text.strip_prefix("<!DOCTYPE html>").unwrap();
    while let Some(start) = rest.find('<') {
        let end = rest[start..].find('>').expect("unterminated tag") + start;
        let tag = &rest[start + 1..end];
        rest = &rest[end + 1..];
        if let Some(name) = tag.strip_prefix('/') {
            let open = stack.pop().unwrap_or_else(|| panic!("stray </{name}>"));
            assert_eq!(open, name, "mismatched close tag");
            continue;
        }
        let name: String = tag
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect();
        assert!(!name.is_empty(), "bad tag <{tag}>");
        if name.len() == 2 && name.starts_with('h') {
            headings.push(name[1..].parse::<u8>().unwrap());
        }
        if name == "table" {
            tables += 1;
        }
        if name == "th" {
            assert!(tag.contains("scope=\"col\"") || tag.contains("scope=\"row\""));
        }
        for attr in ["src=\"", "href=\""] {
            if let Some(i) = tag.find(attr) {
                let value = &tag[i + attr.len()..];
                let value = &value[..value.find('"').unwrap()];
                let ok = match attr {
                    "src=\"" => value.starts_with("data:image/"),
                    _ => {
                        value.starts_with('#')
                            || (name == "a" && value.starts_with("https://learn.microsoft.com/"))
                    }
                };
                assert!(ok, "external asset or link in <{tag}>");
            }
        }
        assert!(!handler.is_match(tag), "event handler attribute in <{tag}>");
        if name == "style" {
            let close = rest.find("</style>").expect("closed style");
            assert!(!rest[..close].contains('<'), "markup inside style");
            rest = &rest[close + "</style>".len()..];
            continue;
        }
        if !void.contains(&name.as_str()) {
            stack.push(name);
        }
    }
    assert!(stack.is_empty(), "unclosed tags: {stack:?}");
    assert_eq!(headings.iter().filter(|h| **h == 1).count(), 1, "one h1");
    assert_eq!(headings[0], 1);
    for pair in headings.windows(2) {
        assert!(pair[1] <= pair[0] + 1, "heading level skipped: {pair:?}");
    }
    let captions = text.matches("<caption>").count();
    assert!(
        tables >= 3 && captions == tables,
        "every table has a caption"
    );
    assert!(text.contains("@media print"));
    assert!(text.contains("break-before:page"));
    assert!(text.contains("estimate, not an assessment"));
}

fn luminance(hex: &str) -> f64 {
    let channel = |i: usize| {
        let c = f64::from(u8::from_str_radix(&hex[i..i + 2], 16).unwrap()) / 255.0;
        if c <= 0.03928 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * channel(1) + 0.7152 * channel(3) + 0.0722 * channel(5)
}

fn contrast(a: &str, b: &str) -> f64 {
    let (x, y) = (luminance(a), luminance(b));
    (x.max(y) + 0.05) / (x.min(y) + 0.05)
}

#[test]
fn html_colours_meet_wcag_aa_contrast() {
    assert!((contrast("#000000", "#ffffff") - 21.0).abs() < 0.01);
    let text = html::render(&sample_report(), &options());
    for (fg, bg, usage) in html::PALETTE {
        let ratio = contrast(fg, bg);
        assert!(ratio >= 4.5, "{usage}: {fg} on {bg} is {ratio:.2}:1");
        assert!(text.contains(fg) && text.contains(bg), "{usage} unused");
    }
    // Status is written as text, not conveyed by colour alone.
    for label in ["Pass", "Fail", "Warning", "Unknown", "Not applicable"] {
        assert!(
            text.contains(&format!("\">{label}</span>")),
            "missing {label}"
        );
    }
}

#[test]
fn logo_is_embedded_as_a_data_uri() {
    let text = html::render(&sample_report(), &options());
    assert!(text.contains("<img src=\"data:image/png;base64,TWE=\" alt=\"Contoso Group logo\">"));
    let mut other = options();
    other.logo = Some(("text/html".into(), b"<b>".to_vec()));
    assert!(!html::render(&sample_report(), &other).contains("<img"));
}

#[test]
fn maturity_estimate_uses_the_lowest_level_fully_met() {
    let report = sample_report();
    let estimates = maturity::estimate(&report.tenants[0], CheckRegistry::builtin());
    assert_eq!(estimates.len(), 8);
    let level = |id: &str| estimates.iter().find(|e| e.strategy == id).unwrap();
    assert_eq!(level("mfa").level, 0);
    assert_eq!(level("mfa").gaps, ["identity.mfa_admins"]);
    assert_eq!(level("patch-applications").level, 1);
    assert!(
        level("patch-applications")
            .basis
            .contains("ML2 not met: endpoint.app_vulnerabilities failed")
    );
    assert_eq!(level("restrict-admin-privileges").level, 3);
    assert_eq!(level("office-macros").level, 0, "warn counts as not met");
    let os = level("patch-operating-systems");
    assert_eq!((os.level, os.gaps.len()), (0, 1), "unknown caps the level");
    assert_eq!(level("regular-backups").level, 0);
    let none = level("application-control");
    assert_eq!(
        (none.level, none.basis.as_str()),
        (0, maturity::NO_EVIDENCE)
    );
    assert!(none.checks.is_empty());
}

#[test]
fn split_gives_safe_unique_stems() {
    let mut report = sample_report();
    let mut copy = report.tenants[0].clone();
    copy.tenant_id = "00000000-0000-4000-8000-000000000003".into();
    report.tenants.push(copy);
    let mut odd = report.tenants[1].clone();
    odd.label = Some("../../CON".into());
    report.tenants.push(odd);
    let mut unlabelled = report.tenants[1].clone();
    unlabelled.label = None;
    report.tenants.push(unlabelled);
    let parts = html::split(&report);
    let stems: Vec<&str> = parts.iter().map(|(s, _)| s.as_str()).collect();
    assert_eq!(
        stems,
        [
            "contoso",
            "fabrikam",
            "contoso-2",
            "con-tenant",
            "00000000-0000-4000-8000-000000000002"
        ]
    );
    for (stem, part) in &parts {
        assert!(
            stem.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        );
        assert_eq!(part.tenants.len(), 1);
        assert_eq!(part.run_id, report.run_id);
    }
}

// Coverage and permission tables from a small registry.

struct Stub(&'static CheckMeta);
impl Check for Stub {
    fn meta(&self) -> &'static CheckMeta {
        self.0
    }
    fn evaluate<'a>(&'a self, _: &'a CheckContext) -> BoxFut<'a, Evaluation> {
        Box::pin(async { Ok(Finding::pass("ok")) })
    }
}

const fn automated(
    id: &'static str,
    pack: Pack,
    apis: &'static [ApiRequirement],
    licences: &'static [&'static str],
) -> CheckMeta {
    CheckMeta {
        kind: CheckKind::Automated,
        manual: None,
        requires: Requirements { apis, licences },
        severity: Severity::High,
        ..CheckMeta::manual(id, "Automated test check", pack, SPEC)
    }
}

const SPEC: ManualSpec = ManualSpec {
    question: "Are break-glass sign-ins monitored?",
    guidance: "Alert on every break-glass sign-in.",
    why_manual: "No API reports who watches the alert.",
};
const ROLES: ApiRequirement = ApiRequirement {
    operation: "graph.role_management.directory.role_assignments.list",
    permissions: &["RoleManagement.Read.Directory", "Directory.Read.All"],
};
const MACHINES: ApiRequirement = ApiRequirement {
    operation: "defender.endpoint.machines.list",
    permissions: &["Machine.Read.All"],
};
const HUNTING: ApiRequirement = ApiRequirement {
    operation: "defender.xdr.advancedhunting.run",
    permissions: &["AdvancedHunting.Read.All"],
};
const INCIDENTS: ApiRequirement = ApiRequirement {
    operation: "sentinel.securityinsights.incidents.list",
    permissions: &["Microsoft Sentinel Reader"],
};
const ARC: ApiRequirement = ApiRequirement {
    operation: "azure.arc.machines.list_by_subscription",
    permissions: &["Reader"],
};
const LOGS: ApiRequirement = ApiRequirement {
    operation: "azure.log_analytics_query.query.execute",
    permissions: &["Data.Read"],
};
const ADMINS: CheckMeta = automated("identity.admins", Pack::Identity, &[ROLES], &[]);
const ADMINS_TOO: CheckMeta = automated("identity.admins_too", Pack::Identity, &[ROLES], &[]);
const DEVICES: CheckMeta = automated(
    "endpoint.devices",
    Pack::Endpoint,
    &[MACHINES, HUNTING],
    &["defender_endpoint"],
);
const SENTINEL: CheckMeta = automated(
    "sentinel.incidents",
    Pack::Sentinel,
    &[INCIDENTS, ARC, LOGS],
    &[],
);
const GLASS: CheckMeta = CheckMeta::manual("identity.glass", "Break glass", Pack::Identity, SPEC);
const TAGS: &str = "\
identity.admins:
  essential_eight:
    - strategy: restrict-admin-privileges
      levels: [1, 2, 3]
  ism: [ISM-1507]
identity.admins_too:
  essential_eight:
    - strategy: mfa
      levels: [1]
  ism: [ISM-1504]
endpoint.devices:
  mitre: [T1078]
sentinel.incidents:
  mitre: [T1078]
identity.glass:
  essential_eight:
    - strategy: restrict-admin-privileges
      levels: [2, 3]
";

fn test_registry() -> CheckRegistry {
    CheckRegistry::new(
        vec![
            Arc::new(Stub(&SENTINEL)),
            Arc::new(Stub(&GLASS)),
            Arc::new(Stub(&ADMINS)),
            Arc::new(Stub(&ADMINS_TOO)),
            Arc::new(Stub(&DEVICES)),
        ],
        &[("test", TAGS)],
    )
    .expect("test registry")
}

#[test]
fn essential_eight_matrix_lists_checks_and_gaps() {
    let registry = test_registry();
    let text = coverage::essential_eight_matrix(&registry);
    assert!(text.contains(
        "| Restrict administrative privileges | `identity.admins` | `identity.admins`<br>`identity.glass` (manual) | `identity.admins`<br>`identity.glass` (manual) |"
    ), "{text}");
    assert!(text.contains("| Multi-factor authentication | `identity.admins_too` | none | none |"));
    assert!(text.contains("| Application control | none | none | none |"));
    assert!(text.contains("## Gaps"));
    assert!(
        text.contains("| ISM-1679 |"),
        "untagged requirement is a gap"
    );
    assert!(
        !text.contains("| ISM-1504 |"),
        "tagged requirement is covered"
    );
    // The built-in registry renders too.
    let builtin = coverage::essential_eight_matrix(CheckRegistry::builtin());
    assert!(builtin.contains("identity.global_admin_count"));
}

#[test]
fn permissions_are_the_least_privilege_union() {
    let registry = test_registry();
    let rows = coverage::permissions(&registry, registry.all());
    let summary: Vec<(&str, &str, usize)> = rows
        .iter()
        .map(|r| (r.permission.as_str(), r.kind.as_str(), r.checks.len()))
        .collect();
    assert_eq!(
        summary,
        [
            (
                "RoleManagement.Read.Directory",
                "Microsoft Graph application",
                2
            ),
            ("Machine.Read.All", "Defender for Endpoint application", 1),
            ("AdvancedHunting.Read.All", "Defender XDR application", 1),
            ("Data.Read", "Log Analytics", 1),
            ("Microsoft Sentinel Reader", "Azure RBAC role", 1),
            ("Reader", "Azure RBAC role", 1),
        ]
    );
    assert_eq!(rows[0].checks, ["identity.admins", "identity.admins_too"]);
    assert_eq!(
        rows[0].operations,
        ["graph.role_management.directory.role_assignments.list"]
    );
    let only = coverage::permissions(&registry, &registry.all()[..1]);
    assert_eq!(only.len(), 3, "selection limits the union");

    let table = coverage::permissions_markdown(&rows);
    assert!(table.starts_with("| Permission | Type | Checks | Operations |"));
    assert!(table.contains(
        "| `Microsoft Sentinel Reader` | Azure RBAC role | `sentinel.incidents` | `sentinel.securityinsights.incidents.list` |"
    ));
    assert!(
        !table.contains("Directory.Read.All"),
        "only least privilege"
    );

    let checks = coverage::checks_markdown(&registry);
    assert_eq!(checks.lines().count(), 2 + 5);
    assert!(checks.contains(
        "| `endpoint.devices` | Automated test check | endpoint | high | automated | `defender_endpoint` | `AdvancedHunting.Read.All`, `Machine.Read.All` |"
    ));
    assert!(
        checks.contains(
            "| `identity.glass` | Break glass | identity | medium | manual | none | none |"
        )
    );
}

#[test]
fn permission_rows_serialise_for_json_output() {
    let registry = test_registry();
    let rows = coverage::permissions(&registry, registry.all());
    let value = serde_json::to_value(&rows).unwrap();
    assert_eq!(value[0]["permission"], "RoleManagement.Read.Directory");
    assert_eq!(value[0]["kind"], "Microsoft Graph application");
    assert_eq!(
        value[0]["checks"],
        json!(["identity.admins", "identity.admins_too"])
    );
}
