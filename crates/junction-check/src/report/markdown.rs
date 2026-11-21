//! Markdown report: summary, score per pack, top 10 quick wins, changes since
//! the last run and findings grouped by pack. Several tenants get an index
//! table and one section each.
//!
//! Every string taken from the report is escaped ([`md`]) because it can hold
//! tenant data. Evidence `data` is never rendered: only the evidence summary
//! and affected items are, so nothing beyond the summary leaves the JSON model.
use super::ReportOptions;
use crate::history::Diff;
use crate::model::{
    CheckResult, Pack, Reason, RunReport, Score, Status, TenantReport, TenantStatus,
};
use crate::tags::Tags;
use std::fmt::Write;

pub const DEFAULT_TITLE: &str = "Junction security posture report";
/// Affected items listed per finding before "and N more".
pub const AFFECTED_SHOWN: usize = 20;
/// Quick wins listed per tenant.
pub const QUICK_WINS: usize = 10;
pub const DISCLAIMER: &str = "Read-only assessment of the configuration Microsoft APIs reported at \
the time of the run. Remediation text is a suggestion only. Junction is not affiliated with or \
endorsed by Microsoft or the Australian Signals Directorate.";

pub fn render(report: &RunReport, options: &ReportOptions) -> String {
    let mut out = String::new();
    let title = options.title.as_deref().unwrap_or(DEFAULT_TITLE);
    let _ = writeln!(out, "# {}\n", md(title));
    if let Some(org) = &options.organisation {
        let _ = writeln!(out, "Prepared for {}.\n", md(org));
    }
    let _ = writeln!(out, "{}\n", run_line(report, md));
    let _ = writeln!(out, "> {DISCLAIMER}\n");
    if report.tenants.len() > 1 {
        out.push_str("## Tenants\n\n");
        out.push_str("| Tenant | Status | Score | Fail | Warn | Unknown | Not applicable |\n");
        out.push_str("|---|---|---:|---:|---:|---:|---:|\n");
        for t in &report.tenants {
            let s = &t.score.statuses;
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} | {} | {} |",
                md(&tenant_name(t)),
                tenant_status(t.status),
                if t.status == TenantStatus::Failed {
                    "not assessed".to_owned()
                } else {
                    score_text(&t.score)
                },
                s.fail,
                s.warn,
                s.unknown,
                s.not_applicable
            );
        }
        out.push('\n');
    }
    if report.tenants.is_empty() {
        out.push_str("No tenants were assessed.\n");
    }
    for tenant in &report.tenants {
        tenant_section(&mut out, tenant);
    }
    out
}

fn tenant_section(out: &mut String, t: &TenantReport) {
    let _ = writeln!(out, "## {}\n", md(&tenant_name(t)));
    out.push_str("### Summary\n\n");
    let _ = writeln!(out, "- **Status:** {}", tenant_status(t.status));
    if let Some(error) = &t.error {
        let _ = writeln!(out, "- **Error:** {}", md(&reason_text(error)));
    }
    if t.status == TenantStatus::Failed {
        out.push_str("\nThis tenant could not be assessed, so it has no score or findings.\n\n");
        return;
    }
    let _ = writeln!(
        out,
        "- **Overall score:** {} ({})",
        score_text(&t.score),
        score_basis(&t.score)
    );
    let _ = writeln!(out, "- **Results:** {}", counts_text(&t.score));
    if let Some(licences) = &t.licences
        && !licences.features.is_empty()
    {
        let _ = writeln!(
            out,
            "- **Licence features detected:** {}",
            md(&licences.features.join(", "))
        );
    }
    out.push('\n');

    if !t.packs.is_empty() {
        out.push_str("### Score by pack\n\n");
        out.push_str("| Pack | Score | Pass | Fail | Warn | Unknown | Not applicable |\n");
        out.push_str("|---|---:|---:|---:|---:|---:|---:|\n");
        for p in &t.packs {
            let s = &p.score.statuses;
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} | {} | {} |",
                p.pack.title(),
                score_text(&p.score),
                s.pass,
                s.fail,
                s.warn,
                s.unknown,
                s.not_applicable
            );
        }
        out.push('\n');
    }

    out.push_str("### Top quick wins\n\n");
    let wins = quick_wins(t, QUICK_WINS);
    if wins.is_empty() {
        out.push_str("No failing or warning checks.\n");
    }
    for (i, r) in wins.iter().enumerate() {
        let _ = writeln!(
            out,
            "{}. **{}** (`{}`; {}): {}",
            i + 1,
            md(&r.title),
            code(&r.id),
            effort_text(r),
            md(&r.evidence.summary)
        );
    }
    out.push('\n');

    if let Some(diff) = &t.diff {
        diff_section(out, diff);
    }

    out.push_str("### Findings\n\n");
    if t.results.is_empty() {
        out.push_str("No checks ran.\n\n");
    }
    for (pack, results) in by_pack(t) {
        let _ = writeln!(out, "#### {}\n", pack.title());
        for r in results {
            finding(out, r);
        }
    }
}

fn finding(out: &mut String, r: &CheckResult) {
    let _ = writeln!(out, "##### {}: {}\n", status_label(r.status), md(&r.title));
    let _ = writeln!(out, "- **Id:** `{}`", code(&r.id));
    let _ = writeln!(
        out,
        "- **Status:** {}; **severity:** {}; **effort:** {}; **impact:** {}",
        status_label(r.status),
        r.severity.as_str(),
        r.effort.as_str(),
        r.impact.as_str()
    );
    let _ = writeln!(out, "- **Evidence:** {}", md(&r.evidence.summary));
    if let Some(reason) = &r.reason {
        let _ = writeln!(out, "- **Reason:** {}", md(&reason_text(reason)));
    }
    if let Some(a) = &r.attested {
        let _ = writeln!(out, "- **Attested:** {}", md(&attestation_text(a)));
    }
    if !r.affected.is_empty() {
        let _ = writeln!(
            out,
            "- **Affected ({}):** {}",
            r.affected.total,
            md(&affected_text(&r.affected))
        );
    }
    if needs_fix(r.status) {
        let _ = writeln!(out, "- **Remediation:** {}", md(&r.remediation.text));
        let links: Vec<String> = r.remediation.links.iter().map(|l| link(l)).collect();
        if !links.is_empty() {
            let _ = writeln!(out, "- **Links:** {}", links.join(", "));
        }
    }
    let frameworks = framework_tags(&r.tags);
    if !frameworks.is_empty() {
        let _ = writeln!(out, "- **Frameworks:** {}", md(&frameworks.join("; ")));
    }
    if !r.references.is_empty() {
        let _ = writeln!(out, "- **References:** {}", md(&r.references.join("; ")));
    }
    out.push('\n');
}

fn diff_section(out: &mut String, d: &Diff) {
    out.push_str("### Changes since last run\n\n");
    let _ = writeln!(
        out,
        "Compared with run {} (finished {}).\n",
        md(&d.previous_run_id),
        md(&d.previous_finished_at)
    );
    for (label, items) in diff_lists(d) {
        if items.is_empty() {
            continue;
        }
        let items: Vec<String> = items.iter().map(|i| format!("`{}`", code(i))).collect();
        let _ = writeln!(out, "- **{label}:** {}", items.join(", "));
    }
    if !d.changed.is_empty() {
        let changes: Vec<String> = d
            .changed
            .iter()
            .map(|c| {
                format!(
                    "`{}` ({} to {})",
                    code(&c.id),
                    status_label(c.before),
                    status_label(c.after)
                )
            })
            .collect();
        let _ = writeln!(out, "- **Other status changes:** {}", changes.join(", "));
    }
    let _ = writeln!(out, "- **Score change:** {}", score_delta(d.score_delta));
    out.push('\n');
}

// Shared helpers (also used by the HTML and table renderers).

/// "Run X from A to B with junction 1.2.3." built with `esc` for the target format.
pub(crate) fn run_line(report: &RunReport, esc: fn(&str) -> String) -> String {
    format!(
        "Run {} from {} to {} with {} {}.",
        esc(&report.run_id),
        esc(&report.started_at),
        esc(&report.finished_at),
        esc(&report.tool.name),
        esc(&report.tool.version)
    )
}

/// Label, with the tenant id in brackets when both exist.
pub(crate) fn tenant_name(t: &TenantReport) -> String {
    match t.label.as_deref().map(str::trim) {
        Some(label) if !label.is_empty() && label != t.tenant_id => {
            format!("{label} ({})", t.tenant_id)
        }
        _ => t.tenant_id.clone(),
    }
}

pub(crate) fn tenant_status(status: TenantStatus) -> &'static str {
    match status {
        TenantStatus::Complete => "complete",
        TenantStatus::Partial => "partial (some checks could not run)",
        TenantStatus::Failed => "failed",
    }
}

pub(crate) fn status_label(status: Status) -> &'static str {
    match status {
        Status::Pass => "Pass",
        Status::Fail => "Fail",
        Status::Warn => "Warning",
        Status::Unknown => "Unknown",
        Status::NotApplicable => "Not applicable",
    }
}

pub(crate) fn needs_fix(status: Status) -> bool {
    matches!(status, Status::Fail | Status::Warn)
}

pub(crate) fn score_text(score: &Score) -> String {
    match score.score {
        Some(s) => format!("{s:.1}"),
        None => "not scored".into(),
    }
}

pub(crate) fn score_basis(score: &Score) -> String {
    format!(
        "{} scored, {} excluded as unknown or not applicable",
        plural(score.counted, "check", "checks"),
        score.excluded
    )
}

pub(crate) fn counts_text(score: &Score) -> String {
    let s = &score.statuses;
    format!(
        "{} pass, {} fail, {} warn, {} unknown, {} not applicable",
        s.pass, s.fail, s.warn, s.unknown, s.not_applicable
    )
}

pub(crate) fn score_delta(delta: Option<f64>) -> String {
    match delta {
        Some(d) if d > 0.0 => format!("up {d:.1} points"),
        Some(d) if d < 0.0 => format!("down {:.1} points", -d),
        Some(_) => "no change".into(),
        None => "not comparable".into(),
    }
}

pub(crate) fn diff_lists(d: &Diff) -> [(&'static str, &[String]); 4] {
    [
        ("New failures", &d.new_failures),
        ("Fixed", &d.fixed),
        ("New checks", &d.added),
        ("No longer run", &d.removed),
    ]
}

pub(crate) fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

pub(crate) fn reason_text(reason: &Reason) -> String {
    let mut text = format!("{}: {}", reason.code, reason.detail);
    if !reason.missing_permissions.is_empty() {
        let _ = write!(text, " (grant: {})", reason.missing_permissions.join(", "));
    }
    text
}

pub(crate) fn attestation_text(a: &crate::model::Attestation) -> String {
    let mut text = format!(
        "{} by {} on {}, expires {}",
        a.answer.as_str(),
        a.author,
        a.attested_at,
        a.expires_at
    );
    if !a.note.trim().is_empty() {
        let _ = write!(text, ". Note: {}", a.note);
    }
    text
}

pub(crate) fn affected_text(affected: &crate::model::Affected) -> String {
    let shown: Vec<&str> = affected
        .items
        .iter()
        .take(AFFECTED_SHOWN)
        .map(String::as_str)
        .collect();
    let more = affected.total.saturating_sub(shown.len());
    let mut text = shown.join(", ");
    if more > 0 {
        let _ = write!(text, " and {more} more");
    }
    text
}

pub(crate) fn effort_text(r: &CheckResult) -> String {
    format!(
        "{} severity, {} effort, {} impact",
        r.severity.as_str(),
        r.effort.as_str(),
        r.impact.as_str()
    )
}

/// The first `n` quick wins, in the runner's order.
pub(crate) fn quick_wins(t: &TenantReport, n: usize) -> Vec<&CheckResult> {
    t.quick_wins
        .iter()
        .filter_map(|id| t.results.iter().find(|r| &r.id == id))
        .take(n)
        .collect()
}

/// Results grouped by pack in pack order, each group in quick-win order.
pub(crate) fn by_pack(t: &TenantReport) -> Vec<(Pack, Vec<&CheckResult>)> {
    Pack::ALL
        .into_iter()
        .map(|p| {
            (
                p,
                t.results.iter().filter(|r| r.pack == p).collect::<Vec<_>>(),
            )
        })
        .filter(|(_, rs)| !rs.is_empty())
        .collect()
}

/// Framework tags as short labels, for example `E8 mfa ML1-ML2` and `ISM-1504`.
pub(crate) fn framework_tags(tags: &Tags) -> Vec<String> {
    let mut out = vec![];
    for e8 in &tags.essential_eight {
        let levels: Vec<String> = e8.levels.iter().map(|l| format!("ML{l}")).collect();
        out.push(format!("E8 {} {}", e8.strategy, levels.join("/")));
    }
    out.extend(tags.ism.iter().cloned());
    out.extend(tags.cis_m365.iter().map(|i| format!("CIS M365 {i}")));
    out.extend(tags.cis_v8.iter().map(|i| format!("CIS v8 {i}")));
    out.extend(tags.nist_csf.iter().map(|i| format!("NIST CSF {i}")));
    out.extend(tags.mitre.iter().map(|i| format!("MITRE {i}")));
    out
}

/// One line of plain text: control characters (including newlines and terminal
/// escapes) become spaces and runs of whitespace collapse.
pub(crate) fn one_line(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut space = false;
    for c in s.chars() {
        if c.is_control() || c.is_whitespace() {
            space = !out.is_empty();
        } else {
            if space {
                out.push(' ');
                space = false;
            }
            out.push(c);
        }
    }
    out
}

/// Escape report text for Markdown: one line, with characters that could start
/// a link, image, HTML tag, code span, emphasis or table cell backslash-escaped.
pub fn md(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in one_line(s).chars() {
        if matches!(c, '\\' | '`' | '*' | '[' | ']' | '<' | '>' | '|' | '!') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Text for inside a code span: backticks and pipes removed.
fn code(s: &str) -> String {
    one_line(s).replace(['`', '|'], "")
}

/// An autolink for plain https URLs, otherwise escaped text.
fn link(url: &str) -> String {
    if safe_url(url) {
        format!("<{url}>")
    } else {
        md(url)
    }
}

/// An https URL with no characters that could break out of an attribute or link.
pub(crate) fn safe_url(url: &str) -> bool {
    url.starts_with("https://")
        && url.len() > "https://".len()
        && !url
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "<>\"'`\\{}|^".contains(c))
}
