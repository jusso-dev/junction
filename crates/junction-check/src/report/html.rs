//! One self-contained HTML file: no scripts, no external assets, inline CSS
//! only, with the logo as a data URI. The executive summary comes first
//! (overall score, pack scores, top quick wins in plain English and the
//! Essential Eight maturity estimate), then a technical appendix like the
//! Markdown report. A print stylesheet gives a clean PDF from any browser.
//!
//! Every string taken from the report is escaped with [`escape`] because it
//! can hold tenant data. Status is always written as text, never colour alone,
//! and every colour pair in [`PALETTE`] meets WCAG AA contrast (tested).
use super::ReportOptions;
use super::markdown::{
    AFFECTED_SHOWN, DEFAULT_TITLE, DISCLAIMER, affected_text, attestation_text, by_pack,
    diff_lists, framework_tags, needs_fix, one_line, plural, quick_wins, reason_text, run_line,
    safe_url, score_basis, score_delta, score_text, status_label, tenant_name, tenant_status,
};
use super::maturity::{self, LABEL};
use crate::history::Diff;
use crate::model::{CheckResult, RunReport, Status, TenantReport, TenantStatus};
use crate::registry::CheckRegistry;
use std::collections::BTreeSet;
use std::fmt::Write;

/// Quick wins in the executive summary (the appendix lists every finding).
const SUMMARY_QUICK_WINS: usize = 5;

const TEXT: &str = "#1b1f24";
const MUTED: &str = "#4a5360";
const LINK: &str = "#0b5cad";
const PAGE: &str = "#ffffff";
const BANNER: &str = "#12355b";
const SUBTLE: &str = "#eef1f5";
const RULE: &str = "#c4ccd6";

/// Text colour, background, and where the pair is used. Each pair must reach
/// a contrast ratio of at least 4.5:1.
pub const PALETTE: [(&str, &str, &str); 11] = [
    (TEXT, PAGE, "body text"),
    (MUTED, PAGE, "secondary text"),
    (LINK, PAGE, "links"),
    (PAGE, BANNER, "report banner"),
    (TEXT, SUBTLE, "table headers and cards"),
    (MUTED, SUBTLE, "secondary text on cards"),
    ("#0f5a2a", "#e3f4e8", "pass"),
    ("#8f1020", "#fde7ea", "fail"),
    ("#6b4200", "#fff1d6", "warning"),
    ("#2f3a47", "#e6eaef", "unknown"),
    ("#4a5360", "#f3f4f6", "not applicable"),
];

fn status_colours(status: Status) -> (&'static str, &'static str) {
    let i = match status {
        Status::Pass => 6,
        Status::Fail => 7,
        Status::Warn => 8,
        Status::Unknown => 9,
        Status::NotApplicable => 10,
    };
    (PALETTE[i].0, PALETTE[i].1)
}

fn status_class(status: Status) -> &'static str {
    match status {
        Status::Pass => "s-pass",
        Status::Fail => "s-fail",
        Status::Warn => "s-warn",
        Status::Unknown => "s-unknown",
        Status::NotApplicable => "s-na",
    }
}

fn stylesheet() -> String {
    let mut css = format!(
        "*{{box-sizing:border-box}}\
body{{margin:0;font:15px/1.5 system-ui,-apple-system,\"Segoe UI\",Roboto,Arial,sans-serif;color:{TEXT};background:{PAGE}}}\
.banner{{background:{BANNER};color:{PAGE};padding:24px 32px}}\
.banner h1{{margin:0;font-size:1.7rem;line-height:1.25}}\
.banner p{{margin:6px 0 0}}\
.banner img{{display:block;max-height:56px;max-width:220px;margin-bottom:12px;background:{PAGE};padding:4px}}\
main{{max-width:1060px;margin:0 auto;padding:8px 32px 48px}}\
h2{{font-size:1.45rem;border-bottom:2px solid {RULE};padding-bottom:4px;margin:40px 0 12px}}\
h3{{font-size:1.2rem;margin:32px 0 8px}}\
h4{{font-size:1.05rem;margin:24px 0 8px}}\
h5{{font-size:1rem;margin:0 0 6px}}\
a{{color:{LINK}}}\
.muted{{color:{MUTED}}}\
.lead{{font-size:1.05rem;max-width:72ch}}\
table{{border-collapse:collapse;width:100%;margin:8px 0 20px}}\
caption{{text-align:left;font-weight:600;padding:4px 0 6px}}\
th,td{{border:1px solid {RULE};padding:6px 8px;text-align:left;vertical-align:top}}\
thead th,tbody th{{background:{SUBTLE}}}\
.num{{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}}\
.cards{{display:flex;flex-wrap:wrap;gap:12px;margin:12px 0 20px;padding:0;list-style:none}}\
.cards li{{border:1px solid {RULE};border-radius:6px;padding:10px 16px;background:{SUBTLE};min-width:140px}}\
.cards .big{{display:block;font-size:1.7rem;font-weight:700;line-height:1.2}}\
.badge{{display:inline-block;border:1px solid currentColor;border-radius:4px;padding:0 6px;font-size:.85rem;font-weight:600;white-space:nowrap}}\
.finding{{border:1px solid {RULE};border-left-width:6px;border-radius:6px;padding:12px 16px;margin:12px 0;break-inside:avoid}}\
.finding dl{{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;margin:8px 0 0}}\
.finding dt{{font-weight:600}}\
.finding dd{{margin:0;overflow-wrap:anywhere}}\
.notice{{border-left:4px solid {RULE};padding:4px 12px;color:{MUTED}}}\
footer{{max-width:1060px;margin:0 auto;padding:16px 32px 40px;color:{MUTED};font-size:.9rem;border-top:1px solid {RULE}}}"
    );
    for status in Status::ALL {
        let (fg, bg) = status_colours(status);
        let _ = write!(
            css,
            ".{c}{{color:{fg};background:{bg}}}.finding.{c}{{color:{TEXT};background:{PAGE};border-left-color:{fg}}}",
            c = status_class(status)
        );
    }
    css.push_str(
        "@media print{\
@page{margin:16mm}\
body{font-size:10.5pt;color:#000;background:none}\
.banner{background:none;color:#000;padding:0 0 10px;border-bottom:2px solid #000}\
.banner img{padding:0}\
main,footer{max-width:none;padding-left:0;padding-right:0}\
.break,.appendix{break-before:page}\
h2,h3,h4,h5{break-after:avoid}\
table,tr,.finding,.cards li{break-inside:avoid}\
thead{display:table-header-group}\
thead th,tbody th,.cards li,.badge{background:none!important}\
.badge{color:#000!important}\
a{color:#000}\
}",
    );
    css
}

/// Escape text for HTML element content and double-quoted attributes.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if c.is_control() && c != '\n' && c != '\t' => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// One line of escaped text.
fn e(s: &str) -> String {
    escape(&one_line(s))
}

pub fn render(report: &RunReport, options: &ReportOptions) -> String {
    let title = options.title.as_deref().unwrap_or(DEFAULT_TITLE);
    let mut out = String::new();
    let _ = write!(
        out,
        "<!DOCTYPE html>\n<html lang=\"en-AU\">\n<head>\n<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
<meta name=\"generator\" content=\"{} {}\">\n<title>{}</title>\n<style>{}</style>\n</head>\n<body>\n",
        e(&report.tool.name),
        e(&report.tool.version),
        e(title),
        stylesheet()
    );
    out.push_str("<header class=\"banner\">\n");
    if let Some((mime, bytes)) = &options.logo
        && let Some(mime) = image_mime(mime)
    {
        let alt = match &options.organisation {
            Some(org) => format!("{} logo", e(org)),
            None => "Logo".into(),
        };
        let _ = writeln!(
            out,
            "<img src=\"data:{mime};base64,{}\" alt=\"{alt}\">",
            base64(bytes)
        );
    }
    let _ = writeln!(out, "<h1>{}</h1>", e(title));
    if let Some(org) = &options.organisation {
        let _ = writeln!(out, "<p>Prepared for {}</p>", e(org));
    }
    let _ = writeln!(out, "<p>{}</p>", run_line(report, e));
    out.push_str("</header>\n<main>\n");

    let multi = report.tenants.len() > 1;
    if multi {
        out.push_str("<section aria-labelledby=\"tenants\">\n<h2 id=\"tenants\">Tenants</h2>\n");
        out.push_str("<table>\n<caption>Tenants in this report</caption>\n<thead><tr><th scope=\"col\">Tenant</th><th scope=\"col\">Status</th><th scope=\"col\" class=\"num\">Score</th><th scope=\"col\" class=\"num\">Fail</th><th scope=\"col\" class=\"num\">Warning</th><th scope=\"col\" class=\"num\">Unknown</th><th scope=\"col\" class=\"num\">Not applicable</th></tr></thead>\n<tbody>\n");
        for (i, t) in report.tenants.iter().enumerate() {
            let s = &t.score.statuses;
            let _ = writeln!(
                out,
                "<tr><th scope=\"row\"><a href=\"#tenant-{}\">{}</a></th><td>{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td></tr>",
                i + 1,
                e(&tenant_name(t)),
                tenant_status(t.status),
                score_cell(t),
                s.fail,
                s.warn,
                s.unknown,
                s.not_applicable
            );
        }
        out.push_str("</tbody>\n</table>\n</section>\n");
    }
    if report.tenants.is_empty() {
        out.push_str("<p>No tenants were assessed.</p>\n");
    }
    let registry = CheckRegistry::builtin();
    for (i, tenant) in report.tenants.iter().enumerate() {
        tenant_section(&mut out, i + 1, tenant, multi, registry);
    }
    let _ = write!(
        out,
        "</main>\n<footer>\n<p>{DISCLAIMER} The Essential Eight maturity figures are an {LABEL}.</p>\n</footer>\n</body>\n</html>\n"
    );
    out
}

fn score_cell(t: &TenantReport) -> String {
    if t.status == TenantStatus::Failed {
        "not assessed".into()
    } else {
        score_text(&t.score)
    }
}

fn tenant_section(
    out: &mut String,
    n: usize,
    t: &TenantReport,
    multi: bool,
    registry: &CheckRegistry,
) {
    let _ = writeln!(
        out,
        "<section class=\"tenant{}\" id=\"tenant-{n}\" aria-labelledby=\"tenant-{n}-h\">\n<h2 id=\"tenant-{n}-h\">{}</h2>",
        if multi { " break" } else { "" },
        e(&tenant_name(t))
    );
    out.push_str("<h3>Executive summary</h3>\n");
    if t.status == TenantStatus::Failed {
        let _ = writeln!(
            out,
            "<p class=\"lead\">This tenant could not be assessed, so it has no score or findings.</p>"
        );
        if let Some(error) = &t.error {
            let _ = writeln!(out, "<p>Error: {}</p>", e(&reason_text(error)));
        }
        out.push_str("</section>\n");
        return;
    }
    let _ = writeln!(out, "<p class=\"lead\">{}</p>", e(&plain_summary(t)));
    if let Some(error) = &t.error {
        let _ = writeln!(out, "<p class=\"notice\">{}</p>", e(&reason_text(error)));
    }
    let s = &t.score.statuses;
    let _ = writeln!(
        out,
        "<ul class=\"cards\">\n<li><span class=\"big\">{}</span>Overall score out of 100</li>\n<li><span class=\"big\">{}</span>Failed</li>\n<li><span class=\"big\">{}</span>Warnings</li>\n<li><span class=\"big\">{}</span>Could not be checked</li>\n<li><span class=\"big\">{}</span>Passed</li>\n</ul>",
        score_text(&t.score),
        s.fail,
        s.warn,
        s.unknown,
        s.pass
    );
    let _ = writeln!(
        out,
        "<p class=\"muted\">Score basis: {}.</p>",
        score_basis(&t.score)
    );

    if !t.packs.is_empty() {
        out.push_str("<table>\n<caption>Score by pack</caption>\n<thead><tr><th scope=\"col\">Pack</th><th scope=\"col\" class=\"num\">Score</th><th scope=\"col\" class=\"num\">Pass</th><th scope=\"col\" class=\"num\">Fail</th><th scope=\"col\" class=\"num\">Warning</th><th scope=\"col\" class=\"num\">Unknown</th><th scope=\"col\" class=\"num\">Not applicable</th></tr></thead>\n<tbody>\n");
        for p in &t.packs {
            let c = &p.score.statuses;
            let _ = writeln!(
                out,
                "<tr><th scope=\"row\">{}</th><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td></tr>",
                escape(p.pack.title()),
                score_text(&p.score),
                c.pass,
                c.fail,
                c.warn,
                c.unknown,
                c.not_applicable
            );
        }
        out.push_str("</tbody>\n</table>\n");
    }

    out.push_str("<h4>Top quick wins</h4>\n");
    let wins = quick_wins(t, SUMMARY_QUICK_WINS);
    if wins.is_empty() {
        out.push_str("<p>No failing or warning checks.</p>\n");
    } else {
        out.push_str(
            "<p>The changes most likely to reduce risk for the least effort, in order.</p>\n<ol>\n",
        );
        for r in wins {
            let _ = writeln!(
                out,
                "<li><a href=\"#{}\"><strong>{}</strong></a>. {} <span class=\"muted\">({} {}: {} severity, {} effort, {} impact.)</span></li>",
                anchor(n, &r.id),
                e(&r.title),
                e(&r.evidence.summary),
                status_label(r.status),
                e(&r.id),
                r.severity.as_str(),
                r.effort.as_str(),
                r.impact.as_str()
            );
        }
        out.push_str("</ol>\n");
    }

    out.push_str("<h4>Essential Eight maturity estimate</h4>\n");
    let _ = writeln!(
        out,
        "<p>This is an {LABEL}. For each strategy it shows the highest maturity level at which every check in this run tagged up to that level passed. Strategies without automated evidence show level 0. Many requirements cannot be read from Microsoft APIs, so confirm any level with a formal assessment.</p>"
    );
    out.push_str("<table>\n<caption>Essential Eight maturity estimate per strategy (estimate, not an assessment)</caption>\n<thead><tr><th scope=\"col\">Strategy</th><th scope=\"col\">Estimated level</th><th scope=\"col\">Basis</th></tr></thead>\n<tbody>\n");
    for est in maturity::estimate(t, registry) {
        let _ = writeln!(
            out,
            "<tr><th scope=\"row\">{}</th><td>Level {}</td><td>{}</td></tr>",
            e(&est.title),
            est.level,
            e(&est.basis)
        );
    }
    out.push_str("</tbody>\n</table>\n");

    if let Some(diff) = &t.diff {
        diff_section(out, diff);
    }

    out.push_str("<section class=\"appendix\">\n<h3>Technical appendix</h3>\n");
    let _ = writeln!(
        out,
        "<p>Every check in pack order, then quick-win order. Affected resources list up to {AFFECTED_SHOWN} items.</p>"
    );
    if t.results.is_empty() {
        out.push_str("<p>No checks ran.</p>\n");
    }
    let mut seen = BTreeSet::new();
    for (pack, results) in by_pack(t) {
        let _ = writeln!(out, "<h4>{}</h4>", escape(pack.title()));
        for r in results {
            finding(out, n, r, &mut seen);
        }
    }
    out.push_str("</section>\n</section>\n");
}

fn plain_summary(t: &TenantReport) -> String {
    let s = &t.score.statuses;
    let score = match t.score.score {
        Some(v) => format!("The overall score is {v:.1} out of 100. "),
        None => "No checks could be scored. ".into(),
    };
    format!(
        "{score}Junction ran {} against this tenant: {} passed, {} failed, {} raised a warning, {} could not be checked and {} did not apply.",
        plural(s.total(), "check", "checks"),
        s.pass,
        s.fail,
        s.warn,
        s.unknown,
        s.not_applicable
    )
}

fn diff_section(out: &mut String, d: &Diff) {
    out.push_str("<h3>Changes since last run</h3>\n");
    let _ = writeln!(
        out,
        "<p>Compared with run {} (finished {}). Score change: {}.</p>\n<ul>",
        e(&d.previous_run_id),
        e(&d.previous_finished_at),
        score_delta(d.score_delta)
    );
    for (label, items) in diff_lists(d) {
        if items.is_empty() {
            continue;
        }
        let items: Vec<String> = items.iter().map(|i| e(i)).collect();
        let _ = writeln!(out, "<li>{label}: {}</li>", items.join(", "));
    }
    if !d.changed.is_empty() {
        let changes: Vec<String> = d
            .changed
            .iter()
            .map(|c| {
                format!(
                    "{} ({} to {})",
                    e(&c.id),
                    status_label(c.before),
                    status_label(c.after)
                )
            })
            .collect();
        let _ = writeln!(out, "<li>Other status changes: {}</li>", changes.join(", "));
    }
    if d.new_failures.is_empty()
        && d.fixed.is_empty()
        && d.added.is_empty()
        && d.removed.is_empty()
        && d.changed.is_empty()
    {
        out.push_str("<li>No status changes.</li>\n");
    }
    out.push_str("</ul>\n");
}

fn finding(out: &mut String, n: usize, r: &CheckResult, seen: &mut BTreeSet<String>) {
    let mut id = anchor(n, &r.id);
    if !seen.insert(id.clone()) {
        id = format!("{id}-{}", seen.len());
        seen.insert(id.clone());
    }
    let class = status_class(r.status);
    let _ = writeln!(
        out,
        "<article class=\"finding {class}\" id=\"{id}\">\n<h5><span class=\"badge {class}\">{}</span> {}</h5>\n<dl>",
        status_label(r.status),
        e(&r.title)
    );
    let mut fact = |term: &str, value: String| {
        let _ = writeln!(out, "<dt>{term}</dt><dd>{value}</dd>");
    };
    fact("Check", format!("<code>{}</code>", e(&r.id)));
    fact(
        "Severity",
        format!(
            "{}; effort {}; impact {}",
            r.severity.as_str(),
            r.effort.as_str(),
            r.impact.as_str()
        ),
    );
    fact("Evidence", e(&r.evidence.summary));
    if let Some(reason) = &r.reason {
        fact("Reason", e(&reason_text(reason)));
    }
    if let Some(a) = &r.attested {
        fact("Attested", e(&attestation_text(a)));
    }
    if !r.affected.is_empty() {
        fact(
            &format!("Affected ({})", r.affected.total),
            e(&affected_text(&r.affected)),
        );
    }
    if needs_fix(r.status) {
        fact("Remediation", e(&r.remediation.text));
        let links: Vec<String> = r
            .remediation
            .links
            .iter()
            .map(|l| {
                if safe_url(l) {
                    format!("<a href=\"{0}\">{0}</a>", escape(l))
                } else {
                    e(l)
                }
            })
            .collect();
        if !links.is_empty() {
            fact("Links", links.join("<br>"));
        }
    }
    let frameworks = framework_tags(&r.tags);
    if !frameworks.is_empty() {
        fact("Frameworks", e(&frameworks.join("; ")));
    }
    if !r.references.is_empty() {
        fact("References", e(&r.references.join("; ")));
    }
    out.push_str("</dl>\n</article>\n");
}

/// Fragment id for a finding: tenant number plus the check id reduced to safe
/// characters.
fn anchor(n: usize, id: &str) -> String {
    let id: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    format!("t{n}-{id}")
}

fn image_mime(mime: &str) -> Option<&'static str> {
    [
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/webp",
        "image/svg+xml",
    ]
    .into_iter()
    .find(|m| m.eq_ignore_ascii_case(mime.trim()))
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// One report per tenant for `--split`, keyed by a file stem made of lower-case
/// letters, digits and hyphens (unique within the run).
pub fn split(report: &RunReport) -> Vec<(String, RunReport)> {
    let mut used = BTreeSet::new();
    report
        .tenants
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let mut base = t.label.as_deref().map(stem).unwrap_or_default();
            if base.is_empty() {
                base = stem(&t.tenant_id);
            }
            if base.is_empty() {
                base = format!("tenant-{}", i + 1);
            }
            let mut name = base.clone();
            let mut k = 2;
            while !used.insert(name.clone()) {
                name = format!("{base}-{k}");
                k += 1;
            }
            (
                name,
                RunReport {
                    tenants: vec![t.clone()],
                    ..report.clone()
                },
            )
        })
        .collect()
}

fn stem(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
        if out.len() >= 60 {
            break;
        }
    }
    let out = out.trim_end_matches('-').to_owned();
    // Names Windows reserves for devices.
    let reserved = matches!(out.as_str(), "con" | "prn" | "aux" | "nul")
        || ((out.starts_with("com") || out.starts_with("lpt"))
            && out.len() == 4
            && out.as_bytes()[3].is_ascii_digit());
    if reserved {
        format!("{out}-tenant")
    } else {
        out
    }
}
