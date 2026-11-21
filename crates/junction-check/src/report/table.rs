//! Plain-text table for terminals: per tenant a header, pack scores, then
//! results in quick-win order. Every line fits in [`WIDTH`] columns, there is
//! no colour, and control characters from tenant data (including terminal
//! escape sequences) are replaced before printing.
use super::markdown::{counts_text, one_line, score_text, tenant_name};
use crate::model::{CheckResult, RunReport, Status, TenantReport, TenantStatus};

pub const WIDTH: usize = 100;
const STATUS_W: usize = 14;
const SEVERITY_W: usize = 8;
const ID_MAX: usize = 44;

pub fn render(report: &RunReport, show_passes: bool) -> String {
    let mut lines = vec![fit(
        &format!(
            "Run {} finished {}",
            one_line(&report.run_id),
            one_line(&report.finished_at)
        ),
        WIDTH,
    )];
    if report.tenants.is_empty() {
        lines.push("No tenants were assessed.".into());
    }
    for tenant in &report.tenants {
        lines.push(String::new());
        tenant_lines(&mut lines, tenant, show_passes);
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

fn tenant_lines(lines: &mut Vec<String>, t: &TenantReport, show_passes: bool) {
    let status = match t.status {
        TenantStatus::Complete => "complete",
        TenantStatus::Partial => "partial",
        TenantStatus::Failed => "FAILED",
    };
    let score = if t.status == TenantStatus::Failed {
        String::new()
    } else {
        format!("  score {}", score_text(&t.score))
    };
    let suffix = format!("  [{status}]{score}");
    let name_w = WIDTH.saturating_sub(char_len(&suffix) + "Tenant ".len());
    lines.push(format!(
        "Tenant {}{suffix}",
        fit(&one_line(&tenant_name(t)), name_w)
    ));
    if let Some(error) = &t.error {
        lines.push(fit(
            &format!(
                "  error: {}: {}",
                one_line(&error.code),
                one_line(&error.detail)
            ),
            WIDTH,
        ));
    }
    if t.status == TenantStatus::Failed {
        return;
    }
    lines.push(fit(&format!("  {}", counts_text(&t.score)), WIDTH));
    if !t.packs.is_empty() {
        lines.push("  Packs".into());
        for p in &t.packs {
            let s = &p.score.statuses;
            lines.push(fit(
                &format!(
                    "    {:<42} {:>10}  {} fail, {} warn, {} unknown",
                    p.pack.title(),
                    score_text(&p.score),
                    s.fail,
                    s.warn,
                    s.unknown
                ),
                WIDTH,
            ));
        }
    }
    let shown: Vec<&CheckResult> = t
        .results
        .iter()
        .filter(|r| show_passes || r.status != Status::Pass)
        .collect();
    let hidden = t.results.len() - shown.len();
    if !shown.is_empty() {
        let id_w = shown
            .iter()
            .map(|r| char_len(&r.id))
            .max()
            .unwrap_or(2)
            .clamp(2, ID_MAX);
        let summary_w = WIDTH - 2 - STATUS_W - 2 - SEVERITY_W - 2 - id_w - 2;
        lines.push(String::new());
        lines.push(format!(
            "  {:<STATUS_W$}  {:<SEVERITY_W$}  {:<id_w$}  SUMMARY",
            "STATUS", "SEVERITY", "ID"
        ));
        for r in shown {
            let summary = match &r.reason {
                Some(reason) if matches!(r.status, Status::Unknown | Status::NotApplicable) => {
                    format!("[{}] {}", reason.code, r.evidence.summary)
                }
                _ => r.evidence.summary.clone(),
            };
            lines.push(
                format!(
                    "  {:<STATUS_W$}  {:<SEVERITY_W$}  {}  {}",
                    r.status.as_str(),
                    r.severity.as_str(),
                    pad(&fit(&one_line(&r.id), id_w), id_w),
                    fit(&one_line(&summary), summary_w)
                )
                .trim_end()
                .to_owned(),
            );
        }
    }
    if hidden > 0 {
        lines.push(String::new());
        lines.push(format!(
            "  {hidden} passing check{} hidden (use --show-passes to list them).",
            if hidden == 1 { "" } else { "s" }
        ));
    }
}

fn char_len(s: &str) -> usize {
    s.chars().count()
}

/// Truncate to `width` characters, ending with an ellipsis when cut.
fn fit(s: &str, width: usize) -> String {
    if char_len(s) <= width {
        return s.to_owned();
    }
    let mut out: String = s.chars().take(width.saturating_sub(1)).collect();
    out.push('…');
    out
}

fn pad(s: &str, width: usize) -> String {
    format!("{s}{}", " ".repeat(width.saturating_sub(char_len(s))))
}
