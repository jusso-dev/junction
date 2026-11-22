//! Table, Markdown and HTML rendering of an inventory. JSON output is the
//! [`Inventory`] itself.
use super::inventory::{App, Inventory, OwnerTenant, Publisher};
use crate::model::Severity;

/// Display filters shared by every format.
#[derive(Debug, Clone, Copy, Default)]
pub struct View {
    /// Only apps with at least one flag.
    pub flagged_only: bool,
    /// Only apps whose highest flag is at least this severe.
    pub min_severity: Option<Severity>,
    /// Include Microsoft first-party apps without flags.
    pub include_microsoft: bool,
}

impl View {
    pub fn keeps(&self, app: &App) -> bool {
        let severity = app.severity();
        if self.flagged_only && severity.is_none() {
            return false;
        }
        if let Some(min) = self.min_severity
            && !severity.is_some_and(|s| s.at_least(min))
        {
            return false;
        }
        self.include_microsoft || !app.is_microsoft() || severity.is_some()
    }
    /// Apps to show, most severe first, then by name.
    pub fn apps<'a>(&self, inventory: &'a Inventory) -> Vec<&'a App> {
        let mut apps: Vec<&App> = inventory.apps.iter().filter(|a| self.keeps(a)).collect();
        apps.sort_by(|a, b| {
            let rank = |x: &App| x.severity().map(|s| s.rank() as i16).unwrap_or(-1);
            rank(b).cmp(&rank(a)).then_with(|| {
                a.display_name
                    .to_lowercase()
                    .cmp(&b.display_name.to_lowercase())
            })
        });
        apps
    }
}

pub fn owner_label(app: &App) -> &'static str {
    match app.owner_tenant {
        OwnerTenant::Home => "this tenant",
        OwnerTenant::Microsoft => "Microsoft",
        OwnerTenant::External => "external",
        OwnerTenant::Unknown => "unknown",
    }
}

pub fn publisher_label(app: &App) -> String {
    match &app.publisher {
        Publisher::Microsoft => "Microsoft".into(),
        Publisher::Verified { name } => format!("verified: {name}"),
        Publisher::Unverified => "unverified".into(),
    }
}

/// Short permission summary, for example `3 app, 2 delegated (all users)`.
pub fn permissions_label(app: &App) -> String {
    let mut parts = vec![];
    if !app.application_permissions.is_empty() {
        parts.push(format!("{} app", app.application_permissions.len()));
    }
    let all: usize = app
        .delegated_grants
        .iter()
        .filter(|g| g.consent_type == "AllPrincipals")
        .map(|g| g.scopes.len())
        .sum();
    if all > 0 {
        parts.push(format!("{all} delegated (all users)"));
    }
    let users = app
        .delegated_grants
        .iter()
        .filter(|g| g.consent_type == "Principal")
        .count();
    if users > 0 {
        parts.push(format!("{users} user consent(s)"));
    }
    if parts.is_empty() {
        "none".into()
    } else {
        parts.join(", ")
    }
}

pub fn sign_in_label(app: &App, _inventory: &Inventory) -> String {
    match (&app.last_sign_in, app.sign_in_data) {
        (_, super::inventory::SignInData::Unavailable) => "unavailable".into(),
        (Some(at), _) => at.get(..10).unwrap_or(at).to_owned(),
        (None, _) => "none recorded".into(),
    }
}

fn cell(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// Aligned plain-text table with a summary and any gaps.
pub fn table(inventory: &Inventory, view: &View) -> String {
    let s = &inventory.summary;
    let mut out = format!(
        "Tenant {}{}: {} apps ({} this tenant, {} external, {} Microsoft)\n",
        inventory.tenant_id,
        inventory
            .label
            .as_deref()
            .map(|l| format!(" ({})", cell(l)))
            .unwrap_or_default(),
        s.apps,
        s.home_tenant,
        s.external,
        s.microsoft
    );
    if !s.flagged.is_empty() {
        let flagged: Vec<String> = Severity::ALL
            .iter()
            .filter_map(|sev| {
                s.flagged
                    .get(sev.as_str())
                    .map(|n| format!("{n} {}", sev.as_str()))
            })
            .collect();
        out.push_str(&format!("Flagged: {}\n", flagged.join(", ")));
    }
    for gap in &inventory.gaps {
        out.push_str(&format!(
            "Not read ({}): {}\n",
            gap.area,
            cell(&gap.reason.detail)
        ));
    }
    out.push('\n');
    let header = [
        "SEVERITY",
        "APP",
        "OWNER",
        "PUBLISHER",
        "PERMISSIONS",
        "LAST SIGN-IN",
        "FLAGS",
    ];
    let rows: Vec<[String; 7]> = view
        .apps(inventory)
        .into_iter()
        .map(|app| {
            [
                app.severity().map(|s| s.as_str()).unwrap_or("-").to_owned(),
                cell(&app.display_name),
                owner_label(app).to_owned(),
                cell(&publisher_label(app)),
                permissions_label(app),
                sign_in_label(app, inventory),
                if app.flags.is_empty() {
                    "-".to_owned()
                } else {
                    app.flags
                        .iter()
                        .map(|f| f.id.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                },
            ]
        })
        .collect();
    if rows.is_empty() {
        out.push_str("No apps match.\n");
        return out;
    }
    let mut widths = header.map(str::len);
    for row in &rows {
        for (w, c) in widths.iter_mut().zip(row) {
            *w = (*w).max(c.chars().count().min(48));
        }
    }
    let line = |cells: Vec<String>| {
        let mut l = String::new();
        for (i, (c, w)) in cells.iter().zip(widths).enumerate() {
            let c: String = c.chars().take(48).collect();
            if i + 1 == cells.len() {
                l.push_str(&c);
            } else {
                l.push_str(&format!("{c:<w$}  "));
            }
        }
        l.trim_end().to_owned() + "\n"
    };
    out.push_str(&line(header.iter().map(|h| (*h).to_owned()).collect()));
    for row in rows {
        out.push_str(&line(row.to_vec()));
    }
    out
}

const DISCLAIMER: &str = "Read-only inventory of what Microsoft Graph reported at the time of the run. \
Nothing in the tenant was changed. Fixes are suggestions only. Junction is not affiliated with or \
endorsed by Microsoft.";

fn flag_list(app: &App) -> String {
    if app.flags.is_empty() {
        "none".into()
    } else {
        app.flags
            .iter()
            .map(|f| format!("{} ({})", f.id, f.severity.as_str()))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn severity_counts(inventory: &Inventory) -> String {
    let parts: Vec<String> = Severity::ALL
        .iter()
        .filter_map(|s| {
            inventory
                .summary
                .flagged
                .get(s.as_str())
                .map(|n| format!("{n} {}", s.as_str()))
        })
        .collect();
    if parts.is_empty() {
        "none".into()
    } else {
        parts.join(", ")
    }
}

/// Markdown report: summary, gaps, a table of apps, then per-app details for
/// flagged apps with each flag's evidence and suggested fix.
pub fn markdown(inventory: &Inventory, view: &View) -> String {
    use super::export::{md_cell, md_text};
    let s = &inventory.summary;
    let mut out = format!(
        "# Connected apps\n\nTenant `{}`{}, inventory captured {}.\n\n\
         {} apps: {} registered in this tenant, {} from other organisations, {} Microsoft first-party. \
         Flagged by highest severity: {}.\n\n",
        inventory.tenant_id,
        inventory
            .label
            .as_deref()
            .map(|l| format!(" ({})", md_text(l)))
            .unwrap_or_default(),
        inventory.captured_at,
        s.apps,
        s.home_tenant,
        s.external,
        s.microsoft,
        severity_counts(inventory)
    );
    if !inventory.gaps.is_empty() {
        out.push_str("## Not read\n\n");
        for g in &inventory.gaps {
            out.push_str(&format!(
                "- **{}**: {}\n",
                g.area,
                md_text(&g.reason.detail)
            ));
        }
        out.push_str("\nFlags that depend on this data were not evaluated.\n\n");
    }
    let apps = view.apps(inventory);
    out.push_str("## Apps\n\n| Severity | App | Owner | Publisher | Permissions | Last sign-in | Flags |\n|---|---|---|---|---|---|---|\n");
    for app in &apps {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} |\n",
            app.severity().map(|s| s.as_str()).unwrap_or("none"),
            md_cell(&app.display_name),
            owner_label(app),
            md_cell(&publisher_label(app)),
            permissions_label(app),
            sign_in_label(app, inventory),
            md_cell(&flag_list(app)),
        ));
    }
    if apps.is_empty() {
        out.push_str("| | No apps match. | | | | | |\n");
    }
    let flagged: Vec<&&App> = apps.iter().filter(|a| !a.flags.is_empty()).collect();
    if !flagged.is_empty() {
        out.push_str("\n## Findings\n");
        for app in flagged {
            out.push_str(&format!(
                "\n### {}\n\nApp id `{}`, service principal `{}`. {} app, publisher {}.\n\n",
                md_text(&app.display_name),
                app.app_id,
                app.service_principal_id,
                owner_label(app),
                md_text(&publisher_label(app))
            ));
            for f in &app.flags {
                out.push_str(&format!(
                    "- **{}** ({}): {}\n",
                    f.id,
                    f.severity.as_str(),
                    md_text(&f.summary)
                ));
                for e in &f.evidence {
                    out.push_str(&format!("  - {}\n", md_text(e)));
                }
                if let Some(doc) = super::flags::doc(&f.id) {
                    out.push_str(&format!("  - Suggested fix: {}\n", doc.fix));
                }
            }
        }
    }
    out.push_str(&format!("\n---\n\n{DISCLAIMER}\n"));
    out
}

/// One self-contained HTML page: inline CSS, no scripts or external assets,
/// every tenant-supplied string escaped.
pub fn html(inventory: &Inventory, view: &View) -> String {
    use crate::report::html::escape;
    let s = &inventory.summary;
    let mut out = String::from(
        "<!doctype html>\n<html lang=\"en-AU\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\n\
         <title>Connected apps</title>\n<style>\
         body{margin:0;font:15px/1.5 system-ui,-apple-system,\"Segoe UI\",Roboto,Arial,sans-serif;color:#1b1f24;background:#fff}\
         header{background:#12355b;color:#fff;padding:24px 32px}header h1{margin:0;font-size:1.7rem}header p{margin:6px 0 0}\
         main{max-width:1200px;margin:0 auto;padding:8px 32px 48px}\
         h2{font-size:1.4rem;border-bottom:2px solid #c4ccd6;padding-bottom:4px;margin:32px 0 12px}\
         table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{border:1px solid #c4ccd6;padding:6px 8px;text-align:left;vertical-align:top}\
         th{background:#eef1f5}.sev{font-weight:600;white-space:nowrap}\
         .critical{color:#8f1020;background:#fde7ea}.high{color:#6b4200;background:#fff1d6}\
         .medium{color:#2f3a47;background:#e6eaef}.low,.info,.none{color:#4a5360;background:#f3f4f6}\
         .gap{border-left:4px solid #6b4200;background:#fff1d6;padding:8px 12px;margin:8px 0}\
         footer{color:#4a5360;font-size:.85rem;margin-top:32px}\
         @media print{header{background:#fff;color:#000}}\
         </style>\n</head>\n<body>\n",
    );
    out.push_str(&format!(
        "<header><h1>Connected apps</h1><p>Tenant {}{}, captured {}</p></header>\n<main>\n",
        escape(&inventory.tenant_id),
        inventory
            .label
            .as_deref()
            .map(|l| format!(" ({})", escape(l)))
            .unwrap_or_default(),
        escape(&inventory.captured_at)
    ));
    out.push_str(&format!(
        "<h2>Summary</h2>\n<p>{} apps: {} registered in this tenant, {} from other organisations, {} Microsoft first-party. \
         {} hold application permissions and {} hold admin consent for all users. Flagged by highest severity: {}.</p>\n",
        s.apps,
        s.home_tenant,
        s.external,
        s.microsoft,
        s.with_application_permissions,
        s.with_tenant_wide_delegated,
        escape(&severity_counts(inventory))
    ));
    for g in &inventory.gaps {
        out.push_str(&format!(
            "<p class=\"gap\"><strong>Not read ({}):</strong> {} Flags that depend on it were not evaluated.</p>\n",
            escape(&g.area),
            escape(&g.reason.detail)
        ));
    }
    out.push_str("<h2>Apps</h2>\n<table>\n<thead><tr><th scope=\"col\">Severity</th><th scope=\"col\">App</th><th scope=\"col\">Owner</th><th scope=\"col\">Publisher</th><th scope=\"col\">Permissions</th><th scope=\"col\">Last sign-in</th><th scope=\"col\">Flags and evidence</th></tr></thead>\n<tbody>\n");
    for app in view.apps(inventory) {
        let severity = app.severity().map(|s| s.as_str()).unwrap_or("none");
        let mut flags = String::new();
        for f in &app.flags {
            flags.push_str(&format!(
                "<div><strong>{}</strong> ({}): {}",
                escape(&f.id),
                f.severity.as_str(),
                escape(&f.summary)
            ));
            if !f.evidence.is_empty() {
                flags.push_str("<ul>");
                for e in &f.evidence {
                    flags.push_str(&format!("<li>{}</li>", escape(e)));
                }
                flags.push_str("</ul>");
            }
            flags.push_str("</div>");
        }
        if flags.is_empty() {
            flags.push_str("none");
        }
        out.push_str(&format!(
            "<tr><td class=\"sev {severity}\">{severity}</td><td>{}<br><small>{}</small></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            escape(&app.display_name),
            escape(&app.app_id),
            owner_label(app),
            escape(&publisher_label(app)),
            escape(&permissions_label(app)),
            escape(&sign_in_label(app, inventory)),
            flags
        ));
    }
    out.push_str("</tbody>\n</table>\n");
    out.push_str(&format!(
        "<footer><p>{}</p></footer>\n</main>\n</body>\n</html>\n",
        escape(DISCLAIMER)
    ));
    out
}
