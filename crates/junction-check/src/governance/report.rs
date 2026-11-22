//! Terminal rendering of an inventory. JSON output is the [`Inventory`] itself.
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

pub fn sign_in_label(app: &App, inventory: &Inventory) -> String {
    match &app.last_sign_in {
        Some(at) => at.get(..10).unwrap_or(at).to_owned(),
        None if inventory.gap("sign_in_activity") => "unavailable".into(),
        None => "none recorded".into(),
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
