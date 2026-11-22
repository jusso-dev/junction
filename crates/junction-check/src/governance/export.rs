//! Evidence pack for an assessment bundle (`junction apps export`).
//!
//! Writes one directory: a human-readable `README.md` (summary, method,
//! permissions used, gaps and limits), the full `inventory.json`, flat CSV
//! files for spreadsheets, optional drift, and `manifest.json` with the
//! SHA-256 of every file so a reviewer can confirm nothing changed after
//! export. The pack is unsigned; sign or archive it with your own tooling.
use super::baseline::{self, Drift};
use super::flags::FLAGS;
use super::inventory::Inventory;
use super::report;
use anyhow::{Context, Result, bail};
use serde_json::json;
use std::path::Path;

/// Files written, in manifest order (drift files only with a baseline).
pub const FILES: &[&str] = &[
    "README.md",
    "inventory.json",
    "apps.csv",
    "permissions.csv",
    "grants.csv",
    "flags.csv",
];

/// A CSV cell: quoted, with formula-looking values neutralised so
/// spreadsheets never evaluate tenant-supplied text. Spreadsheets skip leading
/// whitespace and control characters before deciding a cell is a formula, so
/// the check looks past them, and a leading tab or carriage return is itself
/// neutralised.
pub fn csv_cell(value: &str) -> String {
    let clean: String = value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let formula = clean.trim_start().starts_with([
        '=', '+', '-', '@', '\u{FF1D}', '\u{FF0B}', '\u{FF0D}', '\u{FF20}',
    ]) || value.starts_with(['\t', '\r', '\n']);
    let neutral = if formula { format!("'{clean}") } else { clean };
    format!("\"{}\"", neutral.replace('"', "\"\""))
}

fn csv(header: &[&str], rows: Vec<Vec<String>>) -> String {
    let mut out = header
        .iter()
        .map(|h| csv_cell(h))
        .collect::<Vec<_>>()
        .join(",")
        + "\r\n";
    for row in rows {
        out.push_str(
            &row.iter()
                .map(|c| csv_cell(c))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push_str("\r\n");
    }
    out
}

/// Markdown text that renders as plain text: every character that can open
/// Markdown or HTML syntax (links, images, emphasis, code, headings, block
/// quotes, tables, entities, raw HTML) is backslash-escaped, and line breaks and control
/// characters become spaces, so tenant-supplied names cannot add links, load
/// images or break the layout.
pub fn md_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' | '`' | '*' | '_' | '[' | ']' | '(' | ')' | '#' | '!' | '|' | '<' | '>' | '~'
            | '&' => {
                out.push('\\');
                out.push(c);
            }
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// A Markdown table cell: the same escaping as [`md_text`].
pub fn md_cell(value: &str) -> String {
    md_text(value)
}

/// An identifier inside a code span: only characters that occur in object ids
/// and GUIDs are kept, so it can never close the span.
pub fn md_id(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .collect()
}

pub fn apps_csv(inv: &Inventory) -> String {
    csv(
        &[
            "service_principal_id",
            "app_id",
            "display_name",
            "type",
            "enabled",
            "owner_tenant",
            "owner_tenant_id",
            "publisher",
            "sign_in_audience",
            "assignment_required",
            "owners",
            "last_sign_in",
            "highest_severity",
            "flags",
        ],
        inv.apps
            .iter()
            .map(|a| {
                vec![
                    a.service_principal_id.clone(),
                    a.app_id.clone(),
                    a.display_name.clone(),
                    a.service_principal_type.clone(),
                    a.enabled.to_string(),
                    report::owner_label(a).into(),
                    a.owner_tenant_id.clone().unwrap_or_default(),
                    report::publisher_label(a),
                    a.sign_in_audience.clone().unwrap_or_default(),
                    a.assignment_required.to_string(),
                    a.owners
                        .iter()
                        .map(|o| {
                            o.user_principal_name
                                .clone()
                                .or_else(|| o.display_name.clone())
                                .unwrap_or_else(|| o.id.clone())
                        })
                        .collect::<Vec<_>>()
                        .join("; "),
                    report::sign_in_label(a, inv),
                    a.severity().map(|s| s.as_str()).unwrap_or("").into(),
                    a.flags
                        .iter()
                        .map(|f| f.id.as_str())
                        .collect::<Vec<_>>()
                        .join("; "),
                ]
            })
            .collect(),
    )
}

pub fn permissions_csv(inv: &Inventory) -> String {
    let tiers = super::flags::Tiers::embedded();
    let tier = |p: &str| {
        tiers
            .lookup(p)
            .map(|(t, _)| format!("{t:?}").to_lowercase())
            .unwrap_or_else(|| "unclassified".into())
    };
    csv(
        &[
            "service_principal_id",
            "app",
            "resource",
            "permission",
            "tier",
            "assignment_id",
            "granted_at",
        ],
        inv.apps
            .iter()
            .flat_map(|a| {
                a.application_permissions.iter().map(|p| {
                    vec![
                        a.service_principal_id.clone(),
                        a.display_name.clone(),
                        p.resource_name.clone(),
                        p.permission.clone(),
                        tier(&p.permission),
                        p.assignment_id.clone(),
                        p.granted_at.clone().unwrap_or_default(),
                    ]
                })
            })
            .collect(),
    )
}

pub fn grants_csv(inv: &Inventory) -> String {
    csv(
        &[
            "service_principal_id",
            "app",
            "resource",
            "consent_type",
            "principal_id",
            "principal_is_guest",
            "scopes",
            "grant_id",
        ],
        inv.apps
            .iter()
            .flat_map(|a| {
                a.delegated_grants.iter().map(|g| {
                    vec![
                        a.service_principal_id.clone(),
                        a.display_name.clone(),
                        g.resource_name.clone(),
                        g.consent_type.clone(),
                        g.principal_id.clone().unwrap_or_default(),
                        g.principal_guest.map(|b| b.to_string()).unwrap_or_default(),
                        g.scopes.join(" "),
                        g.grant_id.clone(),
                    ]
                })
            })
            .collect(),
    )
}

pub fn flags_csv(inv: &Inventory) -> String {
    csv(
        &[
            "service_principal_id",
            "app",
            "flag",
            "severity",
            "summary",
            "evidence",
        ],
        inv.apps
            .iter()
            .flat_map(|a| {
                a.flags.iter().map(|f| {
                    vec![
                        a.service_principal_id.clone(),
                        a.display_name.clone(),
                        f.id.clone(),
                        f.severity.as_str().into(),
                        f.summary.clone(),
                        f.evidence.join("; "),
                    ]
                })
            })
            .collect(),
    )
}

pub fn readme(inv: &Inventory, drift: Option<&Drift>) -> String {
    let s = &inv.summary;
    let mut out = format!(
        "# Connected-app evidence pack\n\n\
         Tenant `{}`{}. Inventory captured {} by Junction {} (`junction apps export`).\n\n\
         ## Summary\n\n\
         | Measure | Count |\n|---|---|\n\
         | Applications and service principals | {} |\n\
         | Registered in this tenant | {} |\n\
         | Registered in another organisation | {} |\n\
         | Microsoft first-party | {} |\n\
         | Holding application permissions | {} |\n\
         | Holding admin consent for all users | {} |\n\
         | Holding per-user consent | {} |\n",
        md_id(&inv.tenant_id),
        inv.label
            .as_deref()
            .map(|l| format!(" ({})", md_cell(l)))
            .unwrap_or_default(),
        md_text(&inv.captured_at),
        env!("CARGO_PKG_VERSION"),
        s.apps,
        s.home_tenant,
        s.external,
        s.microsoft,
        s.with_application_permissions,
        s.with_tenant_wide_delegated,
        s.with_user_delegated,
    );
    for severity in crate::model::Severity::ALL {
        if let Some(n) = s.flagged.get(severity.as_str()) {
            out.push_str(&format!(
                "| Apps whose highest flag is {} | {n} |\n",
                severity.as_str()
            ));
        }
    }
    out.push_str("\n## Flags\n\n| Flag | Severity | Apps | Meaning |\n|---|---|---|---|\n");
    let counts = super::flags::counts(inv);
    for f in FLAGS {
        out.push_str(&format!(
            "| `{}` | {} | {} | {} |\n",
            f.id,
            f.severity.as_str(),
            counts.get(f.id).copied().unwrap_or(0),
            f.title
        ));
    }
    out.push_str(
        "\nEach flag's evidence is in `flags.csv` and `inventory.json`. What each flag reads and how to fix it: `junction apps flags --format json`.\n\n\
         ## Method\n\n\
         Junction read Microsoft Graph with the application permissions below, through its read-only policy. Nothing in the tenant was changed. Permission impact tiers come from Junction's reviewed `graph-permission-tiers.yaml`; permissions not in that file are reported as `unclassified`.\n\n\
         | Permission | Used for |\n|---|---|\n",
    );
    for row in super::cli::permissions() {
        out.push_str(&format!(
            "| `{}` | {} |\n",
            row["permission"].as_str().unwrap_or_default(),
            row["operations"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|o| o.as_str())
                .map(|o| format!("`{o}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    out.push_str("\n## Gaps and limits\n\n");
    if inv.gaps.is_empty() {
        out.push_str("Every read completed.\n");
    } else {
        for g in &inv.gaps {
            out.push_str(&format!(
                "- **{}** was not read: {}\n",
                g.area,
                md_cell(&g.reason.detail)
            ));
        }
        out.push_str("\nFlags that depend on missing data were not evaluated, so their absence is not evidence of compliance.\n");
    }
    out.push_str(
        "- Sign-in recency needs Entra ID P1 or P2; workload identity risk needs Workload Identities Premium.\n\
         - Credential values are never read. Only types, key ids, names and dates are included.\n",
    );
    if let Some(d) = drift {
        out.push_str(&format!(
            "\n## Drift since the approved baseline\n\nBaseline captured {}: {} added, {} removed, {} changed. Details in `drift.md` and `drift.json`.\n",
            md_text(&d.baseline_captured_at),
            d.added.len(),
            d.removed.len(),
            d.changed.len()
        ));
    }
    out.push_str(
        "\n## Files\n\n`manifest.json` lists the SHA-256 of every file in this directory.\n",
    );
    out
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    junction_watch::event::hex(&Sha256::digest(bytes))
}

/// Write the evidence pack into `dir` (created if needed; existing pack files
/// are replaced). Returns the manifest.
pub fn write(dir: &Path, inv: &Inventory, drift: Option<&Drift>) -> Result<serde_json::Value> {
    if dir.is_file() {
        bail!("--output must be a directory");
    }
    std::fs::create_dir_all(dir).context("creating the export directory")?;
    let mut files: Vec<(&str, String)> = vec![
        ("README.md", readme(inv, drift)),
        ("inventory.json", serde_json::to_string_pretty(inv)? + "\n"),
        ("apps.csv", apps_csv(inv)),
        ("permissions.csv", permissions_csv(inv)),
        ("grants.csv", grants_csv(inv)),
        ("flags.csv", flags_csv(inv)),
    ];
    if let Some(d) = drift {
        files.push(("drift.json", serde_json::to_string_pretty(d)? + "\n"));
        files.push(("drift.md", baseline::markdown(d)));
    }
    let mut entries = vec![];
    for (name, text) in &files {
        super::cli::write_output(&dir.join(name), text.as_bytes())?;
        entries.push(json!({"file": name, "sha256": sha256(text.as_bytes()), "bytes": text.len()}));
    }
    let manifest = json!({
        "pack_version": 1,
        "tenant_id": inv.tenant_id,
        "captured_at": inv.captured_at,
        "generator": format!("junction {}", env!("CARGO_PKG_VERSION")),
        "files": entries,
    });
    super::cli::write_output(
        &dir.join("manifest.json"),
        (serde_json::to_string_pretty(&manifest)? + "\n").as_bytes(),
    )?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_neutralises_formulas_and_quotes() {
        assert_eq!(csv_cell("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(csv_cell("+1"), "\"'+1\"");
        assert_eq!(csv_cell("-2"), "\"'-2\"");
        assert_eq!(csv_cell("@SUM(A1)"), "\"'@SUM(A1)\"");
        assert_eq!(csv_cell("Mail.Read"), "\"Mail.Read\"");
        assert_eq!(csv_cell("a\nb"), "\"a b\"");
        // Leading whitespace or control characters do not hide a formula.
        assert_eq!(csv_cell("  =1+1"), "\"'  =1+1\"");
        assert_eq!(csv_cell("\t=CMD"), "\"' =CMD\"");
        assert_eq!(csv_cell("\rtext"), "\"' text\"");
        assert_eq!(csv_cell("\u{FF1D}1+1"), "\"'\u{FF1D}1+1\"");
    }

    #[test]
    fn markdown_cells_cannot_break_tables_or_inject_html() {
        assert_eq!(md_cell("a|b<script>\n"), "a\\|b\\<script\\> ");
        let link = md_text("![x](https://attacker.example/p.png)[Fix](https://phish.example)");
        assert!(!link.contains("]("), "{link}");
        assert_eq!(md_id("abc`) [x](y"), "abcxy");
    }
}
