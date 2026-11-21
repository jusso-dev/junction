//! Tables generated from the registry so the docs never drift from the code:
//! the Essential Eight coverage matrix, the least-privilege permission union
//! (`junction check permissions`) and the list of every check.
use super::markdown::md;
use crate::check::Check;
use crate::gateway::token_service;
use crate::model::{CheckKind, Pack};
use crate::registry::CheckRegistry;
use crate::tags::Frameworks;
use junction_core::cloud::CloudService;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::sync::Arc;

/// Essential Eight strategies by maturity level with the checks tagged at each
/// level, then the requirements (ISM ids) no check is tagged with.
pub fn essential_eight_matrix(registry: &CheckRegistry) -> String {
    let e8 = &Frameworks::embedded().essential_eight;
    let ism_titles: BTreeMap<String, String> = Frameworks::embedded()
        .ism
        .controls
        .iter()
        .filter_map(|c| Some((c.id.to_ascii_uppercase(), c.title.clone()?)))
        .collect();
    let mut checks = registry.all().to_vec();
    checks.sort_by(|a, b| a.pack().cmp(&b.pack()).then(a.id().cmp(b.id())));
    let tagged_ism: BTreeSet<String> = checks
        .iter()
        .flat_map(|c| registry.tags(c.id()).ism)
        .map(|i| i.to_ascii_uppercase())
        .collect();

    let mut out = String::new();
    out.push_str("## Matrix\n\n");
    out.push_str("| Strategy | ML1 | ML2 | ML3 |\n|---|---|---|---|\n");
    for strategy in &e8.strategies {
        let mut cells = vec![];
        for level in 1..=3u8 {
            let ids: Vec<String> = checks
                .iter()
                .filter(|c| {
                    registry
                        .tags(c.id())
                        .essential_eight
                        .iter()
                        .any(|t| t.strategy == strategy.id && t.levels.contains(&level))
                })
                .map(|c| match c.meta().kind {
                    CheckKind::Automated => format!("`{}`", c.id()),
                    CheckKind::Manual => format!("`{}` (manual)", c.id()),
                })
                .collect();
            cells.push(if ids.is_empty() {
                "none".to_owned()
            } else {
                ids.join("<br>")
            });
        }
        let _ = writeln!(out, "| {} | {} |", md(&strategy.title), cells.join(" | "));
    }
    out.push_str("\n(manual) marks a check answered by attestation rather than an API.\n\n");

    out.push_str("## Requirements by strategy\n\n");
    out.push_str("| Strategy | Requirements | Tagged by a check | Gaps |\n|---|---:|---:|---:|\n");
    for strategy in &e8.strategies {
        let total = strategy.requirements.len();
        let covered = strategy
            .requirements
            .iter()
            .filter(|r| tagged_ism.contains(&r.id.to_ascii_uppercase()))
            .count();
        let _ = writeln!(
            out,
            "| {} | {total} | {covered} | {} |",
            md(&strategy.title),
            total - covered
        );
    }
    out.push('\n');

    out.push_str("## Gaps\n\n");
    out.push_str("Requirements with no check tagged with the same ISM control.\n\n");
    for strategy in &e8.strategies {
        let gaps: Vec<_> = strategy
            .requirements
            .iter()
            .filter(|r| !tagged_ism.contains(&r.id.to_ascii_uppercase()))
            .collect();
        if gaps.is_empty() {
            continue;
        }
        let _ = writeln!(out, "### {}\n", md(&strategy.title));
        out.push_str("| Requirement | Levels | Control |\n|---|---|---|\n");
        for r in gaps {
            let levels: Vec<String> = r.levels.iter().map(|l| format!("ML{l}")).collect();
            let title = r
                .title
                .clone()
                .or_else(|| ism_titles.get(&r.id.to_ascii_uppercase()).cloned())
                .unwrap_or_default();
            let _ = writeln!(
                out,
                "| {} | {} | {} |",
                md(&r.id),
                levels.join(", "),
                md(&title)
            );
        }
        out.push('\n');
    }
    out
}

/// One permission or role in the least-privilege union.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PermissionRow {
    pub permission: String,
    /// "Microsoft Graph application", "Defender for Endpoint application",
    /// "Defender XDR application", "Log Analytics" or "Azure RBAC role".
    pub kind: String,
    pub operations: Vec<String>,
    pub checks: Vec<String>,
}

const KINDS: [&str; 6] = [
    "Microsoft Graph application",
    "Defender for Endpoint application",
    "Defender XDR application",
    "Log Analytics",
    "Azure RBAC role",
    "Other",
];

fn kind_of(permission: &str, operation: &str) -> &'static str {
    if permission.trim().contains(' ') {
        return KINDS[4];
    }
    match token_service(operation) {
        Some(CloudService::Graph) => KINDS[0],
        Some(CloudService::DefenderEndpoint) => KINDS[1],
        Some(CloudService::DefenderXdr) => KINDS[2],
        Some(CloudService::LogAnalytics) => KINDS[3],
        Some(CloudService::Arm) => KINDS[4],
        _ => KINDS[5],
    }
}

/// The least-privilege union for `checks` (usually a registry selection): the
/// first, least-privileged permission each check declares for each operation,
/// grouped by permission, sorted by kind then name.
pub fn permissions(_registry: &CheckRegistry, checks: &[Arc<dyn Check>]) -> Vec<PermissionRow> {
    let mut rows: BTreeMap<(usize, String), (BTreeSet<String>, BTreeSet<String>)> = BTreeMap::new();
    for check in checks {
        for api in check.requires().apis {
            let Some(permission) = api.permissions.first() else {
                continue;
            };
            let kind = kind_of(permission, api.operation);
            let rank = KINDS.iter().position(|k| *k == kind).unwrap_or(KINDS.len());
            let entry = rows.entry((rank, (*permission).to_owned())).or_default();
            entry.0.insert(api.operation.to_owned());
            entry.1.insert(check.id().to_owned());
        }
    }
    rows.into_iter()
        .map(|((rank, permission), (operations, checks))| PermissionRow {
            permission,
            kind: KINDS[rank].to_owned(),
            operations: operations.into_iter().collect(),
            checks: checks.into_iter().collect(),
        })
        .collect()
}

pub fn permissions_markdown(rows: &[PermissionRow]) -> String {
    let mut out = String::from("| Permission | Type | Checks | Operations |\n|---|---|---|---|\n");
    if rows.is_empty() {
        out.push_str("| none | | | |\n");
    }
    for row in rows {
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | {} |",
            row.permission.replace(['`', '|'], ""),
            row.kind,
            codes(&row.checks),
            codes(&row.operations)
        );
    }
    out
}

/// Every registered check: id, title, pack, severity, kind, licences and
/// least-privilege permissions.
pub fn checks_markdown(registry: &CheckRegistry) -> String {
    let mut checks = registry.all().to_vec();
    checks.sort_by(|a, b| a.pack().cmp(&b.pack()).then(a.id().cmp(b.id())));
    let mut out = String::from(
        "| Id | Title | Pack | Severity | Kind | Licences | Permissions |\n|---|---|---|---|---|---|---|\n",
    );
    for check in checks {
        let meta = check.meta();
        let mut permissions: Vec<String> = meta
            .requires
            .apis
            .iter()
            .filter_map(|a| a.permissions.first().map(|p| (*p).to_owned()))
            .collect();
        permissions.sort();
        permissions.dedup();
        let licences: Vec<String> = meta.requires.licences.iter().map(|l| (*l).into()).collect();
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | {} | {} | {} | {} |",
            meta.id,
            md(meta.title),
            pack_name(meta.pack),
            meta.severity.as_str(),
            match meta.kind {
                CheckKind::Automated => "automated",
                CheckKind::Manual => "manual",
            },
            or_none(codes(&licences)),
            or_none(codes(&permissions))
        );
    }
    out
}

fn pack_name(pack: Pack) -> &'static str {
    pack.as_str()
}

fn codes(items: &[String]) -> String {
    items
        .iter()
        .map(|i| format!("`{}`", i.replace(['`', '|'], "")))
        .collect::<Vec<_>>()
        .join(", ")
}

fn or_none(s: String) -> String {
    if s.is_empty() { "none".into() } else { s }
}
