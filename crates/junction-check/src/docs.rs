//! Generated documentation tables. Permission tables, the check catalogue and
//! the Essential Eight coverage matrix come from the registry, so the docs
//! cannot drift from the code: a test runs [`sync`] in check mode.
use crate::check::Check;
use crate::model::{CheckKind, Pack};
use crate::registry::CheckRegistry;
use crate::report::coverage;
use anyhow::{Context, Result, bail};
use std::path::Path;
use std::sync::Arc;

/// Generated sections: (file in docs/, section name, content).
pub fn sections(registry: &CheckRegistry) -> Vec<(&'static str, &'static str, String)> {
    let mut permissions = String::new();
    for pack in Pack::ALL {
        let checks: Vec<Arc<dyn Check>> = registry.by_pack(pack).into_iter().cloned().collect();
        if checks.is_empty() {
            continue;
        }
        permissions.push_str(&format!("### {} (`{}`)\n\n", pack.title(), pack.as_str()));
        permissions.push_str(&coverage::permissions_markdown(&coverage::permissions(registry, &checks)));
        permissions.push('\n');
    }
    let all: Vec<Arc<dyn Check>> = registry.all().to_vec();
    permissions.push_str("### Every pack\n\n");
    permissions.push_str(&coverage::permissions_markdown(&coverage::permissions(registry, &all)));
    let mut manual = String::from("| Check | Question | Why manual |\n|---|---|---|\n");
    for check in registry.all().iter().filter(|c| c.meta().kind == CheckKind::Manual) {
        let m = check.meta();
        let spec = m.manual.expect("manual checks have a question");
        manual.push_str(&format!(
            "| `{}` | {} | {} |\n",
            m.id,
            spec.question.replace('|', "\\|"),
            spec.why_manual.replace('|', "\\|")
        ));
    }
    vec![
        ("CHECKS.md", "checks", coverage::checks_markdown(registry)),
        ("CHECKS.md", "manual-checks", manual),
        ("CHECKS-PERMISSIONS.md", "permissions", permissions),
        ("ESSENTIAL-EIGHT-COVERAGE.md", "coverage", coverage::essential_eight_matrix(registry)),
    ]
}

fn markers(name: &str) -> (String, String) {
    (
        format!("<!-- generated:{name}:start (junction check docs) -->"),
        format!("<!-- generated:{name}:end -->"),
    )
}

/// Replace a generated section in `text`.
pub fn replace_section(text: &str, name: &str, content: &str) -> Result<String> {
    let (start, end) = markers(name);
    let (Some(a), Some(b)) = (text.find(&start), text.find(&end)) else {
        bail!("missing generated:{name} markers");
    };
    if b < a {
        bail!("generated:{name} markers are out of order");
    }
    Ok(format!(
        "{}{start}\n{}\n{}",
        &text[..a],
        content.trim_end(),
        &text[b..]
    ))
}

/// Write (or, with `check`, compare) every generated section under `dir`.
/// Returns the files that are stale.
pub fn sync(registry: &CheckRegistry, dir: &Path, check: bool) -> Result<Vec<String>> {
    let mut stale = vec![];
    let mut files: std::collections::BTreeMap<&str, String> = Default::default();
    for (file, name, content) in sections(registry) {
        let current = match files.get(file) {
            Some(text) => text.clone(),
            None => std::fs::read_to_string(dir.join(file)).with_context(|| format!("reading docs/{file}"))?,
        };
        let updated = replace_section(&current, name, &content).with_context(|| format!("docs/{file}"))?;
        files.insert(file, updated);
    }
    for (file, text) in files {
        let path = dir.join(file);
        if std::fs::read_to_string(&path)? != text {
            stale.push(file.to_owned());
            if !check {
                std::fs::write(&path, text)?;
            }
        }
    }
    Ok(stale)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sections_replace_between_markers() {
        let text = "intro\n<!-- generated:x:start (junction check docs) -->\nold\n<!-- generated:x:end -->\nouter\n";
        let out = replace_section(text, "x", "new\n").unwrap();
        assert_eq!(out, "intro\n<!-- generated:x:start (junction check docs) -->\nnew\n<!-- generated:x:end -->\nouter\n");
        assert!(replace_section("none", "x", "").is_err());
    }

    #[test]
    fn committed_docs_are_up_to_date() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs");
        let stale = sync(CheckRegistry::builtin(), &dir, true).unwrap();
        assert!(stale.is_empty(), "stale generated docs: {stale:?}; run `junction check docs`");
    }
}
