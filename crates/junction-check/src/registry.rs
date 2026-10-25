//! Static registration of packs and checks, lookup by id, pack and tag, and the
//! invariants every registered check must meet.
use crate::check::Check;
use crate::licensing::LicensingData;
use crate::model::{CheckKind, Pack};
use crate::tags::{Frameworks, TagFilter, Tags, parse_tag_table};
use anyhow::{Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

pub struct CheckRegistry {
    checks: Vec<Arc<dyn Check>>,
    tags: BTreeMap<String, Tags>,
}

/// Which checks to run. Empty lists mean "no restriction".
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Selection {
    pub packs: Vec<Pack>,
    /// Exact check ids. When set, only these run (still subject to `exclude`).
    pub checks: Vec<String>,
    pub exclude: Vec<String>,
    /// `--tag` selectors (see [`TagFilter`]); a check is kept when it matches any.
    pub tags: Vec<String>,
}

fn valid_id(id: &str) -> bool {
    let mut parts = id.split('.');
    let (Some(pack), Some(name), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let snake = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            && s.as_bytes()[0].is_ascii_lowercase()
    };
    snake(pack) && snake(name)
}

impl CheckRegistry {
    /// Every built-in pack. Panics only if the embedded data is inconsistent,
    /// which the registry tests catch first.
    pub fn builtin() -> &'static CheckRegistry {
        static REGISTRY: OnceLock<CheckRegistry> = OnceLock::new();
        REGISTRY.get_or_init(|| {
            Self::new(crate::packs::all(), crate::packs::TAG_FILES)
                .expect("built-in check registry is valid")
        })
    }

    pub fn new(checks: Vec<Arc<dyn Check>>, tag_files: &[(&str, &str)]) -> Result<Self> {
        let mut tags = BTreeMap::new();
        for (name, text) in tag_files {
            for (id, entry) in parse_tag_table(name, text)? {
                if tags.insert(id.clone(), entry).is_some() {
                    bail!("check {id} has tags in more than one tag file");
                }
            }
        }
        let frameworks = Frameworks::embedded();
        let licensing = LicensingData::embedded();
        let mut seen = BTreeSet::new();
        let mut problems = vec![];
        for check in &checks {
            let meta = check.meta();
            let id = meta.id;
            if !seen.insert(id) {
                problems.push(format!("duplicate check id {id}"));
            }
            if !valid_id(id) {
                problems.push(format!("{id}: ids are `<pack>.<snake_case_name>`"));
            } else if id.split('.').next() != Some(meta.pack.as_str()) {
                problems.push(format!(
                    "{id}: id prefix must be its pack `{}`",
                    meta.pack.as_str()
                ));
            }
            for (field, value) in [
                ("title", meta.title),
                ("description", meta.description),
                ("remediation", meta.remediation),
            ] {
                if value.trim().is_empty() {
                    problems.push(format!("{id}: {field} is required"));
                }
            }
            match (meta.kind, meta.manual.is_some()) {
                (CheckKind::Manual, false) => {
                    problems.push(format!("{id}: manual checks need a question"))
                }
                (CheckKind::Automated, true) => {
                    problems.push(format!("{id}: automated checks have no question"))
                }
                (CheckKind::Automated, false) if meta.requires.apis.is_empty() => {
                    problems.push(format!("{id}: automated checks declare the APIs they call"))
                }
                _ => {}
            }
            for api in meta.requires.apis {
                if !crate::catalog::contains(api.operation) {
                    problems.push(format!(
                        "{id}: {} is not in data/operations.txt",
                        api.operation
                    ));
                }
                if api.permissions.is_empty() {
                    problems.push(format!(
                        "{id}: {} needs a least-privilege permission",
                        api.operation
                    ));
                }
            }
            for feature in meta.requires.licences {
                if !licensing.features.contains_key(*feature) {
                    problems.push(format!("{id}: unknown licence feature {feature}"));
                }
            }
            match tags.get(id) {
                None => problems.push(format!(
                    "{id}: no tags in data/tags/{}.yaml",
                    meta.pack.as_str()
                )),
                Some(t) if t.is_empty() => {
                    problems.push(format!("{id}: needs at least one framework tag"))
                }
                Some(t) => {
                    for unknown in frameworks.unknown_ids(t) {
                        problems.push(format!("{id}: unknown framework id {unknown}"));
                    }
                }
            }
        }
        for id in tags.keys() {
            if !seen.contains(id.as_str()) {
                problems.push(format!("tags for unregistered check {id}"));
            }
        }
        if !problems.is_empty() {
            bail!("invalid check registry:\n  {}", problems.join("\n  "));
        }
        Ok(Self { checks, tags })
    }

    pub fn all(&self) -> &[Arc<dyn Check>] {
        &self.checks
    }
    pub fn get(&self, id: &str) -> Option<&Arc<dyn Check>> {
        self.checks.iter().find(|c| c.id() == id)
    }
    pub fn tags(&self, id: &str) -> Tags {
        self.tags.get(id).cloned().unwrap_or_default()
    }
    pub fn by_pack(&self, pack: Pack) -> Vec<&Arc<dyn Check>> {
        self.checks.iter().filter(|c| c.pack() == pack).collect()
    }

    /// Resolve a selection to checks in registration order. Unknown check ids
    /// are an error so a typo never silently skips a control.
    pub fn select(&self, selection: &Selection) -> Result<Vec<Arc<dyn Check>>> {
        for id in selection.checks.iter().chain(&selection.exclude) {
            if self.get(id).is_none() {
                bail!("unknown check id {id} (see `junction check list`)");
            }
        }
        let filters = selection
            .tags
            .iter()
            .map(|t| TagFilter::parse(t))
            .collect::<Result<Vec<_>>>()?;
        Ok(self
            .checks
            .iter()
            .filter(|c| selection.packs.is_empty() || selection.packs.contains(&c.pack()))
            .filter(|c| {
                selection.checks.is_empty() || selection.checks.iter().any(|id| id == c.id())
            })
            .filter(|c| {
                filters.is_empty() || {
                    let tags = self.tags(c.id());
                    filters.iter().any(|f| tags.matches(f))
                }
            })
            .filter(|c| !selection.exclude.iter().any(|id| id == c.id()))
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::{CheckMeta, Finding, ManualSpec, Requirements};
    use crate::context::CheckContext;
    use crate::gateway::BoxFut;
    use crate::model::{Level, Severity};

    struct Stub(&'static CheckMeta);
    impl Check for Stub {
        fn meta(&self) -> &'static CheckMeta {
            self.0
        }
        fn evaluate<'a>(&'a self, _: &'a CheckContext) -> BoxFut<'a, crate::check::Evaluation> {
            Box::pin(async { Ok(Finding::pass("ok")) })
        }
    }

    const SPEC: ManualSpec = ManualSpec {
        question: "Is it monitored?",
        guidance: "Monitor it.",
        why_manual: "No API.",
    };
    const A: CheckMeta = CheckMeta::manual("identity.example_a", "A", Pack::Identity, SPEC);
    const B: CheckMeta = CheckMeta {
        remediation: "",
        ..CheckMeta::manual("identity.example_b", "B", Pack::Identity, SPEC)
    };
    const C: CheckMeta = CheckMeta {
        kind: crate::model::CheckKind::Automated,
        manual: None,
        requires: Requirements::NONE,
        severity: Severity::Low,
        effort: Level::Low,
        ..CheckMeta::manual("email.example_c", "C", Pack::Identity, SPEC)
    };
    const TAGS: &str =
        "identity.example_a:\n  mitre: [T1078]\nidentity.example_b:\n  mitre: [T1078]\n";

    #[test]
    fn duplicate_ids_fail_at_registry_init() {
        let error =
            CheckRegistry::new(vec![Arc::new(Stub(&A)), Arc::new(Stub(&A))], &[("t", TAGS)])
                .err()
                .unwrap()
                .to_string();
        assert!(
            error.contains("duplicate check id identity.example_a"),
            "{error}"
        );
    }

    #[test]
    fn remediation_tags_and_pack_prefix_are_enforced() {
        let error = CheckRegistry::new(
            vec![Arc::new(Stub(&B)), Arc::new(Stub(&C))],
            &[("t", "identity.example_b:\n  ism: [ISM-9999999]\n")],
        )
        .err()
        .unwrap()
        .to_string();
        for expected in [
            "identity.example_b: remediation is required",
            "identity.example_b: unknown framework id ism:ISM-9999999",
            "email.example_c: id prefix must be its pack `identity`",
            "email.example_c: automated checks declare the APIs they call",
            "email.example_c: no tags",
        ] {
            assert!(error.contains(expected), "missing {expected:?} in {error}");
        }
    }

    #[test]
    fn builtin_registry_is_valid() {
        let registry = CheckRegistry::builtin();
        assert!(!registry.all().is_empty());
        for check in registry.all() {
            assert!(!registry.tags(check.id()).is_empty(), "{}", check.id());
        }
    }

    #[test]
    fn selection_filters_and_rejects_unknown_ids() {
        let registry = CheckRegistry::new(
            vec![Arc::new(Stub(&A))],
            &[("t", "identity.example_a:\n  mitre: [T1078]\n")],
        )
        .unwrap();
        let all = registry.select(&Selection::default()).unwrap();
        assert_eq!(all.len(), 1);
        let none = registry
            .select(&Selection {
                tags: vec!["e8:mfa".into()],
                ..Selection::default()
            })
            .unwrap();
        assert!(none.is_empty());
        assert!(
            registry
                .select(&Selection {
                    checks: vec!["identity.nope".into()],
                    ..Selection::default()
                })
                .is_err()
        );
    }
}
