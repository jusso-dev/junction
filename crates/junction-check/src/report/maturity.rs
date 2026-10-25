//! Essential Eight maturity estimate per strategy. Always an estimate, not an
//! assessment: it only reflects the checks in one run.
//!
//! **Rule.** For each strategy in `data/frameworks/essential-eight.yaml`, take
//! the checks in the run tagged with that strategy (the result's recorded tags,
//! or the registry's when a result carries none). Maturity level L is met when
//! at least one of those checks is tagged at level L and every check tagged at
//! any level up to and including L passed. The estimate is the highest level
//! with every level below it also met, so it is the lowest level fully met.
//! A warning counts as not met. `unknown` and `not_applicable` checks are not
//! evidence either way: they are listed as gaps and cap the estimate at the
//! level below the lowest level they are tagged at. A strategy with no tagged
//! checks in the run is level 0 with the basis "no automated evidence".
use crate::model::{CheckResult, Status, TenantReport};
use crate::registry::CheckRegistry;
use crate::tags::Frameworks;

pub const NO_EVIDENCE: &str = "no automated evidence";
pub const LABEL: &str = "estimate, not an assessment";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct StrategyEstimate {
    /// Strategy id, for example `mfa`.
    pub strategy: String,
    pub title: String,
    /// Estimated maturity level, 0 to 3.
    pub level: u8,
    /// Plain-English reason for the level.
    pub basis: String,
    /// Check ids tagged with this strategy in the run.
    pub checks: Vec<String>,
    /// Tagged checks that did not pass (fail, warn, unknown or not applicable).
    pub gaps: Vec<String>,
}

pub fn estimate(tenant: &TenantReport, registry: &CheckRegistry) -> Vec<StrategyEstimate> {
    Frameworks::embedded()
        .essential_eight
        .strategies
        .iter()
        .map(|strategy| {
            let mut tagged: Vec<(&CheckResult, Vec<u8>)> = tenant
                .results
                .iter()
                .filter_map(|r| {
                    let fallback;
                    let tags = if r.tags.is_empty() {
                        fallback = registry.tags(&r.id);
                        &fallback
                    } else {
                        &r.tags
                    };
                    let mut levels: Vec<u8> = tags
                        .essential_eight
                        .iter()
                        .filter(|t| t.strategy == strategy.id)
                        .flat_map(|t| t.levels.iter().copied())
                        .filter(|l| (1..=3).contains(l))
                        .collect();
                    levels.sort_unstable();
                    levels.dedup();
                    (!levels.is_empty()).then_some((r, levels))
                })
                .collect();
            tagged.sort_by(|a, b| a.0.id.cmp(&b.0.id));
            let (level, basis) = level_of(&tagged);
            StrategyEstimate {
                strategy: strategy.id.clone(),
                title: strategy.title.clone(),
                level,
                basis,
                checks: tagged.iter().map(|(r, _)| r.id.clone()).collect(),
                gaps: tagged
                    .iter()
                    .filter(|(r, _)| r.status != Status::Pass)
                    .map(|(r, _)| r.id.clone())
                    .collect(),
            }
        })
        .collect()
}

fn level_of(tagged: &[(&CheckResult, Vec<u8>)]) -> (u8, String) {
    if tagged.is_empty() {
        return (0, NO_EVIDENCE.into());
    }
    let mut level = 0;
    let mut stop = None;
    for l in 1..=3u8 {
        if !tagged.iter().any(|(_, levels)| levels.contains(&l)) {
            stop = Some(format!("no check gives evidence for ML{l}"));
            break;
        }
        let blockers: Vec<String> = tagged
            .iter()
            .filter(|(r, levels)| levels[0] <= l && r.status != Status::Pass)
            .map(|(r, _)| format!("{} {}", r.id, outcome(r.status)))
            .collect();
        if !blockers.is_empty() {
            stop = Some(format!("ML{l} not met: {}", blockers.join(", ")));
            break;
        }
        level = l;
    }
    let passed = tagged
        .iter()
        .filter(|(r, _)| r.status == Status::Pass)
        .count();
    let counted = format!(
        "{passed} of {} tagged check{} passed",
        tagged.len(),
        if tagged.len() == 1 { "" } else { "s" }
    );
    let basis = match stop {
        None => format!("ML3 met: {counted}."),
        Some(why) if level == 0 => format!("{}; {counted}.", capitalise(&why)),
        Some(why) => format!("ML{level} met; {why}; {counted}."),
    };
    (level, basis)
}

fn outcome(status: Status) -> &'static str {
    match status {
        Status::Pass => "passed",
        Status::Fail => "failed",
        Status::Warn => "warned",
        Status::Unknown => "could not be checked",
        Status::NotApplicable => "was not applicable",
    }
}

fn capitalise(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}
