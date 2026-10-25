//! Run history and drift: what got better or worse since a previous run.
use crate::model::{Status, TenantReport};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusChange {
    pub id: String,
    pub before: Status,
    pub after: Status,
}

/// Changes between two runs of the same tenant.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Diff {
    pub previous_run_id: String,
    pub previous_finished_at: String,
    /// Checks that fail now and did not before (including newly added checks).
    pub new_failures: Vec<String>,
    /// Checks that failed before and pass now.
    pub fixed: Vec<String>,
    /// Every other status change.
    pub changed: Vec<StatusChange>,
    /// Checks present now but not in the previous run.
    pub added: Vec<String>,
    /// Checks in the previous run that no longer exist or were not selected.
    pub removed: Vec<String>,
    /// Overall score change (current minus previous), when both scored.
    pub score_delta: Option<f64>,
}

impl Diff {
    /// Something got worse: a new failure, or a pass that became a warning.
    pub fn regressed(&self) -> bool {
        !self.new_failures.is_empty()
            || self
                .changed
                .iter()
                .any(|c| c.before == Status::Pass && c.after == Status::Warn)
    }
}

/// Compare `current` with `previous` (same tenant).
pub fn diff(
    previous_run_id: &str,
    previous_finished_at: &str,
    previous: &TenantReport,
    current: &TenantReport,
) -> Diff {
    let before: BTreeMap<&str, Status> = previous
        .results
        .iter()
        .map(|r| (r.id.as_str(), r.status))
        .collect();
    let after: BTreeMap<&str, Status> = current
        .results
        .iter()
        .map(|r| (r.id.as_str(), r.status))
        .collect();
    let mut d = Diff {
        previous_run_id: previous_run_id.into(),
        previous_finished_at: previous_finished_at.into(),
        score_delta: match (previous.score.score, current.score.score) {
            (Some(a), Some(b)) => Some(((b - a) * 10.0).round() / 10.0),
            _ => None,
        },
        ..Diff::default()
    };
    for (id, now) in &after {
        match before.get(id) {
            None => {
                d.added.push((*id).into());
                if *now == Status::Fail {
                    d.new_failures.push((*id).into());
                }
            }
            Some(was) if was == now => {}
            Some(was) => {
                if *now == Status::Fail {
                    d.new_failures.push((*id).into());
                } else if *was == Status::Fail && *now == Status::Pass {
                    d.fixed.push((*id).into());
                } else {
                    d.changed.push(StatusChange {
                        id: (*id).into(),
                        before: *was,
                        after: *now,
                    });
                }
            }
        }
    }
    d.removed = before
        .keys()
        .filter(|id| !after.contains_key(*id))
        .map(|id| (*id).into())
        .collect();
    d
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Affected, CheckKind, CheckResult, Evidence, Level, Pack, Remediation, Score, Severity,
        TenantStatus,
    };

    fn report(results: &[(&str, Status)], score: Option<f64>) -> TenantReport {
        let results: Vec<CheckResult> = results
            .iter()
            .map(|(id, status)| CheckResult {
                id: (*id).into(),
                title: (*id).into(),
                pack: Pack::Identity,
                kind: CheckKind::Automated,
                status: *status,
                severity: Severity::High,
                effort: Level::Low,
                impact: Level::High,
                evidence: Evidence {
                    summary: String::new(),
                    data: serde_json::Value::Null,
                },
                affected: Affected::default(),
                remediation: Remediation {
                    text: "Fix it.".into(),
                    links: vec![],
                },
                references: vec![],
                tags: Default::default(),
                reason: None,
                attested: None,
            })
            .collect();
        TenantReport {
            tenant_id: "00000000-0000-4000-8000-000000000001".into(),
            label: None,
            status: TenantStatus::Complete,
            error: None,
            licences: None,
            score: Score {
                score,
                ..crate::score::score(&results)
            },
            packs: vec![],
            quick_wins: vec![],
            results,
            diff: None,
        }
    }

    use Status::*;

    #[test]
    fn classifies_every_kind_of_change() {
        let before = report(
            &[
                ("identity.a", Pass),
                ("identity.b", Fail),
                ("identity.c", Warn),
                ("identity.d", Pass),
                ("identity.e", Fail),
                ("identity.f", Unknown),
                ("identity.gone", Fail),
                ("identity.same", Fail),
            ],
            Some(50.0),
        );
        let after = report(
            &[
                ("identity.a", Fail),
                ("identity.b", Pass),
                ("identity.c", Fail),
                ("identity.d", Warn),
                ("identity.e", NotApplicable),
                ("identity.f", Pass),
                ("identity.new_fail", Fail),
                ("identity.new_pass", Pass),
                ("identity.same", Fail),
            ],
            Some(62.35),
        );
        let d = diff("run-1", "2026-10-01T00:00:00.000Z", &before, &after);
        assert_eq!(d.previous_run_id, "run-1");
        assert_eq!(d.previous_finished_at, "2026-10-01T00:00:00.000Z");
        assert_eq!(
            d.new_failures,
            ["identity.a", "identity.c", "identity.new_fail"]
        );
        assert_eq!(d.fixed, ["identity.b"]);
        let changed: Vec<_> = d
            .changed
            .iter()
            .map(|c| (c.id.as_str(), c.before, c.after))
            .collect();
        assert_eq!(
            changed,
            [
                ("identity.d", Pass, Warn),
                ("identity.e", Fail, NotApplicable),
                ("identity.f", Unknown, Pass),
            ]
        );
        assert_eq!(d.added, ["identity.new_fail", "identity.new_pass"]);
        assert_eq!(d.removed, ["identity.gone"]);
        assert_eq!(d.score_delta, Some(12.4), "rounded to one decimal");
        assert!(d.regressed());
    }

    #[test]
    fn regression_is_a_new_failure_or_a_pass_turning_to_warn() {
        let base = report(&[("identity.a", Pass), ("identity.b", Fail)], None);
        let same = diff("r", "t", &base, &base);
        assert_eq!(
            same,
            Diff {
                previous_run_id: "r".into(),
                previous_finished_at: "t".into(),
                ..Diff::default()
            }
        );
        assert!(!same.regressed());

        let warned = report(&[("identity.a", Warn), ("identity.b", Fail)], None);
        assert!(diff("r", "t", &base, &warned).regressed());

        let improved = report(&[("identity.a", Pass), ("identity.b", Warn)], None);
        let d = diff("r", "t", &base, &improved);
        assert!(!d.regressed(), "fail to warn is an improvement");
        assert!(d.fixed.is_empty(), "only fail to pass counts as fixed");

        let unknown = report(&[("identity.a", Unknown), ("identity.b", Fail)], None);
        assert!(
            !diff("r", "t", &base, &unknown).regressed(),
            "a check that could not run is a change, not a regression"
        );
    }

    #[test]
    fn removed_failures_are_not_fixes_and_score_delta_needs_both_scores() {
        let before = report(&[("identity.a", Fail)], Some(0.0));
        let after = report(&[("identity.b", Pass)], None);
        let d = diff("r", "t", &before, &after);
        assert!(d.fixed.is_empty());
        assert_eq!(d.removed, ["identity.a"]);
        assert_eq!(d.added, ["identity.b"]);
        assert_eq!(d.score_delta, None);
        assert!(!d.regressed());
    }
}
