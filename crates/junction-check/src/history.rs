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
