//! Scoring and quick-win ordering.
//!
//! **Score.** Each check has a weight from its severity (critical 10, high 6,
//! medium 3, low 1, info 0). A pass earns its full weight, a warn half, a fail
//! nothing. The score is `100 × earned ÷ possible`, rounded to one decimal.
//! `unknown` and `not_applicable` results are excluded from both sides but
//! counted and shown, so missing permissions never inflate or deflate a score.
//! Pack scores use the pack's checks; the overall score uses every check (it is
//! not an average of pack scores). With nothing to score the score is `null`.
//!
//! **Quick wins.** Failures first, then warnings; within each, higher impact,
//! then lower effort, then higher severity, then pack order (identity, endpoint,
//! Intune patching and admin rights, email, backups, Sentinel, then the rest),
//! then check id. Everything else follows in the same order.
use crate::model::{CheckResult, Pack, PackScore, Score, Status, StatusCounts};

pub fn score<'a>(results: impl IntoIterator<Item = &'a CheckResult>) -> Score {
    let mut statuses = StatusCounts::default();
    let (mut earned, mut possible) = (0u64, 0u64);
    let (mut counted, mut excluded) = (0, 0);
    for result in results {
        statuses.add(result.status);
        if !result.status.scored() {
            excluded += 1;
            continue;
        }
        let weight = u64::from(result.severity.weight());
        if weight == 0 {
            continue;
        }
        counted += 1;
        possible += 2 * weight;
        earned += match result.status {
            Status::Pass => 2 * weight,
            Status::Warn => weight,
            _ => 0,
        };
    }
    let score = (possible > 0).then(|| (earned as f64 * 1000.0 / possible as f64).round() / 10.0);
    Score {
        score,
        counted,
        excluded,
        statuses,
    }
}

pub fn pack_scores(results: &[CheckResult]) -> Vec<PackScore> {
    Pack::ALL
        .into_iter()
        .filter(|p| results.iter().any(|r| r.pack == *p))
        .map(|pack| PackScore {
            pack,
            score: score(results.iter().filter(|r| r.pack == pack)),
        })
        .collect()
}

fn status_rank(status: Status) -> u8 {
    match status {
        Status::Fail => 0,
        Status::Warn => 1,
        Status::Unknown => 2,
        Status::NotApplicable => 3,
        Status::Pass => 4,
    }
}

/// Sort results into quick-win order (see module docs).
pub fn quick_win_order(results: &mut [CheckResult]) {
    results.sort_by(|a, b| {
        status_rank(a.status)
            .cmp(&status_rank(b.status))
            .then(b.impact.rank().cmp(&a.impact.rank()))
            .then(a.effort.rank().cmp(&b.effort.rank()))
            .then(b.severity.rank().cmp(&a.severity.rank()))
            .then(a.pack.cmp(&b.pack))
            .then(a.id.cmp(&b.id))
    });
}

/// Ids of failed and warned checks, in quick-win order.
pub fn quick_wins(results: &[CheckResult]) -> Vec<String> {
    let mut sorted = results.to_vec();
    quick_win_order(&mut sorted);
    sorted
        .into_iter()
        .filter(|r| matches!(r.status, Status::Fail | Status::Warn))
        .map(|r| r.id)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    use crate::tags::Tags;
    use serde_json::Value;

    pub(crate) fn result(
        id: &str,
        pack: Pack,
        status: Status,
        severity: Severity,
        impact: Level,
        effort: Level,
    ) -> CheckResult {
        CheckResult {
            id: id.into(),
            title: id.into(),
            pack,
            kind: CheckKind::Automated,
            status,
            severity,
            effort,
            impact,
            evidence: Evidence {
                summary: String::new(),
                data: Value::Null,
            },
            affected: Affected::default(),
            remediation: Remediation {
                text: "fix".into(),
                links: vec![],
            },
            references: vec![],
            tags: Tags::default(),
            reason: None,
            attested: None,
        }
    }

    fn r(id: &str, status: Status, severity: Severity) -> CheckResult {
        result(
            id,
            Pack::Identity,
            status,
            severity,
            Level::Medium,
            Level::Medium,
        )
    }

    #[test]
    fn every_status_contributes_as_documented() {
        let results = [
            r("identity.a", Status::Pass, Severity::High), // 12 of 12
            r("identity.b", Status::Warn, Severity::High), // 6 of 12
            r("identity.c", Status::Fail, Severity::Medium), // 0 of 6
            r("identity.d", Status::Unknown, Severity::Critical), // excluded
            r("identity.e", Status::NotApplicable, Severity::Low), // excluded
            r("identity.f", Status::Pass, Severity::Info), // no weight
        ];
        let s = score(&results);
        assert_eq!(s.score, Some(60.0)); // 18 / 30
        assert_eq!((s.counted, s.excluded), (3, 2));
        assert_eq!(s.statuses.total(), 6);
        assert_eq!(s.statuses.unknown, 1);
    }

    #[test]
    fn empty_and_unscored_packs_have_no_score() {
        assert_eq!(score(&[]).score, None);
        let s = score(&[r("identity.a", Status::Unknown, Severity::High)]);
        assert_eq!((s.score, s.excluded), (None, 1));
        let packs = pack_scores(&[r("identity.a", Status::Pass, Severity::Low)]);
        assert_eq!(packs.len(), 1);
        assert_eq!(packs[0].score.score, Some(100.0));
    }

    #[test]
    fn score_is_deterministic_and_rounded() {
        let results = [
            r("identity.a", Status::Pass, Severity::Low),
            r("identity.b", Status::Fail, Severity::Low),
            r("identity.c", Status::Fail, Severity::Low),
        ];
        assert_eq!(score(&results).score, Some(33.3));
        assert_eq!(score(&results), score(&results));
    }

    #[test]
    fn quick_wins_break_ties_by_impact_effort_severity_pack_then_id() {
        use Level::*;
        let mut results = vec![
            result(
                "sentinel.z",
                Pack::Sentinel,
                Status::Fail,
                Severity::High,
                High,
                Low,
            ),
            result(
                "identity.y",
                Pack::Identity,
                Status::Fail,
                Severity::High,
                High,
                Low,
            ),
            result(
                "email.x",
                Pack::Email,
                Status::Fail,
                Severity::Critical,
                High,
                Low,
            ),
            result(
                "identity.w",
                Pack::Identity,
                Status::Fail,
                Severity::Critical,
                High,
                High,
            ),
            result(
                "identity.v",
                Pack::Identity,
                Status::Warn,
                Severity::Critical,
                High,
                Low,
            ),
            result(
                "identity.u",
                Pack::Identity,
                Status::Fail,
                Severity::Low,
                Low,
                Low,
            ),
            result(
                "identity.t",
                Pack::Identity,
                Status::Pass,
                Severity::Critical,
                High,
                Low,
            ),
            result(
                "identity.s",
                Pack::Identity,
                Status::Fail,
                Severity::High,
                High,
                Low,
            ),
        ];
        quick_win_order(&mut results);
        let ids: Vec<_> = results.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "email.x",    // critical beats high at equal impact and effort
                "identity.s", // identity before sentinel; id breaks the identity tie
                "identity.y",
                "sentinel.z",
                "identity.w", // high effort after low effort
                "identity.u", // low impact last among failures
                "identity.v", // warnings after failures
                "identity.t", // passes last
            ]
        );
        assert_eq!(quick_wins(&results).len(), 7);
    }
}
