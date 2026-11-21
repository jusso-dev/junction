//! What a security check is.
//!
//! A check is static metadata ([`CheckMeta`]) plus an async `evaluate` that reads
//! Microsoft APIs through the [`CheckContext`] and returns a [`Finding`]. The
//! runner merges the two into a [`crate::model::CheckResult`], adds framework
//! tags from data, and turns gateway failures into `unknown` or
//! `not_applicable` with the reason. Checks never write to a tenant.
use crate::context::{CallFailure, CheckContext};
use crate::gateway::BoxFut;
use crate::model::{Attestation, CheckKind, Level, Pack, Reason, Severity, Status};
use serde_json::Value;

/// One catalogue operation a check calls, and the least-privilege permission
/// (application permission or Azure RBAC role) it needs.
#[derive(Debug, Clone, Copy)]
pub struct ApiRequirement {
    pub operation: &'static str,
    /// Any one of these grants access (least privileged first).
    pub permissions: &'static [&'static str],
}

#[derive(Debug, Clone, Copy)]
pub struct Requirements {
    pub apis: &'static [ApiRequirement],
    /// Licence features from `data/licensing.yaml`; all must be present.
    pub licences: &'static [&'static str],
}

impl Requirements {
    pub const NONE: Requirements = Requirements {
        apis: &[],
        licences: &[],
    };
    /// Permissions for `operation`, as declared by the check.
    pub fn permissions_for(&self, operation: &str) -> Vec<String> {
        self.apis
            .iter()
            .filter(|a| a.operation == operation)
            .flat_map(|a| a.permissions.iter().map(|p| (*p).to_owned()))
            .collect()
    }
}

/// Question and guidance for a manual (attested) check.
#[derive(Debug, Clone, Copy)]
pub struct ManualSpec {
    pub question: &'static str,
    pub guidance: &'static str,
    /// Why no API can answer this.
    pub why_manual: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub struct CheckMeta {
    /// Stable id, `<pack>.<name>` in snake case.
    pub id: &'static str,
    pub title: &'static str,
    pub pack: Pack,
    pub kind: CheckKind,
    pub severity: Severity,
    pub effort: Level,
    pub impact: Level,
    /// What the check reads and why it matters (`junction check explain`).
    pub description: &'static str,
    pub requires: Requirements,
    /// How to fix a failure. Suggestion only.
    pub remediation: &'static str,
    pub links: &'static [&'static str],
    pub references: &'static [&'static str],
    pub manual: Option<ManualSpec>,
}

impl CheckMeta {
    /// Defaults for a manual check; fill in the rest with struct update syntax.
    pub const fn manual(
        id: &'static str,
        title: &'static str,
        pack: Pack,
        spec: ManualSpec,
    ) -> Self {
        Self {
            id,
            title,
            pack,
            kind: CheckKind::Manual,
            severity: Severity::Medium,
            effort: Level::Low,
            impact: Level::Medium,
            description: spec.question,
            requires: Requirements::NONE,
            remediation: spec.guidance,
            links: &[],
            references: &[],
            manual: Some(spec),
        }
    }
}

/// The outcome of evaluating one check.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub status: Status,
    pub summary: String,
    pub data: Value,
    pub affected: Vec<String>,
    pub reason: Option<Reason>,
    /// Set when the status comes from a person's answer (hybrid checks).
    pub attested: Option<Attestation>,
}

impl Finding {
    pub fn new(status: Status, summary: impl Into<String>) -> Self {
        Self {
            status,
            summary: summary.into(),
            data: Value::Null,
            affected: vec![],
            reason: None,
            attested: None,
        }
    }
    /// Use a current attestation as the answer.
    pub fn from_attestation(attestation: &Attestation) -> Self {
        Self {
            attested: Some(attestation.clone()),
            ..Self::new(
                attestation.answer.status(),
                format!(
                    "Attested '{}' by {} on {}.",
                    attestation.answer.as_str(),
                    attestation.author,
                    &attestation.attested_at[..10.min(attestation.attested_at.len())]
                ),
            )
        }
    }
    pub fn pass(summary: impl Into<String>) -> Self {
        Self::new(Status::Pass, summary)
    }
    pub fn fail(summary: impl Into<String>) -> Self {
        Self::new(Status::Fail, summary)
    }
    pub fn warn(summary: impl Into<String>) -> Self {
        Self::new(Status::Warn, summary)
    }
    pub fn unknown(code: &str, detail: impl Into<String>) -> Self {
        let detail = detail.into();
        Self {
            reason: Some(Reason::new(code, detail.clone())),
            ..Self::new(Status::Unknown, detail)
        }
    }
    pub fn not_applicable(code: &str, detail: impl Into<String>) -> Self {
        let detail = detail.into();
        Self {
            reason: Some(Reason::new(code, detail.clone())),
            ..Self::new(Status::NotApplicable, detail)
        }
    }
    /// Pass when `ok`, otherwise `fail`.
    pub fn pass_if(ok: bool, pass: impl Into<String>, fail: impl Into<String>) -> Self {
        if ok {
            Self::pass(pass)
        } else {
            Self::fail(fail)
        }
    }
    pub fn data(mut self, data: Value) -> Self {
        self.data = data;
        self
    }
    pub fn affected<I, S>(mut self, items: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.affected = items.into_iter().map(Into::into).collect();
        self
    }
}

pub type Evaluation = Result<Finding, CallFailure>;

pub trait Check: Send + Sync {
    fn meta(&self) -> &'static CheckMeta;
    /// Read-only evaluation. Return `Err` (usually with `?`) when an API call
    /// fails; the runner maps it to `unknown` or `not_applicable` with the reason.
    fn evaluate<'a>(&'a self, ctx: &'a CheckContext) -> BoxFut<'a, Evaluation>;

    fn id(&self) -> &'static str {
        self.meta().id
    }
    fn title(&self) -> &'static str {
        self.meta().title
    }
    fn pack(&self) -> Pack {
        self.meta().pack
    }
    fn requires(&self) -> &'static Requirements {
        &self.meta().requires
    }
}

/// A check answered only by attestation. The runner supplies the status from a
/// current attestation, or `unknown` (`not_attested`) when there is none.
pub struct ManualCheck(pub &'static CheckMeta);

impl Check for ManualCheck {
    fn meta(&self) -> &'static CheckMeta {
        self.0
    }
    fn evaluate<'a>(&'a self, _ctx: &'a CheckContext) -> BoxFut<'a, Evaluation> {
        Box::pin(async {
            Ok(Finding::unknown(
                "not_attested",
                "No current answer. Run `junction check attest` for this check.",
            ))
        })
    }
}

/// Define an automated check from a metadata constant and an async function
/// `fn(&CheckContext) -> Evaluation`:
///
/// ```ignore
/// junction_check::check!(MfaCoverage, &META, |ctx| async move { ... });
/// ```
#[macro_export]
macro_rules! check {
    ($name:ident, $meta:expr, $eval:path) => {
        pub struct $name;
        impl $crate::check::Check for $name {
            fn meta(&self) -> &'static $crate::check::CheckMeta {
                $meta
            }
            fn evaluate<'a>(
                &'a self,
                ctx: &'a $crate::context::CheckContext,
            ) -> $crate::gateway::BoxFut<'a, $crate::check::Evaluation> {
                Box::pin($eval(ctx))
            }
        }
    };
}
