//! Result model shared by every pack, output format and surface (CLI, MCP, HTTP).
//!
//! The serialised form is versioned by [`SCHEMA_VERSION`] and published as
//! `docs/check-result.schema.json`. Evidence carries counts and identifiers only:
//! never tokens, secrets, recovery keys or raw API payloads.
use crate::tags::Tags;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Bump the minor version for additive fields and the major version for any
/// change that breaks an existing consumer.
pub const SCHEMA_VERSION: &str = "1.0";

/// How many affected resources a result lists before it only counts.
pub const AFFECTED_CAP: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pass,
    Fail,
    Warn,
    Unknown,
    NotApplicable,
}

impl Status {
    pub const ALL: [Status; 5] = [
        Status::Pass,
        Status::Fail,
        Status::Warn,
        Status::Unknown,
        Status::NotApplicable,
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Warn => "warn",
            Self::Unknown => "unknown",
            Self::NotApplicable => "not_applicable",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.as_str() == value)
    }
    /// Counted in a score. Unknown and not-applicable results are shown but never
    /// count as a pass or a fail.
    pub fn scored(self) -> bool {
        matches!(self, Self::Pass | Self::Fail | Self::Warn)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub const ALL: [Severity; 5] = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.as_str() == value)
    }
    /// Score weight. Informational checks are reported but carry no weight.
    pub fn weight(self) -> u32 {
        match self {
            Self::Critical => 10,
            Self::High => 6,
            Self::Medium => 3,
            Self::Low => 1,
            Self::Info => 0,
        }
    }
    /// Higher is more severe.
    pub fn rank(self) -> u8 {
        match self {
            Self::Critical => 4,
            Self::High => 3,
            Self::Medium => 2,
            Self::Low => 1,
            Self::Info => 0,
        }
    }
    /// `--fail-on high` breaches on high and critical findings.
    pub fn at_least(self, threshold: Severity) -> bool {
        self.rank() >= threshold.rank()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Low,
    Medium,
    High,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
    pub fn rank(self) -> u8 {
        match self {
            Self::Low => 0,
            Self::Medium => 1,
            Self::High => 2,
        }
    }
}

/// Packs group checks by the area an operator fixes them in. The declaration
/// order is the quick-win tie-break: identity first, then endpoint, patching and
/// admin rights (Intune), email, backups and Sentinel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pack {
    Identity,
    Endpoint,
    Intune,
    Email,
    Backup,
    Sentinel,
    Apps,
    Collaboration,
    Azure,
}

impl Pack {
    pub const ALL: [Pack; 9] = [
        Pack::Identity,
        Pack::Endpoint,
        Pack::Intune,
        Pack::Email,
        Pack::Backup,
        Pack::Sentinel,
        Pack::Apps,
        Pack::Collaboration,
        Pack::Azure,
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Endpoint => "endpoint",
            Self::Intune => "intune",
            Self::Email => "email",
            Self::Backup => "backup",
            Self::Sentinel => "sentinel",
            Self::Apps => "apps",
            Self::Collaboration => "collaboration",
            Self::Azure => "azure",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == value)
    }
    pub fn title(self) -> &'static str {
        match self {
            Self::Identity => "Identity",
            Self::Endpoint => "Endpoint (Defender for Endpoint and ASR)",
            Self::Intune => "Intune, patching and admin rights",
            Self::Email => "Email",
            Self::Backup => "Backups",
            Self::Sentinel => "Microsoft Sentinel",
            Self::Apps => "Applications and consent",
            Self::Collaboration => "Collaboration",
            Self::Azure => "Azure",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckKind {
    /// Evaluated from Microsoft API responses.
    Automated,
    /// Answered by a person (`junction check attest`) because no API exposes it.
    Manual,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    /// One or two plain-English sentences.
    pub summary: String,
    /// Structured counts and identifiers. Never tokens, secrets or raw payloads.
    #[serde(default)]
    pub data: Value,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Affected {
    /// Total affected resources, including any not listed.
    pub total: usize,
    /// Up to [`AFFECTED_CAP`] resource identifiers (UPNs, device names, domains).
    pub items: Vec<String>,
}

impl Affected {
    pub fn from_items(mut items: Vec<String>) -> Self {
        items.sort();
        items.dedup();
        let total = items.len();
        items.truncate(AFFECTED_CAP);
        Self { total, items }
    }
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Remediation {
    /// Suggestion only. Junction never changes tenant configuration.
    pub text: String,
    #[serde(default)]
    pub links: Vec<String>,
}

/// Why a check is `unknown` or `not_applicable`. Codes are stable identifiers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reason {
    pub code: String,
    pub detail: String,
    /// Permissions or roles that, once granted, let the check run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_permissions: Vec<String>,
}

impl Reason {
    pub fn new(code: &str, detail: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            detail: detail.into(),
            missing_permissions: vec![],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Answer {
    Yes,
    No,
    Partial,
    NotApplicable,
}

impl Answer {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "yes" => Some(Self::Yes),
            "no" => Some(Self::No),
            "partial" => Some(Self::Partial),
            "not_applicable" | "na" | "n/a" => Some(Self::NotApplicable),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Yes => "yes",
            Self::No => "no",
            Self::Partial => "partial",
            Self::NotApplicable => "not_applicable",
        }
    }
    pub fn status(self) -> Status {
        match self {
            Self::Yes => Status::Pass,
            Self::No => Status::Fail,
            Self::Partial => Status::Warn,
            Self::NotApplicable => Status::NotApplicable,
        }
    }
}

/// A person's answer to a manual check. Expired answers are not used.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attestation {
    pub answer: Answer,
    pub note: String,
    pub author: String,
    pub attested_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckResult {
    pub id: String,
    pub title: String,
    pub pack: Pack,
    pub kind: CheckKind,
    pub status: Status,
    pub severity: Severity,
    pub effort: Level,
    pub impact: Level,
    pub evidence: Evidence,
    pub affected: Affected,
    pub remediation: Remediation,
    #[serde(default)]
    pub references: Vec<String>,
    pub tags: Tags,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
    /// Present when the status comes from a person's answer, not an API.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attested: Option<Attestation>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StatusCounts {
    pub pass: usize,
    pub fail: usize,
    pub warn: usize,
    pub unknown: usize,
    pub not_applicable: usize,
}

impl StatusCounts {
    pub fn add(&mut self, status: Status) {
        match status {
            Status::Pass => self.pass += 1,
            Status::Fail => self.fail += 1,
            Status::Warn => self.warn += 1,
            Status::Unknown => self.unknown += 1,
            Status::NotApplicable => self.not_applicable += 1,
        }
    }
    pub fn total(&self) -> usize {
        self.pass + self.fail + self.warn + self.unknown + self.not_applicable
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Score {
    /// 0 to 100 with one decimal, or `None` when nothing scored.
    pub score: Option<f64>,
    /// Checks counted in the score (pass, warn, fail with non-zero weight).
    pub counted: usize,
    /// Checks shown but excluded from the score (unknown, not applicable).
    pub excluded: usize,
    pub statuses: StatusCounts,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PackScore {
    pub pack: Pack,
    #[serde(flatten)]
    pub score: Score,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantStatus {
    /// Every selected check ran (any status).
    Complete,
    /// Some checks could not run (unknown because of errors).
    Partial,
    /// The tenant could not be assessed at all (for example authentication failed).
    Failed,
}

/// Licence features detected from `subscribedSkus` service plans.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LicenceSnapshot {
    /// Features with at least one enabled service plan.
    pub features: Vec<String>,
    /// SKU part numbers, for context only.
    pub skus: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TenantReport {
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub status: TenantStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<Reason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub licences: Option<LicenceSnapshot>,
    pub score: Score,
    pub packs: Vec<PackScore>,
    /// Check ids that failed or warned, highest impact and lowest effort first.
    pub quick_wins: Vec<String>,
    /// Results in quick-win order.
    pub results: Vec<CheckResult>,
    /// Changes since the previous stored run, when history is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff: Option<crate::history::Diff>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Tool {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunReport {
    pub schema_version: String,
    pub run_id: String,
    pub tool: Tool,
    pub started_at: String,
    pub finished_at: String,
    /// Selection that produced this run, for reproducibility.
    pub selection: Value,
    pub tenants: Vec<TenantReport>,
}

impl RunReport {
    /// True when any tenant failed or any check could not run.
    pub fn partial(&self) -> bool {
        self.tenants
            .iter()
            .any(|t| t.status != TenantStatus::Complete)
    }
}
