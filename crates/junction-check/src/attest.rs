//! Attestations: a person's answer to a manual check, with author, time and expiry.
//!
//! Answers are stored per tenant in the history store ([`crate::store`]). An
//! answer counts only until it expires; the runner then reports the check as
//! `unknown` (`not_attested`) again. Notes are free text for an evidence
//! reference (a ticket or document link), never credentials.
use crate::check::CheckMeta;
use crate::model::{Answer, Attestation, CheckKind};
use crate::registry::CheckRegistry;
use anyhow::{Result, bail};
use junction_watch::clock::Instant;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;

pub const DEFAULT_EXPIRY_DAYS: u32 = 180;
pub const MAX_EXPIRY_DAYS: u32 = 730;
pub const MAX_NOTE_CHARS: usize = 2000;
pub const MAX_AUTHOR_CHARS: usize = 200;
/// Answers expiring within this many days are listed as pending (`expiring`).
pub const EXPIRING_WITHIN_DAYS: u32 = 30;

const DAY: Duration = Duration::from_secs(86_400);

/// A validated attestation made at `now` that expires after `expiry_days`.
pub fn new(
    answer: Answer,
    note: &str,
    author: &str,
    now: Instant,
    expiry_days: u32,
) -> Result<Attestation> {
    if !(1..=MAX_EXPIRY_DAYS).contains(&expiry_days) {
        bail!("expiry must be between 1 and {MAX_EXPIRY_DAYS} days");
    }
    let attestation = Attestation {
        answer,
        note: note.trim().to_owned(),
        author: author.trim().to_owned(),
        attested_at: now.to_rfc3339(),
        expires_at: now.plus(DAY * expiry_days).to_rfc3339(),
    };
    validate(&attestation)?;
    Ok(attestation)
}

/// Field limits, enforced again on every store write.
pub fn validate(a: &Attestation) -> Result<()> {
    if a.note.chars().count() > MAX_NOTE_CHARS {
        bail!("note must be at most {MAX_NOTE_CHARS} characters");
    }
    if a.note.chars().any(|c| c.is_control() && c != '\n') {
        bail!("note must not contain control characters other than newlines");
    }
    if a.author.trim().is_empty() {
        bail!("author is required");
    }
    if a.author.chars().count() > MAX_AUTHOR_CHARS {
        bail!("author must be at most {MAX_AUTHOR_CHARS} characters");
    }
    if a.author.chars().any(char::is_control) {
        bail!("author must not contain control characters");
    }
    let (Ok(at), Ok(expires)) = (
        Instant::parse(&a.attested_at),
        Instant::parse(&a.expires_at),
    ) else {
        bail!("attestation timestamps must be RFC 3339");
    };
    if expires <= at {
        bail!("attestation must expire after it was made");
    }
    Ok(())
}

/// Not yet expired at `now`. An unreadable expiry counts as expired.
pub fn is_current(a: &Attestation, now: Instant) -> bool {
    Instant::parse(&a.expires_at).is_ok_and(|expires| expires > now)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingStatus {
    /// Never answered.
    Missing,
    /// Answered, but the answer has expired (the check reports `unknown`).
    Expired,
    /// Answered and current, but expires within [`EXPIRING_WITHIN_DAYS`].
    Expiring,
}

impl PendingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Expired => "expired",
            Self::Expiring => "expiring",
        }
    }
}

/// A manual check that needs a (new) answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Pending {
    pub check_id: String,
    pub title: String,
    pub question: String,
    pub guidance: String,
    pub why_manual: String,
    pub status: PendingStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// Every manual check in `registry` without a current answer, plus current
/// answers expiring within [`EXPIRING_WITHIN_DAYS`], in registry order.
pub fn pending(
    registry: &CheckRegistry,
    stored: &BTreeMap<String, Attestation>,
    now: Instant,
) -> Vec<Pending> {
    let soon = now.plus(DAY * EXPIRING_WITHIN_DAYS);
    registry
        .all()
        .iter()
        .map(|c| c.meta())
        .filter(|meta| meta.kind == CheckKind::Manual)
        .filter_map(|meta| {
            let (status, expires_at) = match stored.get(meta.id) {
                None => (PendingStatus::Missing, None),
                Some(a) if !is_current(a, now) => {
                    (PendingStatus::Expired, Some(a.expires_at.clone()))
                }
                Some(a) if Instant::parse(&a.expires_at).is_ok_and(|e| e <= soon) => {
                    (PendingStatus::Expiring, Some(a.expires_at.clone()))
                }
                Some(_) => return None,
            };
            Some(pending_entry(meta, status, expires_at))
        })
        .collect()
}

fn pending_entry(meta: &CheckMeta, status: PendingStatus, expires_at: Option<String>) -> Pending {
    let spec = meta.manual;
    Pending {
        check_id: meta.id.to_owned(),
        title: meta.title.to_owned(),
        question: spec.map_or(meta.description, |m| m.question).to_owned(),
        guidance: spec.map_or(meta.remediation, |m| m.guidance).to_owned(),
        why_manual: spec.map_or("", |m| m.why_manual).to_owned(),
        status,
        expires_at,
    }
}
