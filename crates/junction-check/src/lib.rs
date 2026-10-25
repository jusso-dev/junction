//! Read-only security posture checks for Microsoft 365, Entra ID, Defender,
//! Intune, email and Sentinel (`junction check`).
//!
//! Checks are grouped in packs, call Microsoft APIs only through Junction's
//! catalogue, registry and read-only policy ([`gateway`]), and report a status
//! with evidence, remediation and framework tags ([`model`]). Missing licences
//! give `not_applicable` and missing permissions give `unknown` with the reason;
//! never a false pass or fail. See `docs/CHECKS.md`.
pub mod attest;
pub mod catalog;
pub mod check;
pub mod config;
pub mod context;
pub mod dns;
pub mod gateway;
pub mod history;
pub mod licensing;
pub mod model;
pub mod outcome;
pub mod packs;
pub mod push;
pub mod registry;
pub mod report;
pub mod runner;
pub mod score;
pub mod scrub;
pub mod store;
pub mod tags;
pub mod testkit;

pub use check::{Check, CheckMeta, Finding};
pub use context::CheckContext;
pub use model::{CheckResult, Pack, RunReport, Severity, Status};
pub use registry::{CheckRegistry, Selection};
