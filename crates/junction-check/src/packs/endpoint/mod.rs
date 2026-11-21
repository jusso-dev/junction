//! `endpoint` pack: Defender for Endpoint coverage and sensor health, protection
//! settings, and attack surface reduction rules.
use crate::check::Check;
use std::sync::Arc;

pub mod asr;
pub mod coverage;
pub mod protection;

pub fn checks() -> Vec<Arc<dyn Check>> {
    let mut all = coverage::checks();
    all.extend(protection::checks());
    all.extend(asr::checks());
    all
}
