//! `sentinel` pack. See docs/CHECKS.md for the checks and their permissions.
use crate::check::Check;
use std::sync::Arc;

pub fn checks() -> Vec<Arc<dyn Check>> {
    vec![]
}
