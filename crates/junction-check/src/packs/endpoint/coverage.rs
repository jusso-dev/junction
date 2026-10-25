//! Endpoint pack: coverage checks.
use crate::check::Check;
use std::sync::Arc;

pub fn checks() -> Vec<Arc<dyn Check>> {
    vec![]
}
