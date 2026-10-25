//! Check configuration (`--config checks.toml`): per-check thresholds and
//! per-pack settings. Everything is optional; checks document their defaults.
//!
//! ```toml
//! [checks."identity.mfa_coverage"]
//! users_percent = 95
//!
//! [packs.sentinel]
//! subscriptions = ["00000000-0000-4000-8000-000000000001"]
//! price_per_gb = 5.22
//! ```
use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckConfig {
    #[serde(default)]
    pub checks: BTreeMap<String, BTreeMap<String, Value>>,
    #[serde(default)]
    pub packs: BTreeMap<String, BTreeMap<String, Value>>,
}

impl CheckConfig {
    pub fn parse_toml(text: &str) -> Result<Self> {
        if text.len() > 1024 * 1024 {
            anyhow::bail!("check configuration is too large");
        }
        toml::from_str(text).context("invalid check configuration")
    }
    pub fn check_setting<T: DeserializeOwned>(&self, check: &str, key: &str) -> Option<T> {
        self.checks
            .get(check)?
            .get(key)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }
    pub fn pack_setting<T: DeserializeOwned>(&self, pack: &str, key: &str) -> Option<T> {
        self.packs
            .get(pack)?
            .get(key)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn settings_parse_from_toml() {
        let config = CheckConfig::parse_toml(
            "[checks.\"identity.mfa_coverage\"]\nusers_percent = 90\n[packs.sentinel]\nsubscriptions = [\"a\"]\n",
        )
        .unwrap();
        assert_eq!(
            config.check_setting::<f64>("identity.mfa_coverage", "users_percent"),
            Some(90.0)
        );
        assert_eq!(
            config.pack_setting::<Vec<String>>("sentinel", "subscriptions"),
            Some(vec!["a".to_owned()])
        );
        assert!(CheckConfig::parse_toml("[unknown]\n").is_err());
    }
}
