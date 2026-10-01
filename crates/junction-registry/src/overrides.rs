//! Trusted operator risk corrections, applied consistently to every registry consumer.
use anyhow::{Result, bail};
use junction_core::OperationRisk;
use serde::Deserialize;
use std::collections::BTreeSet;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskOverride {
    pub operation: String,
    pub risk: OperationRisk,
    pub reason: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskOverrides {
    pub operations: Vec<RiskOverride>,
}
impl RiskOverrides {
    pub fn parse(text: &str) -> Result<Self> {
        if text.len() > 1024 * 1024 {
            bail!("risk override size exceeded");
        }
        let overrides: Self =
            toml::from_str(text).map_err(|_| anyhow::anyhow!("invalid risk overrides"))?;
        overrides.validate()?;
        Ok(overrides)
    }
    pub fn validate(&self) -> Result<()> {
        if self.operations.len() > 4096 {
            bail!("risk override count exceeded");
        }
        let mut names = BTreeSet::new();
        for entry in &self.operations {
            if entry.operation.is_empty()
                || entry.operation.len() > 512
                || entry.reason.trim().is_empty()
                || entry.reason.len() > 1024
                || !names.insert(&entry.operation)
            {
                bail!("invalid or duplicate risk override");
            }
        }
        Ok(())
    }
}
