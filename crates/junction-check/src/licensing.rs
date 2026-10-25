//! Licence feature detection from `subscribedSkus` service plans. The mapping is
//! data (`data/licensing.yaml`); SKU parsing is shared with `junction-watch`.
use crate::model::LicenceSnapshot;
use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureSpec {
    pub title: String,
    pub service_plans: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LicensingData {
    pub features: BTreeMap<String, FeatureSpec>,
}

const DATA: &str = include_str!("../data/licensing.yaml");

impl LicensingData {
    pub fn embedded() -> &'static LicensingData {
        static PARSED: OnceLock<LicensingData> = OnceLock::new();
        PARSED.get_or_init(|| Self::parse(DATA).expect("embedded licensing data is valid"))
    }
    pub fn parse(text: &str) -> Result<Self> {
        serde_saphyr::from_str(text).context("licensing data")
    }
    pub fn title(&self, feature: &str) -> Option<&str> {
        self.features.get(feature).map(|f| f.title.as_str())
    }
}

/// Build the snapshot from a `subscribedSkus` response body. Only SKUs that are
/// usable now (`Enabled`, or `Warning` during the grace period) count.
pub fn snapshot(body: &Value) -> LicenceSnapshot {
    snapshot_with(LicensingData::embedded(), body)
}

pub fn snapshot_with(data: &LicensingData, body: &Value) -> LicenceSnapshot {
    let skus = junction_watch::probe::sku_summaries(body);
    let mut plans = BTreeSet::new();
    let mut names = BTreeSet::new();
    for sku in &skus {
        if !matches!(sku.capability_status.as_str(), "Enabled" | "Warning") {
            continue;
        }
        names.insert(sku.sku_part_number.clone());
        plans.extend(sku.service_plans.iter().cloned());
    }
    let features = data
        .features
        .iter()
        .filter(|(_, spec)| spec.service_plans.iter().any(|p| plans.contains(p)))
        .map(|(name, _)| name.clone())
        .collect();
    LicenceSnapshot {
        features,
        skus: names.into_iter().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sku(part: &str, status: &str, plans: &[&str]) -> Value {
        json!({
            "skuPartNumber": part,
            "capabilityStatus": status,
            "servicePlans": plans.iter().map(|p| json!({"servicePlanName": p, "provisioningStatus": "Success"})).collect::<Vec<_>>()
        })
    }

    #[test]
    fn service_plans_map_to_features() {
        let body = json!({"value": [
            sku("SPB", "Enabled", &["AAD_PREMIUM", "INTUNE_A", "MDE_SMB", "ATP_ENTERPRISE", "EXCHANGE_S_STANDARD"]),
            sku("SUSPENDED_E5", "Suspended", &["AAD_PREMIUM_P2", "WINDEFATP"]),
            json!({"skuPartNumber": "PENDING", "capabilityStatus": "Enabled",
                   "servicePlans": [{"servicePlanName": "AAD_PREMIUM_P2", "provisioningStatus": "PendingActivation"}]}),
        ]});
        let snap = snapshot(&body);
        assert_eq!(
            snap.features,
            [
                "defender_endpoint",
                "defender_endpoint_p2",
                "defender_office_p1",
                "defender_vulnerability_management",
                "defender_xdr_hunting",
                "entra_id_p1",
                "exchange_online",
                "intune"
            ]
        );
        assert_eq!(snap.skus, ["PENDING", "SPB"]);
        assert!(!snap.features.contains(&"entra_id_p2".to_owned()));
    }

    #[test]
    fn plan_names_match_microsoft_reference_examples() {
        let data = LicensingData::embedded();
        for (feature, plan) in [
            ("defender_endpoint", "WINDEFATP"),
            ("defender_endpoint", "MDE_SMB"),
            ("entra_id_p1", "AAD_PREMIUM"),
            ("intune", "INTUNE_A"),
        ] {
            assert!(
                data.features[feature]
                    .service_plans
                    .contains(&plan.to_owned()),
                "{feature} {plan}"
            );
        }
    }
}
