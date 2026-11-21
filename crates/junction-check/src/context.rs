//! Per-tenant context handed to every check: a governed gateway, the licence
//! snapshot, configuration, attestations, a DNS resolver and a clock.
//!
//! Calls are memoised for the run, so packs that need the same data (devices,
//! TVM assessments, Conditional Access policies) share one request.
use crate::config::CheckConfig;
use crate::dns::Resolver;
use crate::gateway::{Gateway, GatewayError, Listing};
use crate::model::{Attestation, LicenceSnapshot};
use junction_watch::clock::Instant;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tokio::sync::OnceCell;

/// A failed API call, with the operation that failed.
#[derive(Debug, Clone)]
pub struct CallFailure {
    pub operation: String,
    pub error: GatewayError,
}

impl std::fmt::Display for CallFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.operation, self.error)
    }
}

#[derive(Clone)]
enum Cached {
    Body(Value),
    Listing(Listing),
}

type Slot = Arc<OnceCell<Result<Cached, GatewayError>>>;

pub struct CheckContext {
    tenant_id: String,
    label: Option<String>,
    gateway: Arc<dyn Gateway>,
    licences: Option<LicenceSnapshot>,
    config: Arc<CheckConfig>,
    attestations: BTreeMap<String, Attestation>,
    dns: Arc<dyn Resolver>,
    now: Instant,
    cache: Mutex<BTreeMap<String, Slot>>,
}

pub struct ContextParts {
    pub tenant_id: String,
    pub label: Option<String>,
    pub gateway: Arc<dyn Gateway>,
    pub licences: Option<LicenceSnapshot>,
    pub config: Arc<CheckConfig>,
    pub attestations: BTreeMap<String, Attestation>,
    pub dns: Arc<dyn Resolver>,
    pub now: Instant,
}

impl CheckContext {
    pub fn new(parts: ContextParts) -> Self {
        Self {
            tenant_id: parts.tenant_id,
            label: parts.label,
            gateway: parts.gateway,
            licences: parts.licences,
            config: parts.config,
            attestations: parts.attestations,
            dns: parts.dns,
            now: parts.now,
            cache: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }
    pub fn now(&self) -> Instant {
        self.now
    }
    pub fn dns(&self) -> &dyn Resolver {
        self.dns.as_ref()
    }
    pub fn config(&self) -> &CheckConfig {
        &self.config
    }
    pub fn licences(&self) -> Option<&LicenceSnapshot> {
        self.licences.as_ref()
    }
    /// `Some(true/false)` when licences were readable, `None` when unknown.
    pub fn has_feature(&self, feature: &str) -> Option<bool> {
        self.licences
            .as_ref()
            .map(|l| l.features.iter().any(|f| f == feature))
    }
    /// A current (unexpired) attestation for `check_id`.
    pub fn attestation(&self, check_id: &str) -> Option<&Attestation> {
        self.attestations.get(check_id)
    }

    /// A per-check setting from `[checks."<id>"]` in the configuration file.
    pub fn setting<T: DeserializeOwned>(&self, check_id: &str, key: &str, default: T) -> T {
        self.config.check_setting(check_id, key).unwrap_or(default)
    }
    /// A per-pack setting from `[packs.<pack>]`.
    pub fn pack_setting<T: DeserializeOwned>(&self, pack: &str, key: &str, default: T) -> T {
        self.config.pack_setting(pack, key).unwrap_or(default)
    }

    fn slot(&self, kind: &str, operation: &str, input: &Value) -> Slot {
        let key = format!("{kind}\u{0}{operation}\u{0}{input}");
        self.cache
            .lock()
            .expect("cache")
            .entry(key)
            .or_default()
            .clone()
    }

    /// One request (memoised for this tenant run).
    pub async fn get(&self, operation: &str, input: Value) -> Result<Value, CallFailure> {
        let slot = self.slot("get", operation, &input);
        let result = slot
            .get_or_init(|| async { self.gateway.get(operation, input).await.map(Cached::Body) })
            .await
            .clone();
        match result {
            Ok(Cached::Body(body)) => Ok(body),
            Ok(Cached::Listing(_)) => unreachable!("get slots hold bodies"),
            Err(error) => Err(CallFailure {
                operation: operation.to_owned(),
                error,
            }),
        }
    }

    /// A paged listing (memoised for this tenant run).
    pub async fn list(&self, operation: &str, input: Value) -> Result<Listing, CallFailure> {
        let slot = self.slot("list", operation, &input);
        let result = slot
            .get_or_init(|| async {
                self.gateway
                    .list(operation, input)
                    .await
                    .map(Cached::Listing)
            })
            .await
            .clone();
        match result {
            Ok(Cached::Listing(listing)) => Ok(listing),
            Ok(Cached::Body(_)) => unreachable!("list slots hold listings"),
            Err(error) => Err(CallFailure {
                operation: operation.to_owned(),
                error,
            }),
        }
    }

    /// Shorthand for `list` with `{"parameters": parameters}`. A listing cut
    /// short by the page limits is a failure (the check becomes `unknown`),
    /// never a silently partial answer.
    pub async fn list_with(
        &self,
        operation: &str,
        parameters: Value,
    ) -> Result<Vec<Value>, CallFailure> {
        let listing = self
            .list(operation, serde_json::json!({ "parameters": parameters }))
            .await?;
        if listing.truncated {
            return Err(CallFailure {
                operation: operation.to_owned(),
                error: GatewayError::Unavailable(format!(
                    "the listing returned more than {} items, so the result would be incomplete; narrow the scope or raise the limits",
                    listing.items.len()
                )),
            });
        }
        Ok(listing.items)
    }

    /// Run a Defender XDR advanced hunting query and return its rows. Uses the
    /// Defender XDR API and falls back to Microsoft Graph `runHuntingQuery` when
    /// the Defender API is not permitted.
    pub async fn hunt(&self, query: &str) -> Result<Vec<Value>, CallFailure> {
        let xdr = self
            .get(
                "defender.xdr.advancedhunting.run",
                serde_json::json!({ "body": { "Query": query } }),
            )
            .await;
        let body = match xdr {
            Ok(body) => body,
            Err(failure)
                if failure
                    .error
                    .call()
                    .is_some_and(|e| matches!(e.status, Some(401 | 403 | 404))) =>
            {
                self.get(
                    "graph.security.run_hunting_query",
                    serde_json::json!({ "body": { "Query": query } }),
                )
                .await?
            }
            Err(failure) => return Err(failure),
        };
        Ok(body
            .get("Results")
            .or_else(|| body.get("results"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }

    /// Run a KQL query against a Log Analytics workspace (by workspace id) and
    /// return rows as objects keyed by column name.
    pub async fn log_query(
        &self,
        workspace_id: &str,
        query: &str,
        timespan: Option<&str>,
    ) -> Result<Vec<Value>, CallFailure> {
        let mut body = serde_json::json!({ "query": query });
        if let Some(span) = timespan {
            body["timespan"] = Value::String(span.to_owned());
        }
        let response = self
            .get(
                "azure.log_analytics_query.query.execute",
                serde_json::json!({ "parameters": { "workspaceId": workspace_id }, "body": body }),
            )
            .await?;
        Ok(log_rows(&response))
    }
}

/// Convert a Log Analytics query response (`tables[0].columns/rows`) to objects.
pub fn log_rows(response: &Value) -> Vec<Value> {
    let Some(table) = response
        .get("tables")
        .and_then(Value::as_array)
        .and_then(|t| t.first())
    else {
        return vec![];
    };
    let columns: Vec<String> = table
        .get("columns")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|c| c.get("name").and_then(Value::as_str).map(str::to_owned))
        .collect();
    table
        .get("rows")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_array)
        .map(|row| Value::Object(columns.iter().cloned().zip(row.iter().cloned()).collect()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{FixtureGateway, TENANT};
    use serde_json::json;

    pub(crate) fn context(gateway: FixtureGateway) -> (CheckContext, Arc<FixtureGateway>) {
        let gateway = Arc::new(gateway);
        (
            CheckContext::new(ContextParts {
                tenant_id: TENANT.into(),
                label: None,
                gateway: gateway.clone(),
                licences: None,
                config: Arc::new(CheckConfig::default()),
                attestations: BTreeMap::new(),
                dns: Arc::new(crate::dns::NoDns),
                now: Instant(0),
            }),
            gateway,
        )
    }

    #[tokio::test]
    async fn repeated_calls_are_served_once() {
        let (ctx, gateway) = context(
            FixtureGateway::new(TENANT).with("graph.users.list", json!({"value": [{"id": "1"}]})),
        );
        let (a, b) = tokio::join!(
            ctx.list("graph.users.list", json!({})),
            ctx.list("graph.users.list", json!({}))
        );
        assert_eq!(a.unwrap(), b.unwrap());
        ctx.list("graph.users.list", json!({})).await.unwrap();
        assert_eq!(gateway.calls().len(), 1);
    }

    #[tokio::test]
    async fn truncated_listings_are_failures_not_partial_answers() {
        let gateway = FixtureGateway::new(TENANT);
        let mut entries = vec![];
        for page in 0..=200 {
            entries.push(json!({
                "url": format!("fixture:p{page}"),
                "responses": [{"body": {"value": [{"id": page}], "@odata.nextLink": format!("fixture:p{}", page + 1)}}]
            }));
        }
        entries.push(json!({"operation": "graph.users.list",
            "responses": [{"body": {"value": [{"id": "first"}], "@odata.nextLink": "fixture:p0"}}]}));
        for e in entries {
            gateway.push(serde_json::from_value(e).unwrap()).unwrap();
        }
        let (ctx, _) = context(gateway);
        let failure = ctx
            .list_with("graph.users.list", json!({}))
            .await
            .unwrap_err();
        assert!(
            matches!(failure.error, GatewayError::Unavailable(ref m) if m.contains("incomplete"))
        );
    }

    #[test]
    fn log_rows_zip_columns() {
        let rows = log_rows(
            &json!({"tables": [{"columns": [{"name": "a"}, {"name": "b"}], "rows": [[1, "x"], [2, "y"]]}]}),
        );
        assert_eq!(rows, [json!({"a": 1, "b": "x"}), json!({"a": 2, "b": "y"})]);
    }
}
