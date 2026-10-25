//! Workspace discovery shared by every `sentinel` check.
//!
//! Scope comes from `[packs.sentinel]` (`subscriptions`, or `workspaces` as ARM
//! resource ids), else every workspace Resource Graph can see. Sentinel is
//! detected per workspace from its onboarding states. Every call goes through
//! the context, so the checks of one run share the same requests.
use crate::check::{ApiRequirement, Finding};
use crate::context::{CallFailure, CheckContext};
use futures_util::future::join_all;
use serde_json::{Value, json};

pub const RESOURCE_GRAPH: ApiRequirement = ApiRequirement {
    operation: "azure.resource_graph.resources.post",
    permissions: &["Reader"],
};
pub const ONBOARDING: ApiRequirement = ApiRequirement {
    operation: "sentinel.securityinsights.sentinel_onboarding_states.list",
    permissions: &["Microsoft Sentinel Reader"],
};

const WORKSPACES_KQL: &str = include_str!("../../../queries/sentinel/workspaces.kql");
const SUBSCRIPTIONS_KQL: &str = include_str!("../../../queries/sentinel/subscriptions.kql");
/// Resource Graph pages to follow (1,000 rows each).
const MAX_PAGES: usize = 20;

#[derive(Debug, Clone, PartialEq)]
pub struct Workspace {
    /// ARM resource id.
    pub id: String,
    pub subscription_id: String,
    pub resource_group: String,
    pub name: String,
    /// Workspace GUID for Log Analytics queries (`properties.customerId`).
    pub customer_id: Option<String>,
    pub retention_days: Option<i64>,
}

impl Workspace {
    /// Path parameters for workspace-scoped ARM operations.
    pub fn params(&self) -> Value {
        json!({
            "subscriptionId": self.subscription_id,
            "resourceGroupName": self.resource_group,
            "workspaceName": self.name,
        })
    }
    fn from_row(row: &Value) -> Option<Self> {
        let text = |key: &str| row.get(key).and_then(Value::as_str).map(str::to_owned);
        let id = text("id")?;
        let (subscription, group, name) = parse_workspace_id(&id)?;
        Some(Self {
            subscription_id: text("subscriptionId").unwrap_or(subscription),
            resource_group: text("resourceGroup").unwrap_or(group),
            name: text("name").unwrap_or(name),
            customer_id: text("customerId").filter(|c| !c.is_empty()),
            retention_days: row.get("retentionInDays").and_then(Value::as_i64),
            id,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct Discovery {
    /// Log Analytics workspaces in scope.
    pub workspaces: Vec<Workspace>,
    /// Those with Microsoft Sentinel onboarded.
    pub sentinel: Vec<Workspace>,
    /// Configured workspace ids that are not workspace resource ids.
    pub invalid: Vec<String>,
    /// Configured workspace ids Resource Graph did not return.
    pub not_found: Vec<String>,
    /// Workspaces whose onboarding state could not be read.
    pub unreadable: Vec<String>,
}

/// `(subscriptionId, resourceGroupName, workspaceName)` from a workspace resource id.
pub fn parse_workspace_id(id: &str) -> Option<(String, String, String)> {
    let parts: Vec<&str> = id.split('/').filter(|p| !p.is_empty()).collect();
    match parts.as_slice() {
        [s, sub, rg, group, p, provider, w, name]
            if s.eq_ignore_ascii_case("subscriptions")
                && rg.eq_ignore_ascii_case("resourceGroups")
                && p.eq_ignore_ascii_case("providers")
                && provider.eq_ignore_ascii_case("Microsoft.OperationalInsights")
                && w.eq_ignore_ascii_case("workspaces") =>
        {
            Some(((*sub).into(), (*group).into(), (*name).into()))
        }
        _ => None,
    }
}

/// Run a Resource Graph query and follow `$skipToken` pages.
async fn resource_graph(
    ctx: &CheckContext,
    query: &str,
    subscriptions: &[String],
) -> Result<Vec<Value>, CallFailure> {
    let mut rows = vec![];
    let mut skip: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let mut body = json!({"query": query, "options": {"resultFormat": "objectArray"}});
        if !subscriptions.is_empty() {
            body["subscriptions"] = json!(subscriptions);
        }
        if let Some(token) = &skip {
            body["options"]["$skipToken"] = json!(token);
        }
        let page = ctx
            .get(RESOURCE_GRAPH.operation, json!({ "body": body }))
            .await?;
        rows.extend(
            page.get("data")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .cloned(),
        );
        match page.get("$skipToken").and_then(Value::as_str) {
            Some(token) if !token.is_empty() => skip = Some(token.to_owned()),
            _ => break,
        }
    }
    Ok(rows)
}

/// Workspaces in scope and which have Sentinel. A refused Resource Graph call
/// fails the whole discovery; refused onboarding reads fail it only when no
/// workspace could be confirmed.
pub async fn discover(ctx: &CheckContext) -> Result<Discovery, CallFailure> {
    let mut discovery = Discovery::default();
    let mut subscriptions: Vec<String> = ctx.pack_setting("sentinel", "subscriptions", vec![]);
    let configured: Vec<String> = ctx.pack_setting("sentinel", "workspaces", vec![]);
    let mut wanted = vec![];
    for id in configured {
        match parse_workspace_id(&id) {
            // Ids go into the query text, so only plain ARM id characters pass.
            Some((sub, _, _)) if !id.contains(['\'', '"', '\\']) => {
                if !subscriptions.contains(&sub) {
                    subscriptions.push(sub);
                }
                wanted.push(id.to_ascii_lowercase());
            }
            _ => discovery.invalid.push(id),
        }
    }
    let mut query = WORKSPACES_KQL.trim_end().to_owned();
    if !wanted.is_empty() {
        let list: Vec<String> = wanted.iter().map(|id| format!("'{id}'")).collect();
        query.push_str(&format!("\n| where tolower(id) in ({})", list.join(", ")));
    }
    if !discovery.invalid.is_empty() && wanted.is_empty() {
        return Ok(discovery);
    }
    let rows = resource_graph(ctx, &query, &subscriptions).await?;
    discovery.workspaces = rows.iter().filter_map(Workspace::from_row).collect();
    discovery.not_found = wanted
        .into_iter()
        .filter(|id| {
            !discovery
                .workspaces
                .iter()
                .any(|w| w.id.eq_ignore_ascii_case(id))
        })
        .collect();

    let states = join_all(
        discovery
            .workspaces
            .iter()
            .map(|w| ctx.list(ONBOARDING.operation, json!({ "parameters": w.params() }))),
    )
    .await;
    let mut refused = None;
    for (workspace, state) in discovery.workspaces.iter().zip(states) {
        match state {
            Ok(listing) if !listing.items.is_empty() => discovery.sentinel.push(workspace.clone()),
            Ok(_) => {}
            // No onboarding state resource: Sentinel is not on this workspace.
            Err(f) if f.error.call().is_some_and(|e| e.status == Some(404)) => {}
            Err(f) => {
                discovery.unreadable.push(workspace.name.clone());
                refused.get_or_insert(f);
            }
        }
    }
    match refused {
        Some(failure) if discovery.sentinel.is_empty() => Err(failure),
        _ => Ok(discovery),
    }
}

/// Number of subscriptions the identity can read (Resource Graph).
pub async fn readable_subscriptions(ctx: &CheckContext) -> Result<i64, CallFailure> {
    let subscriptions: Vec<String> = ctx.pack_setting("sentinel", "subscriptions", vec![]);
    let rows = resource_graph(ctx, SUBSCRIPTIONS_KQL, &subscriptions).await?;
    Ok(rows
        .first()
        .and_then(|r| r.get("subscriptions"))
        .and_then(Value::as_i64)
        .unwrap_or(0))
}

/// Unknown result for configured workspace ids that are not workspace resource ids.
pub fn invalid_config(invalid: &[String]) -> Finding {
    Finding::unknown(
        "invalid_config",
        format!(
            "[packs.sentinel] workspaces has {} value(s) that are not Log Analytics workspace resource ids (/subscriptions/<id>/resourceGroups/<group>/providers/Microsoft.OperationalInsights/workspaces/<name>): {}.",
            invalid.len(),
            invalid.join(", ")
        ),
    )
}

/// Sentinel workspaces in scope, or the finding to return when there are none:
/// `not_applicable` without Sentinel, `unknown` for invalid configuration.
pub async fn scope(ctx: &CheckContext) -> Result<Result<Vec<Workspace>, Finding>, CallFailure> {
    let discovery = discover(ctx).await?;
    if !discovery.invalid.is_empty() {
        return Ok(Err(invalid_config(&discovery.invalid)));
    }
    if discovery.sentinel.is_empty() {
        return Ok(Err(Finding::not_applicable(
            "no_sentinel_workspace",
            format!(
                "No workspace in scope has Microsoft Sentinel ({} Log Analytics workspace{} found).",
                discovery.workspaces.len(),
                if discovery.workspaces.len() == 1 {
                    ""
                } else {
                    "s"
                }
            ),
        )));
    }
    Ok(Ok(discovery.sentinel))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_ids_parse_case_insensitively() {
        let id = "/subscriptions/S/resourcegroups/RG/providers/microsoft.operationalinsights/workspaces/law-1";
        assert_eq!(
            parse_workspace_id(id),
            Some(("S".into(), "RG".into(), "law-1".into()))
        );
        assert!(parse_workspace_id("/subscriptions/S/resourceGroups/RG").is_none());
        assert!(
            parse_workspace_id(
                "/subscriptions/S/resourceGroups/RG/providers/Microsoft.Storage/storageAccounts/x"
            )
            .is_none()
        );
    }
}
