//! Human-approved revoke and restrict (`junction apps plan`, `junction apps apply`).
//!
//! # The only writes
//!
//! Inventory, flags, drift and export never write to a tenant. This module is
//! the one place `junction apps` can change Microsoft Graph, and it is built
//! so that nothing changes without an operator approving each item:
//!
//! - **Plans are files.** `junction apps plan` reads the current inventory and
//!   writes the exact operation and input for each suggested change to a local
//!   JSON file. Nothing is sent.
//! - **Apply is CLI-only.** `junction apps apply --plan FILE` exists only in the
//!   CLI. MCP and HTTP hosts have no apply tool or route (tested).
//! - **Fresh state.** Before anything is sent, apply re-reads the tenant and
//!   refuses every item whose target no longer matches the plan (stale plan).
//! - **Per-item terminal approval.** Each item is shown on the controlling
//!   terminal and needs the existing confirmation (`docs/APPROVALS.md`). A
//!   single-use grant bound to the exact operation, input, tenant, endpoint,
//!   audience, credential profile and policy is issued and consumed by
//!   `Executor::execute_with_approval`. There is no flag that skips it.
//! - **A minimal registry.** Writes run through a registry holding only
//!   [`OPERATIONS`] (`data/apps-write.json`), with reviewed overrides that
//!   raise both PATCH operations to `privileged`, so every item needs approval
//!   and no policy can authorise any other write through this path. The request
//!   schemas only allow narrowing a grant's `scope` and setting
//!   `accountEnabled` to `false`.
//! - **Operator policy still wins.** Apply runs under the operator's policy
//!   (deny rules, tenant allow-list, limits) upgraded to safe-write mode only
//!   for approval. A deny rule matching an operation can never be approved away.
use super::inventory::{App, Inventory};
use crate::gateway::{BoxFut, LiveTarget, TokenProvider};
use anyhow::{Context, Result, bail};
use junction_auth::TokenRequest;
use junction_core::{JunctionOperation, RegistryManifest};
use junction_policy::{AgentMode, Decision, Policy};
use junction_registry::Registry;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;

const DATA: &str = include_str!("../../data/apps-write.json");
const RISK_OVERRIDES: &str = include_str!("../../data/apps-write-risk-overrides.toml");

pub const PLAN_VERSION: u32 = 1;
/// A plan older than this is refused; re-plan from a fresh inventory.
pub const MAX_PLAN_AGE_HOURS: u64 = 24;

pub const REVOKE_DELEGATED: &str = "graph.oauth2permission_grants.delete";
pub const NARROW_DELEGATED: &str = "graph.oauth2permission_grants.update";
pub const REMOVE_APP_ROLE: &str = "graph.service_principals.app_role_assigned_to.delete";
pub const DISABLE: &str = "graph.service_principals.update";
/// Every operation apply may send.
pub const OPERATIONS: &[&str] = &[REVOKE_DELEGATED, NARROW_DELEGATED, REMOVE_APP_ROLE, DISABLE];

/// Least-privilege permission for each write (granted separately from the
/// read-only inventory app).
pub const WRITE_PERMISSIONS: &[(&str, &str)] = &[
    (REVOKE_DELEGATED, "DelegatedPermissionGrant.ReadWrite.All"),
    (NARROW_DELEGATED, "DelegatedPermissionGrant.ReadWrite.All"),
    (REMOVE_APP_ROLE, "AppRoleAssignment.ReadWrite.All"),
    (DISABLE, "Application.ReadWrite.All"),
];

pub fn manifest() -> RegistryManifest {
    serde_json::from_str(DATA).expect("embedded apps write registry parses")
}

/// The registry apply executes against: only [`OPERATIONS`], with overrides.
pub fn registry() -> Result<Registry> {
    Registry::load(manifest())
        .context("loading the apps write registry")?
        .with_risk_overrides(junction_registry::overrides::RiskOverrides::parse(
            RISK_OVERRIDES,
        )?)
        .context("applying apps write risk overrides")
}

pub fn operation(id: &str) -> Result<JunctionOperation> {
    Ok(registry()?.resolve(id, None, false)?.clone())
}

/// The kind of change an item makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    /// Delete delegated consent grants (admin and per-user).
    RevokeDelegated,
    /// Remove high-impact scopes from delegated grants, keeping the rest.
    NarrowDelegated,
    /// Remove application permissions (app role assignments).
    RemoveAppRole,
    /// Disable the service principal so the app can no longer sign in.
    Disable,
}

/// One change, exactly as it would be sent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Item {
    pub id: String,
    pub action: Action,
    pub service_principal_id: String,
    pub app: String,
    pub operation: String,
    pub input: Value,
    pub risk: String,
    /// The current state this item expects; apply refuses it if this changed.
    pub expects: Value,
    pub why: String,
    pub rollback: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub plan_version: u32,
    pub tenant_id: String,
    pub created_at: String,
    pub items: Vec<Item>,
}

impl Plan {
    pub fn parse(text: &str) -> Result<Self> {
        if text.len() > 4 * 1024 * 1024 {
            bail!("the plan is too large");
        }
        let plan: Self =
            serde_json::from_str(text).map_err(|_| anyhow::anyhow!("invalid plan file"))?;
        if plan.plan_version != PLAN_VERSION {
            bail!("unsupported plan version {}", plan.plan_version);
        }
        junction_watch::store::validate_tenant(&plan.tenant_id)?;
        if plan.items.is_empty() || plan.items.len() > 100 {
            bail!("a plan holds between 1 and 100 items");
        }
        let mut ids = BTreeSet::new();
        for item in &plan.items {
            if !ids.insert(&item.id) {
                bail!("duplicate plan item {}", item.id);
            }
            validate_item(item)?;
        }
        Ok(plan)
    }
}

fn is_guid_like(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

/// Structural checks on an item, independent of tenant state. The registry
/// schema check happens again when the approval grant is issued.
pub fn validate_item(item: &Item) -> Result<()> {
    let expected = match item.action {
        Action::RevokeDelegated => REVOKE_DELEGATED,
        Action::NarrowDelegated => NARROW_DELEGATED,
        Action::RemoveAppRole => REMOVE_APP_ROLE,
        Action::Disable => DISABLE,
    };
    if item.operation != expected {
        bail!(
            "item {}: action {:?} must use {expected}",
            item.id,
            item.action
        );
    }
    let p = &item.input["parameters"];
    let ok = match item.action {
        Action::RevokeDelegated => {
            p["oAuth2PermissionGrant-id"]
                .as_str()
                .is_some_and(is_guid_like)
                && item.input.get("body").is_none()
        }
        Action::NarrowDelegated => {
            p["oAuth2PermissionGrant-id"]
                .as_str()
                .is_some_and(is_guid_like)
                && item.input["body"].as_object().is_some_and(|b| {
                    b.len() == 1 && b["scope"].as_str().is_some_and(|s| !s.trim().is_empty())
                })
        }
        Action::RemoveAppRole => {
            p["servicePrincipal-id"].as_str().is_some_and(is_guid_like)
                && p["appRoleAssignment-id"].as_str().is_some_and(is_guid_like)
                && item.input.get("body").is_none()
        }
        Action::Disable => {
            p["servicePrincipal-id"].as_str() == Some(item.service_principal_id.as_str())
                && is_guid_like(&item.service_principal_id)
                && item.input["body"] == json!({"accountEnabled": false})
        }
    };
    if !ok {
        bail!(
            "item {}: input does not match the {:?} action (disable only allows {{\"accountEnabled\": false}})",
            item.id,
            item.action
        );
    }
    Ok(())
}

fn risk_label(operation: &str) -> String {
    registry()
        .ok()
        .and_then(|r| {
            r.resolve(operation, None, false)
                .ok()
                .and_then(|o| serde_json::to_value(&o.risk).ok())
        })
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".into())
}

fn high_impact(scope: &str) -> bool {
    super::flags::Tiers::embedded()
        .lookup(scope)
        .is_some_and(|(t, _)| matches!(t, super::flags::Tier::Critical | super::flags::Tier::High))
}

fn why(app: &App) -> String {
    if app.flags.is_empty() {
        "Requested by the operator (no flags on this app).".into()
    } else {
        format!(
            "Flags: {}.",
            app.flags
                .iter()
                .map(|f| f.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

/// Items for `action` on `app`, from the current inventory. Narrowing keeps
/// every scope that is not high or critical impact; a grant with nothing
/// high-impact is left alone.
pub fn items_for(app: &App, action: Action) -> Vec<Item> {
    let mut items = vec![];
    let label = &app.display_name;
    match action {
        Action::RevokeDelegated => {
            for g in &app.delegated_grants {
                items.push(Item {
                    id: String::new(),
                    action,
                    service_principal_id: app.service_principal_id.clone(),
                    app: label.clone(),
                    operation: REVOKE_DELEGATED.into(),
                    input: json!({"parameters": {"oAuth2PermissionGrant-id": g.grant_id}}),
                    risk: risk_label(REVOKE_DELEGATED),
                    expects: json!({"grant_id": g.grant_id, "client": app.service_principal_id,
                        "consent_type": g.consent_type, "scopes": g.scopes}),
                    why: why(app),
                    rollback: format!(
                        "Grant consent again ({} {} on {}) through the Entra admin centre or POST /oauth2PermissionGrants.",
                        g.consent_type,
                        g.scopes.join(" "),
                        g.resource_name
                    ),
                });
            }
        }
        Action::NarrowDelegated => {
            for g in &app.delegated_grants {
                let keep: Vec<&String> = g.scopes.iter().filter(|s| !high_impact(s)).collect();
                if keep.len() == g.scopes.len() {
                    continue; // nothing high-impact to remove
                }
                if keep.is_empty() {
                    continue; // narrowing to nothing is a revoke; plan that explicitly
                }
                let scope = keep
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(" ");
                items.push(Item {
                    id: String::new(),
                    action,
                    service_principal_id: app.service_principal_id.clone(),
                    app: label.clone(),
                    operation: NARROW_DELEGATED.into(),
                    input: json!({"parameters": {"oAuth2PermissionGrant-id": g.grant_id},
                        "body": {"scope": scope}}),
                    risk: risk_label(NARROW_DELEGATED),
                    expects: json!({"grant_id": g.grant_id, "client": app.service_principal_id,
                        "consent_type": g.consent_type, "scopes": g.scopes}),
                    why: format!(
                        "{} Removes {}.",
                        why(app),
                        g.scopes
                            .iter()
                            .filter(|s| high_impact(s))
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(" ")
                    ),
                    rollback: format!(
                        "PATCH the grant's scope back to \"{}\".",
                        g.scopes.join(" ")
                    ),
                });
            }
        }
        Action::RemoveAppRole => {
            for p in &app.application_permissions {
                items.push(Item {
                    id: String::new(),
                    action,
                    service_principal_id: app.service_principal_id.clone(),
                    app: label.clone(),
                    operation: REMOVE_APP_ROLE.into(),
                    input: json!({"parameters": {"servicePrincipal-id": p.resource_id,
                        "appRoleAssignment-id": p.assignment_id}}),
                    risk: risk_label(REMOVE_APP_ROLE),
                    expects: json!({"assignment_id": p.assignment_id, "client": app.service_principal_id,
                        "resource_id": p.resource_id, "app_role_id": p.app_role_id}),
                    why: format!("{} Removes {} ({}).", why(app), p.permission, p.resource_name),
                    rollback: format!(
                        "Grant {} on {} again (admin consent, or POST appRoleAssignedTo with appRoleId {}).",
                        p.permission, p.resource_name, p.app_role_id
                    ),
                });
            }
        }
        Action::Disable => {
            if app.enabled {
                items.push(Item {
                    id: String::new(),
                    action,
                    service_principal_id: app.service_principal_id.clone(),
                    app: label.clone(),
                    operation: DISABLE.into(),
                    input: json!({"parameters": {"servicePrincipal-id": app.service_principal_id},
                        "body": {"accountEnabled": false}}),
                    risk: risk_label(DISABLE),
                    expects: json!({"service_principal_id": app.service_principal_id, "enabled": true}),
                    why: why(app),
                    rollback: "Set accountEnabled back to true on the enterprise application.".into(),
                });
            }
        }
    }
    items
}

/// Build a plan for `apps` (service principal or app ids) and `actions`.
pub fn build(inventory: &Inventory, apps: &[String], actions: &[Action]) -> Result<Plan> {
    if apps.is_empty() || actions.is_empty() {
        bail!("name at least one --app and one --action");
    }
    let mut items = vec![];
    for id in apps {
        let app = inventory
            .app(id)
            .with_context(|| format!("no app {id} in the inventory"))?;
        if app.is_microsoft() {
            bail!(
                "{} is a Microsoft first-party application; Junction does not plan changes to it",
                app.display_name
            );
        }
        for action in actions {
            items.extend(items_for(app, *action));
        }
    }
    if items.is_empty() {
        bail!("nothing to change: the selected apps have nothing the selected actions apply to");
    }
    for (i, item) in items.iter_mut().enumerate() {
        item.id = format!("item-{}", i + 1);
    }
    let plan = Plan {
        plan_version: PLAN_VERSION,
        tenant_id: inventory.tenant_id.clone(),
        created_at: inventory.captured_at.clone(),
        items,
    };
    for item in &plan.items {
        validate_item(item)?;
    }
    Ok(plan)
}

/// What the item expects, recomputed from a fresh inventory (`None` when the
/// target no longer exists).
fn current_state(item: &Item, inventory: &Inventory) -> Option<Value> {
    let app = inventory.app(&item.service_principal_id)?;
    match item.action {
        Action::RevokeDelegated | Action::NarrowDelegated => {
            let grant_id = item.expects["grant_id"].as_str()?;
            let g = app
                .delegated_grants
                .iter()
                .find(|g| g.grant_id == grant_id)?;
            Some(
                json!({"grant_id": g.grant_id, "client": app.service_principal_id,
                "consent_type": g.consent_type, "scopes": g.scopes}),
            )
        }
        Action::RemoveAppRole => {
            let id = item.expects["assignment_id"].as_str()?;
            let p = app
                .application_permissions
                .iter()
                .find(|p| p.assignment_id == id)?;
            Some(
                json!({"assignment_id": p.assignment_id, "client": app.service_principal_id,
                "resource_id": p.resource_id, "app_role_id": p.app_role_id}),
            )
        }
        Action::Disable => Some(json!({"service_principal_id": app.service_principal_id,
            "enabled": app.enabled})),
    }
}

/// Why an item may not be applied now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Refusal {
    pub item: String,
    pub reason: String,
}

/// Check a plan against a fresh inventory. Returns the items still valid and
/// the refusals; nothing is sent.
pub fn check_fresh<'a>(
    plan: &'a Plan,
    inventory: &Inventory,
    now: junction_watch::clock::Instant,
) -> Result<(Vec<&'a Item>, Vec<Refusal>)> {
    if !plan.tenant_id.eq_ignore_ascii_case(&inventory.tenant_id) {
        bail!(
            "the plan is for tenant {}, not {}",
            plan.tenant_id,
            inventory.tenant_id
        );
    }
    let created = junction_watch::clock::Instant::parse(&plan.created_at)
        .context("the plan's created_at is not a timestamp")?;
    if now.since(created) > std::time::Duration::from_secs(MAX_PLAN_AGE_HOURS * 3600) {
        bail!("the plan is older than {MAX_PLAN_AGE_HOURS} hours; run `junction apps plan` again");
    }
    let mut valid = vec![];
    let mut refused = vec![];
    for item in &plan.items {
        match current_state(item, inventory) {
            Some(state) if state == item.expects => valid.push(item),
            Some(_) => refused.push(Refusal {
                item: item.id.clone(),
                reason: "the target changed since the plan was made (stale plan)".into(),
            }),
            None => refused.push(Refusal {
                item: item.id.clone(),
                reason: "the target no longer exists".into(),
            }),
        }
    }
    Ok((valid, refused))
}

/// The policy apply runs under: the operator's policy with its deny rules,
/// tenant allow-list and limits, upgraded to safe-write so privileged and
/// destructive items qualify for approval. Fails when a deny rule forbids an
/// operation the plan uses.
pub fn effective_policy(operator: &Policy, plan: &Plan) -> Result<Policy> {
    let policy = Policy {
        agent: junction_policy::Agent {
            mode: AgentMode::SafeWrite,
        },
        ..operator.clone()
    };
    let registry = registry()?;
    let used: BTreeSet<&str> = plan.items.iter().map(|i| i.operation.as_str()).collect();
    for id in used {
        let op = registry.resolve(id, None, false)?;
        match policy.authorize_operation(op, &plan.tenant_id) {
            Decision::ApprovalRequired { .. } => {}
            Decision::PolicyRejected { reason, .. } => {
                bail!("the policy forbids {id}: {reason}")
            }
            // The overrides make every apply operation approval-required; an
            // Allowed decision would mean a write could run unapproved.
            Decision::Allowed => bail!("{id} would run without approval; refusing"),
        }
    }
    Ok(policy)
}

/// Asks the operator to approve one item. The CLI implements this with the
/// controlling terminal; tests use a scripted approver.
pub trait Approver: Send + Sync {
    fn approve(
        &self,
        item: &Item,
        operation: &JunctionOperation,
        endpoint: &str,
        audience: &str,
    ) -> Result<()>;
}

/// Sends one approved request. The live implementation consumes a grant in
/// `Executor::execute_with_approval`; tests record what would be sent.
pub trait Sender: Send + Sync {
    fn send<'a>(&'a self, item: &'a Item) -> BoxFut<'a, Result<()>>;
}

/// Outcome of one item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Outcome {
    pub item: String,
    pub operation: String,
    pub app: String,
    /// `applied`, `declined`, `failed` or `refused`.
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Approve and send each still-valid item in order. A declined or failed item
/// stops the run, so the operator can review before anything else changes.
pub async fn run(
    valid: &[&Item],
    refused: &[Refusal],
    approver: &dyn Approver,
    sender: &dyn Sender,
    endpoint: &str,
    audience: &str,
) -> Result<Vec<Outcome>> {
    let registry = registry()?;
    let mut out: Vec<Outcome> = refused
        .iter()
        .map(|r| Outcome {
            item: r.item.clone(),
            operation: String::new(),
            app: String::new(),
            status: "refused".into(),
            reason: Some(r.reason.clone()),
        })
        .collect();
    for item in valid {
        let op = registry.resolve(&item.operation, None, false)?;
        let base = |status: &str, reason: Option<String>| Outcome {
            item: item.id.clone(),
            operation: item.operation.clone(),
            app: item.app.clone(),
            status: status.into(),
            reason,
        };
        if let Err(e) = approver.approve(item, op, endpoint, audience) {
            out.push(base("declined", Some(e.to_string())));
            break;
        }
        match sender.send(item).await {
            Ok(()) => out.push(base("applied", None)),
            Err(e) => {
                out.push(base("failed", Some(format!("{e:#}"))));
                break;
            }
        }
    }
    Ok(out)
}

/// Live sender: issues a single-use grant per item after approval and
/// consumes it in `Executor::execute_with_approval`.
pub struct ExecutorSender {
    executor: junction_runtime::Executor,
    live: LiveTarget,
    tokens: std::sync::Arc<dyn TokenProvider>,
    context: junction_policy::approval::ApprovalContext,
}

impl ExecutorSender {
    pub fn new(
        live: LiveTarget,
        tokens: std::sync::Arc<dyn TokenProvider>,
        policy: Policy,
        cloud: junction_core::cloud::MicrosoftCloud,
    ) -> Result<Self> {
        live.endpoints.validate()?;
        let (endpoint, audience) = graph_route(&live)?;
        let context = junction_policy::approval::ApprovalContext::new(
            cloud,
            &endpoint,
            &audience,
            &live.credential_profile,
        )?;
        Ok(Self {
            executor: junction_runtime::Executor::new(registry()?, policy)?,
            live,
            tokens,
            context,
        })
    }
    pub fn endpoint(&self) -> &str {
        self.context.endpoint()
    }
    pub fn audience(&self) -> &str {
        self.context.audience()
    }
}

/// Graph v1.0 endpoint and token audience for the target's cloud.
pub fn graph_route(live: &LiveTarget) -> Result<(String, String)> {
    let op = operation(DISABLE)?;
    let route = crate::catalog::route(&op, &live.endpoints)?;
    Ok((route.endpoint, route.audience))
}

impl Sender for ExecutorSender {
    fn send<'a>(&'a self, item: &'a Item) -> BoxFut<'a, Result<()>> {
        Box::pin(async move {
            if crate::gateway::NetworkGuard::from_env() == crate::gateway::NetworkGuard::Offline {
                bail!(
                    "live Microsoft calls are disabled ({} is set)",
                    crate::gateway::OFFLINE_ENV
                );
            }
            let options = || junction_runtime::ApprovalOptions {
                api_version: None,
                allow_preview: false,
                lifetime: std::time::Duration::from_secs(300),
            };
            // Issued only now, after the operator approved this exact item.
            let grant = self.executor.issue_approval(
                &item.operation,
                &item.input,
                &self.live.tenant_id,
                &self.context,
                options(),
            )?;
            let token = self
                .tokens
                .token(TokenRequest {
                    tenant: self.live.tenant_id.clone(),
                    authority: self.live.endpoints.authority.clone(),
                    audience: self.context.audience().to_owned(),
                    scopes: vec![],
                    credential_profile: self.live.credential_profile.clone(),
                    flow: self.live.flow,
                    api_key: None,
                })
                .await
                .map_err(|e| anyhow::anyhow!("token: {}", e.summary()))?;
            self.executor
                .execute_with_approval(
                    &item.operation,
                    item.input.clone(),
                    junction_runtime::ExecutionContext {
                        tenant: &self.live.tenant_id,
                        audience: self.context.audience(),
                        endpoint: self.context.endpoint(),
                        token: &token,
                    },
                    None,
                    false,
                    junction_runtime::ApprovedExecution {
                        context: &self.context,
                        grant,
                    },
                )
                .await
                .map(|_| ())
                .map_err(|e| {
                    let failure = crate::gateway::classify_runtime_error(e);
                    anyhow::anyhow!("{failure}")
                })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_registry_holds_only_the_apply_operations_and_all_need_approval() {
        let registry = registry().unwrap();
        let ids: BTreeSet<String> = registry.all().map(|o| o.id.clone()).collect();
        let wanted: BTreeSet<String> = OPERATIONS.iter().map(|s| (*s).to_owned()).collect();
        assert_eq!(ids, wanted);
        let policy = Policy {
            agent: junction_policy::Agent {
                mode: AgentMode::Full,
            },
            ..Policy::default()
        };
        for id in OPERATIONS {
            let op = registry.resolve(id, None, false).unwrap();
            assert!(
                matches!(
                    policy.authorize_operation(op, "tenant"),
                    Decision::ApprovalRequired { .. }
                ),
                "{id} must always need approval, even in full mode"
            );
            // Read-only mode refuses every one of them outright.
            assert!(matches!(
                Policy::default().authorize_operation(op, "tenant"),
                Decision::PolicyRejected { .. }
            ));
        }
        for (op, _) in WRITE_PERMISSIONS {
            assert!(OPERATIONS.contains(op));
        }
    }

    #[test]
    fn disable_only_accepts_account_enabled_false() {
        let mut item = Item {
            id: "item-1".into(),
            action: Action::Disable,
            service_principal_id: "sp1".into(),
            app: "x".into(),
            operation: DISABLE.into(),
            input: json!({"parameters": {"servicePrincipal-id": "sp1"}, "body": {"accountEnabled": false}}),
            risk: "privileged".into(),
            expects: json!({}),
            why: String::new(),
            rollback: String::new(),
        };
        validate_item(&item).unwrap();
        for body in [
            json!({"accountEnabled": true}),
            json!({"accountEnabled": false, "displayName": "x"}),
            json!({"appRoleAssignmentRequired": false}),
        ] {
            item.input["body"] = body.clone();
            assert!(validate_item(&item).is_err(), "{body}");
        }
        item.input = json!({"parameters": {"servicePrincipal-id": "other"}, "body": {"accountEnabled": false}});
        assert!(
            validate_item(&item).is_err(),
            "target must be the item's app"
        );
        item.operation = REVOKE_DELEGATED.into();
        assert!(validate_item(&item).is_err());
    }

    #[test]
    fn registry_schema_rejects_extra_properties_on_patch() {
        let executor = junction_runtime::Executor::new(
            registry().unwrap(),
            Policy {
                agent: junction_policy::Agent {
                    mode: AgentMode::SafeWrite,
                },
                ..Policy::default()
            },
        )
        .unwrap();
        let context = junction_policy::approval::ApprovalContext::new(
            junction_core::cloud::MicrosoftCloud::Public,
            "https://graph.microsoft.com/v1.0",
            "https://graph.microsoft.com",
            "test",
        )
        .unwrap();
        let options = || junction_runtime::ApprovalOptions {
            api_version: None,
            allow_preview: false,
            lifetime: std::time::Duration::from_secs(60),
        };
        let tenant = "00000000-0000-4000-8000-000000000001";
        let ok = json!({"parameters": {"servicePrincipal-id": "sp1"}, "body": {"accountEnabled": false}});
        assert!(
            executor
                .issue_approval(DISABLE, &ok, tenant, &context, options())
                .is_ok()
        );
        let widened = json!({"parameters": {"servicePrincipal-id": "sp1"},
            "body": {"accountEnabled": false, "appRoleAssignmentRequired": false}});
        assert!(
            executor
                .issue_approval(DISABLE, &widened, tenant, &context, options())
                .is_err()
        );
        let enable =
            json!({"parameters": {"servicePrincipal-id": "sp1"}, "body": {"accountEnabled": true}});
        assert!(
            executor
                .issue_approval(DISABLE, &enable, tenant, &context, options())
                .is_err()
        );
    }
}
