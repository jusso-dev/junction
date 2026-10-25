//! Optional push of results to a Log Analytics custom table (Logs Ingestion API).
//!
//! # The only write
//!
//! Checks never write to a tenant. Pushing results is the one write in
//! `junction check`, and it writes to the operator's own Log Analytics
//! workspace, never to tenant configuration. It is off unless the operator opts
//! in (`--push-sentinel`), and it goes through Junction's policy and approval
//! model (`docs/APPROVALS.md`):
//!
//! - the push runs through [`junction_runtime::Executor`] with a registry that
//!   holds only [`OPERATION`] ([`registry`]), so no policy can authorise any other
//!   write through this path;
//! - the operation is classified `write`, so the default read-only policy
//!   refuses it. It needs an operator policy in `safe-write` or `full` mode that
//!   does not deny it, or an explicit interactive approval, after which the CLI
//!   uses a safe-write policy that keeps the operator's deny rules
//!   ([`effective_policy`]);
//! - rows carry ids, statuses, scores, tags and a short summary only ([`rows`]),
//!   never raw evidence data or affected-resource lists.
//!
//! The only role the pushing identity needs is Monitoring Metrics Publisher on
//! the data collection rule, with a token for audience [`AUDIENCE`]. See
//! `examples/sentinel/README.md`.
use crate::gateway::{
    BoxFut, CallError, FailureKind, GatewayError, LiveTarget, TokenProvider,
    classify_preflight_error, classify_runtime_error,
};
use crate::model::{RunReport, TenantStatus};
use crate::tags::Tags;
use anyhow::{Context, Result, bail};
use junction_auth::{AccessToken, TokenRequest};
use junction_core::{JunctionOperation, RegistryManifest};
use junction_policy::{AgentMode, Decision, Policy};
use junction_registry::Registry;
use junction_runtime::{ExecutionContext, Executor, PreparedRequest};
use junction_watch::backoff::Backoff;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex;
use url::Url;

/// The single operation a push may perform.
pub const OPERATION: &str = "azure.monitor.logs_ingestion.upload";
pub const API_VERSION: &str = "2023-01-01";
/// Token audience for the Logs Ingestion API.
pub const AUDIENCE: &str = "https://monitor.azure.com";
/// Stream declared by `examples/sentinel/junction-check-table.bicep`.
pub const DEFAULT_STREAM: &str = "Custom-JunctionCheck_CL";
/// The API accepts 1 MB per call; keep a margin for encoding differences.
pub const MAX_BATCH_BYTES: usize = 900_000;
/// Longest evidence summary sent, in characters.
pub const SUMMARY_CHARS: usize = 1024;
/// `CheckId` of the row reporting a tenant that could not be assessed.
pub const TENANT_ROW: &str = "_tenant";

const DATA: &str = include_str!("../data/logs-ingestion.json");

/// The embedded, hand-checked manifest holding only [`OPERATION`].
pub fn manifest() -> RegistryManifest {
    serde_json::from_str(DATA).expect("embedded logs ingestion operation parses")
}

pub fn operation() -> JunctionOperation {
    manifest()
        .operations
        .into_iter()
        .find(|o| o.id == OPERATION)
        .expect("embedded logs ingestion operation")
}

/// A registry containing only [`OPERATION`].
pub fn registry() -> Result<Registry> {
    Registry::load(manifest()).context("loading logs ingestion operation")
}

/// Where results go: a data collection endpoint, rule and stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushTarget {
    /// Logs ingestion endpoint of the DCE (plain HTTPS origin).
    pub dce: Url,
    /// Immutable id of the DCR (`dcr-` and 32 hex digits).
    pub dcr_immutable_id: String,
    /// Stream declared in the DCR (`Custom-...`).
    pub stream: String,
}

impl PushTarget {
    /// Validate operator input. Errors never echo the supplied values.
    pub fn parse(dce: &str, dcr: &str, stream: &str) -> Result<Self> {
        let url = Url::parse(dce.trim()).map_err(|_| anyhow::anyhow!("--dce must be a URL"))?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            bail!(
                "--dce must be the plain HTTPS logs ingestion endpoint of the data collection endpoint, with no path, credentials or query"
            );
        }
        let dcr = dcr.trim().to_ascii_lowercase();
        let valid_dcr = dcr
            .strip_prefix("dcr-")
            .is_some_and(|hex| hex.len() == 32 && hex.bytes().all(|b| b.is_ascii_hexdigit()));
        if !valid_dcr {
            bail!("--dcr must be the rule's immutable id: dcr- followed by 32 hex digits");
        }
        let stream = stream.trim();
        let valid_stream = stream.len() <= 128
            && stream.strip_prefix("Custom-").is_some_and(|rest| {
                !rest.is_empty()
                    && rest
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
            });
        if !valid_stream {
            bail!(
                "--stream must be a custom stream name such as {DEFAULT_STREAM} (letters, digits, _ and -, at most 128 characters)"
            );
        }
        Ok(Self {
            dce: url,
            dcr_immutable_id: dcr,
            stream: stream.to_owned(),
        })
    }

    /// The execution endpoint: the operation's endpoint template bound to the DCE.
    pub fn endpoint(&self) -> Result<String> {
        let template = operation()
            .endpoint_template
            .context("logs ingestion operation has no endpoint template")?;
        template.resolve(&BTreeMap::from([(
            "endpoint".to_owned(),
            self.dce.as_str().trim_end_matches('/').to_owned(),
        )]))
    }
}

/// The policy's decision for [`OPERATION`], ignoring its tenant allow-list
/// (the executor still enforces that against the workspace tenant when sending).
pub fn policy_allows(policy: &Policy) -> bool {
    let mut policy = policy.clone();
    policy.allow.tenants.clear();
    policy.authorize_operation(&operation(), "workspace") == Decision::Allowed
}

/// The policy a push runs under, or why it may not run.
///
/// Pushing requires `opt_in` (the operator passed `--push-sentinel`) and either
/// an operator policy that allows [`OPERATION`] (safe-write or full mode, not
/// matched by `deny.operations`) or an explicit interactive approval. Approval
/// upgrades the mode to safe-write but keeps the operator's deny rules, tenant
/// allow-list and limits, so a deny rule can never be approved away.
pub fn effective_policy(opt_in: bool, policy: &Policy, approved: bool) -> Result<Policy> {
    if !opt_in {
        bail!("pushing results is off unless --push-sentinel is set");
    }
    if policy_allows(policy) {
        return Ok(policy.clone());
    }
    let upgraded = Policy {
        agent: junction_policy::Agent {
            mode: AgentMode::SafeWrite,
        },
        ..policy.clone()
    };
    if !policy_allows(&upgraded) {
        bail!(
            "the policy's deny.operations rules forbid {OPERATION}; remove the rule to push results"
        );
    }
    if approved {
        return Ok(upgraded);
    }
    bail!(
        "pushing results writes to your Log Analytics workspace, and the current policy is read-only. \
         Either use a policy with agent.mode = \"safe-write\" that does not deny {OPERATION}, \
         or approve the push interactively (see docs/APPROVALS.md)"
    )
}

/// Framework tags as compact strings in `--tag` syntax, for example
/// `e8:mfa:ml1`, `ism:ISM-1504`, `mitre:T1078`.
pub fn compact_tags(tags: &Tags) -> Vec<String> {
    let mut out = Vec::new();
    for tag in &tags.essential_eight {
        if tag.levels.is_empty() {
            out.push(format!("e8:{}", tag.strategy));
        }
        for level in &tag.levels {
            out.push(format!("e8:{}:ml{level}", tag.strategy));
        }
    }
    for (scheme, ids) in [
        ("ism", &tags.ism),
        ("cis", &tags.cis_m365),
        ("cisv8", &tags.cis_v8),
        ("nist", &tags.nist_csf),
        ("mitre", &tags.mitre),
    ] {
        out.extend(ids.iter().map(|id| format!("{scheme}:{id}")));
    }
    out
}

/// At most `max` characters, ending in an ellipsis when cut.
fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// One row per (tenant, check) with the `JunctionCheck_CL` columns, plus one
/// `_tenant` row with status `failed` and the error code as its summary for
/// each tenant that could not be assessed. The tenant id column is
/// `EntraTenantId` because Log Analytics reserves `TenantId`. Never raw
/// evidence data, affected lists or remediation text.
pub fn rows(report: &RunReport) -> Vec<Value> {
    let mut out = Vec::new();
    for tenant in &report.tenants {
        if tenant.status == TenantStatus::Failed {
            let code = tenant
                .error
                .as_ref()
                .map_or("tenant_failed", |e| e.code.as_str());
            out.push(json!({
                "TimeGenerated": report.finished_at,
                "RunId": report.run_id,
                "EntraTenantId": tenant.tenant_id,
                "TenantLabel": tenant.label,
                "CheckId": TENANT_ROW,
                "Pack": null,
                "Status": "failed",
                "Severity": null,
                "Score": tenant.score.score,
                "PackScore": null,
                "Tags": [],
                "Summary": truncate_chars(code, SUMMARY_CHARS),
                "Attested": false,
            }));
        }
        for result in &tenant.results {
            let pack_score = tenant
                .packs
                .iter()
                .find(|p| p.pack == result.pack)
                .and_then(|p| p.score.score);
            out.push(json!({
                "TimeGenerated": report.finished_at,
                "RunId": report.run_id,
                "EntraTenantId": tenant.tenant_id,
                "TenantLabel": tenant.label,
                "CheckId": result.id,
                "Pack": result.pack.as_str(),
                "Status": result.status.as_str(),
                "Severity": result.severity.as_str(),
                "Score": tenant.score.score,
                "PackScore": pack_score,
                "Tags": compact_tags(&result.tags),
                "Summary": truncate_chars(&result.evidence.summary, SUMMARY_CHARS),
                "Attested": result.attested.is_some(),
            }));
        }
    }
    out
}

fn json_len(value: &Value) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |b| b.len())
}

/// Shrink a row until it serialises within `budget` bytes: halve the summary,
/// then drop tags, then the tenant label. Ids, status and scores are kept, so a
/// row is never dropped; one that still does not fit is sent on its own.
fn shrink(mut row: Value, budget: usize) -> Value {
    while json_len(&row) > budget {
        let summary = row["Summary"].as_str().unwrap_or_default();
        let chars = summary.chars().count();
        if chars > 1 {
            row["Summary"] = Value::String(truncate_chars(summary, chars / 2));
        } else if row["Tags"].as_array().is_some_and(|t| !t.is_empty()) {
            row["Tags"].as_array_mut().expect("array").pop();
        } else if !row["TenantLabel"].is_null() {
            row["TenantLabel"] = Value::Null;
        } else {
            break;
        }
    }
    row
}

/// Split rows into request bodies whose serialised JSON array stays within
/// `max_bytes` (use [`MAX_BATCH_BYTES`]). Order is preserved and no row is
/// dropped; an oversized row is truncated first.
pub fn batches(rows: Vec<Value>, max_bytes: usize) -> Vec<Vec<Value>> {
    let mut out = Vec::new();
    let mut current: Vec<Value> = Vec::new();
    let mut size = 2; // "[]"
    for mut row in rows {
        let mut len = json_len(&row);
        if len.saturating_add(2) > max_bytes {
            row = shrink(row, max_bytes.saturating_sub(2));
            len = json_len(&row);
        }
        if !current.is_empty() && size + 1 + len > max_bytes {
            out.push(std::mem::take(&mut current));
            size = 2;
        }
        size += len + usize::from(!current.is_empty());
        current.push(row);
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// The operation input envelope for one batch.
pub fn input(target: &PushTarget, rows: Vec<Value>) -> Value {
    json!({
        "parameters": {
            "ruleId": target.dcr_immutable_id,
            "stream": target.stream,
            "api-version": API_VERSION,
        },
        "body": rows,
    })
}

/// Plan one batch through the runtime and `policy` without credentials or
/// network. `tenant` is the workspace's tenant, checked against the policy.
pub fn prepare_request(
    target: &PushTarget,
    rows: Vec<Value>,
    tenant: &str,
    policy: &Policy,
) -> Result<PreparedRequest> {
    junction_runtime::prepare(
        &operation(),
        &input(target, rows),
        tenant,
        &target.endpoint()?,
        policy,
    )
}

/// Sends one batch input envelope. Tests script outcomes; the CLI uses
/// [`ExecutorSender`].
pub trait Sender: Send + Sync {
    fn send<'a>(&'a self, input: Value) -> BoxFut<'a, Result<(), CallError>>;
}

/// Sends through a single-operation [`Executor`] under the push policy. The
/// token for [`AUDIENCE`] is acquired on first send and reused while fresh.
pub struct ExecutorSender {
    executor: Executor,
    live: LiveTarget,
    tokens: Arc<dyn TokenProvider>,
    endpoint: String,
    token: Mutex<Option<Arc<AccessToken>>>,
}

impl ExecutorSender {
    /// `policy` is the result of [`effective_policy`]. `live` describes the
    /// workspace's tenant and credential; the executor checks the policy's
    /// tenant allow-list against it on every send.
    pub fn new(
        target: &PushTarget,
        live: LiveTarget,
        tokens: Arc<dyn TokenProvider>,
        policy: Policy,
    ) -> Result<Self> {
        if !policy_allows(&policy) {
            bail!("the push policy does not allow {OPERATION}");
        }
        live.endpoints.validate()?;
        Ok(Self {
            executor: Executor::new(registry()?, policy)?,
            live,
            tokens,
            endpoint: target.endpoint()?,
            token: Mutex::new(None),
        })
    }

    async fn token(&self) -> Result<Arc<AccessToken>, CallError> {
        let mut cached = self.token.lock().await;
        if let Some(token) = cached.as_ref()
            && token.metadata().expires_at > SystemTime::now() + Duration::from_secs(300)
        {
            return Ok(token.clone());
        }
        let request = TokenRequest {
            tenant: self.live.tenant_id.clone(),
            authority: self.live.endpoints.authority.clone(),
            audience: AUDIENCE.to_owned(),
            scopes: vec![],
            credential_profile: self.live.credential_profile.clone(),
            flow: self.live.flow,
            api_key: None,
        };
        let token = Arc::new(self.tokens.token(request).await?);
        *cached = Some(token.clone());
        Ok(token)
    }
}

impl Sender for ExecutorSender {
    fn send<'a>(&'a self, input: Value) -> BoxFut<'a, Result<(), CallError>> {
        Box::pin(async move {
            let failure = |error: GatewayError| match error {
                GatewayError::Call(e) => e,
                other => CallError::other(FailureKind::Malformed, &other.to_string()),
            };
            // Policy and input are checked before any credential is requested.
            self.executor
                .preflight(
                    OPERATION,
                    &input,
                    &self.live.tenant_id,
                    &self.endpoint,
                    None,
                    false,
                )
                .map_err(|e| failure(classify_preflight_error(e)))?;
            let token = self.token().await?;
            let context = ExecutionContext {
                tenant: &self.live.tenant_id,
                audience: AUDIENCE,
                endpoint: &self.endpoint,
                token: &token,
            };
            self.executor
                .execute(OPERATION, input, context, None, false)
                .await
                .map(|_| ())
                .map_err(|e| failure(classify_runtime_error(e)))
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushSummary {
    pub rows: usize,
    pub batches: usize,
    pub run_id: String,
}

fn explain(error: &CallError, batch: usize, total: usize) -> anyhow::Error {
    let what = match (error.kind, error.status) {
        (FailureKind::Http, Some(403)) => {
            "forbidden: grant Monitoring Metrics Publisher on the DCR to the pushing identity (it can take up to 30 minutes to apply)".to_owned()
        }
        (FailureKind::Http, Some(401)) => {
            format!("unauthorised: the token must be issued for audience {AUDIENCE}")
        }
        (FailureKind::Http, Some(404)) => {
            "not found: check --dcr (immutable id), --stream and that --dce is the DCR's endpoint".to_owned()
        }
        (FailureKind::Http, Some(400)) => format!(
            "rejected ({}): check the DCR stream declares the JunctionCheck_CL columns",
            error.summary()
        ),
        (FailureKind::Http, Some(429)) if error.retry_after.is_some() => format!(
            "throttled; Log Analytics asked to wait {} seconds",
            error.retry_after.unwrap_or_default().as_secs()
        ),
        (FailureKind::Http, Some(500..=599)) => {
            format!("{} persisted after retries", error.summary())
        }
        (FailureKind::Http, _) => error.summary(),
        _ => error.message.clone().unwrap_or_else(|| error.summary()),
    };
    let sent = if batch > 0 {
        format!("; batches 1 to {batch} were already ingested")
    } else {
        String::new()
    };
    anyhow::anyhow!(
        "pushing results to Log Analytics failed on batch {} of {total}: {what}{sent}",
        batch + 1
    )
}

/// Send every row of `report` in batches within the API limit. Throttling
/// (429) and server errors are retried honouring `Retry-After`; any other
/// failure stops the push with an explanation.
pub async fn push(
    target: &PushTarget,
    report: &RunReport,
    sender: &dyn Sender,
    backoff: Backoff,
) -> Result<PushSummary> {
    let rows = rows(report);
    let count = rows.len();
    let batches = batches(rows, MAX_BATCH_BYTES);
    let total = batches.len();
    for (index, batch) in batches.into_iter().enumerate() {
        let input = input(target, batch);
        backoff
            .run(|| sender.send(input.clone()))
            .await
            .map_err(|e| explain(&e, index, total))?;
    }
    Ok(PushSummary {
        rows: count,
        batches: total,
        run_id: report.run_id.clone(),
    })
}
