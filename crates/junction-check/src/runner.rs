//! Run selected checks against one or many tenants.
//!
//! Tenants run in parallel (bounded), each with its own governed gateway (per-
//! host concurrency limit, `Retry-After`-aware backoff). A tenant whose
//! credential fails is reported with the reason and never stops the others; a
//! check whose API call fails becomes `unknown` or `not_applicable` with the
//! reason. Licences are read once per tenant and shared by every check.
use crate::check::{Check, Finding};
use crate::config::CheckConfig;
use crate::context::{CheckContext, ContextParts};
use crate::dns::Resolver;
use crate::gateway::{Gateway, Governed};
use crate::licensing::{self, LicensingData};
use crate::model::*;
use crate::outcome::{self, AWAITING_ANSWER};
use crate::registry::{CheckRegistry, Selection};
use crate::score;
use anyhow::Result;
use futures_util::{FutureExt, StreamExt};
use junction_watch::backoff::Backoff;
use junction_watch::clock::Instant;
use std::collections::BTreeMap;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

/// Live progress of a run, for background runs polled over MCP or HTTP.
#[derive(Debug, Default)]
pub struct Progress {
    pub total: std::sync::atomic::AtomicUsize,
    pub done: std::sync::atomic::AtomicUsize,
}

impl Progress {
    pub fn snapshot(&self) -> (usize, usize) {
        use std::sync::atomic::Ordering::SeqCst;
        (self.done.load(SeqCst), self.total.load(SeqCst))
    }
}

/// One tenant to assess.
pub struct TenantPlan {
    pub tenant_id: String,
    pub label: Option<String>,
    /// The gateway, or why one could not be built (bad context, no credential).
    pub gateway: Result<Arc<dyn Gateway>, Reason>,
    /// Stored attestations for this tenant; expired ones are ignored.
    pub attestations: BTreeMap<String, Attestation>,
}

#[derive(Clone)]
pub struct RunOptions {
    pub selection: Selection,
    /// Tenants assessed at once.
    pub parallel: usize,
    /// Concurrent requests per API host within one tenant.
    pub per_host: usize,
    /// Checks evaluated at once within one tenant.
    pub check_concurrency: usize,
    pub check_timeout: Duration,
    pub backoff: Backoff,
    pub config: Arc<CheckConfig>,
    pub dns: Arc<dyn Resolver>,
    /// Clock for timestamps and attestation expiry (fixed in tests).
    pub now: Instant,
    /// Fixed run id (tests); random when `None`.
    pub run_id: Option<String>,
    pub progress: Option<Arc<Progress>>,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            selection: Selection::default(),
            parallel: 4,
            per_host: 4,
            check_concurrency: 8,
            check_timeout: Duration::from_secs(300),
            backoff: Backoff::default(),
            config: Arc::new(CheckConfig::default()),
            dns: Arc::new(crate::dns::NoDns),
            now: Instant::now(),
            run_id: None,
            progress: None,
        }
    }
}

pub fn new_run_id() -> String {
    let mut bytes = [0u8; 8];
    let _ = getrandom::fill(&mut bytes);
    let stamp = Instant::now().to_rfc3339();
    format!(
        "{}-{}",
        stamp[..19].replace([':', '-'], "").replace('T', "t"),
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

/// Run `options.selection` against every plan. Fails only for an invalid
/// selection; every other problem is reported inside the result.
pub async fn run(
    registry: &CheckRegistry,
    plans: Vec<TenantPlan>,
    options: &RunOptions,
) -> Result<RunReport> {
    let checks = registry.select(&options.selection)?;
    if let Some(progress) = &options.progress {
        progress
            .total
            .fetch_add(checks.len() * plans.len(), std::sync::atomic::Ordering::SeqCst);
    }
    let started = std::time::Instant::now();
    let mut tenants: Vec<(usize, TenantReport)> =
        futures_util::stream::iter(plans.into_iter().enumerate())
            .map(|(index, plan)| {
                let checks = &checks;
                async move { (index, run_tenant(registry, checks, plan, options).await) }
            })
            .buffer_unordered(options.parallel.max(1))
            .collect()
            .await;
    tenants.sort_by_key(|(i, _)| *i);
    Ok(RunReport {
        schema_version: SCHEMA_VERSION.into(),
        run_id: options.run_id.clone().unwrap_or_else(new_run_id),
        tool: Tool {
            name: "junction".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        },
        started_at: options.now.to_rfc3339(),
        finished_at: options.now.plus(started.elapsed()).to_rfc3339(),
        selection: serde_json::to_value(&options.selection)?,
        tenants: tenants.into_iter().map(|(_, t)| t).collect(),
    })
}

fn failed(plan_id: String, label: Option<String>, reason: Reason) -> TenantReport {
    TenantReport {
        tenant_id: plan_id,
        label,
        status: TenantStatus::Failed,
        error: Some(reason),
        licences: None,
        score: score::score(&[]),
        packs: vec![],
        quick_wins: vec![],
        results: vec![],
        diff: None,
    }
}

async fn run_tenant(
    registry: &CheckRegistry,
    checks: &[Arc<dyn Check>],
    plan: TenantPlan,
    options: &RunOptions,
) -> TenantReport {
    let report = assess_tenant(registry, checks, plan, options).await;
    if report.status == TenantStatus::Failed
        && let Some(progress) = &options.progress
    {
        progress
            .done
            .fetch_add(checks.len(), std::sync::atomic::Ordering::SeqCst);
    }
    report
}

async fn assess_tenant(
    registry: &CheckRegistry,
    checks: &[Arc<dyn Check>],
    plan: TenantPlan,
    options: &RunOptions,
) -> TenantReport {
    let gateway = match plan.gateway {
        Ok(g) => g,
        Err(reason) => return failed(plan.tenant_id, plan.label, reason),
    };
    let governed: Arc<dyn Gateway> =
        Arc::new(Governed::new(gateway, options.per_host, options.backoff));
    // Licence pre-flight. A credential failure means nothing else can run.
    let licences = match governed
        .list("graph.subscribed_skus.list", serde_json::json!({}))
        .await
    {
        Ok(listing) => Some(licensing::snapshot(
            &serde_json::json!({ "value": listing.items }),
        )),
        Err(error) if error.is_credential() => {
            return failed(
                plan.tenant_id,
                plan.label,
                Reason::new(
                    "credential_rejected",
                    format!("Could not sign in to the tenant: {error}. No checks ran."),
                ),
            );
        }
        // Without licence data every check is attempted and reports its own outcome.
        Err(_) => None,
    };
    let attestations = plan
        .attestations
        .into_iter()
        .filter(|(_, a)| Instant::parse(&a.expires_at).is_ok_and(|e| e > options.now))
        .collect();
    let ctx = CheckContext::new(ContextParts {
        tenant_id: plan.tenant_id.clone(),
        label: plan.label.clone(),
        gateway: governed,
        licences: licences.clone(),
        config: options.config.clone(),
        attestations,
        dns: options.dns.clone(),
        now: options.now,
    });
    let mut results: Vec<CheckResult> = futures_util::stream::iter(checks.iter())
        .map(|check| async {
            let result = evaluate(registry, check.as_ref(), &ctx, options.check_timeout).await;
            if let Some(progress) = &options.progress {
                progress.done.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            result
        })
        .buffer_unordered(options.check_concurrency.max(1))
        .collect()
        .await;
    score::quick_win_order(&mut results);
    let could_not_run = results.iter().any(|r| {
        r.status == Status::Unknown
            && r.reason
                .as_ref()
                .is_none_or(|reason| !AWAITING_ANSWER.contains(&reason.code.as_str()))
    });
    TenantReport {
        tenant_id: plan.tenant_id,
        label: plan.label,
        status: if could_not_run {
            TenantStatus::Partial
        } else {
            TenantStatus::Complete
        },
        error: None,
        licences,
        score: score::score(&results),
        packs: score::pack_scores(&results),
        quick_wins: score::quick_wins(&results),
        results,
        diff: None,
    }
}

/// Evaluate one check and build its result.
pub async fn evaluate(
    registry: &CheckRegistry,
    check: &dyn Check,
    ctx: &CheckContext,
    timeout: Duration,
) -> CheckResult {
    let meta = check.meta();
    let finding = if let Some(missing) = missing_licence(meta.requires.licences, ctx) {
        let title = LicensingData::embedded().title(missing).unwrap_or(missing);
        Finding::not_applicable(
            "licence_required",
            format!("The tenant has no {title} licence, which this check needs."),
        )
    } else if meta.kind == CheckKind::Manual {
        match ctx.attestation(meta.id) {
            Some(a) => Finding::from_attestation(a),
            None => Finding::unknown(
                "not_attested",
                format!(
                    "Needs a person's answer: {} Run `junction check attest {}`.",
                    meta.manual.map(|m| m.question).unwrap_or(meta.title),
                    meta.id
                ),
            ),
        }
    } else {
        let run = AssertUnwindSafe(check.evaluate(ctx)).catch_unwind();
        match tokio::time::timeout(timeout, run).await {
            Ok(Ok(Ok(finding))) => finding,
            Ok(Ok(Err(failure))) => {
                let (status, reason) = outcome::from_failure(meta, &failure);
                Finding {
                    reason: Some(reason.clone()),
                    ..Finding::new(status, reason.detail)
                }
            }
            Ok(Err(_panic)) => Finding::unknown(
                "check_error",
                "The check failed internally; please report it.",
            ),
            Err(_) => Finding::unknown(
                "timeout",
                format!(
                    "The check did not finish within {} seconds.",
                    timeout.as_secs()
                ),
            ),
        }
    };
    CheckResult {
        id: meta.id.into(),
        title: meta.title.into(),
        pack: meta.pack,
        kind: meta.kind,
        status: finding.status,
        severity: meta.severity,
        effort: meta.effort,
        impact: meta.impact,
        evidence: Evidence {
            summary: finding.summary,
            data: finding.data,
        },
        affected: Affected::from_items(finding.affected),
        remediation: Remediation {
            text: meta.remediation.into(),
            links: meta.links.iter().map(|l| (*l).to_owned()).collect(),
        },
        references: meta.references.iter().map(|l| (*l).to_owned()).collect(),
        tags: registry.tags(meta.id),
        reason: finding.reason,
        attested: finding.attested,
    }
}

fn missing_licence<'a>(features: &'a [&'a str], ctx: &CheckContext) -> Option<&'a str> {
    features
        .iter()
        .copied()
        .find(|f| ctx.has_feature(f) == Some(false))
}
