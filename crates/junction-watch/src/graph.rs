//! Bounded Graph audit collection. A window commits its checkpoint only after
//! every page succeeds; retrying a partial window deduplicates stored events.
use crate::{
    backoff::Backoff,
    clock::Instant,
    event::SecurityEvent,
    probe::graph_url,
    store::{InsertCounts, RunSummary, Store},
    upstream::{Api, CallError, FailureKind, Upstream},
};
use anyhow::{Result, bail};
use serde_json::{Value, json};
use std::{collections::HashSet, time::Duration};

pub const SOURCES: [&str; 2] = ["graph:directoryAudits", "graph:signIns"];

pub fn normalise(tenant: &str, source: &str, raw: &Value, now: Instant) -> Option<SecurityEvent> {
    use crate::event::{clean, event_id, normalise_ip, sanitise, sha256_hex};
    if !SOURCES.contains(&source) {
        return None;
    }
    if raw
        .get("tenantId")
        .and_then(Value::as_str)
        .is_some_and(|t| !t.eq_ignore_ascii_case(tenant))
    {
        return None;
    }
    let sign_in = source == SOURCES[1];
    let id = raw.get("id")?.as_str()?;
    if id.is_empty() || id.len() > 256 {
        return None;
    }
    let timestamp = Instant::parse(
        raw.get(if sign_in {
            "createdDateTime"
        } else {
            "activityDateTime"
        })?
        .as_str()?,
    )
    .ok()?;
    let text = |v: Option<&Value>| v.and_then(Value::as_str).map(|s| clean(s, 1024));
    let actor = raw.pointer("/initiatedBy/user");
    let target = raw
        .get("targetResources")
        .and_then(Value::as_array)
        .and_then(|a| a.first());
    let mut metadata = serde_json::Map::new();
    let fields: &[&str] = if sign_in {
        &[
            "status",
            "conditionalAccessStatus",
            "clientAppUsed",
            "appId",
            "riskLevelDuringSignIn",
            "riskLevelAggregated",
            "riskState",
        ]
    } else {
        &[
            "category",
            "targetResources",
            "additionalDetails",
            "loggedByService",
        ]
    };
    for key in fields {
        if let Some(value) = raw.get(*key) {
            metadata.insert((*key).into(), sanitise(value));
        }
    }
    Some(SecurityEvent {
        id: event_id(tenant, source, id),
        tenant_id: tenant.into(),
        source: source.into(),
        source_event_id: id.into(),
        event_type: if sign_in { "signIn" } else { "directoryAudit" }.into(),
        timestamp: timestamp.to_rfc3339(),
        ingested_at: now.to_rfc3339(),
        actor_id: text(if sign_in {
            raw.get("userId")
        } else {
            actor
                .and_then(|a| a.get("id"))
                .or_else(|| raw.pointer("/initiatedBy/app/servicePrincipalId"))
        }),
        actor_upn: text(if sign_in {
            raw.get("userPrincipalName")
        } else {
            actor.and_then(|a| a.get("userPrincipalName"))
        })
        .map(|s| s.to_lowercase()),
        target_id: text(if sign_in {
            raw.get("appId")
        } else {
            target.and_then(|a| a.get("id"))
        }),
        target_type: text(target.and_then(|a| a.get("type"))),
        operation: if sign_in {
            "SignIn".into()
        } else {
            text(raw.get("activityDisplayName"))?
        },
        result: if sign_in {
            raw.pointer("/status/errorCode")
                .and_then(Value::as_i64)
                .map(|n| if n == 0 { "success" } else { "failure" }.into())
        } else {
            text(raw.get("result"))
        },
        ip_address: raw
            .get("ipAddress")
            .or_else(|| actor.and_then(|a| a.get("ipAddress")))
            .and_then(Value::as_str)
            .and_then(normalise_ip),
        user_agent: None,
        correlation_id: text(raw.get("correlationId")),
        metadata,
        raw_sha256: sha256_hex(&serde_json::to_vec(raw).ok()?),
        raw_evidence_reference: None,
    })
}

pub async fn collect(
    up: &impl Upstream,
    store: &Store,
    source: &str,
    now: Instant,
    retry: Backoff,
) -> Result<Value> {
    if !SOURCES.contains(&source) || !up.tenant_id().eq_ignore_ascii_case(store.tenant_id()) {
        bail!("invalid Graph collector context");
    }
    // Sign-ins must never be tried before a positive capability probe.
    if !store.capability(source)?.is_some_and(|c| c.state.usable()) {
        return Ok(json!({"source":source,"status":"skipped","reason":"capability not available"}));
    }
    if store
        .meta(&format!("retry_after:{source}"))?
        .and_then(|v| Instant::parse(&v).ok())
        .is_some_and(|until| until > now)
    {
        return Ok(
            json!({"source":source,"status":"skipped","reason":"Server Retry-After interval still active"}),
        );
    }
    let retention = Duration::from_secs(7 * 86400); // conservative; never infer 30 days from a SKU name
    let floor = now.minus(retention);
    let checkpoint = store.checkpoint(source)?.unwrap_or(floor);
    if checkpoint < floor {
        store.record_gap(
            source,
            checkpoint,
            floor,
            "Graph retention boundary; older records may be unavailable",
        )?;
    }
    let start = checkpoint.minus(Duration::from_secs(6 * 3600)).max(floor);
    let end = start.plus(Duration::from_secs(86400)).min(now);
    let run = store.start_run(source)?;
    let mut counts = InsertCounts::default();
    let mut rejected = 0;
    let result = collect_window(
        up,
        store,
        source,
        start,
        end,
        now,
        retry,
        &mut counts,
        &mut rejected,
    )
    .await;
    let status = if result.is_err() {
        "failed"
    } else if rejected > 0 {
        "ok_with_warnings"
    } else {
        "ok"
    };
    if let Some(error) = result
        .as_ref()
        .err()
        .and_then(|e| e.downcast_ref::<CallError>())
    {
        if let Some(delay) = error.retry_after {
            store.put_meta(
                &format!("retry_after:{source}"),
                &now.plus(delay).to_rfc3339(),
            )?;
        }
        let reason = crate::capability::classify(error, None);
        if reason.state().is_settled_negative()
            && let Some(mut c) = store.capability(source)?
        {
            c.state = reason.state();
            c.reason = reason;
            c.http_status = error.status;
            c.error_code = error.code.clone();
            c.detail = Some(error.summary());
            c.checked_at = now.to_rfc3339();
            store.put_capability(&c)?;
        }
    }
    let error = result.as_ref().err().map(|e| e.to_string());
    store.finish_run(
        run,
        &RunSummary {
            status,
            window: Some((start, end)),
            content_blobs: 0,
            counts,
            max_delay_seconds: None,
            rejected_entries: 0,
            unparseable_records: rejected,
            quarantined_blobs: 0,
            error: error.as_deref(),
        },
    )?;
    Ok(
        json!({"source":source,"status":status,"rejected_records":rejected,"events_new":counts.new,"error":error}),
    )
}

#[allow(clippy::too_many_arguments)]
async fn collect_window(
    up: &impl Upstream,
    store: &Store,
    source: &str,
    start: Instant,
    end: Instant,
    now: Instant,
    retry: Backoff,
    counts: &mut InsertCounts,
    rejected: &mut u64,
) -> Result<()> {
    let (path, field) = if source == SOURCES[0] {
        ("/v1.0/auditLogs/directoryAudits", "activityDateTime")
    } else {
        ("/v1.0/auditLogs/signIns", "createdDateTime")
    };
    let filter = format!(
        "{field} ge {} and {field} lt {}",
        start.to_rfc3339(),
        end.to_rfc3339()
    );
    let mut url = graph_url(up, path, &[("$filter", &filter), ("$top", "500")]);
    let origin = url.origin();
    let mut visited = HashSet::new();
    for _ in 0..1000 {
        if !visited.insert(url.to_string()) {
            bail!("Graph pagination cycle");
        }
        let reply = retry.run(|| up.get(Api::Graph, url.clone())).await?;
        let records = reply
            .body
            .get("value")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                CallError::other(FailureKind::Malformed, "Graph value is not an array")
            })?;
        let mut events = Vec::new();
        let mut accepted_raw = Vec::new();
        for raw in records {
            match normalise(store.tenant_id(), source, raw, now) {
                Some(event) => {
                    events.push(event);
                    accepted_raw.push(raw);
                }
                None => {
                    *rejected += 1;
                    // No raw malformed or foreign-tenant payload enters the store.
                    // Record a visible gap and continue healthy records/pages.
                    store.record_gap(source,start,end,"Malformed or foreign-tenant Graph records rejected; see collector rejection count")?;
                }
            }
        }
        if events
            .iter()
            .any(|e| Instant::parse(&e.timestamp).is_ok_and(|t| t < start || t >= end))
        {
            bail!("Graph returned record outside requested window");
        }
        let added = store.insert_events(&events)?;
        if let Some(key) = crate::evidence::EvidenceKey::environment()? {
            for (event, raw) in events.iter().zip(accepted_raw) {
                store.retain_raw(&event.id, &serde_json::to_vec(raw)?, &key)?;
            }
        }
        counts.new += added.new;
        counts.duplicate += added.duplicate;
        let next = match reply.body.get("@odata.nextLink") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(
                url::Url::parse(s).map_err(|_| anyhow::anyhow!("invalid Graph continuation"))?,
            ),
            _ => bail!("invalid Graph continuation"),
        };
        match next {
            None => {
                store.advance_checkpoint(source, end)?;
                return Ok(());
            }
            Some(next)
                if next.origin() == origin
                    && next.path() == path
                    && next.username().is_empty()
                    && next.password().is_none()
                    && next.fragment().is_none() =>
            {
                url = next
            }
            _ => bail!("unsafe Graph continuation refused"),
        }
    }
    bail!("Graph page budget exhausted; checkpoint retained")
}
