//! Office 365 Management Activity API collector.
//!
//! Timing model (Microsoft docs): listings filter on `contentCreated`, the time a
//! blob became available, not the event time. Blobs stay fetchable for 7 days and
//! may arrive hours after the events they contain. So the collector:
//! - keeps a per-content-type watermark on `contentCreated`,
//! - re-lists an overlap before the watermark to catch late listings,
//! - dedupes on blob ID and on record ID,
//! - only advances the watermark after a whole window is stored,
//! - records a gap when the laptop was offline longer than the 7-day window.
//!
//! The 7-day API window is unrelated to Purview's 180-day searchable retention:
//! anything this collector misses is still searchable in Purview, but not here.
use crate::{
    backoff::Backoff,
    capability::{Reason, classify},
    catalog,
    clock::Instant,
    event::from_management_record,
    probe::feed_url,
    store::{CapabilityRecord, InsertCounts, RunSummary, Store},
    upstream::{Api, CallError, FailureKind, Upstream},
};
use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use std::{collections::HashSet, time::Duration};
use url::Url;

/// Microsoft accepts start times up to 7 days back; keep a margin for clock skew.
pub const CONTENT_WINDOW: Duration = Duration::from_secs(7 * 86_400 - 15 * 60);
/// Listing windows must not exceed 24 hours.
pub const MAX_LIST_WINDOW: Duration = Duration::from_secs(24 * 3600 - 60);
const MAX_PAGES_PER_WINDOW: usize = 500;

#[derive(Debug, Clone)]
pub struct CollectOptions {
    pub overlap: Duration,
    pub backoff: Backoff,
    pub max_blobs_per_run: usize,
}

impl Default for CollectOptions {
    fn default() -> Self {
        Self {
            overlap: Duration::from_secs(3600),
            backoff: Backoff::default(),
            max_blobs_per_run: 5_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Ok,
    /// Collected, but some content was rejected or quarantined (see gaps).
    OkWithWarnings,
    /// Stopped at the per-run blob budget; the next run continues.
    Partial,
    Failed,
    /// Source known to be unavailable (permission, licence, not enabled).
    Skipped,
}

impl RunStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::OkWithWarnings => "ok_with_warnings",
            Self::Partial => "partial",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CollectOutcome {
    pub content_type: String,
    pub status: RunStatus,
    pub blobs: u64,
    pub events_new: u64,
    pub events_duplicate: u64,
    /// Records that could not be normalised or named another organisation.
    pub unparseable_records: u64,
    /// Listing entries refused (bad URI, wrong tenant path, missing fields).
    pub rejected_entries: u64,
    /// Blobs skipped after Microsoft refused them or repeated failures.
    pub quarantined_blobs: u64,
    pub max_delay_seconds: Option<i64>,
    pub error: Option<String>,
}

struct ContentItem {
    id: String,
    uri: Url,
    created: String,
    expiration: Option<String>,
}

pub async fn collect(
    up: &impl Upstream,
    store: &Store,
    content_type: &str,
    now: Instant,
    options: &CollectOptions,
) -> Result<CollectOutcome> {
    let source = format!("o365:{content_type}");
    let mut outcome = CollectOutcome {
        content_type: content_type.to_owned(),
        status: RunStatus::Ok,
        blobs: 0,
        events_new: 0,
        events_duplicate: 0,
        unparseable_records: 0,
        rejected_entries: 0,
        quarantined_blobs: 0,
        max_delay_seconds: None,
        error: None,
    };
    if let Some(cap) = store.capability(&source)?
        && cap.state.is_settled_negative()
    {
        // Known unavailable: do not poll. An operator re-test (or the daily
        // re-probe) clears this.
        outcome.status = RunStatus::Skipped;
        outcome.error = Some(format!("{} ({})", cap.state.as_str(), cap.reason.as_str()));
        return Ok(outcome);
    }

    let run = store.start_run(&source)?;
    let mut window = None;
    let mut counts = InsertCounts::default();
    let result = collect_windows(
        up,
        store,
        content_type,
        now,
        options,
        &mut outcome,
        &mut counts,
        &mut window,
    )
    .await;
    outcome.events_new = counts.new;
    outcome.events_duplicate = counts.duplicate;
    if let Err(e) = &result {
        outcome.status = RunStatus::Failed;
        outcome.error = Some(format!("local store error: {e:#}"));
    }
    if outcome.status == RunStatus::Ok
        && (outcome.rejected_entries > 0
            || outcome.unparseable_records > 0
            || outcome.quarantined_blobs > 0)
    {
        outcome.status = RunStatus::OkWithWarnings;
    }
    // The run row is closed on every path, including store errors above.
    store.finish_run(
        run,
        &RunSummary {
            status: outcome.status.as_str(),
            window,
            content_blobs: outcome.blobs,
            counts,
            max_delay_seconds: outcome.max_delay_seconds,
            rejected_entries: outcome.rejected_entries,
            unparseable_records: outcome.unparseable_records,
            quarantined_blobs: outcome.quarantined_blobs,
            error: outcome.error.as_deref(),
        },
    )?;
    result.map(|()| outcome)
}

/// Collect every configured feed. Feeds are isolated: one feed's failure (even a
/// local store error) is reported and the rest still run. The feed that has gone
/// longest without a successful run goes first, so a feed starved by the request
/// budget in one run is served first in the next.
pub async fn collect_all(
    up: &impl Upstream,
    store: &Store,
    content_types: &[String],
    options: &CollectOptions,
) -> Vec<CollectOutcome> {
    let mut order: Vec<(Option<String>, &String)> = content_types
        .iter()
        .map(|ct| {
            let last = store
                .last_success(&format!("o365:{ct}"))
                .ok()
                .flatten()
                .and_then(|r| r.finished_at);
            (last, ct)
        })
        .collect();
    // None (never succeeded) sorts first.
    order.sort();
    let mut outcomes = Vec::with_capacity(order.len());
    for (_, ct) in order {
        let outcome = match collect(up, store, ct, Instant::now(), options).await {
            Ok(outcome) => outcome,
            Err(e) => CollectOutcome {
                content_type: ct.clone(),
                status: RunStatus::Failed,
                blobs: 0,
                events_new: 0,
                events_duplicate: 0,
                unparseable_records: 0,
                rejected_entries: 0,
                quarantined_blobs: 0,
                max_delay_seconds: None,
                error: Some(format!("local store error: {e:#}")),
            },
        };
        outcomes.push(outcome);
    }
    let _ = store.prune_processed_content(Instant::now());
    outcomes
}

/// Microsoft refused this one blob for a reason that will not change on retry.
/// Authentication and permission failures are deliberately excluded: they are
/// about the app, not the blob, and must never cause content to be skipped.
fn is_poison(e: &CallError) -> bool {
    match e.kind {
        FailureKind::Malformed => true,
        FailureKind::Http => {
            matches!(e.code.as_deref(), Some("AF20050" | "AF20051" | "AF20052"))
                || (matches!(e.status, Some(400 | 404 | 410))
                    && e.code.as_deref() != Some("AF10001"))
        }
        _ => false,
    }
}

fn is_throttle(e: &CallError) -> bool {
    matches!(e.kind, FailureKind::LocalThrottle)
        || (matches!(e.kind, FailureKind::Http)
            && (e.status == Some(429) || e.code.as_deref() == Some("AF429")))
}

const BLOB_RETRY_RUNS: u32 = 3;

#[allow(clippy::too_many_arguments)]
async fn collect_windows(
    up: &impl Upstream,
    store: &Store,
    content_type: &str,
    now: Instant,
    options: &CollectOptions,
    outcome: &mut CollectOutcome,
    counts: &mut InsertCounts,
    window: &mut Option<(Instant, Instant)>,
) -> Result<()> {
    let source = format!("o365:{content_type}");
    let earliest = now.minus(CONTENT_WINDOW);
    let mut watermark = store.checkpoint(&source)?;
    if let Some(mark) = watermark
        && mark < earliest
    {
        store.record_gap(
            &source,
            mark,
            earliest,
            "collector was offline longer than the 7-day API content window; these events remain searchable in Purview but were not collected",
        )?;
        // Nothing older is fetchable; move on so the gap is recorded once.
        store.advance_checkpoint(&source, earliest)?;
        watermark = Some(earliest);
    }
    let start = match watermark {
        Some(mark) => mark.minus(options.overlap).max(earliest),
        None => earliest,
    };

    let mut window_start = start;
    let mut failure: Option<CallError> = None;
    let mut listing_failed = false;
    'windows: while now.since(window_start) > Duration::from_secs(60) {
        let window_end = window_start.plus(MAX_LIST_WINDOW).min(now);
        let (items, rejected) =
            match list_window(up, content_type, window_start, window_end, &options.backoff).await {
                Ok(listing) => listing,
                Err(e) => {
                    failure = Some(e);
                    listing_failed = true;
                    break;
                }
            };
        outcome.rejected_entries += rejected;
        for item in items {
            if store.content_processed(&item.id)? {
                continue;
            }
            if outcome.blobs as usize >= options.max_blobs_per_run {
                outcome.status = RunStatus::Partial;
                break 'windows;
            }
            match fetch_blob(up, &item.uri, &options.backoff).await {
                Ok(records) => {
                    let ingested = Instant::now();
                    let mut events = Vec::with_capacity(records.len());
                    for raw in &records {
                        // Records naming another organisation are never stored.
                        let foreign = raw
                            .get("OrganizationId")
                            .and_then(Value::as_str)
                            .is_some_and(|org| !org.eq_ignore_ascii_case(store.tenant_id()));
                        let event = if foreign {
                            None
                        } else {
                            from_management_record(store.tenant_id(), content_type, raw, ingested)
                        };
                        match event {
                            Some(e) => {
                                if let Ok(t) = Instant::parse(&e.timestamp) {
                                    let delay = ingested.since(t).as_secs() as i64;
                                    outcome.max_delay_seconds = Some(
                                        outcome.max_delay_seconds.map_or(delay, |d| d.max(delay)),
                                    );
                                }
                                events.push(e);
                            }
                            None => outcome.unparseable_records += 1,
                        }
                    }
                    let c = store.ingest_content(
                        &item.id,
                        content_type,
                        &item.created,
                        item.expiration.as_deref(),
                        &events,
                    )?;
                    store.delete_meta(&blob_failure_key(&item.id))?;
                    counts.new += c.new;
                    counts.duplicate += c.duplicate;
                    outcome.blobs += 1;
                }
                Err(e) if is_poison(&e) => {
                    quarantine(
                        store,
                        &source,
                        content_type,
                        &item,
                        &format!(
                            "audit content blob could not be used ({}); skipped",
                            e.summary()
                        ),
                    )?;
                    outcome.quarantined_blobs += 1;
                }
                // Throttling is about the app's request budget, not this blob: stop
                // and retry next run without counting a strike against it.
                Err(e) if is_throttle(&e) => {
                    failure = Some(e);
                    break 'windows;
                }
                Err(e) if e.is_transient() => {
                    let key = blob_failure_key(&item.id);
                    let failures = store
                        .meta(&key)?
                        .and_then(|v| v.parse::<u32>().ok())
                        .unwrap_or(0)
                        + 1;
                    if failures >= BLOB_RETRY_RUNS {
                        quarantine(
                            store,
                            &source,
                            content_type,
                            &item,
                            &format!(
                                "audit content blob failed in {failures} consecutive runs ({}); skipped",
                                e.summary()
                            ),
                        )?;
                        store.delete_meta(&key)?;
                        outcome.quarantined_blobs += 1;
                    } else {
                        store.put_meta(&key, &failures.to_string())?;
                        failure = Some(e);
                        break 'windows;
                    }
                }
                // Credential and permission failures stop the run without touching
                // the blob; the next listing re-tests access.
                Err(e) => {
                    failure = Some(e);
                    break 'windows;
                }
            }
        }
        store.advance_checkpoint(&source, window_end)?;
        window_start = window_end;
    }
    *window = Some((start, window_start));

    if outcome.rejected_entries > 0 || outcome.unparseable_records > 0 {
        store.record_gap(
            &source,
            start,
            window_start,
            &format!(
                "{} content listing entr(ies) and {} audit record(s) were rejected as invalid or foreign and not stored",
                outcome.rejected_entries, outcome.unparseable_records
            ),
        )?;
    }

    let spec = catalog::source(&source).expect("catalogued content type");
    match &failure {
        None => store.put_capability(&capability(spec, Reason::Ok, None))?,
        Some(e) => {
            outcome.status = RunStatus::Failed;
            outcome.error = Some(e.summary());
            let reason = classify(e, None);
            // Only listing failures say something about the feed as a whole; a
            // blob failure must never switch the feed off.
            if listing_failed && reason.state().is_settled_negative() {
                store.put_capability(&capability(spec, reason, Some(e)))?;
            }
        }
    }
    Ok(())
}

fn blob_failure_key(content_id: &str) -> String {
    format!("blob_failures:{content_id}")
}

fn quarantine(
    store: &Store,
    source: &str,
    content_type: &str,
    item: &ContentItem,
    reason: &str,
) -> Result<()> {
    let created = Instant::parse(&item.created)?;
    store.record_gap(source, created, created, reason)?;
    store.ingest_content(
        &item.id,
        content_type,
        &item.created,
        item.expiration.as_deref(),
        &[],
    )?;
    Ok(())
}

fn capability(
    spec: &catalog::SourceSpec,
    reason: Reason,
    error: Option<&CallError>,
) -> CapabilityRecord {
    CapabilityRecord {
        source: spec.id.to_owned(),
        state: reason.state(),
        reason,
        http_status: error.and_then(|e| e.status),
        error_code: error.and_then(|e| e.code.clone()),
        detail: error.and_then(|e| e.message.clone()),
        required_permission: spec.permission.to_owned(),
        licence_note: spec.licence_note.to_owned(),
        docs_url: spec.docs_url.to_owned(),
        checked_at: Instant::now().to_rfc3339(),
    }
}

async fn list_window(
    up: &impl Upstream,
    content_type: &str,
    start: Instant,
    end: Instant,
    backoff: &Backoff,
) -> Result<(Vec<ContentItem>, u64), CallError> {
    let first = feed_url(
        up,
        &["subscriptions", "content"],
        &[
            ("contentType", content_type),
            ("startTime", &start.to_api_seconds()),
            ("endTime", &end.to_api_seconds()),
        ],
    );
    let listing_path = first.path().to_owned();
    let mut next = Some(first);
    let mut items = vec![];
    let mut rejected = 0;
    let mut seen_pages = HashSet::new();
    let mut pages = 0;
    while let Some(url) = next.take() {
        pages += 1;
        if pages > MAX_PAGES_PER_WINDOW || !seen_pages.insert(url.to_string()) {
            return Err(CallError::other(
                FailureKind::Malformed,
                "content listing did not terminate",
            ));
        }
        let reply = backoff
            .run(|| up.get(Api::ManagementActivity, url.clone()))
            .await?;
        let entries = match &reply.body {
            Value::Array(entries) => entries.as_slice(),
            // An empty HTTP body; the transport maps it to null.
            Value::Null => &[],
            _ => {
                return Err(CallError::other(
                    FailureKind::Malformed,
                    "content listing was not a JSON array",
                ));
            }
        };
        for raw in entries {
            match content_item(up, raw) {
                Some(item) => items.push(item),
                None => rejected += 1,
            }
        }
        next = match reply.next_page {
            // Pages must stay on this tenant's content listing; anything else is
            // refused before the window is counted as collected.
            Some(url)
                if url.origin() != up.base(Api::ManagementActivity).origin()
                    || url.path() != listing_path =>
            {
                return Err(CallError::other(
                    FailureKind::Malformed,
                    "next page left the content listing endpoint",
                ));
            }
            Some(mut url) => {
                // Page links do not always repeat the publisher identifier; without it
                // later pages fall into the shared throttling pool.
                if !url.query_pairs().any(|(k, _)| k == "PublisherIdentifier") {
                    url.query_pairs_mut()
                        .append_pair("PublisherIdentifier", up.tenant_id());
                }
                Some(url)
            }
            None => None,
        };
    }
    Ok((items, rejected))
}

/// Accept only blob URIs on the feed's own origin and tenant path, so a crafted
/// listing can never send our token elsewhere.
fn content_item(up: &impl Upstream, raw: &Value) -> Option<ContentItem> {
    let id = raw.get("contentId")?.as_str()?;
    if id.is_empty() || id.len() > 512 || id.chars().any(char::is_control) {
        return None;
    }
    let mut uri = Url::parse(raw.get("contentUri")?.as_str()?).ok()?;
    let base = up.base(Api::ManagementActivity);
    let prefix = format!("/api/v1.0/{}/activity/feed/audit/", up.tenant_id());
    if uri.origin() != base.origin()
        || !uri
            .path()
            .to_ascii_lowercase()
            .starts_with(&prefix.to_ascii_lowercase())
        || uri.fragment().is_some()
        || !uri.username().is_empty()
    {
        return None;
    }
    if !uri.query_pairs().any(|(k, _)| k == "PublisherIdentifier") {
        uri.query_pairs_mut()
            .append_pair("PublisherIdentifier", up.tenant_id());
    }
    let created = raw
        .get("contentCreated")?
        .as_str()
        .and_then(|t| Instant::parse(t).ok())?;
    let expiration = raw
        .get("contentExpiration")
        .and_then(Value::as_str)
        .and_then(|t| Instant::parse(t).ok())
        .map(Instant::to_rfc3339);
    Some(ContentItem {
        id: id.to_owned(),
        uri,
        created: created.to_rfc3339(),
        expiration,
    })
}

async fn fetch_blob(
    up: &impl Upstream,
    uri: &Url,
    backoff: &Backoff,
) -> Result<Vec<Value>, CallError> {
    let reply = backoff
        .run(|| up.get(Api::ManagementActivity, uri.clone()))
        .await?;
    match reply.body {
        Value::Array(records) => Ok(records),
        _ => Err(CallError::other(
            FailureKind::Malformed,
            "content blob was not a JSON array",
        )),
    }
}
