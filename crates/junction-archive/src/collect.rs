//! Collect audit sources into the store.
//!
//! # Exactness
//!
//! Delivery into the archive is **at least once**, with duplicates removed
//! when reading (search and export deduplicate on the stable record id):
//!
//! - A window's objects and manifest are stored before its checkpoint moves.
//!   A crash in between replays the window on the next run. Nothing is skipped;
//!   the replay may store a second copy of some records.
//! - Management Activity content blobs are remembered by content id for eight
//!   days, so the overlap re-list never fetches an archived blob twice.
//!   Microsoft documents that the same record can appear in more than one
//!   blob; those copies are kept and deduplicated on read.
//! - Graph windows overlap the previous one (default two hours) to catch late
//!   records. Record ids seen inside the overlap are remembered (at most
//!   [`MAX_RECENT_IDS`]) so the overlap does not re-store them.
//!
//! Gaps are never hidden: content older than the API window, quarantined
//! blobs and rejected records are written to the window's manifest and shown
//! by `junction archive status`.
use crate::{
    checkpoint::{Checkpoint, SourceState},
    manifest::{Gap, Manifest, ObjectEntry},
    record::{self, ArchiveRecord},
    store::{ObjectStore, PutOutcome},
};
use anyhow::{Context, Result, bail};
use junction_watch::{
    activity::{
        CONTENT_WINDOW, ContentItem, MAX_LIST_WINDOW, fetch_blob, is_poison, is_throttle,
        list_window,
    },
    backoff::Backoff,
    capability::classify,
    clock::Instant,
    event::from_management_record,
    probe::graph_url,
    upstream::{Api, CallError, FailureKind, Upstream},
};
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

/// Records held in memory before they are written out as objects.
pub const FLUSH_RECORDS: usize = 20_000;
/// Graph record ids remembered from the overlap.
pub const MAX_RECENT_IDS: usize = 500_000;
/// Graph keeps sign-in and audit records for 7 days on Entra ID Free and 30 on
/// P1 or P2. The archive starts no further back than 7 days, conservatively.
pub const GRAPH_START_WINDOW: Duration = Duration::from_secs(7 * 86_400);
const GRAPH_WINDOW: Duration = Duration::from_secs(24 * 3600);
const GRAPH_MAX_PAGES: usize = 2_000;
const BLOB_RETRY_RUNS: u32 = 3;
/// Licence and permission problems are re-tested once a day.
const UNAVAILABLE_RETEST: Duration = Duration::from_secs(24 * 3600);

#[derive(Debug, Clone)]
pub struct CollectOptions {
    pub backoff: Backoff,
    /// Management Activity listing overlap before the watermark.
    pub mgmt_overlap: Duration,
    /// Graph window overlap before the watermark.
    pub graph_overlap: Duration,
    pub max_blobs_per_run: usize,
}

impl Default for CollectOptions {
    fn default() -> Self {
        Self {
            backoff: Backoff::default(),
            mgmt_overlap: Duration::from_secs(3600),
            graph_overlap: Duration::from_secs(2 * 3600),
            max_blobs_per_run: 5_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    OkWithWarnings,
    /// Stopped at a per-run budget; the next run continues.
    Partial,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize)]
pub struct Outcome {
    pub source: String,
    pub status: Status,
    pub records_stored: u64,
    pub objects_created: u64,
    pub objects_already_present: u64,
    pub duplicates_skipped: u64,
    pub rejected_records: u64,
    pub quarantined_blobs: u64,
    pub windows_completed: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watermark: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Outcome {
    fn new(source: &str) -> Self {
        Self {
            source: source.to_owned(),
            status: Status::Ok,
            records_stored: 0,
            objects_created: 0,
            objects_already_present: 0,
            duplicates_skipped: 0,
            rejected_records: 0,
            quarantined_blobs: 0,
            windows_completed: 0,
            watermark: None,
            detail: None,
        }
    }
    fn skipped(source: &str, detail: String) -> Self {
        let mut o = Self::new(source);
        o.status = Status::Skipped;
        o.detail = Some(detail);
        o
    }
}

/// How a Graph source is windowed and versioned.
#[derive(Debug, Clone, Copy)]
pub struct GraphSpec {
    pub source: &'static str,
    pub path: &'static str,
    /// Field filtered and windowed on.
    pub time_field: &'static str,
    pub page_size: &'static str,
}

pub const GRAPH_SOURCES: &[GraphSpec] = &[
    GraphSpec {
        source: "graph:directoryAudits",
        path: "/v1.0/auditLogs/directoryAudits",
        time_field: "activityDateTime",
        page_size: "500",
    },
    GraphSpec {
        source: "graph:signIns",
        path: "/v1.0/auditLogs/signIns",
        time_field: "createdDateTime",
        page_size: "1000",
    },
];

pub fn graph_spec(source: &str) -> Option<&'static GraphSpec> {
    GRAPH_SOURCES.iter().find(|s| s.source == source)
}

/// Normalise one Graph record into an archive record, or None to reject it.
fn graph_record(
    tenant: &str,
    spec: &GraphSpec,
    raw: &Value,
    now: Instant,
) -> Option<ArchiveRecord> {
    let event = junction_watch::graph::normalise(tenant, spec.source, raw, now)?;
    Some(ArchiveRecord::from_event(&event, raw, None))
}

/// Writes records out as objects plus one manifest per flush.
struct Writer<'a> {
    store: &'a dyn ObjectStore,
    tenant: &'a str,
    source: &'a str,
    run_id: &'a str,
    pending: Vec<ArchiveRecord>,
    gaps: Vec<Gap>,
}

impl<'a> Writer<'a> {
    /// Store pending records and a manifest for `[start, end)`. Returns the
    /// manifest hash; the caller then records it in the checkpoint.
    async fn flush(
        &mut self,
        state: &SourceState,
        start: Instant,
        end: Instant,
        complete: bool,
        outcome: &mut Outcome,
    ) -> Result<String> {
        let records = std::mem::take(&mut self.pending);
        let count = records.len();
        let objects = record::encode(self.tenant, records)?;
        let mut entries = Vec::with_capacity(objects.len());
        for object in objects {
            match self
                .store
                .put_new(&object.key, object.bytes, "application/gzip")
                .await
                .with_context(|| format!("storing {}", self.source))?
            {
                PutOutcome::Created => outcome.objects_created += 1,
                PutOutcome::AlreadyExists => outcome.objects_already_present += 1,
            }
            entries.push(ObjectEntry {
                key: object.key,
                content_sha256: object.content_sha256,
                records: object.records,
                first_event: object.first_event,
                last_event: object.last_event,
            });
        }
        outcome.records_stored += count as u64;
        let manifest = Manifest::new(
            self.tenant,
            self.source,
            self.run_id,
            start,
            end,
            complete,
            entries,
            std::mem::take(&mut self.gaps),
            state.last_manifest_sha256.clone(),
        );
        let (key, bytes, sha) = manifest.encode()?;
        self.store
            .put_new(&key, bytes, "application/json")
            .await
            .context("storing manifest")?;
        Ok(sha)
    }
}

/// Stop calling a source while a server `Retry-After` or a re-test delay runs.
fn paused(state: &SourceState, now: Instant) -> Option<String> {
    let until = state.retry_after()?;
    (until > now).then(|| match &state.unavailable {
        Some(reason) => format!("{reason}; re-tested after {}", until.to_rfc3339()),
        None => format!("Retry-After active until {}", until.to_rfc3339()),
    })
}

/// Record why a source failed, and when to try again.
fn note_failure(state: &mut SourceState, error: &CallError, now: Instant, outcome: &mut Outcome) {
    outcome.status = Status::Failed;
    outcome.detail = Some(error.summary());
    let reason = classify(error, None);
    if reason.state().is_settled_negative() {
        state.unavailable = Some(format!(
            "{} ({})",
            reason.state().as_str().to_ascii_lowercase(),
            reason.as_str()
        ));
        state.retry_after = Some(now.plus(UNAVAILABLE_RETEST).to_rfc3339());
    } else if let Some(delay) = error.retry_after {
        state.retry_after = Some(now.plus(delay).to_rfc3339());
    }
}

// ---------------------------------------------------------------------------
// Management Activity API

/// Archive one Management Activity content type (`Audit.Exchange` and so on).
pub async fn collect_management(
    up: &impl Upstream,
    store: &dyn ObjectStore,
    checkpoint: &mut Checkpoint,
    content_type: &str,
    run_id: &str,
    now: Instant,
    options: &CollectOptions,
) -> Result<Outcome> {
    let source = format!("o365:{content_type}");
    let tenant = checkpoint.state.tenant_id.clone();
    if let Some(why) = paused(checkpoint.source(&source), now) {
        return Ok(Outcome::skipped(&source, why));
    }
    let mut outcome = Outcome::new(&source);
    let mut writer = Writer {
        store,
        tenant: &tenant,
        source: &source,
        run_id,
        pending: vec![],
        gaps: vec![],
    };
    let earliest = now.minus(CONTENT_WINDOW);
    {
        let state = checkpoint.source(&source);
        state.prune(now);
        if let Some(mark) = state.watermark()
            && mark < earliest
        {
            writer.gaps.push(Gap::new(
                mark,
                earliest,
                "collector was offline longer than the 7-day Management Activity content window; these records remain in Purview for its retention period but are not in the archive",
            ));
        }
    }
    let start = match checkpoint.source(&source).watermark() {
        Some(mark) => mark.minus(options.mgmt_overlap).max(earliest),
        None => earliest,
    };
    let mut window_start = start;
    let mut blobs = 0usize;
    // Blob ids stored since the last commit; kept across a failed window so the
    // final commit remembers them and the next run does not refetch them.
    let mut archived_here: Vec<(String, String)> = Vec::new();
    'windows: while now.since(window_start) > Duration::from_secs(60) {
        let window_end = window_start.plus(MAX_LIST_WINDOW).min(now);
        let (items, rejected) =
            match list_window(up, content_type, window_start, window_end, &options.backoff).await {
                Ok(listing) => listing,
                Err(e) => {
                    note_failure(checkpoint.source(&source), &e, now, &mut outcome);
                    break;
                }
            };
        if rejected > 0 {
            outcome.rejected_records += rejected;
            writer.gaps.push(Gap::new(
                window_start,
                window_end,
                &format!("{rejected} content listing entr(ies) refused (unexpected link or missing fields)"),
            ));
        }
        for item in items {
            if checkpoint
                .source(&source)
                .archived_blobs
                .contains_key(&item.id)
            {
                continue;
            }
            if blobs >= options.max_blobs_per_run {
                outcome.status = Status::Partial;
                outcome.detail = Some("per-run blob budget reached; the next run continues".into());
                break 'windows;
            }
            match fetch_blob(up, &item.uri, &options.backoff).await {
                Ok(records) => {
                    blobs += 1;
                    let ingested = Instant::now();
                    for raw in &records {
                        let foreign = raw
                            .get("OrganizationId")
                            .and_then(Value::as_str)
                            .is_some_and(|org| !org.eq_ignore_ascii_case(&tenant));
                        let event = (!foreign)
                            .then(|| from_management_record(&tenant, content_type, raw, ingested))
                            .flatten();
                        match event {
                            Some(e) => writer
                                .pending
                                .push(ArchiveRecord::from_event(&e, raw, None)),
                            None => outcome.rejected_records += 1,
                        }
                    }
                    checkpoint.source(&source).blob_failures.remove(&item.id);
                    archived_here.push((item.id.clone(), item.created.clone()));
                }
                Err(e) if is_poison(&e) => {
                    quarantine(&mut writer, &item, &e.summary())?;
                    outcome.quarantined_blobs += 1;
                    archived_here.push((item.id.clone(), item.created.clone()));
                }
                Err(e) if is_throttle(&e) => {
                    note_failure(checkpoint.source(&source), &e, now, &mut outcome);
                    break 'windows;
                }
                Err(e) if e.is_transient() => {
                    let failures = {
                        let state = checkpoint.source(&source);
                        let n = state.blob_failures.entry(item.id.clone()).or_insert(0);
                        *n += 1;
                        *n
                    };
                    if failures >= BLOB_RETRY_RUNS {
                        quarantine(
                            &mut writer,
                            &item,
                            &format!("failed in {failures} consecutive runs ({})", e.summary()),
                        )?;
                        checkpoint.source(&source).blob_failures.remove(&item.id);
                        outcome.quarantined_blobs += 1;
                        archived_here.push((item.id.clone(), item.created.clone()));
                    } else {
                        note_failure(checkpoint.source(&source), &e, now, &mut outcome);
                        break 'windows;
                    }
                }
                Err(e) => {
                    note_failure(checkpoint.source(&source), &e, now, &mut outcome);
                    break 'windows;
                }
            }
            if writer.pending.len() >= FLUSH_RECORDS {
                commit(
                    &mut writer,
                    checkpoint,
                    &source,
                    window_start,
                    window_end,
                    false,
                    &mut archived_here,
                    &mut outcome,
                )
                .await?;
            }
        }
        commit(
            &mut writer,
            checkpoint,
            &source,
            window_start,
            window_end,
            true,
            &mut archived_here,
            &mut outcome,
        )
        .await?;
        outcome.windows_completed += 1;
        window_start = window_end;
    }
    // Store anything fetched before a failure, so the next run does not refetch it.
    if !writer.pending.is_empty() || !writer.gaps.is_empty() || !archived_here.is_empty() {
        commit(
            &mut writer,
            checkpoint,
            &source,
            window_start,
            window_start,
            false,
            &mut archived_here,
            &mut outcome,
        )
        .await?;
    }
    finish(checkpoint, &source, &mut outcome)
}

fn quarantine(writer: &mut Writer<'_>, item: &ContentItem, why: &str) -> Result<()> {
    let created = Instant::parse(&item.created)?;
    writer.gaps.push(Gap::new(
        created,
        created,
        &format!(
            "audit content blob {} could not be used ({why}); skipped",
            item.id
        ),
    ));
    Ok(())
}

/// Flush, then record progress. `complete` advances the watermark to `end`.
#[allow(clippy::too_many_arguments)]
async fn commit(
    writer: &mut Writer<'_>,
    checkpoint: &mut Checkpoint,
    source: &str,
    start: Instant,
    end: Instant,
    complete: bool,
    archived: &mut Vec<(String, String)>,
    outcome: &mut Outcome,
) -> Result<()> {
    if !complete && writer.pending.is_empty() && writer.gaps.is_empty() && archived.is_empty() {
        return Ok(());
    }
    let sha = writer
        .flush(checkpoint.source(source), start, end, complete, outcome)
        .await?;
    let state = checkpoint.source(source);
    state.last_manifest_sha256 = Some(sha);
    state.archived_blobs.extend(archived.drain(..));
    if complete {
        state.set_watermark(end);
    }
    checkpoint.save()
}

fn finish(checkpoint: &mut Checkpoint, source: &str, outcome: &mut Outcome) -> Result<Outcome> {
    let state = checkpoint.source(source);
    if matches!(outcome.status, Status::Ok) {
        state.unavailable = None;
        state.retry_after = None;
        if outcome.rejected_records > 0 || outcome.quarantined_blobs > 0 {
            outcome.status = Status::OkWithWarnings;
        }
    }
    outcome.watermark = state.watermark.clone();
    checkpoint.save()?;
    Ok(outcome.clone())
}

// ---------------------------------------------------------------------------
// Microsoft Graph

/// Archive one Graph source, window by window up to `now`.
pub async fn collect_graph(
    up: &impl Upstream,
    store: &dyn ObjectStore,
    checkpoint: &mut Checkpoint,
    spec: &GraphSpec,
    run_id: &str,
    now: Instant,
    options: &CollectOptions,
) -> Result<Outcome> {
    let source = spec.source;
    let tenant = checkpoint.state.tenant_id.clone();
    if !up.tenant_id().eq_ignore_ascii_case(&tenant) {
        bail!("collector tenant does not match the archive tenant");
    }
    if let Some(why) = paused(checkpoint.source(source), now) {
        return Ok(Outcome::skipped(source, why));
    }
    let mut outcome = Outcome::new(source);
    let mut writer = Writer {
        store,
        tenant: &tenant,
        source,
        run_id,
        pending: vec![],
        gaps: vec![],
    };
    let floor = now.minus(GRAPH_START_WINDOW);
    let mut start = match checkpoint.source(source).watermark() {
        Some(mark) if mark < floor => {
            writer.gaps.push(Gap::new(
                mark,
                floor,
                "collector was offline longer than the Graph start window; older records may no longer be available from Microsoft",
            ));
            floor
        }
        Some(mark) => mark.minus(options.graph_overlap).max(floor),
        None => floor,
    };
    let mut seen: HashMap<String, String> = HashMap::new();
    let mut pages = 0usize;
    while now.since(start) > Duration::from_secs(60) {
        let end = start.plus(GRAPH_WINDOW).min(now);
        match graph_window(
            up,
            &tenant,
            spec,
            start,
            end,
            now,
            options,
            &mut writer,
            &mut seen,
            &mut pages,
            &mut outcome,
            checkpoint,
        )
        .await
        {
            Ok(()) => {}
            Err(WindowError::Call(e)) => {
                note_failure(checkpoint.source(source), &e, now, &mut outcome);
                break;
            }
            Err(WindowError::Budget) => {
                outcome.status = Status::Partial;
                outcome.detail = Some("per-run page budget reached; the next run continues".into());
                break;
            }
            Err(WindowError::Local(e)) => return Err(e),
        }
        let mut none = Vec::new();
        commit(
            &mut writer,
            checkpoint,
            source,
            start,
            end,
            true,
            &mut none,
            &mut outcome,
        )
        .await?;
        remember(checkpoint.source(source), &seen, options.graph_overlap);
        checkpoint.save()?;
        outcome.windows_completed += 1;
        start = end;
    }
    if !writer.pending.is_empty() || !writer.gaps.is_empty() {
        let mut none = Vec::new();
        commit(
            &mut writer,
            checkpoint,
            source,
            start,
            start,
            false,
            &mut none,
            &mut outcome,
        )
        .await?;
        remember(checkpoint.source(source), &seen, options.graph_overlap);
        checkpoint.save()?;
    }
    finish(checkpoint, source, &mut outcome)
}

enum WindowError {
    Call(CallError),
    Budget,
    Local(anyhow::Error),
}

impl From<anyhow::Error> for WindowError {
    fn from(e: anyhow::Error) -> Self {
        Self::Local(e)
    }
}

/// Keep the ids of stored records the next run's overlap will list again:
/// those at or after `watermark - overlap`. Called only after the records are
/// stored, so a remembered id always names a stored record.
fn remember(state: &mut SourceState, seen: &HashMap<String, String>, overlap: Duration) {
    let Some(mark) = state.watermark() else {
        return;
    };
    let keep_from = mark.minus(overlap).to_rfc3339();
    state.recent_records.retain(|_, at| *at >= keep_from);
    for (id, at) in seen {
        if *at >= keep_from && state.recent_records.len() < MAX_RECENT_IDS {
            state.recent_records.insert(id.clone(), at.clone());
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn graph_window(
    up: &impl Upstream,
    tenant: &str,
    spec: &GraphSpec,
    start: Instant,
    end: Instant,
    now: Instant,
    options: &CollectOptions,
    writer: &mut Writer<'_>,
    seen: &mut HashMap<String, String>,
    pages: &mut usize,
    outcome: &mut Outcome,
    checkpoint: &mut Checkpoint,
) -> Result<(), WindowError> {
    let field = spec.time_field;
    let filter = format!(
        "{field} ge {} and {field} lt {}",
        start.to_rfc3339(),
        end.to_rfc3339()
    );
    let mut url = graph_url(
        up,
        spec.path,
        &[("$filter", &filter), ("$top", spec.page_size)],
    );
    let origin = url.origin();
    let mut visited = HashSet::new();
    let mut rejected_here = 0u64;
    loop {
        *pages += 1;
        if *pages > GRAPH_MAX_PAGES {
            return Err(WindowError::Budget);
        }
        if !visited.insert(url.to_string()) {
            return Err(WindowError::Call(CallError::other(
                FailureKind::Malformed,
                "Graph pagination cycle",
            )));
        }
        let reply = options
            .backoff
            .run(|| up.get(Api::Graph, url.clone()))
            .await
            .map_err(WindowError::Call)?;
        let records = reply
            .body
            .get("value")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                WindowError::Call(CallError::other(
                    FailureKind::Malformed,
                    "Graph value is not an array",
                ))
            })?;
        for raw in records {
            let Some(record) = graph_record(tenant, spec, raw, now) else {
                rejected_here += 1;
                continue;
            };
            let in_window =
                Instant::parse(raw.get(field).and_then(Value::as_str).unwrap_or_default())
                    .is_ok_and(|t| t >= start && t < end);
            if !in_window {
                rejected_here += 1;
                continue;
            }
            let recent = &checkpoint.source(spec.source).recent_records;
            if recent.contains_key(&record.record_id) || seen.contains_key(&record.record_id) {
                outcome.duplicates_skipped += 1;
                continue;
            }
            seen.insert(record.record_id.clone(), record.event_time.clone());
            writer.pending.push(record);
        }
        if writer.pending.len() >= FLUSH_RECORDS {
            let mut none = Vec::new();
            commit(
                writer,
                checkpoint,
                spec.source,
                start,
                end,
                false,
                &mut none,
                outcome,
            )
            .await?;
        }
        let next = match reply.body.get("@odata.nextLink") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(url::Url::parse(s).map_err(|_| {
                WindowError::Call(CallError::other(
                    FailureKind::Malformed,
                    "invalid Graph continuation",
                ))
            })?),
            _ => {
                return Err(WindowError::Call(CallError::other(
                    FailureKind::Malformed,
                    "invalid Graph continuation",
                )));
            }
        };
        match next {
            None => break,
            Some(next)
                if next.origin() == origin
                    && next.path() == spec.path
                    && next.username().is_empty()
                    && next.password().is_none()
                    && next.fragment().is_none() =>
            {
                url = next;
            }
            Some(_) => {
                return Err(WindowError::Call(CallError::other(
                    FailureKind::Malformed,
                    "unsafe Graph continuation refused",
                )));
            }
        }
    }
    if rejected_here > 0 {
        outcome.rejected_records += rejected_here;
        writer.gaps.push(Gap::new(
            start,
            end,
            &format!("{rejected_here} malformed, foreign-tenant or out-of-window record(s) rejected and not stored"),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// One pass over every configured source

/// Collect every configured source once. Sources are isolated: one failure
/// (including a storage error) is reported and the rest still run.
pub async fn collect_all(
    up: &impl Upstream,
    store: &dyn ObjectStore,
    checkpoint: &mut Checkpoint,
    sources: &[String],
    now: Instant,
    options: &CollectOptions,
) -> Vec<Outcome> {
    let run_id = format!("run-{}", now.to_rfc3339().replace([':', '.'], "-"));
    let mut outcomes = Vec::with_capacity(sources.len());
    for source in sources {
        let result = if let Some(content_type) = source.strip_prefix("o365:") {
            collect_management(up, store, checkpoint, content_type, &run_id, now, options).await
        } else if let Some(spec) = graph_spec(source) {
            collect_graph(up, store, checkpoint, spec, &run_id, now, options).await
        } else {
            Ok(Outcome::skipped(
                source,
                "source not supported by this release".into(),
            ))
        };
        outcomes.push(result.unwrap_or_else(|e| {
            let mut o = Outcome::new(source);
            o.status = Status::Failed;
            o.detail = Some(format!("local error: {e:#}"));
            o
        }));
    }
    outcomes
}
