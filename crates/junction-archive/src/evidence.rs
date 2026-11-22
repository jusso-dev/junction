//! Legal holds and evidence bundles.
//!
//! # Legal hold
//!
//! A hold protects every object holding a matching record past its normal
//! retention. A hold manifest is written first (who, when, why, the query and
//! every held record id with its raw hash), then each object is held:
//!
//! - Azure Blob: `Set Blob Legal Hold` on the object itself.
//! - R2 and the local store: a copy under `holds/<hold-id>/`, which an
//!   indefinite bucket lock rule protects.
//!
//! Hold creation fails closed: if any object cannot be held, the command
//! fails and reports which ones, and the hold manifest says so.
//!
//! # Evidence bundle
//!
//! `junction archive export` writes a directory:
//!
//! - `records.ndjson`: the matching records (redacted unless `--full`),
//!   deduplicated, ordered by event time then record id.
//! - `manifest.json`: tool version, tenant, range, query and its hash, the
//!   sources searched, record count, the SHA-256 of each file, a result-set
//!   hash, the storage objects read, gaps overlapping the range, and problems.
//! - `README.txt`: how to verify the bundle.
//!
//! The result-set hash is the SHA-256 of the sorted lines `recordId rawSha256`.
//! It does not depend on redaction or order, so a redacted bundle and a full
//! bundle of the same query share it, and an assessor can confirm both describe
//! the same records.
use crate::{
    manifest::{Gap, Manifest, manifest_date_prefix},
    record::ArchiveRecord,
    search::{self, Query, Results},
    store::{ObjectStore, PutOutcome, validate_hold_id},
};
use anyhow::{Context, Result, bail};
use junction_watch::{clock::Instant, event::sha256_hex};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

pub const BUNDLE_SCHEMA: &str = "junction.archive.evidence/1";
pub const HOLD_SCHEMA: &str = "junction.archive.hold/1";

/// SHA-256 over sorted `recordId rawSha256` lines.
pub fn result_set_sha256(records: &[ArchiveRecord]) -> String {
    let mut lines: Vec<String> = records
        .iter()
        .map(|r| format!("{} {}", r.record_id, r.raw_sha256))
        .collect();
    lines.sort();
    lines.dedup();
    let mut joined = lines.join("\n");
    joined.push('\n');
    sha256_hex(joined.as_bytes())
}

// ---------------------------------------------------------------------------
// Holds

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeldObject {
    pub key: String,
    pub method: String,
    pub held_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HoldManifest {
    pub schema: String,
    pub hold_id: String,
    pub tenant_id: String,
    /// `create` or `release`.
    pub action: String,
    pub created_at: String,
    pub created_by: String,
    pub reason: String,
    pub query: Query,
    pub query_sha256: String,
    /// Record id to raw hash, for every record the hold covers.
    pub records: BTreeMap<String, String>,
    pub result_set_sha256: String,
    pub objects: Vec<HeldObject>,
    /// Objects that could not be held; non-empty means the hold failed.
    pub failed: Vec<String>,
}

fn hold_prefix(tenant: &str) -> String {
    format!("v1/tenant={tenant}/holds/")
}

/// Who is acting, for the audit trail. Never a credential.
pub fn operator() -> String {
    let name = std::env::var("JUNCTION_ARCHIVE_OPERATOR")
        .or_else(|_| std::env::var("USER"))
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".into());
    junction_watch::event::clean(&name, 128)
}

async fn write_hold_manifest(store: &dyn ObjectStore, m: &HoldManifest) -> Result<String> {
    let bytes = serde_json::to_vec_pretty(m)?;
    let sha = sha256_hex(&bytes);
    let stamp = m.created_at.replace([':', '.', '-'], "");
    let key = format!(
        "{}{}/{}-{}-{sha}.json",
        hold_prefix(&m.tenant_id),
        m.hold_id,
        stamp,
        m.action
    );
    store.put_new(&key, bytes, "application/json").await?;
    audit(
        store,
        &m.tenant_id,
        &format!("hold_{}", m.action),
        &json!({
            "holdId": m.hold_id, "manifest": key, "records": m.records.len(),
            "objects": m.objects.len(), "failed": m.failed.len(), "by": m.created_by,
        }),
    )
    .await?;
    Ok(key)
}

/// Create a hold over every object holding a record matching `query`.
pub async fn create_hold(
    store: &dyn ObjectStore,
    tenant: &str,
    hold_id: &str,
    reason: &str,
    query: &Query,
    now: Instant,
) -> Result<HoldManifest> {
    validate_hold_id(hold_id)?;
    let reason = junction_watch::event::clean(reason.trim(), 1024);
    if reason.is_empty() {
        bail!("a hold needs a reason");
    }
    if !hold_manifests(store, tenant, hold_id).await?.is_empty() {
        bail!("hold {hold_id} already exists; choose another id");
    }
    let results = search::search(store, tenant, query, search::MAX_LIMIT).await?;
    if results.truncated {
        bail!(
            "the query matches more than {} records; narrow it",
            search::MAX_LIMIT
        );
    }
    // An unreadable object might hold matching records; a hold that silently
    // skipped it would not protect what it claims to.
    if !results.problems.is_empty() {
        bail!(
            "{} object(s) in range could not be read, so the hold cannot be complete: {}",
            results.problems.len(),
            results
                .problems
                .iter()
                .map(|p| format!("{} ({})", p.key, p.problem))
                .collect::<Vec<_>>()
                .join("; ")
        );
    }
    let mut keys = BTreeSet::new();
    for key in &results.objects_read {
        keys.insert(key.clone());
    }
    // Only objects that actually hold a matching record are held.
    let matching = objects_with_records(store, &keys, &results).await?;
    let mut manifest = HoldManifest {
        schema: HOLD_SCHEMA.into(),
        hold_id: hold_id.to_owned(),
        tenant_id: tenant.to_owned(),
        action: "create".into(),
        created_at: now.to_rfc3339(),
        created_by: operator(),
        reason,
        query: query.clone(),
        query_sha256: query.sha256(),
        records: results
            .records
            .iter()
            .map(|r| (r.record_id.clone(), r.raw_sha256.clone()))
            .collect(),
        result_set_sha256: result_set_sha256(&results.records),
        objects: vec![],
        failed: vec![],
    };
    // Record the intent, naming every object, before anything is held, so a
    // crash part-way leaves a manifest that accounts for each held object.
    let intent = HoldManifest {
        action: "intent".into(),
        failed: matching.iter().map(|k| format!("{k}: pending")).collect(),
        ..manifest.clone()
    };
    write_hold_manifest(store, &intent).await?;
    for key in matching {
        match store.hold(&key, hold_id).await {
            Ok(h) => manifest.objects.push(HeldObject {
                key,
                method: h.method.into(),
                held_key: h.held_key,
            }),
            Err(e) => manifest.failed.push(format!("{key}: {e:#}")),
        }
    }
    write_hold_manifest(store, &manifest).await?;
    if !manifest.failed.is_empty() {
        bail!(
            "hold {hold_id} is incomplete: {} of {} object(s) could not be held: {}",
            manifest.failed.len(),
            manifest.failed.len() + manifest.objects.len(),
            manifest.failed.join("; ")
        );
    }
    Ok(manifest)
}

async fn objects_with_records(
    store: &dyn ObjectStore,
    keys: &BTreeSet<String>,
    results: &Results,
) -> Result<Vec<String>> {
    let wanted: BTreeSet<&str> = results
        .records
        .iter()
        .map(|r| r.record_id.as_str())
        .collect();
    let mut out = vec![];
    for key in keys {
        let bytes = store
            .get(key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("object {key} disappeared while placing the hold"))?;
        let decoded = crate::record::decode(key, &bytes)?;
        if decoded
            .records
            .iter()
            .any(|r| wanted.contains(r.record_id.as_str()))
        {
            out.push(key.clone());
        }
    }
    Ok(out)
}

/// Every manifest of one hold. Fails if any is missing, altered or names
/// another hold: release decisions must never be made on partial knowledge.
async fn hold_manifests(
    store: &dyn ObjectStore,
    tenant: &str,
    hold_id: &str,
) -> Result<Vec<HoldManifest>> {
    let mut out = vec![];
    for key in store
        .list(&format!("{}{hold_id}/", hold_prefix(tenant)))
        .await?
    {
        let bytes = store
            .get(&key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("hold manifest {key} is listed but missing"))?;
        let named = key
            .rsplit('/')
            .next()
            .and_then(|n| n.strip_suffix(".json"))
            .and_then(|n| n.rsplit('-').next());
        if named != Some(sha256_hex(&bytes).as_str()) {
            bail!("hold manifest {key} does not match its hash");
        }
        let m: HoldManifest = serde_json::from_slice(&bytes)
            .with_context(|| format!("hold manifest {key} is unreadable"))?;
        if m.schema != HOLD_SCHEMA || m.hold_id != hold_id {
            bail!("hold manifest {key} does not belong to hold {hold_id}");
        }
        out.push(m);
    }
    // Same-second actions keep their written order: intent, create, release.
    let rank = |a: &str| match a {
        "intent" => 0,
        "create" => 1,
        _ => 2,
    };
    out.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then(rank(&a.action).cmp(&rank(&b.action)))
    });
    Ok(out)
}

/// Every object a hold may protect: those it held, plus those its intent
/// named (a crash between intent and create can leave held objects the
/// create manifest never recorded).
fn protected_keys(manifests: &[HoldManifest]) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    for m in manifests.iter().filter(|m| m.action != "release") {
        keys.extend(m.objects.iter().map(|o| o.key.clone()));
        keys.extend(
            m.failed
                .iter()
                .filter_map(|f| f.split(": ").next())
                .map(str::to_owned),
        );
    }
    keys
}

/// Active holds: created and not released, newest action last.
pub async fn list_holds(store: &dyn ObjectStore, tenant: &str) -> Result<Vec<Value>> {
    let mut ids = BTreeSet::new();
    let prefix = hold_prefix(tenant);
    for key in store.list(&prefix).await? {
        if let Some(id) = key.strip_prefix(&prefix).and_then(|r| r.split('/').next()) {
            ids.insert(id.to_owned());
        }
    }
    let mut out = vec![];
    for id in ids {
        let manifests = match hold_manifests(store, tenant, &id).await {
            Ok(m) => m,
            Err(e) => {
                out.push(json!({"holdId": id, "state": "unreadable", "problem": format!("{e:#}")}));
                continue;
            }
        };
        let Some(created) = manifests
            .iter()
            .rev()
            .find(|m| m.action == "create")
            .or_else(|| manifests.iter().find(|m| m.action == "intent"))
        else {
            continue;
        };
        let released = manifests.iter().rev().find(|m| m.action == "release");
        let state = match released {
            Some(r) if r.failed.is_empty() => "released",
            Some(_) => "release_incomplete",
            None if created.action == "intent" => "incomplete",
            None if created.failed.is_empty() => "active",
            None => "incomplete",
        };
        out.push(json!({
            "holdId": id,
            "state": state,
            "createdAt": created.created_at,
            "createdBy": created.created_by,
            "reason": created.reason,
            "records": created.records.len(),
            "objects": created.objects.len(),
            "releasedAt": released.map(|r| r.created_at.clone()),
        }));
    }
    Ok(out)
}

/// Release a hold. On Azure the legal hold flag is cleared only on objects no
/// other active hold covers. On R2 and local stores the copies stay under
/// `holds/` until an administrator changes the lock rule; the release is
/// recorded so the copies can be reviewed and removed.
pub async fn release_hold(
    store: &dyn ObjectStore,
    tenant: &str,
    hold_id: &str,
    reason: &str,
    now: Instant,
) -> Result<HoldManifest> {
    validate_hold_id(hold_id)?;
    let manifests = hold_manifests(store, tenant, hold_id).await?;
    let created = manifests
        .iter()
        .rev()
        .find(|m| m.action == "create")
        .or_else(|| manifests.iter().find(|m| m.action == "intent"))
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("no hold named {hold_id}"))?;
    // Objects an earlier, partial release already cleared.
    let already: BTreeSet<String> = manifests
        .iter()
        .filter(|m| m.action == "release")
        .flat_map(|m| m.objects.iter().map(|o| o.key.clone()))
        .collect();
    let last_release = manifests.iter().rev().find(|m| m.action == "release");
    if last_release.is_some_and(|r| r.failed.is_empty()) {
        bail!("hold {hold_id} is already released");
    }
    // Objects other holds still need. Any hold that cannot be read fails the
    // release: clearing a flag on partial knowledge could drop protection.
    let mut covered_elsewhere = BTreeSet::new();
    let prefix = hold_prefix(tenant);
    let mut others = BTreeSet::new();
    for key in store.list(&prefix).await? {
        if let Some(id) = key.strip_prefix(&prefix).and_then(|r| r.split('/').next())
            && id != hold_id
        {
            others.insert(id.to_owned());
        }
    }
    for id in others {
        let theirs = hold_manifests(store, tenant, &id).await.with_context(|| {
            format!("cannot confirm what hold {id} still protects; release refused")
        })?;
        let released = theirs
            .iter()
            .rev()
            .find(|m| m.action == "release")
            .is_some_and(|r| r.failed.is_empty());
        if !released {
            covered_elsewhere.extend(protected_keys(&theirs));
        }
    }
    let mut release = HoldManifest {
        action: "release".into(),
        created_at: now.to_rfc3339(),
        created_by: operator(),
        reason: junction_watch::event::clean(reason.trim(), 1024),
        objects: vec![],
        failed: vec![],
        ..created.clone()
    };
    let mut targets: Vec<HeldObject> = created.objects.clone();
    // Objects named only in the intent (a crash before create) are released too.
    for key in protected_keys(&manifests) {
        if !targets.iter().any(|o| o.key == key) {
            targets.push(HeldObject {
                key: key.clone(),
                method: created
                    .objects
                    .first()
                    .map_or("unknown".into(), |o| o.method.clone()),
                held_key: key,
            });
        }
    }
    for object in targets {
        if already.contains(&object.key) {
            continue;
        }
        if covered_elsewhere.contains(&object.key) {
            continue;
        }
        match store.release(&object.key).await {
            Ok(()) => release.objects.push(object),
            Err(e) => release.failed.push(format!("{}: {e:#}", object.key)),
        }
    }
    write_hold_manifest(store, &release).await?;
    if !release.failed.is_empty() {
        bail!(
            "release of {hold_id} is incomplete; run the release again to retry: {}",
            release.failed.join("; ")
        );
    }
    Ok(release)
}

/// Append an audit entry to the store's own `audit/` prefix (create-only).
pub async fn audit(
    store: &dyn ObjectStore,
    tenant: &str,
    action: &str,
    detail: &Value,
) -> Result<()> {
    let now = Instant::now();
    let body = serde_json::to_vec(&json!({
        "schema": "junction.archive.audit/1",
        "at": now.to_rfc3339(),
        "action": action,
        "by": operator(),
        "detail": detail,
    }))?;
    let sha = sha256_hex(&body);
    let key = format!(
        "v1/tenant={tenant}/audit/date={}/{}-{action}-{}.json",
        &now.to_rfc3339()[..10],
        now.to_rfc3339().replace([':', '.', '-'], ""),
        &sha[..16]
    );
    match store.put_new(&key, body, "application/json").await? {
        PutOutcome::Created | PutOutcome::AlreadyExists => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Export and verify

/// What an evidence bundle can say about completeness for one source.
///
/// Two kinds of gap are reported:
///
/// - **recorded**: gaps written into manifests (offline past the API window,
///   quarantined blobs, rejected records) that overlap the range;
/// - **uncovered**: parts of the range that no complete window manifest
///   covers, because the collector was not running, has not reached them
///   yet, or the source was never collected.
///
/// Offline gaps are filed with the window that resumed collection, which
/// starts at the end of the gap, so manifests are read from 8 days before
/// the range to 8 days after it.
async fn gaps_in_range(
    store: &dyn ObjectStore,
    tenant: &str,
    sources: &[String],
    from: Instant,
    to: Instant,
) -> Result<Vec<Value>> {
    let margin = std::time::Duration::from_secs(8 * 86_400);
    let mut out = vec![];
    for source in sources {
        let mut covered: Vec<(Instant, Instant)> = vec![];
        let start = from.minus(margin);
        let end = to.plus(margin);
        let mut day = Instant(start.0.div_euclid(86_400_000) * 86_400_000);
        while day < end {
            for key in store
                .list(&manifest_date_prefix(tenant, source, day))
                .await?
            {
                let Some(bytes) = store.get(&key).await? else {
                    out.push(
                        json!({"source": source, "kind": "recorded", "manifest": key,
                        "reason": "manifest listed but missing"}),
                    );
                    continue;
                };
                let Ok(m) = Manifest::decode(&key, &bytes) else {
                    out.push(
                        json!({"source": source, "kind": "recorded", "manifest": key,
                        "reason": "manifest unreadable or altered"}),
                    );
                    continue;
                };
                for g in &m.gaps {
                    if overlaps(g, from, to) {
                        out.push(json!({"source": source, "kind": "recorded",
                            "from": g.from, "to": g.to, "reason": g.reason}));
                    }
                }
                if m.complete
                    && let (Ok(a), Ok(b)) = (
                        Instant::parse(&m.window_start),
                        Instant::parse(&m.window_end),
                    )
                    && b > a
                {
                    covered.push((a, b));
                }
            }
            day = day.plus(std::time::Duration::from_secs(86_400));
        }
        for (a, b) in uncovered(covered, from, to) {
            out.push(json!({"source": source, "kind": "uncovered",
                "from": a.to_rfc3339(), "to": b.to_rfc3339(),
                "reason": "no complete collection window covers this period; records may be missing"}));
        }
    }
    Ok(out)
}

/// Parts of `[from, to)` not covered by any interval in `covered`.
fn uncovered(
    mut covered: Vec<(Instant, Instant)>,
    from: Instant,
    to: Instant,
) -> Vec<(Instant, Instant)> {
    covered.sort();
    let mut out = vec![];
    let mut cursor = from;
    for (a, b) in covered {
        if b <= cursor {
            continue;
        }
        if a >= to {
            break;
        }
        if a > cursor {
            out.push((cursor, a.min(to)));
        }
        cursor = cursor.max(b);
        if cursor >= to {
            break;
        }
    }
    if cursor < to {
        out.push((cursor, to));
    }
    out
}

fn overlaps(g: &Gap, from: Instant, to: Instant) -> bool {
    match (Instant::parse(&g.from), Instant::parse(&g.to)) {
        (Ok(a), Ok(b)) => a < to && b >= from,
        _ => true,
    }
}

const README: &str = "Junction archive evidence bundle

Files
  records.ndjson  One archived record per line, ordered by event time then
                  record id. Redacted unless manifest.json says \"redacted\": false.
  manifest.json   What was asked, what was found and the hashes below.

Verify
  1. sha256sum records.ndjson and compare with files[\"records.ndjson\"].
  2. Recompute the result-set hash: for each line take recordId and rawSha256,
     sort the \"recordId rawSha256\" lines, join with newlines, add a final
     newline and SHA-256 it. Compare with resultSetSha256.
  3. Or run: junction archive verify <this directory>

Completeness
  gaps lists every period inside the range where collection was incomplete:
  recorded gaps written by the collector, and uncovered periods that no
  complete collection window covers. A bundle never proves more than its gaps
  allow.
";

pub struct Export {
    pub manifest: Value,
    /// Whether the export's audit entry was written to the store.
    pub audit_written: bool,
    pub audit_error: Option<String>,
}

/// Write an evidence bundle for `query` into `output` (a new directory).
#[allow(clippy::too_many_arguments)]
pub async fn export(
    store: &dyn ObjectStore,
    tenant: &str,
    query: &Query,
    full: bool,
    purpose: &str,
    output: &Path,
    now: Instant,
) -> Result<Export> {
    let (from, to) = query.range()?;
    let results = search::search(store, tenant, query, search::MAX_LIMIT).await?;
    if results.truncated {
        bail!(
            "the query matches more than {} records; narrow it",
            search::MAX_LIMIT
        );
    }
    let view = if full { search::full } else { search::redacted };
    let mut ndjson = Vec::new();
    for r in &results.records {
        serde_json::to_writer(&mut ndjson, &view(r))?;
        ndjson.push(b'\n');
    }
    let sources: Vec<String> = if query.sources.is_empty() {
        crate::config::ALL_SOURCES
            .iter()
            .map(|s| s.to_string())
            .collect()
    } else {
        query.sources.clone()
    };
    let gaps = gaps_in_range(store, tenant, &sources, from, to).await?;
    let manifest = json!({
        "schema": BUNDLE_SCHEMA,
        "tool": format!("junction {}", env!("CARGO_PKG_VERSION")),
        "createdAt": now.to_rfc3339(),
        "createdBy": operator(),
        "purpose": junction_watch::event::clean(purpose, 1024),
        "tenantId": tenant,
        "storage": store.describe(),
        "range": {"from": from.to_rfc3339(), "to": to.to_rfc3339()},
        "query": if full { serde_json::to_value(query)? } else { query.redacted() },
        "querySha256": query.sha256(),
        "sources": sources,
        "redacted": !full,
        "recordCount": results.records.len(),
        "duplicatesRemoved": results.duplicates_removed,
        "resultSetSha256": result_set_sha256(&results.records),
        "files": {"records.ndjson": sha256_hex(&ndjson)},
        "objectsRead": results.objects_read,
        "gaps": gaps,
        "problems": results.problems,
    });
    std::fs::create_dir(output)
        .with_context(|| format!("{} already exists or cannot be created", output.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(output, std::fs::Permissions::from_mode(0o700))?;
    }
    crate::config::write_new_private(
        &output.join("records.ndjson"),
        std::str::from_utf8(&ndjson)?,
    )?;
    crate::config::write_new_private(
        &output.join("manifest.json"),
        &serde_json::to_string_pretty(&manifest)?,
    )?;
    crate::config::write_new_private(&output.join("README.txt"), README)?;
    // Exports run under the read-only searcher identity, which cannot write
    // to the store. The audit entry is then reported as not written, and the
    // bundle itself stays valid.
    let audited = audit(
        store,
        tenant,
        "export",
        &json!({
            "querySha256": manifest["querySha256"], "records": results.records.len(),
            "redacted": !full, "resultSetSha256": manifest["resultSetSha256"],
        }),
    )
    .await;
    Ok(Export {
        manifest,
        audit_written: audited.is_ok(),
        audit_error: audited.err().map(|e| format!("{e:#}")),
    })
}

/// Recompute every hash in a bundle directory. Returns the problems found.
pub fn verify(bundle: &Path) -> Result<Vec<String>> {
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(bundle.join("manifest.json")).context("manifest.json unreadable")?,
    )
    .context("manifest.json is not JSON")?;
    if manifest["schema"] != BUNDLE_SCHEMA {
        bail!("not a junction archive evidence bundle");
    }
    let mut problems = vec![];
    let records =
        std::fs::read(bundle.join("records.ndjson")).context("records.ndjson unreadable")?;
    if manifest["files"]["records.ndjson"].as_str() != Some(sha256_hex(&records).as_str()) {
        problems.push("records.ndjson does not match its recorded SHA-256".to_owned());
    }
    let mut lines = vec![];
    for (n, line) in records.split(|b| *b == b'\n').enumerate() {
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_slice::<Value>(line) else {
            problems.push(format!("records.ndjson line {} is not JSON", n + 1));
            continue;
        };
        match (v["recordId"].as_str(), v["rawSha256"].as_str()) {
            (Some(id), Some(h)) => lines.push(format!("{id} {h}")),
            _ => problems.push(format!(
                "records.ndjson line {} lacks recordId or rawSha256",
                n + 1
            )),
        }
    }
    if manifest["recordCount"].as_u64() != Some(lines.len() as u64) {
        problems.push("record count does not match the records".to_owned());
    }
    lines.sort();
    let total = lines.len();
    lines.dedup();
    if lines.len() != total {
        problems.push(format!(
            "records.ndjson repeats {} record(s)",
            total - lines.len()
        ));
    }
    let mut joined = lines.join("\n");
    joined.push('\n');
    if manifest["resultSetSha256"].as_str() != Some(sha256_hex(joined.as_bytes()).as_str()) {
        problems.push("result-set hash does not match the records".to_owned());
    }
    // A full bundle carries the exact query, so its hash can be recomputed.
    // A redacted bundle carries the hash inside its redacted query too.
    match (
        manifest["redacted"].as_bool(),
        manifest["querySha256"].as_str(),
    ) {
        (Some(false), Some(expected)) => {
            let recomputed = serde_json::from_value::<Query>(manifest["query"].clone())
                .map(|q| q.sha256())
                .unwrap_or_default();
            if recomputed != expected {
                problems.push("query does not match querySha256".to_owned());
            }
        }
        (Some(true), Some(expected)) => {
            if manifest["query"]["querySha256"].as_str() != Some(expected) {
                problems.push("query does not match querySha256".to_owned());
            }
        }
        _ => problems.push("manifest lacks querySha256 or redacted".to_owned()),
    }
    Ok(problems)
}
