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
        let Some(bytes) = store.get(key).await? else {
            continue;
        };
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
        if let Some(bytes) = store.get(&key).await?
            && let Ok(m) = serde_json::from_slice::<HoldManifest>(&bytes)
            && m.schema == HOLD_SCHEMA
            && m.hold_id == hold_id
        {
            out.push(m);
        }
    }
    out.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    Ok(out)
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
        let manifests = hold_manifests(store, tenant, &id).await?;
        let Some(created) = manifests.iter().find(|m| m.action == "create") else {
            continue;
        };
        let released = manifests.iter().rev().find(|m| m.action == "release");
        out.push(json!({
            "holdId": id,
            "state": if released.is_some() { "released" } else if created.failed.is_empty() { "active" } else { "incomplete" },
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
        .find(|m| m.action == "create")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("no hold named {hold_id}"))?;
    if manifests.iter().any(|m| m.action == "release") {
        bail!("hold {hold_id} is already released");
    }
    // Objects still covered by other active holds keep their flag.
    let mut covered_elsewhere = BTreeSet::new();
    for other in list_holds(store, tenant).await? {
        let id = other["holdId"].as_str().unwrap_or_default();
        if id != hold_id && other["state"] != "released" {
            for m in hold_manifests(store, tenant, id).await? {
                covered_elsewhere.extend(m.objects.into_iter().map(|o| o.key));
            }
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
    for object in &created.objects {
        if object.method == "legal_hold_flag" && covered_elsewhere.contains(&object.key) {
            continue;
        }
        match store.release(&object.key).await {
            Ok(()) => release.objects.push(object.clone()),
            Err(e) => release.failed.push(format!("{}: {e:#}", object.key)),
        }
    }
    write_hold_manifest(store, &release).await?;
    if !release.failed.is_empty() {
        bail!(
            "release of {hold_id} is incomplete: {}",
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

/// Gaps recorded in manifests that overlap the range, for the searched sources.
async fn gaps_in_range(
    store: &dyn ObjectStore,
    tenant: &str,
    sources: &[String],
    from: Instant,
    to: Instant,
) -> Result<Vec<Value>> {
    let mut out = vec![];
    // Manifests are filed by window start; a window that started up to 7 days
    // before `from` can record a gap reaching into the range.
    let start = from.minus(std::time::Duration::from_secs(8 * 86_400));
    for source in sources {
        let mut day = Instant(start.0.div_euclid(86_400_000) * 86_400_000);
        while day < to {
            for key in store
                .list(&manifest_date_prefix(tenant, source, day))
                .await?
            {
                let Some(bytes) = store.get(&key).await? else {
                    continue;
                };
                let Ok(m) = Manifest::decode(&key, &bytes) else {
                    out.push(json!({"source": source, "manifest": key, "reason": "manifest unreadable or altered"}));
                    continue;
                };
                for g in &m.gaps {
                    if overlaps(g, from, to) {
                        out.push(json!({"source": source, "from": g.from, "to": g.to, "reason": g.reason}));
                    }
                }
            }
            day = day.plus(std::time::Duration::from_secs(86_400));
        }
    }
    Ok(out)
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
  gaps lists every period inside the range where collection was incomplete.
  A bundle never proves more than its gaps allow.
";

pub struct Export {
    pub manifest: Value,
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
        "query": query,
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
    audit(
        store,
        tenant,
        "export",
        &json!({
            "querySha256": manifest["querySha256"], "records": results.records.len(),
            "redacted": !full, "resultSetSha256": manifest["resultSetSha256"],
        }),
    )
    .await?;
    Ok(Export { manifest })
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
    lines.sort();
    lines.dedup();
    let mut joined = lines.join("\n");
    joined.push('\n');
    if manifest["resultSetSha256"].as_str() != Some(sha256_hex(joined.as_bytes()).as_str()) {
        problems.push("result-set hash does not match the records".to_owned());
    }
    if manifest["recordCount"].as_u64() != Some(lines.len() as u64) {
        problems.push("record count does not match the records".to_owned());
    }
    Ok(problems)
}
