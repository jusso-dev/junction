//! The archive record envelope and its on-storage encoding.
//!
//! Each stored object is gzip-compressed NDJSON: one [`ArchiveRecord`] per line,
//! sorted by record id. Objects are keyed by the SHA-256 of their uncompressed
//! content, so writing the same batch twice names the same object and the
//! create-only put turns the retry into a no-op.
use anyhow::{Context, Result, bail};
use flate2::{Compression, GzBuilder, read::GzDecoder};
use junction_watch::{
    clock::Instant,
    event::{SecurityEvent, event_id, sha256_hex},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    io::{Read, Write},
};

pub const RECORD_SCHEMA: &str = "junction.archive.record/1";
/// Largest raw record kept verbatim. Bigger records keep their hash and
/// normalised fields, and are flagged `rawOmitted`.
pub const MAX_RAW_BYTES: usize = 1024 * 1024;
/// Largest decompressed object accepted when reading.
pub const MAX_OBJECT_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveRecord {
    pub schema: String,
    /// Stable id: the same tenant, source, upstream id and version always give
    /// the same record id. Duplicates are removed on read by this id.
    pub record_id: String,
    pub tenant_id: String,
    pub source: String,
    pub source_event_id: String,
    /// Set for sources whose records change over time (Defender alerts and
    /// incidents): the upstream last-update time of this copy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub event_time: String,
    pub ingested_at: String,
    pub operation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_upn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// SHA-256 of the record as received (re-serialised JSON).
    pub raw_sha256: String,
    /// `too_large` when the raw record exceeded [`MAX_RAW_BYTES`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_omitted: Option<String>,
    /// True when `raw` is an allow-listed reduction of the upstream record.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub raw_reduced: bool,
    #[serde(default)]
    pub raw: Value,
}

impl ArchiveRecord {
    /// Build a record from a watch-normalised event and the raw upstream record.
    pub fn from_event(event: &SecurityEvent, raw: &Value, version: Option<&str>) -> Self {
        Self::from_parts(event, raw, raw, version)
    }

    /// As [`from_event`](Self::from_event), but store `kept` (an allow-listed
    /// reduction of `raw`) instead of the full upstream record.
    pub fn from_reduced(event: &SecurityEvent, raw: &Value, kept: Value, version: &str) -> Self {
        let mut record = Self::from_parts(event, raw, &kept, Some(version));
        record.raw_reduced = true;
        record
    }

    fn from_parts(event: &SecurityEvent, raw: &Value, kept: &Value, version: Option<&str>) -> Self {
        let upstream_id = match version {
            Some(v) => format!("{}@{v}", event.source_event_id),
            None => event.source_event_id.clone(),
        };
        let raw_bytes = serde_json::to_vec(raw).unwrap_or_default();
        let kept_len = serde_json::to_vec(kept).map_or(usize::MAX, |b| b.len());
        let (raw_value, omitted) = if kept_len > MAX_RAW_BYTES {
            (Value::Null, Some("too_large".to_owned()))
        } else {
            (kept.clone(), None)
        };
        Self {
            schema: RECORD_SCHEMA.to_owned(),
            record_id: event_id(&event.tenant_id, &event.source, &upstream_id),
            tenant_id: event.tenant_id.clone(),
            source: event.source.clone(),
            source_event_id: event.source_event_id.clone(),
            version: version.map(str::to_owned),
            event_time: event.timestamp.clone(),
            ingested_at: event.ingested_at.clone(),
            operation: event.operation.clone(),
            result: event.result.clone(),
            actor_upn: event.actor_upn.clone(),
            actor_id: event.actor_id.clone(),
            target_id: event.target_id.clone(),
            ip_address: event.ip_address.clone(),
            correlation_id: event.correlation_id.clone(),
            raw_sha256: sha256_hex(&raw_bytes),
            raw_omitted: omitted,
            raw_reduced: false,
            raw: raw_value,
        }
    }

    pub fn event_instant(&self) -> Option<Instant> {
        Instant::parse(&self.event_time).ok()
    }
}

/// Key-safe form of a source id: `o365:Audit.Exchange` becomes `o365-Audit.Exchange`.
pub fn source_slug(source: &str) -> String {
    source
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// `v1/tenant=<id>/source=<slug>/`
pub fn source_prefix(tenant: &str, source: &str) -> String {
    format!("v1/tenant={tenant}/source={}/", source_slug(source))
}

/// `v1/tenant=<id>/source=<slug>/date=YYYY-MM-DD/`
pub fn date_prefix(tenant: &str, source: &str, day: Instant) -> String {
    format!(
        "{}date={}/",
        source_prefix(tenant, source),
        &day.to_rfc3339()[..10]
    )
}

/// One encoded object ready for a create-only put.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedObject {
    pub key: String,
    /// gzip-compressed NDJSON.
    pub bytes: Vec<u8>,
    /// SHA-256 of the uncompressed NDJSON (also the object name).
    pub content_sha256: String,
    pub records: usize,
    pub first_event: String,
    pub last_event: String,
}

/// Split records into one object per (source, event hour), each sorted by
/// record id and with exact duplicates removed. Records whose event time does
/// not parse are refused: the normalisers never produce them.
pub fn encode(tenant: &str, records: Vec<ArchiveRecord>) -> Result<Vec<EncodedObject>> {
    let mut groups: BTreeMap<(String, String), BTreeMap<String, ArchiveRecord>> = BTreeMap::new();
    for record in records {
        if record.tenant_id != tenant {
            bail!("record belongs to another tenant");
        }
        let at = record
            .event_instant()
            .context("record event time is not a timestamp")?;
        let stamp = at.to_rfc3339();
        let partition = format!(
            "{}date={}/hour={}/",
            source_prefix(tenant, &record.source),
            &stamp[..10],
            &stamp[11..13]
        );
        groups
            .entry((record.source.clone(), partition))
            .or_default()
            .insert(record.record_id.clone(), record);
    }
    let mut out = Vec::with_capacity(groups.len());
    for ((_, partition), records) in groups {
        let mut ndjson = Vec::new();
        let mut first = String::new();
        let mut last = String::new();
        for record in records.values() {
            serde_json::to_writer(&mut ndjson, record)?;
            ndjson.push(b'\n');
            if first.is_empty() || record.event_time < first {
                first = record.event_time.clone();
            }
            if record.event_time > last {
                last = record.event_time.clone();
            }
        }
        let content_sha256 = sha256_hex(&ndjson);
        // A fixed gzip header (no name, mtime 0) keeps the bytes reproducible.
        let mut encoder = GzBuilder::new()
            .mtime(0)
            .write(Vec::new(), Compression::best());
        encoder.write_all(&ndjson)?;
        let bytes = encoder.finish()?;
        out.push(EncodedObject {
            key: format!("{partition}{content_sha256}.ndjson.gz"),
            bytes,
            content_sha256,
            records: records.len(),
            first_event: first,
            last_event: last,
        });
    }
    Ok(out)
}

/// Decoded object: the records that parsed and how many lines did not.
#[derive(Debug, Default)]
pub struct Decoded {
    pub records: Vec<ArchiveRecord>,
    pub bad_lines: usize,
    /// The uncompressed content hash did not match the object name.
    pub hash_mismatch: bool,
}

/// Decode one stored object. `key` is used to check the content hash.
pub fn decode(key: &str, bytes: &[u8]) -> Result<Decoded> {
    let mut ndjson = Vec::new();
    GzDecoder::new(bytes)
        .take(MAX_OBJECT_BYTES + 1)
        .read_to_end(&mut ndjson)
        .context("object is not valid gzip")?;
    if ndjson.len() as u64 > MAX_OBJECT_BYTES {
        bail!("object exceeds the decompressed size limit");
    }
    let expected = key
        .rsplit('/')
        .next()
        .and_then(|name| name.strip_suffix(".ndjson.gz"));
    let mut decoded = Decoded {
        hash_mismatch: expected.is_some_and(|h| h != sha256_hex(&ndjson)),
        ..Decoded::default()
    };
    for line in ndjson.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        match serde_json::from_slice::<ArchiveRecord>(line) {
            Ok(record) if record.schema == RECORD_SCHEMA => decoded.records.push(record),
            _ => decoded.bad_lines += 1,
        }
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const T: &str = "11111111-1111-4111-8111-111111111111";

    pub fn record(id: &str, time: &str) -> ArchiveRecord {
        let raw = json!({"Id": id, "CreationTime": time, "Operation": "FileAccessed"});
        let event = junction_watch::event::from_management_record(
            T,
            "Audit.SharePoint",
            &raw,
            Instant::parse("2026-11-01T00:00:00Z").unwrap(),
        )
        .unwrap();
        ArchiveRecord::from_event(&event, &raw, None)
    }

    #[test]
    fn encoding_is_reproducible_partitioned_and_deduplicated() {
        let a = record("a", "2026-10-31T10:15:00Z");
        let b = record("b", "2026-10-31T10:45:00Z");
        let c = record("c", "2026-10-31T11:05:00Z");
        let one = encode(T, vec![b.clone(), a.clone(), c.clone(), a.clone()]).unwrap();
        let two = encode(T, vec![c, a, b]).unwrap();
        assert_eq!(one, two, "order and duplicates do not change the objects");
        assert_eq!(one.len(), 2, "one object per event hour");
        assert_eq!(one[0].records, 2);
        assert!(one[0].key.starts_with(&format!(
            "v1/tenant={T}/source=o365-Audit.SharePoint/date=2026-10-31/hour=10/"
        )));
        assert!(
            one[0]
                .key
                .ends_with(&format!("{}.ndjson.gz", one[0].content_sha256))
        );
        let decoded = decode(&one[0].key, &one[0].bytes).unwrap();
        assert_eq!(decoded.records.len(), 2);
        assert_eq!(decoded.bad_lines, 0);
        assert!(!decoded.hash_mismatch);
    }

    #[test]
    fn foreign_tenant_records_are_refused() {
        let mut r = record("a", "2026-10-31T10:15:00Z");
        r.tenant_id = "22222222-2222-4222-8222-222222222222".into();
        assert!(encode(T, vec![r]).is_err());
    }

    #[test]
    fn decode_reports_tampering_and_bad_lines() {
        let objects = encode(T, vec![record("a", "2026-10-31T10:15:00Z")]).unwrap();
        let mut encoder = GzBuilder::new().write(Vec::new(), Compression::fast());
        encoder.write_all(b"{\"not\":\"a record\"}\n").unwrap();
        let bytes = encoder.finish().unwrap();
        let decoded = decode(&objects[0].key, &bytes).unwrap();
        assert!(decoded.hash_mismatch);
        assert_eq!(decoded.bad_lines, 1);
        assert!(decode(&objects[0].key, b"not gzip").is_err());
    }

    #[test]
    fn versions_give_distinct_ids_and_large_raw_is_omitted() {
        let raw = json!({"id": "x", "activityDateTime": "2026-10-31T10:15:00Z", "activityDisplayName": "Add member to role"});
        let event = junction_watch::graph::normalise(
            T,
            "graph:directoryAudits",
            &raw,
            Instant::parse("2026-11-01T00:00:00Z").unwrap(),
        )
        .unwrap();
        let v1 = ArchiveRecord::from_event(&event, &raw, Some("2026-10-31T10:15:00.000Z"));
        let v2 = ArchiveRecord::from_event(&event, &raw, Some("2026-10-31T12:00:00.000Z"));
        assert_ne!(v1.record_id, v2.record_id);
        let big = json!({"blob": "x".repeat(MAX_RAW_BYTES + 1)});
        let r = ArchiveRecord::from_event(&event, &big, None);
        assert_eq!(r.raw_omitted.as_deref(), Some("too_large"));
        assert!(r.raw.is_null());
        assert_eq!(r.raw_sha256.len(), 64);
    }

    #[test]
    fn slugs_are_key_safe() {
        assert_eq!(source_slug("o365:Audit.Exchange"), "o365-Audit.Exchange");
        assert_eq!(source_slug("graph:signIns"), "graph-signIns");
        assert_eq!(source_slug("a/../b"), "a-..-b");
    }
}
