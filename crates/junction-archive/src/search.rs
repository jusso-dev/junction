//! Search the archive by time range and simple field filters.
//!
//! Only the date partitions that overlap the time range are listed and read.
//! Results are deduplicated by record id (the archive is at-least-once). The
//! default view redacts personal data: the actor is a short hash, the IP is
//! truncated to its network, and raw records are not shown.
use crate::{
    record::{self, ArchiveRecord, date_prefix},
    store::ObjectStore,
};
use anyhow::{Result, bail};
use junction_watch::{clock::Instant, event::sha256_hex};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, time::Duration};

/// Longest time range one search may cover.
pub const MAX_RANGE_DAYS: u64 = 3660;
pub const DEFAULT_LIMIT: usize = 1000;
pub const MAX_LIMIT: usize = 1_000_000;

/// A search. Every filter is optional; all given filters must match.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Query {
    pub from: String,
    pub to: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    /// Exact operation, case-insensitive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    /// Actor UPN, case-insensitive exact match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Exact IP address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// Case-insensitive substring of the record id, raw hash, Microsoft id,
    /// operation, target, result, correlation id, actor, IP or raw record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contains: Option<String>,
}

impl Query {
    pub fn range(&self) -> Result<(Instant, Instant)> {
        let from = Instant::parse(&self.from)
            .map_err(|_| anyhow::anyhow!("--from must be an RFC 3339 time"))?;
        let to = Instant::parse(&self.to)
            .map_err(|_| anyhow::anyhow!("--to must be an RFC 3339 time"))?;
        if to <= from {
            bail!("--to must be after --from");
        }
        if to.since(from) > Duration::from_secs(MAX_RANGE_DAYS * 86_400) {
            bail!("a search may cover at most {MAX_RANGE_DAYS} days");
        }
        for s in &self.sources {
            if !crate::config::ALL_SOURCES.contains(&s.as_str()) {
                bail!("unknown source {s:?}");
            }
        }
        for v in [&self.operation, &self.actor, &self.ip, &self.contains]
            .into_iter()
            .flatten()
        {
            if v.is_empty() || v.len() > 512 || v.chars().any(char::is_control) {
                bail!("filters must be 1-512 printable characters");
            }
        }
        Ok((from, to))
    }

    pub fn matches(&self, r: &ArchiveRecord, from: Instant, to: Instant) -> bool {
        let Some(at) = r.event_instant() else {
            return false;
        };
        if at < from || at >= to {
            return false;
        }
        if !self.sources.is_empty() && !self.sources.contains(&r.source) {
            return false;
        }
        if let Some(op) = &self.operation
            && !r.operation.eq_ignore_ascii_case(op)
        {
            return false;
        }
        if let Some(actor) = &self.actor
            && !r
                .actor_upn
                .as_deref()
                .is_some_and(|u| u.eq_ignore_ascii_case(actor))
        {
            return false;
        }
        if let Some(ip) = &self.ip
            && r.ip_address.as_deref() != Some(ip.as_str())
        {
            return false;
        }
        if let Some(needle) = &self.contains {
            let needle = needle.to_lowercase();
            // Identifiers are included so a record can be found from a
            // forwarded event's record id or raw hash.
            let haystack = [
                r.record_id.as_str(),
                r.raw_sha256.as_str(),
                r.source_event_id.as_str(),
                r.operation.as_str(),
                r.target_id.as_deref().unwrap_or_default(),
                r.result.as_deref().unwrap_or_default(),
                r.correlation_id.as_deref().unwrap_or_default(),
                r.actor_upn.as_deref().unwrap_or_default(),
                r.actor_id.as_deref().unwrap_or_default(),
                r.ip_address.as_deref().unwrap_or_default(),
            ];
            let hit = haystack.iter().any(|h| h.to_lowercase().contains(&needle))
                || r.raw.to_string().to_lowercase().contains(&needle);
            if !hit {
                return false;
            }
        }
        true
    }

    /// Stable hash of the query, recorded in evidence bundles.
    pub fn sha256(&self) -> String {
        sha256_hex(&serde_json::to_vec(self).unwrap_or_default())
    }

    /// The query as shown in redacted output: the actor is a pseudonym, the
    /// IP a network, and free text is replaced by its hash, so the redacted
    /// view cannot be used to reverse the pseudonyms in its own results.
    pub fn redacted(&self) -> Value {
        json!({
            "from": self.from,
            "to": self.to,
            "sources": self.sources,
            "operation": self.operation,
            "actor": self.actor.as_deref().map(pseudonym),
            "ip": self.ip.as_deref().map(truncate_ip),
            "contains": self.contains.as_deref().map(|c| format!("sha256:{}", &sha256_hex(c.as_bytes())[..12])),
            "querySha256": self.sha256(),
        })
    }
}

/// Short, stable pseudonym for an identifier: `sha256:` and 12 hex digits.
/// Not a secret mapping: anyone with the archive can hash a known UPN and
/// compare. It keeps identities out of casual output and screen shares.
pub fn pseudonym(value: &str) -> String {
    format!(
        "sha256:{}",
        &sha256_hex(value.to_lowercase().as_bytes())[..12]
    )
}

/// IPv4 to /24, IPv6 to /48.
pub fn truncate_ip(ip: &str) -> String {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            let o = v4.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
        Err(_) => "[invalid]".into(),
    }
}

/// The default, redacted view of a record.
pub fn redacted(r: &ArchiveRecord) -> Value {
    json!({
        "recordId": r.record_id,
        "eventTime": r.event_time,
        "source": r.source,
        "operation": r.operation,
        "result": r.result,
        "actor": r.actor_upn.as_deref().or(r.actor_id.as_deref()).map(pseudonym),
        "ip": r.ip_address.as_deref().map(truncate_ip),
        "version": r.version,
        "rawSha256": r.raw_sha256,
    })
}

/// The full normalised record, including raw. Shown only with `--full`.
pub fn full(r: &ArchiveRecord) -> Value {
    serde_json::to_value(r).unwrap_or(Value::Null)
}

/// An object that could not be read or did not match its name.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Problem {
    pub key: String,
    pub problem: String,
}

#[derive(Debug, Default)]
pub struct Results {
    /// Matching records, deduplicated and ordered by event time then id.
    pub records: Vec<ArchiveRecord>,
    pub objects_read: Vec<String>,
    pub duplicates_removed: usize,
    pub problems: Vec<Problem>,
    /// More matches existed than `limit`.
    pub truncated: bool,
}

/// Every UTC date between `from` and `to` (inclusive of the end date).
fn days(from: Instant, to: Instant) -> Vec<Instant> {
    let mut out = vec![];
    let day = Duration::from_secs(86_400);
    let mut d = Instant(from.0.div_euclid(86_400_000) * 86_400_000);
    while d < to {
        out.push(d);
        d = d.plus(day);
    }
    out
}

/// Run `query` against `store`.
pub async fn search(
    store: &dyn ObjectStore,
    tenant: &str,
    query: &Query,
    limit: usize,
) -> Result<Results> {
    let (from, to) = query.range()?;
    let limit = limit.clamp(1, MAX_LIMIT);
    let sources: Vec<String> = if query.sources.is_empty() {
        crate::config::ALL_SOURCES
            .iter()
            .map(|s| s.to_string())
            .collect()
    } else {
        query.sources.clone()
    };
    let mut results = Results::default();
    // record id -> the copy kept (latest ingest wins).
    let mut found: BTreeMap<String, ArchiveRecord> = BTreeMap::new();
    'outer: for source in &sources {
        for day in days(from, to) {
            let prefix = date_prefix(tenant, source, day);
            for key in store.list(&prefix).await? {
                if !key.ends_with(".ndjson.gz") || !hour_overlaps(&key, from, to) {
                    continue;
                }
                let Some(bytes) = store.get(&key).await? else {
                    results.problems.push(Problem {
                        key,
                        problem: "listed but missing".into(),
                    });
                    continue;
                };
                let decoded = match record::decode(&key, &bytes) {
                    Ok(d) => d,
                    Err(e) => {
                        results.problems.push(Problem {
                            key,
                            problem: format!("{e:#}"),
                        });
                        continue;
                    }
                };
                if decoded.hash_mismatch {
                    results.problems.push(Problem {
                        key: key.clone(),
                        problem: "content does not match its hash; object skipped".into(),
                    });
                    continue;
                }
                if decoded.bad_lines > 0 {
                    results.problems.push(Problem {
                        key: key.clone(),
                        problem: format!("{} unreadable line(s) skipped", decoded.bad_lines),
                    });
                }
                results.objects_read.push(key);
                for r in decoded.records {
                    if r.tenant_id != tenant || !query.matches(&r, from, to) {
                        continue;
                    }
                    match found.get(&r.record_id) {
                        Some(existing) => {
                            results.duplicates_removed += 1;
                            if r.ingested_at > existing.ingested_at {
                                found.insert(r.record_id.clone(), r);
                            }
                        }
                        None => {
                            if found.len() >= limit {
                                results.truncated = true;
                                break 'outer;
                            }
                            found.insert(r.record_id.clone(), r);
                        }
                    }
                }
            }
        }
    }
    let mut records: Vec<ArchiveRecord> = found.into_values().collect();
    records.sort_by(|a, b| {
        a.event_time
            .cmp(&b.event_time)
            .then_with(|| a.record_id.cmp(&b.record_id))
    });
    results.records = records;
    Ok(results)
}

/// Skip hour partitions entirely outside the range.
fn hour_overlaps(key: &str, from: Instant, to: Instant) -> bool {
    let date = key.split("/date=").nth(1).and_then(|r| r.get(..10));
    let hour = key.split("/hour=").nth(1).and_then(|r| r.get(..2));
    let (Some(date), Some(hour)) = (date, hour) else {
        return true;
    };
    let Ok(start) = Instant::parse(&format!("{date}T{hour}:00:00Z")) else {
        return true;
    };
    let end = start.plus(Duration::from_secs(3600));
    start < to && end > from
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn redaction_helpers() {
        assert_eq!(truncate_ip("203.0.113.77"), "203.0.113.0/24");
        assert_eq!(truncate_ip("2001:db8:abcd:12::1"), "2001:db8:abcd::/48");
        assert_eq!(truncate_ip("nonsense"), "[invalid]");
        assert_eq!(
            pseudonym("Person@Example.Test"),
            pseudonym("person@example.test")
        );
        assert!(pseudonym("a").starts_with("sha256:") && pseudonym("a").len() == 19);
    }
    #[test]
    fn query_validation() {
        let q = |from: &str, to: &str| Query {
            from: from.into(),
            to: to.into(),
            ..Query::default()
        };
        q("2026-11-01T00:00:00Z", "2026-11-02T00:00:00Z")
            .range()
            .unwrap();
        assert!(
            q("2026-11-02T00:00:00Z", "2026-11-01T00:00:00Z")
                .range()
                .is_err()
        );
        assert!(
            q("2000-01-01T00:00:00Z", "2026-11-01T00:00:00Z")
                .range()
                .is_err()
        );
        let mut bad = q("2026-11-01T00:00:00Z", "2026-11-02T00:00:00Z");
        bad.sources = vec!["intune:devices".into()];
        assert!(bad.range().is_err());
    }
    #[test]
    fn hour_filter() {
        let from = Instant::parse("2026-11-01T10:30:00Z").unwrap();
        let to = Instant::parse("2026-11-01T12:00:00Z").unwrap();
        assert!(hour_overlaps(
            "v1/x/date=2026-11-01/hour=10/a.ndjson.gz",
            from,
            to
        ));
        assert!(hour_overlaps(
            "v1/x/date=2026-11-01/hour=11/a.ndjson.gz",
            from,
            to
        ));
        assert!(!hour_overlaps(
            "v1/x/date=2026-11-01/hour=12/a.ndjson.gz",
            from,
            to
        ));
        assert!(!hour_overlaps(
            "v1/x/date=2026-11-01/hour=09/a.ndjson.gz",
            from,
            to
        ));
    }
}
