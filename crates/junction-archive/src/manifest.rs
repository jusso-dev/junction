//! Per-window manifests: what was collected, what was missed, and a hash chain.
//!
//! Every committed window writes one manifest, including windows that held no
//! records, so the archive can show it looked at a period rather than leaving
//! an unexplained hole. Each manifest names the SHA-256 of the previous
//! manifest for the same source. Manifests are create-only objects like the
//! records, so the chain cannot be rewritten while retention protects it.
use crate::record::{date_prefix, source_slug};
use anyhow::{Result, bail};
use junction_watch::{clock::Instant, event::sha256_hex};
use serde::{Deserialize, Serialize};

pub const MANIFEST_SCHEMA: &str = "junction.archive.manifest/1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Gap {
    pub from: String,
    pub to: String,
    pub reason: String,
}

impl Gap {
    pub fn new(from: Instant, to: Instant, reason: &str) -> Self {
        Self {
            from: from.to_rfc3339(),
            to: to.to_rfc3339(),
            reason: junction_watch::event::clean(reason, 512),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectEntry {
    pub key: String,
    pub content_sha256: String,
    pub records: usize,
    pub first_event: String,
    pub last_event: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub schema: String,
    pub tenant_id: String,
    pub source: String,
    pub run_id: String,
    pub window_start: String,
    pub window_end: String,
    /// True when the whole window was listed and stored; false for a partial
    /// flush (budget, failure) whose window will be collected again.
    pub complete: bool,
    pub written_at: String,
    pub records: usize,
    pub objects: Vec<ObjectEntry>,
    pub gaps: Vec<Gap>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_manifest_sha256: Option<String>,
}

impl Manifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: &str,
        source: &str,
        run_id: &str,
        start: Instant,
        end: Instant,
        complete: bool,
        objects: Vec<ObjectEntry>,
        gaps: Vec<Gap>,
        previous: Option<String>,
    ) -> Self {
        Self {
            schema: MANIFEST_SCHEMA.into(),
            tenant_id: tenant.into(),
            source: source.into(),
            run_id: run_id.into(),
            window_start: start.to_rfc3339(),
            window_end: end.to_rfc3339(),
            complete,
            written_at: Instant::now().to_rfc3339(),
            records: objects.iter().map(|o| o.records).sum(),
            objects,
            gaps,
            previous_manifest_sha256: previous,
        }
    }

    /// Object key, bytes and SHA-256 of the bytes.
    pub fn encode(&self) -> Result<(String, Vec<u8>, String)> {
        let bytes = serde_json::to_vec_pretty(self)?;
        let sha = sha256_hex(&bytes);
        let start = Instant::parse(&self.window_start)?;
        let stamp = self.window_start.replace([':', '.', '-'], "");
        let key = format!(
            "{}{stamp}-{sha}.json",
            manifest_date_prefix(&self.tenant_id, &self.source, start)
        );
        Ok((key, bytes, sha))
    }

    pub fn decode(key: &str, bytes: &[u8]) -> Result<Self> {
        let manifest: Self = serde_json::from_slice(bytes)?;
        if manifest.schema != MANIFEST_SCHEMA {
            bail!("unknown manifest schema");
        }
        let expected = key
            .rsplit('/')
            .next()
            .and_then(|n| n.strip_suffix(".json"))
            .and_then(|n| n.rsplit('-').next());
        if expected != Some(sha256_hex(bytes).as_str()) {
            bail!("manifest content does not match its name");
        }
        Ok(manifest)
    }
}

/// `v1/tenant=<id>/manifests/source=<slug>/`
pub fn manifest_prefix(tenant: &str, source: &str) -> String {
    format!(
        "v1/tenant={tenant}/manifests/source={}/",
        source_slug(source)
    )
}

/// `v1/tenant=<id>/manifests/source=<slug>/date=YYYY-MM-DD/`
pub fn manifest_date_prefix(tenant: &str, source: &str, day: Instant) -> String {
    // Reuse the record layout's date formatting for one consistent scheme.
    let records = date_prefix(tenant, source, day);
    let date = records
        .rsplit_once("date=")
        .map(|(_, d)| d)
        .unwrap_or_default();
    format!("{}date={date}", manifest_prefix(tenant, source))
}

#[cfg(test)]
mod tests {
    use super::*;
    const T: &str = "11111111-1111-4111-8111-111111111111";

    #[test]
    fn manifests_round_trip_and_detect_tampering() {
        let t = Instant::parse("2026-11-01T10:00:00Z").unwrap();
        let m = Manifest::new(
            T,
            "graph:signIns",
            "run-1",
            t,
            t.plus(std::time::Duration::from_secs(3600)),
            true,
            vec![],
            vec![Gap::new(t, t, "x\u{202e}y")],
            None,
        );
        let (key, bytes, sha) = m.encode().unwrap();
        assert!(key.starts_with(&format!(
            "v1/tenant={T}/manifests/source=graph-signIns/date=2026-11-01/"
        )));
        assert!(key.ends_with(&format!("-{sha}.json")));
        let back = Manifest::decode(&key, &bytes).unwrap();
        assert_eq!(
            back.gaps[0].reason, "xy",
            "control and bidi characters are stripped"
        );
        let mut tampered = bytes.clone();
        tampered[10] ^= 1;
        assert!(Manifest::decode(&key, &tampered).is_err());
    }
}
