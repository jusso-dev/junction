//! M365-Secure JSON schema 1.1 export (`--format m365-secure-json`), so existing
//! crownguard imports (`content/imports/m365-secure.yaml`) keep working.
//!
//! Junction results are mapped back to M365-Secure check ids with
//! `data/m365-secure-map.yaml`; results with no mapping are skipped. One finding is
//! written per mapped M365-Secure id. Statuses use M365-Secure's vocabulary.
use crate::model::{CheckResult, RunReport, Status, TenantReport};
use crate::outcome::AWAITING_ANSWER;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::sync::OnceLock;

pub const SCHEMA_VERSION: &str = "1.1";

/// Junction check id -> M365-Secure check ids.
pub fn mapping() -> &'static BTreeMap<String, Vec<String>> {
    static MAP: OnceLock<BTreeMap<String, Vec<String>>> = OnceLock::new();
    MAP.get_or_init(|| {
        serde_saphyr::from_str(include_str!("../../data/m365-secure-map.yaml"))
            .expect("data/m365-secure-map.yaml")
    })
}

/// M365-Secure's status vocabulary (`pass`, `fail`, `warning`, `review`, `info`,
/// `unknown`, `notlicensed`).
pub fn status(result: &CheckResult) -> &'static str {
    let code = result.reason.as_ref().map(|r| r.code.as_str());
    match result.status {
        Status::Pass => "pass",
        Status::Fail => "fail",
        Status::Warn => "warning",
        Status::Unknown if code.is_some_and(|c| AWAITING_ANSWER.contains(&c)) => "review",
        Status::Unknown => "unknown",
        Status::NotApplicable if code == Some("licence_required") => "notlicensed",
        Status::NotApplicable => "info",
    }
}

/// One schema 1.1 document per tenant: a single object for a one-tenant run,
/// otherwise an array (write each element to its own
/// `_Assessment-Results_<domain>.json` for crownguard).
pub fn render(report: &RunReport) -> Value {
    let docs: Vec<Value> = report
        .tenants
        .iter()
        .map(|t| render_tenant(report, t))
        .collect();
    match <[Value; 1]>::try_from(docs) {
        Ok([one]) => one,
        Err(many) => Value::Array(many),
    }
}

/// The schema 1.1 document for one tenant of a run.
pub fn render_tenant(report: &RunReport, tenant: &TenantReport) -> Value {
    let findings: Vec<Value> = tenant
        .results
        .iter()
        .flat_map(|r| {
            mapping()
                .get(&r.id)
                .into_iter()
                .flatten()
                .map(move |id| finding(id, r, &report.finished_at))
        })
        .collect();
    let mut status_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut severity_counts: BTreeMap<String, usize> = BTreeMap::new();
    for f in &findings {
        *status_counts.entry(display(&f["status"])).or_default() += 1;
        *severity_counts.entry(display(&f["severity"])).or_default() += 1;
    }
    // M365-Secure's score: passes over pass plus fail.
    let pass = status_counts.get("Pass").copied().unwrap_or(0);
    let scored = pass + status_counts.get("Fail").copied().unwrap_or(0);
    let score = if scored == 0 {
        0.0
    } else {
        pass as f64 * 100.0 / scored as f64
    };
    let label = tenant
        .label
        .clone()
        .unwrap_or_else(|| tenant.tenant_id.clone());
    let domain = if label.contains('.') {
        label.clone()
    } else {
        tenant.tenant_id.clone()
    };
    let skus: Vec<Value> = tenant
        .licences
        .iter()
        .flat_map(|l| &l.skus)
        .map(|sku| {
            json!({ "sku_id": "", "sku_part_number": sku, "consumed_units": 0, "prepaid_units": 0, "service_plans": [] })
        })
        .collect();
    let mut packs: Vec<&str> = tenant.results.iter().map(|r| r.pack.as_str()).collect();
    packs.dedup();
    json!({
        "schema_version": SCHEMA_VERSION,
        "tool": { "name": report.tool.name, "version": report.tool.version },
        "summary": {
            "tenant": {
                "tenant_id": tenant.tenant_id,
                "display_name": label,
                "verified_domains": if domain.contains('.') { vec![domain.clone()] } else { vec![] },
                "primary_domain": domain,
                "license_skus": skus,
            },
            "timestamp": report.finished_at,
            "duration_seconds": duration(report),
            "total_checks": findings.len(),
            "status_counts": status_counts,
            "severity_counts": severity_counts,
            "score": score,
            "modules_run": packs,
            "modules_failed": if tenant.error.is_some() { vec![tenant.tenant_id.clone()] } else { vec![] },
        },
        "findings": findings,
        "compliance": [],
    })
}

fn finding(check_id: &str, r: &CheckResult, timestamp: &str) -> Value {
    let mut f = Map::new();
    f.insert("check_id".into(), json!(check_id));
    f.insert("category".into(), json!(r.pack.title()));
    f.insert("section".into(), json!(r.pack.as_str()));
    f.insert("setting".into(), json!(r.title));
    f.insert("description".into(), json!(r.title));
    f.insert("status".into(), json!(status(r)));
    f.insert("severity".into(), json!(r.severity.as_str()));
    f.insert("current_value".into(), json!(r.evidence.summary));
    f.insert("expected_value".into(), json!(r.title));
    f.insert("remediation".into(), json!(r.remediation.text));
    f.insert("framework_mappings".into(), mappings(r));
    f.insert("timestamp".into(), json!(timestamp));
    f.insert(
        "details".into(),
        json!({ "junction_check_id": r.id, "evidence": r.evidence.data, "reason": r.reason }),
    );
    if !r.affected.items.is_empty() {
        f.insert("affected_resources".into(), json!(r.affected.items));
    }
    Value::Object(f)
}

/// Junction tags in M365-Secure's `FrameworkMappings` keys.
fn mappings(r: &CheckResult) -> Value {
    let t = &r.tags;
    let mut m = Map::new();
    let mut put = |key: &str, ids: Vec<String>| {
        if !ids.is_empty() {
            m.insert(key.into(), json!(ids));
        }
    };
    put("cis_v7", t.cis_m365.clone());
    put("nist_csf", t.nist_csf.clone());
    put("mitre_attack", t.mitre.clone());
    put(
        "essential_eight",
        t.essential_eight
            .iter()
            .flat_map(|e| {
                e.levels
                    .iter()
                    .map(move |l| format!("ML{l}-{}", e.strategy))
            })
            .collect(),
    );
    let mut other = Map::new();
    if !t.ism.is_empty() {
        other.insert("ism".into(), json!(t.ism));
    }
    if !t.cis_v8.is_empty() {
        other.insert("cis-v8".into(), json!(t.cis_v8));
    }
    if !other.is_empty() {
        m.insert("other".into(), Value::Object(other));
    }
    Value::Object(m)
}

/// `Pass`, `Warning`, `Not Licensed`: M365-Secure's display names, used as count keys.
fn display(v: &Value) -> String {
    match v.as_str().unwrap_or("") {
        "notlicensed" => "Not Licensed".into(),
        s => {
            let mut c = s.chars();
            c.next()
                .map(|f| f.to_ascii_uppercase().to_string() + c.as_str())
                .unwrap_or_default()
        }
    }
}

fn duration(report: &RunReport) -> f64 {
    use junction_watch::clock::Instant;
    match (
        Instant::parse(&report.started_at),
        Instant::parse(&report.finished_at),
    ) {
        (Ok(a), Ok(b)) => b.since(a).as_secs_f64(),
        _ => 0.0,
    }
}
