//! Fixture harness: replay recorded, synthetic Microsoft API responses with no
//! network. Used by every pack's tests and by the CLI, MCP and HTTP tests.
//!
//! A fixture case is a directory of JSON files under
//! `crates/junction-check/tests/fixtures/<pack>/<case>/`. Each file holds one
//! entry or an array of entries:
//!
//! ```json
//! {
//!   "operation": "graph.users.list",
//!   "match": {"parameters": {"$filter": "accountEnabled eq true"}},
//!   "responses": [
//!     {"status": 429, "retry_after": 0},
//!     {"status": 200, "body": {"value": [], "@odata.nextLink": "fixture:users-2"}}
//!   ]
//! }
//! ```
//!
//! * `operation` matches the catalogue id; optional `match` must be a subset of
//!   the call's input. The most specific matching entry wins.
//! * `url` (instead of `operation`) answers a page link such as `fixture:users-2`.
//! * `responses` replay in order and the last one repeats. A response is
//!   `{"status", "body"}`, an error `{"status": 403, "error": {"code", "message"}}`,
//!   or a throttle `{"status": 429, "retry_after": seconds}`.
//!
//! Every call is still validated against the embedded catalogue and Junction's
//! read-only policy (`Executor::preflight`), so a fixture cannot exercise an
//! operation the live path would refuse.
use crate::catalog;
use crate::gateway::{
    BoxFut, CallError, FailureKind, Gateway, GatewayError, Listing, check_policy,
    classify_preflight_error, items_of, with_api_version,
};
use anyhow::{Context, Result, bail};
use junction_core::cloud::MicrosoftCloud;
use junction_runtime::Executor;
use serde::Deserialize;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

pub const TENANT: &str = "00000000-0000-4000-8000-000000000001";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureResponse {
    #[serde(default = "ok")]
    pub status: u16,
    #[serde(default)]
    pub body: Value,
    #[serde(default)]
    pub error: Option<FixtureError>,
    /// Seconds for a `Retry-After` header.
    #[serde(default)]
    pub retry_after: Option<u64>,
}
fn ok() -> u16 {
    200
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureError {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureEntry {
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default, rename = "match")]
    pub matcher: Option<Value>,
    pub responses: Vec<FixtureResponse>,
}

struct Slot {
    entry: FixtureEntry,
    served: usize,
}

/// One recorded call, for assertions.
#[derive(Debug, Clone, PartialEq)]
pub struct Call {
    pub operation: String,
    pub input: Value,
}

pub struct FixtureGateway {
    tenant: String,
    slots: Mutex<Vec<Slot>>,
    calls: Mutex<Vec<Call>>,
    executor: Executor,
    endpoints: junction_core::cloud::CloudEndpoints,
    in_flight: std::sync::atomic::AtomicUsize,
    peak: std::sync::atomic::AtomicUsize,
    delay: Duration,
}

/// `crates/junction-check/tests/fixtures`.
pub fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Is `subset` contained in `value` (objects by key, everything else by equality)?
pub fn contains(value: &Value, subset: &Value) -> bool {
    match (value, subset) {
        (Value::Object(v), Value::Object(s)) => s
            .iter()
            .all(|(k, sv)| v.get(k).is_some_and(|vv| contains(vv, sv))),
        _ => value == subset,
    }
}

fn specificity(matcher: &Option<Value>) -> usize {
    fn count(v: &Value) -> usize {
        match v {
            Value::Object(m) => m.values().map(count).sum::<usize>().max(1),
            _ => 1,
        }
    }
    matcher.as_ref().map(count).unwrap_or(0)
}

impl FixtureGateway {
    pub fn new(tenant: &str) -> Self {
        Self {
            tenant: tenant.to_owned(),
            slots: Mutex::new(vec![]),
            calls: Mutex::new(vec![]),
            executor: Executor::new(catalog::registry().expect("catalogue"), check_policy())
                .expect("executor"),
            endpoints: MicrosoftCloud::Public.endpoints().expect("public cloud"),
            in_flight: Default::default(),
            peak: Default::default(),
            delay: Duration::ZERO,
        }
    }

    /// Load every `*.json` file in `dir` (sorted; not recursive).
    pub fn load(tenant: &str, dir: &Path) -> Result<Self> {
        let gateway = Self::new(tenant);
        let mut files: Vec<_> = std::fs::read_dir(dir)
            .with_context(|| format!("fixture case {}", dir.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .collect();
        files.sort();
        if files.is_empty() {
            bail!("fixture case {} has no JSON files", dir.display());
        }
        for file in files {
            let text = std::fs::read_to_string(&file)?;
            let value: Value = serde_json::from_str(&text)
                .with_context(|| format!("fixture {}", file.display()))?;
            let entries: Vec<FixtureEntry> = match value {
                Value::Array(_) => serde_json::from_value(value),
                _ => serde_json::from_value(value).map(|e| vec![e]),
            }
            .with_context(|| format!("fixture {}", file.display()))?;
            for entry in entries {
                gateway.push(entry)?;
            }
        }
        Ok(gateway)
    }

    /// Load `tests/fixtures/<pack>/<case>`.
    pub fn case(pack: &str, case: &str) -> Result<Self> {
        Self::load(TENANT, &fixtures_root().join(pack).join(case))
    }

    pub fn push(&self, entry: FixtureEntry) -> Result<()> {
        match (&entry.operation, &entry.url) {
            (Some(op), None) if catalog::contains(op) => {}
            (Some(op), None) => bail!("fixture names {op}, which is not in the check catalogue"),
            (None, Some(_)) => {}
            _ => bail!("fixture entry needs exactly one of operation or url"),
        }
        if entry.responses.is_empty() {
            bail!("fixture entry has no responses");
        }
        self.slots
            .lock()
            .expect("slots")
            .push(Slot { entry, served: 0 });
        Ok(())
    }

    /// Builder: answer `operation` with `body`.
    pub fn with(self, operation: &str, body: Value) -> Self {
        self.push(FixtureEntry {
            operation: Some(operation.into()),
            url: None,
            matcher: None,
            responses: vec![FixtureResponse {
                status: 200,
                body,
                error: None,
                retry_after: None,
            }],
        })
        .expect("valid fixture");
        self
    }

    /// Builder: answer `operation` with an HTTP error.
    pub fn with_error(self, operation: &str, status: u16, code: &str) -> Self {
        self.push(FixtureEntry {
            operation: Some(operation.into()),
            url: None,
            matcher: None,
            responses: vec![FixtureResponse {
                status,
                body: Value::Null,
                error: Some(FixtureError {
                    code: Some(code.into()),
                    message: None,
                }),
                retry_after: None,
            }],
        })
        .expect("valid fixture");
        self
    }

    /// Hold each response this long, so concurrency limits can be observed.
    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    pub fn calls(&self) -> Vec<Call> {
        self.calls.lock().expect("calls").clone()
    }

    /// The most calls that were in flight at once.
    pub fn peak_concurrency(&self) -> usize {
        self.peak.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn validate(&self, operation: &str, input: &Value) -> Result<(), GatewayError> {
        let preview = catalog::preview_only(operation);
        let op = self
            .executor
            .registry()
            .resolve(operation, None, preview)
            .map_err(|_| {
                GatewayError::Unavailable(format!("{operation} is not in the check catalogue"))
            })?;
        let route = catalog::route(op, &self.endpoints)
            .map_err(|e| GatewayError::Unavailable(e.to_string()))?;
        self.executor
            .preflight(
                operation,
                input,
                &self.tenant,
                &route.endpoint,
                None,
                preview,
            )
            .map_err(classify_preflight_error)
    }

    fn next(
        &self,
        operation: Option<&str>,
        url: Option<&str>,
        input: &Value,
    ) -> Result<FixtureResponse, GatewayError> {
        let mut slots = self.slots.lock().expect("slots");
        let best = slots
            .iter_mut()
            .filter(|s| match (operation, url) {
                (Some(op), _) => {
                    s.entry.operation.as_deref() == Some(op)
                        && s.entry.matcher.as_ref().is_none_or(|m| contains(input, m))
                }
                (None, Some(u)) => s.entry.url.as_deref() == Some(u),
                _ => false,
            })
            .max_by_key(|s| specificity(&s.entry.matcher));
        let Some(slot) = best else {
            return Err(GatewayError::Unavailable(format!(
                "no fixture for {} with input {}",
                operation.or(url).unwrap_or("?"),
                input
            )));
        };
        let index = slot.served.min(slot.entry.responses.len() - 1);
        slot.served += 1;
        Ok(slot.entry.responses[index].clone())
    }

    async fn serve(
        &self,
        operation: Option<&str>,
        url: Option<&str>,
        input: &Value,
    ) -> Result<Value, GatewayError> {
        use std::sync::atomic::Ordering;
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        let response = self.next(operation, url, input);
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        let response = response?;
        if (200..300).contains(&response.status) {
            return Ok(response.body);
        }
        let error = response.error.unwrap_or(FixtureError {
            code: None,
            message: None,
        });
        Err(GatewayError::Call(CallError {
            kind: FailureKind::Http,
            status: Some(response.status),
            code: error.code,
            message: error.message,
            retry_after: response.retry_after.map(Duration::from_secs),
        }))
    }
}

impl Gateway for FixtureGateway {
    fn tenant_id(&self) -> &str {
        &self.tenant
    }
    fn get<'a>(
        &'a self,
        operation: &'a str,
        input: Value,
    ) -> BoxFut<'a, Result<Value, GatewayError>> {
        Box::pin(async move {
            let input = with_api_version(operation, input);
            self.validate(operation, &input)?;
            self.calls.lock().expect("calls").push(Call {
                operation: operation.into(),
                input: input.clone(),
            });
            self.serve(Some(operation), None, &input).await
        })
    }
    fn list<'a>(
        &'a self,
        operation: &'a str,
        input: Value,
    ) -> BoxFut<'a, Result<Listing, GatewayError>> {
        Box::pin(async move {
            let input = with_api_version(operation, input);
            self.validate(operation, &input)?;
            self.calls.lock().expect("calls").push(Call {
                operation: operation.into(),
                input: input.clone(),
            });
            let mut body = self.serve(Some(operation), None, &input).await?;
            let mut items = vec![];
            let limit = check_policy().limits.max_pages;
            for _ in 0..limit {
                let next = body
                    .get("@odata.nextLink")
                    .or_else(|| body.get("nextLink"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                items.extend(items_of(body));
                match next {
                    None => {
                        return Ok(Listing {
                            items,
                            truncated: false,
                        });
                    }
                    Some(link) => {
                        body = self.serve(None, Some(&link), &Value::Null).await?;
                    }
                }
            }
            Ok(Listing {
                items,
                truncated: true,
            })
        })
    }
}

/// Synthetic-data guard for fixtures: no JWTs and only reserved example domains.
/// Returns one message per problem.
pub fn scan_fixture_text(name: &str, text: &str) -> Vec<String> {
    let mut problems = vec![];
    if text.contains("eyJ") {
        problems.push(format!("{name}: contains a JWT-like `eyJ` value"));
    }
    for domain in domains(text) {
        let allowed = [
            "contoso.example",
            "fabrikam.example",
            "example.org",
            "example.com",
            "example.net",
        ]
        .iter()
        .any(|ok| domain == ok.trim_start_matches('.') || domain.ends_with(ok))
            || MICROSOFT_HOSTS
                .iter()
                .any(|h| domain == *h || domain.ends_with(&format!(".{h}")));
        if !allowed {
            problems.push(format!("{name}: non-synthetic domain {domain}"));
        }
    }
    problems
}

/// Public Microsoft service names that appear in genuine response shapes
/// (DNS targets, documentation links). Tenant-specific names never do.
const MICROSOFT_HOSTS: &[&str] = &[
    "microsoft.com",
    "outlook.com",
    "protection.outlook.com",
    "onmicrosoft.com.example",
    "windows.net",
    "azure.com",
    "office.com",
    "office365.com",
    "microsoftonline.com",
    "loganalytics.io",
    "learn.microsoft.com",
    "graph.microsoft.com",
];

/// Top-level domains that mark a real, registrable name. Reserved names such as
/// `.example`, `.test` and `.invalid` are synthetic by definition.
pub(crate) const REAL_TLDS: &[&str] = &[
    "com", "net", "org", "au", "uk", "nz", "io", "co", "gov", "edu", "info", "biz", "de", "fr",
    "us", "ca", "jp", "cn", "in", "ai", "app", "dev", "cloud", "tech", "me", "eu", "ms", "mil",
];

/// Lower-cased hostnames (also the domain part of e-mail addresses) whose
/// top-level domain is real.
fn domains(text: &str) -> Vec<String> {
    let mut out = vec![];
    for raw in
        text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '@'))
    {
        let candidate = raw
            .rsplit('@')
            .next()
            .unwrap_or(raw)
            .trim_matches(|c| c == '.' || c == '-');
        let lower = candidate.to_ascii_lowercase();
        let parts: Vec<&str> = lower.split('.').collect();
        if parts.len() < 2 || parts.iter().any(|p| p.is_empty()) {
            continue;
        }
        // Check ids (`endpoint.cloud_protection`) are not hostnames.
        let check_id = parts.len() == 2
            && crate::model::Pack::ALL
                .iter()
                .any(|p| p.as_str() == parts[0]);
        if !check_id && REAL_TLDS.contains(&parts[parts.len() - 1]) {
            out.push(lower);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Fail with every problem across all fixture files under `root`.
pub fn scan_fixture_tree(root: &Path) -> Vec<String> {
    let mut problems = vec![];
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(text) = std::fs::read_to_string(&path) {
                problems.extend(scan_fixture_text(&path.display().to_string(), &text));
            }
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn pages_follow_next_links() {
        let gateway = FixtureGateway::new(TENANT);
        gateway
            .push(serde_json::from_value(json!({
                "operation": "graph.users.list",
                "responses": [{"body": {"value": [{"id": "1"}], "@odata.nextLink": "fixture:users-2"}}]
            })).unwrap())
            .unwrap();
        gateway
            .push(
                serde_json::from_value(json!({
                    "url": "fixture:users-2",
                    "responses": [{"body": {"value": [{"id": "2"}]}}]
                }))
                .unwrap(),
            )
            .unwrap();
        let listing = gateway.list("graph.users.list", json!({})).await.unwrap();
        assert_eq!(listing.items, [json!({"id": "1"}), json!({"id": "2"})]);
        assert!(!listing.truncated);
    }

    #[tokio::test]
    async fn throttling_is_retried_by_the_governed_wrapper() {
        use crate::gateway::Governed;
        let gateway = std::sync::Arc::new(FixtureGateway::new(TENANT));
        gateway
            .push(
                serde_json::from_value(json!({
                    "operation": "graph.organization.list",
                    "responses": [
                        {"status": 429, "retry_after": 0, "error": {"code": "TooManyRequests"}},
                        {"status": 503},
                        {"body": {"value": [{"id": "org"}]}}
                    ]
                }))
                .unwrap(),
            )
            .unwrap();
        let governed = Governed::new(
            gateway.clone(),
            2,
            junction_watch::backoff::Backoff::IMMEDIATE,
        );
        let body = governed
            .get("graph.organization.list", json!({}))
            .await
            .unwrap();
        assert_eq!(body["value"][0]["id"], "org");
        assert_eq!(gateway.calls().len(), 3);
    }

    #[tokio::test]
    async fn forbidden_maps_to_call_error_and_missing_fixture_is_clear() {
        let gateway = FixtureGateway::new(TENANT).with_error(
            "graph.users.list",
            403,
            "Authorization_RequestDenied",
        );
        match gateway
            .list("graph.users.list", json!({}))
            .await
            .unwrap_err()
        {
            GatewayError::Call(e) => {
                assert_eq!(e.status, Some(403));
                assert_eq!(e.code.as_deref(), Some("Authorization_RequestDenied"));
            }
            other => panic!("{other}"),
        }
        let missing = gateway
            .get("graph.organization.list", json!({}))
            .await
            .unwrap_err();
        assert!(
            matches!(missing, GatewayError::Unavailable(m) if m.contains("no fixture for graph.organization.list"))
        );
    }

    #[tokio::test]
    async fn fixtures_still_pass_through_registry_and_policy() {
        let gateway = FixtureGateway::new(TENANT).with("graph.users.list", json!({"value": []}));
        // Unknown input fields are rejected by Junction's input validation, before any fixture.
        let error = gateway
            .list("graph.users.list", json!({"parameters": {"$nope": "1"}}))
            .await
            .unwrap_err();
        assert!(
            matches!(error, GatewayError::Unavailable(m) if m.contains("invalid operation input"))
        );
        assert!(
            FixtureGateway::new(TENANT)
                .push(
                    serde_json::from_value(
                        json!({"operation": "graph.users.delete", "responses": [{}]})
                    )
                    .unwrap()
                )
                .is_err()
        );
    }

    #[tokio::test]
    async fn the_most_specific_match_wins() {
        let gateway =
            FixtureGateway::new(TENANT).with("graph.users.list", json!({"value": [{"id": "all"}]}));
        gateway
            .push(
                serde_json::from_value(json!({
                    "operation": "graph.users.list",
                    "match": {"parameters": {"$filter": "accountEnabled eq true"}},
                    "responses": [{"body": {"value": [{"id": "enabled"}]}}]
                }))
                .unwrap(),
            )
            .unwrap();
        let enabled = gateway
            .list(
                "graph.users.list",
                json!({"parameters": {"$filter": "accountEnabled eq true"}}),
            )
            .await
            .unwrap();
        assert_eq!(enabled.items[0]["id"], "enabled");
        let all = gateway.list("graph.users.list", json!({})).await.unwrap();
        assert_eq!(all.items[0]["id"], "all");
    }

    #[test]
    fn scanner_flags_tokens_and_real_domains() {
        assert!(
            scan_fixture_text(
                "a",
                r#"{"upn":"ann@contoso.example","t":"https://graph.microsoft.com/v1.0/users"}"#
            )
            .is_empty()
        );
        assert!(
            scan_fixture_text("a", r##"{"x":"@odata.type","y":"#microsoft.graph.user"}"##)
                .is_empty()
        );
        let bad = scan_fixture_text(
            "a",
            r#"{"upn":"ann@realcustomer.com.au","token":"eyJhbGciOi"}"#,
        );
        assert_eq!(bad.len(), 2, "{bad:?}");
    }

    #[test]
    fn committed_fixtures_are_synthetic() {
        let problems = scan_fixture_tree(&fixtures_root());
        assert!(problems.is_empty(), "{}", problems.join("\n"));
    }
}

/// Optional `case.toml` in a fixture case: tenant facts the fixtures alone do
/// not carry.
///
/// ```toml
/// licences = ["entra_id_p1"]   # omit for "licences unknown"; [] for "none"
/// now = "2026-10-25T00:00:00Z"  # fixed clock (default 2026-10-25)
///
/// [config.checks."identity.global_admin_count"]
/// max = 4
///
/// [[attestations]]
/// check = "identity.break_glass_monitored"
/// answer = "yes"
/// expires_at = "2027-01-01T00:00:00Z"
///
/// [dns."_dmarc.contoso.example"]
/// txt = ["v=DMARC1; p=reject"]
///
/// [dns."fabrikam.example"]
/// fail = ["txt"]               # lookups of these types fail (timeout)
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseSettings {
    /// Tenant id for CLI fixture runs (`junction check run --fixtures`).
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub licences: Option<Vec<String>>,
    #[serde(default)]
    pub now: Option<String>,
    #[serde(default)]
    pub config: crate::config::CheckConfig,
    #[serde(default)]
    pub attestations: Vec<CaseAttestation>,
    #[serde(default)]
    pub dns: std::collections::BTreeMap<String, CaseDns>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseAttestation {
    pub check: String,
    pub answer: String,
    #[serde(default)]
    pub note: String,
    #[serde(default = "default_expiry")]
    pub expires_at: String,
}
fn default_expiry() -> String {
    "2099-01-01T00:00:00.000Z".into()
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseDns {
    #[serde(default)]
    pub txt: Vec<String>,
    #[serde(default)]
    pub cname: Vec<String>,
    #[serde(default)]
    pub mx: Vec<String>,
    /// Record types (`txt`, `cname`, `mx`) whose lookups fail.
    #[serde(default)]
    pub fail: Vec<String>,
}

/// Default fixed clock for fixture runs.
pub const FIXTURE_NOW: &str = "2026-10-25T00:00:00.000Z";

/// Read `case.toml` from a fixture case directory (defaults when absent).
pub fn case_settings(dir: &Path) -> Result<CaseSettings> {
    match std::fs::read_to_string(dir.join("case.toml")) {
        Ok(text) => toml::from_str(&text).with_context(|| format!("{}/case.toml", dir.display())),
        Err(_) => Ok(CaseSettings::default()),
    }
}

/// The fixture gateway and DNS records for a case directory.
pub fn case_gateway(
    tenant: &str,
    dir: &Path,
    settings: &CaseSettings,
) -> Result<(
    std::sync::Arc<dyn crate::gateway::Gateway>,
    std::sync::Arc<dyn crate::dns::Resolver>,
)> {
    let gateway = std::sync::Arc::new(FixtureGateway::load(tenant, dir)?);
    Ok((gateway, std::sync::Arc::new(case_dns(settings)?)))
}

fn case_dns(settings: &CaseSettings) -> Result<crate::dns::StaticDns> {
    use crate::dns::{RecordType, StaticDns};
    let mut dns = StaticDns::new();
    for (name, records) in &settings.dns {
        for (kind, values) in [
            (RecordType::Txt, &records.txt),
            (RecordType::Cname, &records.cname),
            (RecordType::Mx, &records.mx),
        ] {
            if !values.is_empty() {
                let refs: Vec<&str> = values.iter().map(String::as_str).collect();
                dns = dns.with(name, kind, &refs);
            }
        }
        for kind in &records.fail {
            let kind = match kind.as_str() {
                "txt" => RecordType::Txt,
                "cname" => RecordType::Cname,
                "mx" => RecordType::Mx,
                other => bail!("case.toml: unknown DNS type {other}"),
            };
            dns = dns.failing(name, kind);
        }
    }
    Ok(dns)
}

fn case_attestations(
    settings: &CaseSettings,
) -> Result<std::collections::BTreeMap<String, crate::model::Attestation>> {
    let mut attestations = std::collections::BTreeMap::new();
    for a in &settings.attestations {
        attestations.insert(
            a.check.clone(),
            crate::model::Attestation {
                answer: crate::model::Answer::parse(&a.answer)
                    .with_context(|| format!("attestation answer {}", a.answer))?,
                note: a.note.clone(),
                author: "fixture".into(),
                attested_at: FIXTURE_NOW.into(),
                expires_at: a.expires_at.clone(),
            },
        );
    }
    Ok(attestations)
}

/// Build a context for a fixture case directory (fixtures plus `case.toml`).
pub fn case_context(
    dir: &Path,
) -> Result<(crate::context::CheckContext, std::sync::Arc<FixtureGateway>)> {
    let settings = case_settings(dir)?;
    let gateway = std::sync::Arc::new(FixtureGateway::load(TENANT, dir)?);
    let now =
        junction_watch::clock::Instant::parse(settings.now.as_deref().unwrap_or(FIXTURE_NOW))?;
    let ctx = crate::context::CheckContext::new(crate::context::ContextParts {
        tenant_id: TENANT.into(),
        label: None,
        gateway: gateway.clone(),
        licences: settings
            .licences
            .clone()
            .map(|features| crate::model::LicenceSnapshot {
                features,
                skus: vec![],
            }),
        config: std::sync::Arc::new(settings.config.clone()),
        attestations: case_attestations(&settings)?,
        dns: std::sync::Arc::new(case_dns(&settings)?),
        now,
    });
    Ok((ctx, gateway))
}

/// Evaluate the built-in check `check_id` against `tests/fixtures/<pack>/<case>`.
pub async fn run_case(check_id: &str, pack: &str, case: &str) -> crate::model::CheckResult {
    let registry = crate::registry::CheckRegistry::builtin();
    let check = registry
        .get(check_id)
        .unwrap_or_else(|| panic!("{check_id} is not registered"));
    let dir = fixtures_root().join(pack).join(case);
    let (ctx, _) = case_context(&dir).unwrap_or_else(|e| panic!("{}: {e:#}", dir.display()));
    crate::runner::evaluate(registry, check.as_ref(), &ctx, Duration::from_secs(30)).await
}

/// Assert a result's status, showing the evidence when it differs.
#[track_caller]
pub fn assert_status(result: &crate::model::CheckResult, expected: crate::model::Status) {
    assert_eq!(
        result.status, expected,
        "{}: expected {:?}, got {:?}: {} {:?}",
        result.id, expected, result.status, result.evidence.summary, result.reason
    );
}

/// Compare status, evidence, affected and reason with `expected.snap` in the
/// case directory. Set `UPDATE_SNAPSHOTS=1` to (re)write it.
#[track_caller]
pub fn assert_snapshot(result: &crate::model::CheckResult, pack: &str, case: &str) {
    let path = fixtures_root().join(pack).join(case).join("expected.snap");
    let actual = serde_json::to_string_pretty(&serde_json::json!({
        "id": result.id,
        "status": result.status,
        "evidence": result.evidence,
        "affected": result.affected,
        "reason": result.reason,
    }))
    .expect("serialise")
        + "\n";
    if std::env::var_os("UPDATE_SNAPSHOTS").is_some() {
        std::fs::write(&path, &actual).expect("write snapshot");
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "missing snapshot {}; run with UPDATE_SNAPSHOTS=1",
            path.display()
        )
    });
    assert_eq!(expected, actual, "snapshot {} differs", path.display());
}
