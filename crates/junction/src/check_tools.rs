//! `junction_check_*` MCP tools and `/v1/checks` HTTP routes. Execution is the
//! same as `junction check run --format json`; this layer only parses input,
//! keeps background runs and serialises output. Checks are read-only; agents
//! can read pending attestations but submit them only when the operator
//! started the host with `--allow-attest`.
use anyhow::Result;
use junction_check::cli::{RunRequest, Targets};
use junction_check::gateway::{LiveTarget, TokenProvider};
use junction_check::model::{Answer, RunReport};
use junction_check::registry::{CheckRegistry, Selection};
use junction_check::runner::Progress;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Name used for the host's own `--context`/`--context-file` context.
const HOST_CONTEXT: &str = "host-context";
const MAX_BACKGROUND: usize = 32;

/// A safe, structured tool failure.
#[derive(Debug, serde::Serialize)]
pub struct CheckToolError {
    pub status: &'static str,
    pub reason: String,
}
impl std::fmt::Display for CheckToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}
impl std::error::Error for CheckToolError {}

fn fail(status: &'static str, reason: impl Into<String>) -> anyhow::Error {
    CheckToolError {
        status,
        reason: reason.into(),
    }
    .into()
}

#[derive(Clone)]
struct HostEnvironment {
    contexts: PathBuf,
    fixed: Option<Arc<Vec<u8>>>,
}

impl junction_check::cli::Environment for HostEnvironment {
    fn context_names(&self) -> Result<Vec<String>> {
        crate::context_store::list(&self.contexts)
    }
    fn live_target(&self, context: &str) -> Result<LiveTarget> {
        match (&self.fixed, context) {
            (Some(bytes), HOST_CONTEXT) => crate::check_host::live_target(bytes),
            _ => crate::check_host::Environment::new(self.contexts.clone()).live_target(context),
        }
    }
    fn tokens(&self) -> Arc<dyn TokenProvider> {
        crate::check_host::Environment::new(self.contexts.clone()).tokens()
    }
    fn confirm_push(&self, _: &str, _: &str, _: &str) -> Result<()> {
        Err(fail(
            "push_disabled",
            "Pushing results is a CLI-only operator action.",
        ))
    }
}

type Outcome = Arc<Mutex<Option<std::result::Result<RunReport, String>>>>;

struct Background {
    progress: Arc<Progress>,
    outcome: Outcome,
}

pub struct CheckTools {
    env: HostEnvironment,
    history: PathBuf,
    allow_attest: bool,
    runs: Mutex<BTreeMap<String, Background>>,
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

/// Fixture replay for host tests: honoured only with the offline guard on.
fn fixtures() -> Option<PathBuf> {
    let offline = junction_check::gateway::NetworkGuard::from_env()
        == junction_check::gateway::NetworkGuard::Offline;
    std::env::var_os("JUNCTION_CHECK_FIXTURES")
        .filter(|_| offline)
        .map(PathBuf::from)
}

impl CheckTools {
    pub fn new(
        contexts: PathBuf,
        fixed: Option<Vec<u8>>,
        history: PathBuf,
        allow_attest: bool,
    ) -> Self {
        Self {
            env: HostEnvironment {
                contexts,
                fixed: fixed.map(Arc::new),
            },
            history,
            allow_attest,
            runs: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn handles(name: &str) -> bool {
        name.starts_with("junction_check_")
    }

    fn contexts(&self, args: &Value) -> Result<(Vec<String>, Targets)> {
        let mut contexts = strings(&args["contexts"]);
        let all = args["all_contexts"].as_bool().unwrap_or(false);
        if contexts.is_empty() && !all {
            if self.env.fixed.is_none() && fixtures().is_none() {
                return Err(fail(
                    "context_required",
                    "Name contexts (see junction_context) or set all_contexts.",
                ));
            }
            if self.env.fixed.is_some() {
                contexts.push(HOST_CONTEXT.into());
            }
        }
        Ok((
            contexts,
            Targets {
                all_contexts: all,
                tenants: None,
                fixtures: fixtures(),
            },
        ))
    }

    pub async fn call(&self, name: &str, args: Value) -> Result<Value> {
        let registry = CheckRegistry::builtin();
        match name {
            "junction_check_list" => {
                let selection = Selection {
                    packs: strings(&args["packs"])
                        .iter()
                        .filter_map(|p| junction_check::model::Pack::parse(p))
                        .collect(),
                    checks: strings(&args["checks"]),
                    exclude: strings(&args["exclude"]),
                    tags: strings(&args["tags"]),
                };
                let checks = registry
                    .select(&selection)
                    .map_err(|e| fail("invalid_selection", e.to_string()))?;
                Ok(json!({"checks": checks
                    .iter()
                    .map(|c| junction_check::cli::describe(registry, c.id()))
                    .collect::<Vec<_>>()}))
            }
            "junction_check_run" => {
                let (contexts, targets) = self.contexts(&args)?;
                let selection = Selection {
                    packs: strings(&args["packs"])
                        .iter()
                        .filter_map(|p| junction_check::model::Pack::parse(p))
                        .collect(),
                    checks: strings(&args["checks"]),
                    exclude: strings(&args["exclude"]),
                    tags: strings(&args["tags"]),
                };
                registry
                    .select(&selection)
                    .map_err(|e| fail("invalid_selection", e.to_string()))?;
                let env = self.env.clone();
                let history = self.history.clone();
                let progress = Arc::new(Progress::default());
                let run = {
                    let progress = progress.clone();
                    async move {
                        junction_check::cli::execute_run(
                            registry,
                            RunRequest {
                                contexts: &contexts,
                                targets: &targets,
                                selection,
                                config: Default::default(),
                                dns: junction_check::dns::configured(&[])?,
                                parallel: 4,
                                per_host: 4,
                                history: Some((history.as_path(), 365)),
                                progress: Some(progress),
                            },
                            Some(&env),
                        )
                        .await
                    }
                };
                if !args["background"].as_bool().unwrap_or(false) {
                    let report = run
                        .await
                        .map_err(|e| fail("check_run_failed", format!("{e:#}")))?;
                    return Ok(serde_json::to_value(report)?);
                }
                let outcome: Outcome = Arc::new(Mutex::new(None));
                let run_id = junction_check::runner::new_run_id();
                {
                    let mut runs = self.runs.lock().expect("runs");
                    if runs
                        .values()
                        .filter(|r| r.outcome.lock().expect("outcome").is_none())
                        .count()
                        >= 4
                    {
                        return Err(fail(
                            "server_busy",
                            "Four background check runs are already active.",
                        ));
                    }
                    while runs.len() >= MAX_BACKGROUND {
                        let oldest = runs.keys().next().cloned().expect("non-empty");
                        runs.remove(&oldest);
                    }
                    runs.insert(
                        run_id.clone(),
                        Background {
                            progress,
                            outcome: outcome.clone(),
                        },
                    );
                }
                tokio::spawn(async move {
                    let result = run.await.map_err(|e| format!("{e:#}"));
                    *outcome.lock().expect("outcome") = Some(result);
                });
                Ok(json!({"run_id": run_id, "status": "running"}))
            }
            "junction_check_run_status" => {
                let run_id = args["run_id"].as_str().unwrap_or_default();
                if let Some(run) = self.runs.lock().expect("runs").get(run_id) {
                    let (done, total) = run.progress.snapshot();
                    return Ok(match &*run.outcome.lock().expect("outcome") {
                        None => {
                            json!({"run_id": run_id, "status": "running", "progress": {"done": done, "total": total}})
                        }
                        Some(Ok(report)) => {
                            json!({"run_id": run_id, "status": "complete", "report": report})
                        }
                        Some(Err(reason)) => {
                            json!({"run_id": run_id, "status": "failed", "reason": reason})
                        }
                    });
                }
                let Some(context) = args["context"].as_str() else {
                    return Err(fail(
                        "not_found",
                        "No such background run; give a context to look in its history.",
                    ));
                };
                let tenant = self.tenant(context)?;
                let store = junction_check::store::Store::open(&self.history, &tenant)?;
                match store.load_run(run_id)? {
                    Some(stored) => Ok(
                        json!({"run_id": run_id, "status": "complete", "source": "history",
                        "finished_at": stored.finished_at, "tenant": stored.report}),
                    ),
                    None => Err(fail("not_found", "No such run in this context's history.")),
                }
            }
            "junction_check_attestations" => {
                let context = match args["context"].as_str() {
                    Some(c) => c.to_owned(),
                    None if self.env.fixed.is_some() => HOST_CONTEXT.into(),
                    None => {
                        return Err(fail(
                            "context_required",
                            "Name the context to read answers for.",
                        ));
                    }
                };
                let tenant = self.tenant(&context)?;
                let store = junction_check::store::Store::open(&self.history, &tenant)?;
                let now = junction_watch::clock::Instant::now();
                if args["action"] == "submit" {
                    if !self.allow_attest {
                        return Err(fail(
                            "attestation_disabled",
                            "Agents cannot submit attestations unless the operator starts the host with --allow-attest. Ask the operator to run `junction check attest`.",
                        ));
                    }
                    let id = args["check"].as_str().unwrap_or_default();
                    let check = registry
                        .get(id)
                        .filter(|c| c.meta().manual.is_some())
                        .ok_or_else(|| fail("invalid_check", "Not a manual check."))?;
                    let answer = Answer::parse(args["answer"].as_str().unwrap_or_default())
                        .ok_or_else(|| {
                            fail(
                                "invalid_answer",
                                "Answer yes, no, partial or not_applicable.",
                            )
                        })?;
                    let attestation = junction_check::attest::new(
                        answer,
                        args["note"].as_str().unwrap_or_default(),
                        "agent (host --allow-attest)",
                        now,
                        junction_check::attest::DEFAULT_EXPIRY_DAYS,
                    )?;
                    store.put_attestation(check.id(), &attestation)?;
                    return Ok(
                        json!({"status": "recorded", "check": check.id(), "attestation": attestation}),
                    );
                }
                let stored = store.attestations()?;
                Ok(json!({"pending": junction_check::attest::pending(registry, &stored, now)}))
            }
            _ => Err(fail("unknown_tool", "Unknown check tool.")),
        }
    }

    fn tenant(&self, context: &str) -> Result<String> {
        if let Some(dir) = fixtures() {
            return Ok(junction_check::testkit::case_settings(&dir.join(context))?
                .tenant_id
                .unwrap_or_else(|| junction_check::testkit::TENANT.into()));
        }
        use junction_check::cli::Environment as _;
        Ok(self.env.live_target(context)?.tenant_id)
    }
}
