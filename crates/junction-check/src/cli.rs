//! `junction check`: run read-only posture checks against one or many tenants.
//!
//! The command logic lives here; the `junction` binary supplies an
//! [`Environment`] (named contexts, credentials, terminal) and prints the output.
use crate::attest;
use crate::config::CheckConfig;
use crate::dns::Resolver;
use crate::gateway::{Gateway, LiveGateway, LiveTarget, NetworkGuard, TokenProvider};
use crate::model::{Answer, Pack, Reason, RunReport, Severity, TenantStatus};
use crate::registry::{CheckRegistry, Selection};
use crate::report::{self, ReportOptions};
use crate::runner::{self, RunOptions, TenantPlan};
use crate::store::Store;
use crate::testkit;
use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand, ValueEnum};
use junction_watch::clock::Instant;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Exit codes (documented in docs/CHECKS.md).
pub mod exit {
    /// Every tenant assessed, no threshold breached.
    pub const OK: i32 = 0;
    /// `--fail-on`, `--min-score` or `--fail-on-regression` breached.
    pub const THRESHOLD: i32 = 1;
    /// The run could not start or no tenant could be assessed (auth, config).
    pub const ERROR: i32 = 2;
    /// Some tenants or checks could not run (without `--allow-partial`).
    pub const PARTIAL: i32 = 3;
}

#[derive(Args, Debug)]
#[command(after_help = "Examples:
  junction check run --context contoso --pack identity,endpoint --fail-on high
  junction check run --all-contexts --format html --output posture.html
  junction check run --tenants customers.toml --context partner --min-score 70 --allow-partial
  junction check list --tag e8:ml1
  junction check permissions --pack sentinel
  junction check explain identity.mfa_coverage
  junction check attest backup.restore_tested --answer yes --note \"Restore tested 2026-09-30\" --context contoso

Exit codes: 0 all good, 1 threshold breached, 2 run error, 3 partial (some tenants or checks could not run) unless --allow-partial.
Checks are read-only and always run under Junction's read-only policy, whatever policy a context uses.")]
pub struct CheckArgs {
    #[command(subcommand)]
    pub command: CheckCommand,
}

#[derive(Subcommand, Debug)]
pub enum CheckCommand {
    /// Run checks against the selected tenants.
    Run(Box<RunArgs>),
    /// List checks with severity, tags and required permissions.
    List(ListArgs),
    /// Print the least-privilege permissions the selected checks need.
    Permissions(ListArgs),
    /// Explain what a check reads, why, and how to fix a failure.
    Explain { id: String },
    /// Record a person's answer to a manual check, or work through pending ones.
    Attest(AttestArgs),
    /// List stored runs with scores.
    History(HistoryArgs),
    /// Show what changed since a previous run.
    Diff(DiffArgs),
    /// Regenerate the generated tables in docs/ (or verify them with --check).
    #[command(hide = true)]
    Docs {
        #[arg(long, default_value = "docs")]
        dir: PathBuf,
        #[arg(long)]
        check: bool,
    },
    /// Turn a recorded API response on stdin into a synthetic fixture entry.
    #[command(hide = true)]
    ScrubFixture {
        #[arg(long)]
        operation: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Table,
    Json,
    Markdown,
    Html,
    #[value(name = "m365-secure-json")]
    M365SecureJson,
}

#[derive(Args, Debug, Clone, Default)]
pub struct Targets {
    /// Assess every named context.
    #[arg(long)]
    pub all_contexts: bool,
    /// TOML file mapping tenant ids to a context and label (delegated access).
    #[arg(long, value_name = "FILE")]
    pub tenants: Option<PathBuf>,
    /// Replay recorded fixtures from DIR/<context>/ instead of calling Microsoft.
    #[arg(long, hide = true, value_name = "DIR")]
    pub fixtures: Option<PathBuf>,
}

#[derive(Args, Debug, Clone, Default)]
pub struct Filters {
    /// Packs to run (comma separated): identity, endpoint, intune, email, backup, sentinel, apps, collaboration, azure.
    #[arg(long, value_delimiter = ',')]
    pub pack: Vec<String>,
    /// Exact check ids to run (repeatable).
    #[arg(long = "check")]
    pub checks: Vec<String>,
    /// Check ids to skip (repeatable).
    #[arg(long)]
    pub exclude: Vec<String>,
    /// Framework tag selectors: e8, e8:ml2, e8:mfa:ml1, ism:ISM-1504, cis:1.1.3, cisv8:6.5, nist:PR.AA-03, mitre:T1078.
    #[arg(long = "tag")]
    pub tags: Vec<String>,
}

impl Filters {
    pub fn selection(&self) -> Result<Selection> {
        Ok(Selection {
            packs: self
                .pack
                .iter()
                .map(|p| Pack::parse(p.trim()).with_context(|| format!("unknown pack {p}")))
                .collect::<Result<_>>()?,
            checks: self.checks.clone(),
            exclude: self.exclude.clone(),
            tags: self.tags.clone(),
        })
    }
}

#[derive(Args, Debug, Clone)]
pub struct RunArgs {
    #[command(flatten)]
    pub targets: Targets,
    #[command(flatten)]
    pub filters: Filters,
    #[arg(long, value_enum, default_value = "table")]
    pub format: Format,
    /// Write the report to a file (or a directory with --split).
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// One file per tenant in the --output directory (markdown, html, json).
    #[arg(long, requires = "output")]
    pub split: bool,
    /// Exit 1 when any check fails at or above this severity.
    #[arg(long, value_name = "SEVERITY", value_parser = ["critical", "high", "medium", "low", "info"])]
    pub fail_on: Option<String>,
    /// Exit 1 when any assessed tenant scores below this.
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=100))]
    pub min_score: Option<u8>,
    /// Exit 1 when anything regressed since the previous stored run.
    #[arg(long)]
    pub fail_on_regression: bool,
    /// Do not exit 3 when some tenants or checks could not run.
    #[arg(long)]
    pub allow_partial: bool,
    /// Show passing checks in the table output.
    #[arg(long)]
    pub show_passes: bool,
    /// Thresholds and pack settings (TOML).
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Tenants assessed at once.
    #[arg(long, default_value_t = 4, value_parser = clap::value_parser!(u16).range(1..=32))]
    pub parallel: u16,
    /// Concurrent requests per API host within a tenant.
    #[arg(long, default_value_t = 4, value_parser = clap::value_parser!(u16).range(1..=16))]
    pub per_host: u16,
    /// DNS servers for the email pack (IP or IP:port, repeatable). Default: the system resolver.
    #[arg(long = "dns-server")]
    pub dns_servers: Vec<String>,
    #[command(flatten)]
    pub history: HistoryLocation,
    /// Do not store this run or compare it with the previous one.
    #[arg(long, conflicts_with = "fail_on_regression")]
    pub no_history: bool,
    /// Delete stored runs older than this many days (the latest run is always kept).
    #[arg(long, default_value_t = 365)]
    pub retention_days: u32,
    /// Report title.
    #[arg(long)]
    pub title: Option<String>,
    /// Organisation name shown in reports.
    #[arg(long)]
    pub organisation: Option<String>,
    /// PNG, JPEG or SVG logo embedded in HTML reports.
    #[arg(long)]
    pub logo: Option<PathBuf>,
    #[command(flatten)]
    pub push: PushArgs,
}

#[derive(Args, Debug, Clone, Default)]
pub struct PushArgs {
    /// Also send results to your own Log Analytics custom table (the only write; opt-in).
    #[arg(long, requires_all = ["dce", "dcr", "stream"])]
    pub push_sentinel: bool,
    /// Data collection endpoint logs ingestion URL.
    #[arg(long, requires = "push_sentinel")]
    pub dce: Option<String>,
    /// Data collection rule immutable id (dcr-...).
    #[arg(long, requires = "push_sentinel")]
    pub dcr: Option<String>,
    /// Stream name, for example Custom-JunctionCheck_CL.
    #[arg(long, requires = "push_sentinel")]
    pub stream: Option<String>,
    /// Context whose credential sends the rows (audience https://monitor.azure.com).
    #[arg(long, requires = "push_sentinel")]
    pub push_context: Option<String>,
    /// Policy file that allows azure.monitor.logs_ingestion.upload.
    #[arg(long, requires = "push_sentinel", conflicts_with = "approve_push")]
    pub push_policy: Option<PathBuf>,
    /// Approve the push on this terminal instead of with a policy file.
    #[arg(long, requires = "push_sentinel")]
    pub approve_push: bool,
}

#[derive(Args, Debug, Clone)]
pub struct HistoryLocation {
    /// Directory holding one history database per tenant.
    #[arg(long, default_value = ".junction/check-history")]
    pub history_dir: PathBuf,
}

#[derive(Args, Debug, Clone)]
pub struct ListArgs {
    #[command(flatten)]
    pub filters: Filters,
    #[arg(long, value_enum, default_value = "table")]
    pub format: Format,
}

#[derive(Args, Debug, Clone)]
pub struct AttestArgs {
    /// Manual check id. Omit with --pending.
    pub id: Option<String>,
    #[arg(long, value_parser = ["yes", "no", "partial", "not_applicable"], required_unless_present = "pending")]
    pub answer: Option<String>,
    /// Evidence note or link.
    #[arg(long, default_value = "")]
    pub note: String,
    /// Who is answering (default: the operating system user).
    #[arg(long)]
    pub author: Option<String>,
    #[arg(long, default_value_t = attest::DEFAULT_EXPIRY_DAYS)]
    pub expires_days: u32,
    /// List manual checks without a current answer; answer them interactively on a terminal.
    #[arg(long, conflicts_with_all = ["id", "answer"])]
    pub pending: bool,
    #[command(flatten)]
    pub targets: Targets,
    #[command(flatten)]
    pub history: HistoryLocation,
}

#[derive(Args, Debug, Clone)]
pub struct HistoryArgs {
    #[command(flatten)]
    pub targets: Targets,
    #[command(flatten)]
    pub history: HistoryLocation,
    #[arg(long, default_value_t = 20)]
    pub limit: u32,
}

#[derive(Args, Debug, Clone)]
pub struct DiffArgs {
    #[command(flatten)]
    pub targets: Targets,
    #[command(flatten)]
    pub history: HistoryLocation,
    /// Compare the latest run with this run id or date (YYYY-MM-DD). Default: the run before it.
    #[arg(long)]
    pub since: Option<String>,
    #[arg(long, value_enum, default_value = "table")]
    pub format: Format,
}

/// What the `junction` binary provides.
pub trait Environment: Send + Sync {
    /// Every named context.
    fn context_names(&self) -> Result<Vec<String>>;
    /// Tenant, cloud and credential of a named context (no secrets).
    fn live_target(&self, context: &str) -> Result<LiveTarget>;
    fn tokens(&self) -> Arc<dyn TokenProvider>;
    /// Ask the operator to approve the Sentinel push on the controlling terminal.
    fn confirm_push(&self, context: &str, endpoint: &str, summary: &str) -> Result<()>;
}

/// `--tenants` file: one entry per tenant, each naming the context whose
/// credential reaches it. With partner (delegated) access one context covers
/// many tenant ids; with per-tenant app consent each entry names its own context.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantsFile {
    pub tenant: Vec<TenantEntry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantEntry {
    pub id: String,
    /// Context to use; defaults to the single `--context`.
    #[serde(default)]
    pub context: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
}

/// One tenant to assess, before its gateway is built.
#[derive(Debug, Clone)]
pub struct Target {
    pub context: String,
    /// Tenant id override (tenants file); `None` uses the context's tenant.
    pub tenant_id: Option<String>,
    pub label: Option<String>,
}

pub fn targets(contexts: &[String], args: &Targets, env: Option<&dyn Environment>) -> Result<Vec<Target>> {
    if let Some(path) = &args.tenants {
        let text = std::fs::read_to_string(path).context("reading the tenants file")?;
        let file: TenantsFile = toml::from_str(&text).context("invalid tenants file")?;
        if file.tenant.is_empty() || file.tenant.len() > 1000 {
            bail!("the tenants file must list between 1 and 1000 tenants");
        }
        return file
            .tenant
            .into_iter()
            .map(|t| {
                junction_watch::store::validate_tenant(&t.id)?;
                let context = match (t.context, contexts) {
                    (Some(c), _) => c,
                    (None, [only]) => only.clone(),
                    (None, _) => bail!("tenant {} needs a context (or pass exactly one --context)", t.id),
                };
                Ok(Target {
                    context,
                    tenant_id: Some(t.id),
                    label: t.label,
                })
            })
            .collect();
    }
    let names: Vec<String> = if args.all_contexts {
        if !contexts.is_empty() {
            bail!("use either --context or --all-contexts");
        }
        match (&args.fixtures, env) {
            (Some(dir), _) => fixture_contexts(dir)?,
            (None, Some(env)) => env.context_names()?,
            (None, None) => vec![],
        }
    } else {
        contexts.to_vec()
    };
    if names.is_empty() {
        bail!("select tenants with --context NAME, --all-contexts or --tenants FILE");
    }
    Ok(names
        .into_iter()
        .map(|context| Target {
            context,
            tenant_id: None,
            label: None,
        })
        .collect())
}

fn fixture_contexts(dir: &Path) -> Result<Vec<String>> {
    let mut names: Vec<String> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().to_str().map(str::to_owned))
        .collect();
    names.sort();
    Ok(names)
}

fn safe_context_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 80
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        || name.starts_with('.')
    {
        bail!("invalid context name");
    }
    Ok(())
}

/// A planned tenant with its gateway (or the reason none could be built).
pub struct Planned {
    pub plan: TenantPlan,
    /// DNS records from a fixture case (testing only).
    pub dns: Option<Arc<dyn Resolver>>,
}

/// Build gateways for every target.
pub fn plan(targets: &[Target], args: &Targets, env: Option<&dyn Environment>) -> Result<Vec<Planned>> {
    targets
        .iter()
        .map(|target| {
            safe_context_name(&target.context)?;
            if let Some(dir) = &args.fixtures {
                let case = dir.join(&target.context);
                let settings = testkit::case_settings(&case)?;
                let tenant_id = target
                    .tenant_id
                    .clone()
                    .or(settings.tenant_id.clone())
                    .unwrap_or_else(|| testkit::TENANT.to_owned());
                let (ctx_gateway, dns) = testkit::case_gateway(&tenant_id, &case, &settings)?;
                return Ok(Planned {
                    plan: TenantPlan {
                        tenant_id,
                        label: target.label.clone().or(settings.label.clone()),
                        gateway: Ok(ctx_gateway),
                        attestations: BTreeMap::new(),
                    },
                    dns: Some(dns),
                });
            }
            let env = env.context("named contexts are unavailable")?;
            let built = env.live_target(&target.context).and_then(|mut live| {
                if let Some(id) = &target.tenant_id {
                    live.tenant_id = id.clone();
                }
                junction_watch::store::validate_tenant(&live.tenant_id)?;
                Ok(live)
            });
            let (tenant_id, gateway) = match built {
                Ok(live) => {
                    let tenant = live.tenant_id.clone();
                    let gateway = LiveGateway::new(live, env.tokens(), NetworkGuard::from_env())
                        .map(|g| Arc::new(g) as Arc<dyn Gateway>)
                        .map_err(|_| Reason::new("context_invalid", "The context's cloud endpoints are invalid."));
                    (tenant, gateway)
                }
                Err(_) => (
                    target.tenant_id.clone().unwrap_or_else(|| target.context.clone()),
                    Err(Reason::new(
                        "context_invalid",
                        format!(
                            "Context {} could not be used for checks. Use a cloud context (`junction context add`) with a tenant id, cloud and credential profile.",
                            target.context
                        ),
                    )),
                ),
            };
            Ok(Planned {
                plan: TenantPlan {
                    tenant_id,
                    label: target.label.clone().or_else(|| Some(target.context.clone())),
                    gateway,
                    attestations: BTreeMap::new(),
                },
                dns: None,
            })
        })
        .collect()
}

fn open_store(dir: &Path, tenant: &str) -> Result<Option<Store>> {
    if junction_watch::store::validate_tenant(tenant).is_err() {
        return Ok(None);
    }
    Store::open(dir, tenant).map(Some)
}

fn write_output(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let temp = parent.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("report")
    ));
    std::fs::write(&temp, bytes)?;
    std::fs::rename(&temp, path)?;
    Ok(())
}

fn report_options(args: &RunArgs) -> Result<ReportOptions> {
    let logo = match &args.logo {
        None => None,
        Some(path) => {
            let mime = match path.extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase).as_deref() {
                Some("png") => "image/png",
                Some("jpg" | "jpeg") => "image/jpeg",
                Some("svg") => "image/svg+xml",
                _ => bail!("the logo must be a .png, .jpg or .svg file"),
            };
            let bytes = std::fs::read(path).context("reading the logo")?;
            if bytes.len() > 512 * 1024 {
                bail!("the logo must be at most 512 KiB");
            }
            Some((mime.to_owned(), bytes))
        }
    };
    Ok(ReportOptions {
        title: args.title.clone(),
        organisation: args.organisation.clone(),
        logo,
    })
}

/// Render a report in `format`.
pub fn render(report: &RunReport, format: Format, options: &ReportOptions, show_passes: bool) -> Result<String> {
    Ok(match format {
        Format::Table => report::table::render(report, show_passes),
        Format::Json => serde_json::to_string_pretty(report)? + "\n",
        Format::Markdown => report::markdown::render(report, options),
        Format::Html => report::html::render(report, options),
        Format::M365SecureJson => serde_json::to_string_pretty(&report::m365_secure::render(report))? + "\n",
    })
}

/// The exit code for a finished run.
pub fn exit_code(report: &RunReport, args: &RunArgs) -> i32 {
    if !report.tenants.is_empty() && report.tenants.iter().all(|t| t.status == TenantStatus::Failed) {
        return exit::ERROR;
    }
    let threshold = args.fail_on.as_deref().and_then(Severity::parse);
    let breached = report.tenants.iter().any(|t| {
        threshold.is_some_and(|s| {
            t.results
                .iter()
                .any(|r| r.status == crate::model::Status::Fail && r.severity.at_least(s))
        }) || args
            .min_score
            .is_some_and(|min| t.score.score.is_some_and(|score| score < f64::from(min)))
            || (args.fail_on_regression && t.diff.as_ref().is_some_and(|d| d.regressed()))
    });
    if breached {
        exit::THRESHOLD
    } else if report.partial() && !args.allow_partial {
        exit::PARTIAL
    } else {
        exit::OK
    }
}

/// Everything a run needs besides the registry and environment.
pub struct RunRequest<'a> {
    /// `--context` values.
    pub contexts: &'a [String],
    pub targets: &'a Targets,
    pub selection: Selection,
    pub config: CheckConfig,
    pub dns: Arc<dyn Resolver>,
    pub parallel: usize,
    pub per_host: usize,
    /// History directory and retention in days; `None` disables history.
    pub history: Option<(&'a Path, u32)>,
    pub progress: Option<Arc<runner::Progress>>,
}

/// Run checks and return the report (shared by the CLI, MCP and HTTP).
pub async fn execute_run(
    registry: &CheckRegistry,
    request: RunRequest<'_>,
    env: Option<&dyn Environment>,
) -> Result<RunReport> {
    let RunRequest {
        contexts,
        targets: targets_args,
        selection,
        config,
        dns,
        parallel,
        per_host,
        history,
        progress,
    } = request;
    // Fail fast on a bad selection before resolving credentials.
    registry.select(&selection)?;
    let resolved = targets(contexts, targets_args, env)?;
    let mut planned = plan(&resolved, targets_args, env)?;
    let now = match &targets_args.fixtures {
        Some(_) => Instant::parse(testkit::FIXTURE_NOW)?,
        None => Instant::now(),
    };
    if let Some((dir, _)) = history {
        for p in &mut planned {
            if let Some(store) = open_store(dir, &p.plan.tenant_id)? {
                p.plan.attestations = store.attestations()?;
            }
        }
    }
    // Fixture runs carry their own DNS records; the first one applies.
    let dns = planned.iter().find_map(|p| p.dns.clone()).unwrap_or(dns);
    let options = RunOptions {
        selection,
        parallel,
        per_host,
        config: Arc::new(config),
        dns,
        now,
        run_id: targets_args.fixtures.as_ref().map(|_| "fixture-run".to_owned()),
        progress,
        ..RunOptions::default()
    };
    let mut report = runner::run(registry, planned.into_iter().map(|p| p.plan).collect(), &options).await?;
    if let Some((dir, retention)) = history {
        for tenant in &mut report.tenants {
            if tenant.status == TenantStatus::Failed {
                continue;
            }
            let Some(store) = open_store(dir, &tenant.tenant_id)? else {
                continue;
            };
            if let Some(previous) = store.latest()? {
                tenant.diff = Some(crate::history::diff(
                    &previous.run_id,
                    &previous.finished_at,
                    &previous.report,
                    tenant,
                ));
            }
            store.save_run(&report.run_id, &report.started_at, &report.finished_at, tenant)?;
            store.prune(retention, now)?;
        }
    }
    Ok(report)
}

/// Run a `junction check` command and return its exit code.
pub async fn run(args: CheckArgs, contexts: Vec<String>, env: &dyn Environment, out: &mut dyn Write) -> Result<i32> {
    let registry = CheckRegistry::builtin();
    match args.command {
        CheckCommand::Run(args) => {
            let selection = args.filters.selection()?;
            let config = match &args.config {
                Some(path) => CheckConfig::parse_toml(&std::fs::read_to_string(path).context("reading --config")?)?,
                None => CheckConfig::default(),
            };
            let options = report_options(&args)?;
            if args.split && !matches!(args.format, Format::Markdown | Format::Html | Format::Json) {
                bail!("--split works with markdown, html or json");
            }
            let dns: Arc<dyn Resolver> = crate::dns::configured(&args.dns_servers)?;
            let history = (!args.no_history).then_some((args.history.history_dir.as_path(), args.retention_days));
            let push = push_plan(&args.push, env)?;
            let report = execute_run(
                registry,
                RunRequest {
                    contexts: &contexts,
                    targets: &args.targets,
                    selection,
                    config,
                    dns,
                    parallel: usize::from(args.parallel),
                    per_host: usize::from(args.per_host),
                    history,
                    progress: None,
                },
                Some(env),
            )
            .await?;
            if let Some(push) = push {
                push.send(&report, env).await?;
            }
            if args.split {
                let dir = args.output.as_ref().expect("clap requires --output");
                std::fs::create_dir_all(dir)?;
                let extension = match args.format {
                    Format::Html => "html",
                    Format::Markdown => "md",
                    _ => "json",
                };
                for (stem, part) in report::html::split(&report) {
                    let text = render(&part, args.format, &options, args.show_passes)?;
                    write_output(&dir.join(format!("{stem}.{extension}")), text.as_bytes())?;
                }
            } else {
                let text = render(&report, args.format, &options, args.show_passes)?;
                match &args.output {
                    Some(path) => write_output(path, text.as_bytes())?,
                    None => out.write_all(text.as_bytes())?,
                }
            }
            Ok(exit_code(&report, &args))
        }
        CheckCommand::List(args) => {
            let checks = registry.select(&args.filters.selection()?)?;
            let text = match args.format {
                Format::Json => serde_json::to_string_pretty(&checks.iter().map(|c| describe(registry, c.id())).collect::<Vec<_>>())? + "\n",
                Format::Markdown => report::coverage::checks_markdown(registry),
                _ => list_table(registry, &checks),
            };
            out.write_all(text.as_bytes())?;
            Ok(exit::OK)
        }
        CheckCommand::Permissions(args) => {
            let checks = registry.select(&args.filters.selection()?)?;
            let rows = report::coverage::permissions(registry, &checks);
            let text = match args.format {
                Format::Json => serde_json::to_string_pretty(&rows)? + "\n",
                Format::Markdown => report::coverage::permissions_markdown(&rows),
                _ => rows
                    .iter()
                    .map(|r| format!("{:<45} {}\n", r.permission, r.kind))
                    .collect(),
            };
            out.write_all(text.as_bytes())?;
            Ok(exit::OK)
        }
        CheckCommand::Explain { id } => {
            let check = registry.get(&id).with_context(|| format!("unknown check id {id}"))?;
            out.write_all(explain(registry, check.as_ref()).as_bytes())?;
            Ok(exit::OK)
        }
        CheckCommand::Attest(args) => attest_command(registry, &contexts, args, env, out).await,
        CheckCommand::History(args) => {
            for target in targets(&contexts, &args.targets, Some(env))? {
                let tenant = tenant_of(&target, &args.targets, env)?;
                let Some(store) = open_store(&args.history.history_dir, &tenant)? else { continue };
                writeln!(out, "{} ({tenant})", target.label.as_deref().unwrap_or(&target.context))?;
                for run in store.runs(args.limit)? {
                    writeln!(
                        out,
                        "  {}  {}  score {}  fail {} warn {} unknown {}",
                        run.finished_at,
                        run.run_id,
                        run.score.map(|s| format!("{s:.1}")).unwrap_or_else(|| "-".into()),
                        run.statuses.fail,
                        run.statuses.warn,
                        run.statuses.unknown
                    )?;
                }
            }
            Ok(exit::OK)
        }
        CheckCommand::Diff(args) => {
            let mut diffs = vec![];
            for target in targets(&contexts, &args.targets, Some(env))? {
                let tenant = tenant_of(&target, &args.targets, env)?;
                let store = open_store(&args.history.history_dir, &tenant)?.context("invalid tenant id")?;
                let latest = store.latest()?.context("no stored runs for this tenant")?;
                let previous = match args.since.as_deref() {
                    None => store.latest_before(&latest.finished_at)?,
                    Some(s) if s.len() == 10 && s.as_bytes()[4] == b'-' => store.run_at_or_before_date(s)?,
                    Some(run_id) => store.load_run(run_id)?,
                }
                .context("no earlier run to compare with")?;
                let diff = crate::history::diff(&previous.run_id, &previous.finished_at, &previous.report, &latest.report);
                diffs.push(json!({"tenant_id": tenant, "label": target.label, "latest_run_id": latest.run_id, "diff": diff}));
            }
            let text = match args.format {
                Format::Json => serde_json::to_string_pretty(&diffs)? + "\n",
                _ => diffs.iter().map(diff_text).collect(),
            };
            out.write_all(text.as_bytes())?;
            Ok(exit::OK)
        }
        CheckCommand::Docs { dir, check } => {
            let stale = crate::docs::sync(registry, &dir, check)?;
            if check && !stale.is_empty() {
                bail!("generated docs are stale: {} (run `junction check docs`)", stale.join(", "));
            }
            Ok(exit::OK)
        }
        CheckCommand::ScrubFixture { operation } => {
            if !crate::catalog::contains(&operation) {
                bail!("{operation} is not in the check catalogue");
            }
            let mut input = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin().take(32 * 1024 * 1024), &mut input)?;
            let value: Value = serde_json::from_str(&input).context("stdin is not JSON")?;
            // Accept `junction execute` output ({"status", "body", ...}) or a bare body.
            let (status, body) = match (value.get("status").and_then(Value::as_u64), value.get("body")) {
                (Some(status), Some(body)) => (status, body.clone()),
                _ => (200, value),
            };
            let body = crate::scrub::Scrubber::new().scrub(&body);
            let entry = json!({"operation": operation, "responses": [{"status": status, "body": body}]});
            out.write_all((serde_json::to_string_pretty(&entry)? + "\n").as_bytes())?;
            Ok(exit::OK)
        }
    }
}

use std::io::Read as _;

fn tenant_of(target: &Target, args: &Targets, env: &dyn Environment) -> Result<String> {
    if let Some(id) = &target.tenant_id {
        return Ok(id.clone());
    }
    if let Some(dir) = &args.fixtures {
        return Ok(testkit::case_settings(&dir.join(&target.context))?
            .tenant_id
            .unwrap_or_else(|| testkit::TENANT.to_owned()));
    }
    Ok(env.live_target(&target.context)?.tenant_id)
}

fn diff_text(entry: &Value) -> String {
    let d = &entry["diff"];
    let list = |key: &str| {
        d[key]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "none".into())
    };
    format!(
        "{} since {}\n  score change: {}\n  new failures: {}\n  fixed: {}\n  added: {}\n  removed: {}\n  other changes: {}\n",
        entry["label"].as_str().or(entry["tenant_id"].as_str()).unwrap_or("tenant"),
        d["previous_finished_at"].as_str().unwrap_or("?"),
        d["score_delta"].as_f64().map(|v| format!("{v:+.1}")).unwrap_or_else(|| "n/a".into()),
        list("new_failures"),
        list("fixed"),
        list("added"),
        list("removed"),
        d["changed"].as_array().map(|a| a.len()).unwrap_or(0)
    )
}

/// Structured description of a check (list --format json, explain, MCP).
pub fn describe(registry: &CheckRegistry, id: &str) -> Value {
    let Some(check) = registry.get(id) else {
        return Value::Null;
    };
    let m = check.meta();
    json!({
        "id": m.id,
        "title": m.title,
        "pack": m.pack,
        "kind": m.kind,
        "severity": m.severity,
        "effort": m.effort,
        "impact": m.impact,
        "description": m.description,
        "reads": m.requires.apis.iter().map(|a| json!({"operation": a.operation, "permissions": a.permissions})).collect::<Vec<_>>(),
        "licences": m.requires.licences,
        "remediation": m.remediation,
        "links": m.links,
        "references": m.references,
        "question": m.manual.map(|q| q.question),
        "guidance": m.manual.map(|q| q.guidance),
        "why_manual": m.manual.map(|q| q.why_manual),
        "tags": registry.tags(m.id),
    })
}

fn list_table(registry: &CheckRegistry, checks: &[Arc<dyn crate::check::Check>]) -> String {
    let mut text = String::new();
    for check in checks {
        let m = check.meta();
        let permissions: Vec<&str> = m.requires.apis.iter().flat_map(|a| a.permissions.iter().copied()).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
        let tags = registry.tags(m.id);
        let e8: Vec<String> = tags.essential_eight.iter().map(|t| t.strategy.clone()).collect();
        text.push_str(&format!(
            "{:<42} {:<8} {:<9} {}\n    {}\n    permissions: {}{}\n",
            m.id,
            m.severity.as_str(),
            if m.kind == crate::model::CheckKind::Manual { "manual" } else { "automated" },
            if e8.is_empty() { String::new() } else { format!("E8: {}", e8.join(", ")) },
            m.title,
            if permissions.is_empty() { "none (attested)".to_owned() } else { permissions.join(", ") },
            if m.requires.licences.is_empty() { String::new() } else { format!("\n    licences: {}", m.requires.licences.join(", ")) },
        ));
    }
    text
}

fn explain(registry: &CheckRegistry, check: &dyn crate::check::Check) -> String {
    let m = check.meta();
    let mut text = format!("{} ({})\n{}\n\nWhy: {}\n", m.id, m.severity.as_str(), m.title, m.description);
    if let Some(manual) = m.manual {
        text.push_str(&format!(
            "\nManual check: {}\nWhy manual: {}\nAnswer with: junction check attest {} --answer yes|no|partial|not_applicable --note \"...\"\n",
            manual.question, manual.why_manual, m.id
        ));
    }
    if !m.requires.apis.is_empty() {
        text.push_str("\nReads (read-only):\n");
        for api in m.requires.apis {
            text.push_str(&format!("  {}  needs {}\n", api.operation, api.permissions.join(" or ")));
        }
    }
    if !m.requires.licences.is_empty() {
        text.push_str(&format!("Licences: {}\n", m.requires.licences.join(", ")));
    }
    text.push_str(&format!("\nTo fix a failure (suggestion only):\n  {}\n", m.remediation));
    for link in m.links {
        text.push_str(&format!("  {link}\n"));
    }
    let tags = registry.tags(m.id);
    text.push_str(&format!("\nTags: {}\n", serde_json::to_string(&tags).unwrap_or_default()));
    text
}

async fn attest_command(
    registry: &CheckRegistry,
    contexts: &[String],
    args: AttestArgs,
    env: &dyn Environment,
    out: &mut dyn Write,
) -> Result<i32> {
    let now = match &args.targets.fixtures {
        Some(_) => Instant::parse(testkit::FIXTURE_NOW)?,
        None => Instant::now(),
    };
    let author = args
        .author
        .clone()
        .or_else(|| std::env::var("USER").ok())
        .or_else(|| std::env::var("USERNAME").ok())
        .unwrap_or_else(|| "operator".into());
    for target in targets(contexts, &args.targets, Some(env))? {
        let tenant = tenant_of(&target, &args.targets, env)?;
        let store = open_store(&args.history.history_dir, &tenant)?.context("invalid tenant id")?;
        if args.pending {
            let stored = store.attestations()?;
            let pending = attest::pending(registry, &stored, now);
            writeln!(out, "{} ({tenant}): {} pending", target.label.as_deref().unwrap_or(&target.context), pending.len())?;
            let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
            for item in pending {
                writeln!(out, "\n{} [{}]\n  {}\n  {}", item.check_id, item.status.as_str(), item.question, item.guidance)?;
                if !interactive {
                    continue;
                }
                write!(out, "  Answer (yes/no/partial/not_applicable, blank to skip): ")?;
                out.flush()?;
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                let Some(answer) = Answer::parse(answer.trim()) else { continue };
                write!(out, "  Evidence note or link: ")?;
                out.flush()?;
                let mut note = String::new();
                std::io::stdin().read_line(&mut note)?;
                let a = attest::new(answer, note.trim(), &author, now, args.expires_days)?;
                store.put_attestation(&item.check_id, &a)?;
                writeln!(out, "  Recorded; expires {}.", a.expires_at)?;
            }
            continue;
        }
        let id = args.id.as_deref().context("give a check id or --pending")?;
        let check = registry.get(id).with_context(|| format!("unknown check id {id}"))?;
        if check.meta().manual.is_none() {
            bail!("{id} is automated; only manual checks take attestations");
        }
        let answer = Answer::parse(args.answer.as_deref().unwrap_or_default()).context("invalid answer")?;
        let a = attest::new(answer, &args.note, &author, now, args.expires_days)?;
        store.put_attestation(id, &a)?;
        writeln!(out, "Recorded {id} = {} for {tenant}; expires {}.", answer.as_str(), a.expires_at)?;
    }
    Ok(exit::OK)
}

/// A validated push, ready to send after the run.
pub struct PushPlan {
    target: crate::push::PushTarget,
    context: String,
    policy: junction_policy::Policy,
}

fn push_plan(args: &PushArgs, env: &dyn Environment) -> Result<Option<PushPlan>> {
    if !args.push_sentinel {
        return Ok(None);
    }
    let target = crate::push::PushTarget::parse(
        args.dce.as_deref().unwrap_or_default(),
        args.dcr.as_deref().unwrap_or_default(),
        args.stream.as_deref().unwrap_or_default(),
    )?;
    let context = args.push_context.clone().context("--push-context names the context whose credential sends the rows")?;
    let policy = match (&args.push_policy, args.approve_push) {
        (Some(path), _) => junction_policy::Policy::parse(&std::fs::read_to_string(path)?)?,
        (None, true) => {
            env.confirm_push(&context, target.dce.as_str(), &format!(
                "Send check results (status, severity, score, tags and one-line summaries; no raw tenant data) to stream {} via DCR {} at {}?",
                target.stream, target.dcr_immutable_id, target.dce
            ))?;
            junction_policy::Policy::parse("[agent]\nmode = 'safe-write'\n")?
        }
        (None, false) => junction_policy::Policy::default(),
    };
    if !crate::push::policy_allows(&policy) {
        bail!("pushing to Sentinel writes to your workspace: pass --approve-push to confirm on this terminal, or --push-policy with a policy that allows azure.monitor.logs_ingestion.upload");
    }
    Ok(Some(PushPlan { target, context, policy }))
}

impl PushPlan {
    async fn send(self, report: &RunReport, env: &dyn Environment) -> Result<()> {
        let live = env.live_target(&self.context)?;
        let sender = crate::push::ExecutorSender::new(&self.target, live, env.tokens(), self.policy)?;
        crate::push::push(&self.target, report, &sender, junction_watch::backoff::Backoff::default()).await?;
        Ok(())
    }
}
