//! `junction apps`: connected-app inventory and governance for one tenant.
//!
//! Reads reuse `junction check`'s contexts, credentials, gateway and fixture
//! replay ([`crate::cli::Environment`], [`crate::cli::plan`]), so they always
//! run under Junction's read-only policy.
use super::inventory::{Inventory, READS};
use super::report::{self, View};
use crate::cli::{Environment, Targets, exit};
use crate::config::CheckConfig;
use crate::model::Severity;
use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand, ValueEnum};
use junction_watch::clock::Instant;
use serde_json::json;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Args, Debug)]
#[command(after_help = "Examples:
  junction apps inventory --context contoso
  junction apps inventory --context contoso --flagged-only --min-severity high
  junction apps inventory --context contoso --format json --output apps.json
  junction apps inventory --context contoso --format html --output apps.html
  junction apps baseline save --context contoso --output contoso-baseline.json
  junction apps diff --context contoso --baseline contoso-baseline.json --fail-on-drift
  junction apps export --context contoso --baseline contoso-baseline.json --output evidence/
  junction apps plan --context contoso --app <id> --action revoke-delegated --output plan.json
  junction apps apply --context contoso --plan plan.json
  junction apps flags
  junction apps permissions

Reads run under Junction's read-only policy, whatever policy the context uses.
`apply` is the only command that writes: CLI only, each item approved on the
controlling terminal (docs/APPROVALS.md). Nothing is ever revoked automatically.
Exit codes: 0 done, 1 --fail-on threshold or --fail-on-drift breached, 2 error.")]
pub struct AppsArgs {
    #[command(subcommand)]
    pub command: AppsCommand,
}

#[derive(Subcommand, Debug)]
pub enum AppsCommand {
    /// Inventory enterprise apps, OAuth clients, permissions, consent grants and owners, with risk flags.
    Inventory(Box<InventoryArgs>),
    /// Save the current inventory as an approved baseline for later drift checks.
    Baseline {
        #[command(subcommand)]
        command: BaselineCommand,
    },
    /// Show what changed since an approved baseline.
    Diff(Box<DiffArgs>),
    /// Write an evidence pack (Markdown, JSON, CSV and a SHA-256 manifest).
    Export(Box<ExportArgs>),
    /// Write a reviewable plan to revoke or restrict access for named apps. Read-only.
    Plan(Box<PlanArgs>),
    /// Apply a plan. Every item is approved on the controlling terminal; agents cannot run this.
    Apply(Box<ApplyArgs>),
    /// Describe every risk flag: what it reads, why it matters and how to fix it.
    Flags {
        #[arg(long, value_enum, default_value = "table")]
        format: ListFormat,
    },
    /// Print the least-privilege Microsoft Graph permissions the inventory reads with.
    Permissions {
        #[arg(long, value_enum, default_value = "table")]
        format: ListFormat,
    },
}

#[derive(Subcommand, Debug)]
pub enum BaselineCommand {
    /// Read the tenant and write a baseline file.
    Save(Box<BaselineArgs>),
}

#[derive(Args, Debug, Clone)]
pub struct BaselineArgs {
    #[command(flatten)]
    pub source: Source,
    /// Baseline file to write.
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DiffFormat {
    Json,
    Markdown,
}

#[derive(Args, Debug, Clone)]
pub struct DiffArgs {
    #[command(flatten)]
    pub source: Source,
    /// Approved baseline from `junction apps baseline save`.
    #[arg(long)]
    pub baseline: PathBuf,
    #[arg(long, value_enum, default_value = "markdown")]
    pub format: DiffFormat,
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Exit 1 when apps were added or gained permissions, scopes or owners.
    #[arg(long)]
    pub fail_on_drift: bool,
}

#[derive(Args, Debug, Clone)]
pub struct ExportArgs {
    #[command(flatten)]
    pub source: Source,
    /// Directory to write the evidence pack into.
    #[arg(long)]
    pub output: PathBuf,
    /// Include drift against this approved baseline.
    #[arg(long)]
    pub baseline: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct PlanArgs {
    #[command(flatten)]
    pub source: Source,
    /// Service principal object id or app id (repeatable).
    #[arg(long = "app", required = true)]
    pub apps: Vec<String>,
    /// What to change (repeatable).
    #[arg(long = "action", value_enum, required = true)]
    pub actions: Vec<super::apply::Action>,
    /// Plan file to write.
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Args, Debug, Clone)]
pub struct ApplyArgs {
    #[command(flatten)]
    pub source: Source,
    /// Plan from `junction apps plan`.
    #[arg(long)]
    pub plan: PathBuf,
    /// Operator policy whose deny rules, tenant allow-list and limits apply.
    #[arg(long)]
    pub policy: Option<PathBuf>,
    /// Check the plan against the tenant and print what would be sent; send nothing.
    #[arg(long)]
    pub dry_run: bool,
}

/// What the `junction` binary provides for `apply`: the terminal approver and
/// the live sender. MCP and HTTP hosts never implement this.
pub trait ApplyEnvironment: Environment {
    fn approver(&self, context: &str) -> Result<Box<dyn super::apply::Approver>>;
    fn sender(
        &self,
        context: &str,
        policy: junction_policy::Policy,
    ) -> Result<(Box<dyn super::apply::Sender>, String, String)>;
}

fn read_baseline(path: &Path) -> Result<super::baseline::Baseline> {
    super::baseline::Baseline::parse(&std::fs::read_to_string(path).context("reading --baseline")?)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Table,
    Json,
    Markdown,
    Html,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ListFormat {
    Table,
    Json,
}

#[derive(Args, Debug, Clone, Default)]
pub struct Source {
    /// Replay recorded fixtures from DIR/<context>/ instead of calling Microsoft.
    #[arg(long, hide = true, value_name = "DIR")]
    pub fixtures: Option<PathBuf>,
    /// Thresholds (`[packs.governance] unused_days = 90`) as TOML.
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Concurrent requests per API host.
    #[arg(long, default_value_t = 4, value_parser = clap::value_parser!(u16).range(1..=16))]
    pub per_host: u16,
}

#[derive(Args, Debug, Clone)]
pub struct InventoryArgs {
    #[command(flatten)]
    pub source: Source,
    #[arg(long, value_enum, default_value = "table")]
    pub format: Format,
    /// Write to a file instead of standard output.
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Only apps with at least one flag.
    #[arg(long)]
    pub flagged_only: bool,
    /// Only apps whose highest flag is at least this severe.
    #[arg(long, value_parser = ["critical", "high", "medium", "low"])]
    pub min_severity: Option<String>,
    /// Also list Microsoft first-party apps without flags (always in JSON).
    #[arg(long)]
    pub include_microsoft: bool,
    /// Exit 1 when any app has a flag at or above this severity.
    #[arg(long, value_parser = ["critical", "high", "medium", "low"])]
    pub fail_on: Option<String>,
}

impl InventoryArgs {
    pub fn view(&self) -> View {
        View {
            flagged_only: self.flagged_only,
            min_severity: self.min_severity.as_deref().and_then(Severity::parse),
            include_microsoft: self.include_microsoft,
        }
    }
}

fn one_context(contexts: &[String]) -> Result<&str> {
    match contexts {
        [one] => Ok(one),
        [] => bail!("select the tenant with --context NAME"),
        _ => bail!("`junction apps` reads one tenant at a time; pass a single --context"),
    }
}

fn load_config(path: Option<&Path>) -> Result<CheckConfig> {
    match path {
        Some(path) => {
            CheckConfig::parse_toml(&std::fs::read_to_string(path).context("reading --config")?)
        }
        None => Ok(CheckConfig::default()),
    }
}

/// Read and flag the inventory of the tenant behind `context`. A
/// `host_policy` (MCP or HTTP host) keeps its deny rules and tenant
/// allow-list; reads still run read-only.
pub async fn collect(
    context: &str,
    source: &Source,
    env: Option<&dyn Environment>,
    host_policy: Option<&junction_policy::Policy>,
) -> Result<Inventory> {
    let config = Arc::new(load_config(source.config.as_deref())?);
    let targets = Targets {
        fixtures: source.fixtures.clone(),
        ..Targets::default()
    };
    let target = crate::cli::Target {
        context: context.to_owned(),
        tenant_id: None,
        label: None,
    };
    let planned = crate::cli::plan(&[target], &targets, env, host_policy)?
        .pop()
        .context("no tenant planned")?;
    let gateway = planned
        .plan
        .gateway
        .map_err(|reason| anyhow::anyhow!("{}", reason.detail))?;
    let now = match &source.fixtures {
        Some(dir) => {
            let settings = crate::testkit::case_settings(&dir.join(context))?;
            Instant::parse(
                settings
                    .now
                    .as_deref()
                    .unwrap_or(crate::testkit::FIXTURE_NOW),
            )?
        }
        None => Instant::now(),
    };
    super::run(
        gateway,
        planned.plan.label,
        config,
        now,
        usize::from(source.per_host),
    )
    .await
    .map_err(|e| anyhow::anyhow!("the inventory could not be read: {e}"))
}

/// Write `bytes` to `path` atomically. The temporary file has a random name,
/// is created new (never through an existing file or symlink) and, on Unix,
/// is readable only by the owner, because outputs hold tenant data.
pub(crate) fn write_output(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).map_err(|_| anyhow::anyhow!("random source unavailable"))?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("apps"),
        random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let written = (|| -> Result<()> {
        let mut file = options.open(&temp).context("creating the output file")?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)?;
        Ok(())
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    written
}

fn render(inventory: &Inventory, format: Format, view: &View) -> Result<String> {
    Ok(match format {
        Format::Table => report::table(inventory, view),
        Format::Json => serde_json::to_string_pretty(&report::json(inventory, view))? + "\n",
        Format::Markdown => report::markdown(inventory, view),
        Format::Html => report::html(inventory, view),
    })
}

/// Exit code for `--fail-on`.
pub fn breached(inventory: &Inventory, fail_on: Option<&str>) -> bool {
    let Some(threshold) = fail_on.and_then(Severity::parse) else {
        return false;
    };
    inventory
        .apps
        .iter()
        .any(|a| a.severity().is_some_and(|s| s.at_least(threshold)))
}

/// The permissions the inventory uses, one row per permission.
pub fn permissions() -> Vec<serde_json::Value> {
    let mut rows: std::collections::BTreeMap<&str, Vec<&str>> = Default::default();
    for read in READS {
        rows.entry(read.permissions[0])
            .or_default()
            .push(read.operation);
    }
    rows.into_iter()
        .map(|(permission, operations)| {
            json!({"permission": permission, "type": "Microsoft Graph application", "access": "read",
                "operations": operations})
        })
        .collect()
}

/// Run a `junction apps` command and return its exit code.
pub async fn run(
    args: AppsArgs,
    contexts: Vec<String>,
    env: &dyn ApplyEnvironment,
    out: &mut dyn Write,
) -> Result<i32> {
    match args.command {
        AppsCommand::Plan(args) => {
            let context = one_context(&contexts)?;
            let inventory = collect(context, &args.source, Some(env), None).await?;
            let plan = super::apply::build(&inventory, &args.apps, &args.actions)?;
            write_output(
                &args.output,
                (serde_json::to_string_pretty(&plan)? + "\n").as_bytes(),
            )?;
            out.write_all(
                (serde_json::to_string_pretty(&json!({
                    "status": "planned",
                    "plan": args.output,
                    "items": plan.items.iter().map(|i| json!({"id": i.id, "app": i.app,
                        "operation": i.operation, "risk": i.risk})).collect::<Vec<_>>(),
                    "next": "Review the plan, then run `junction apps apply --plan FILE` on a terminal.",
                }))? + "\n")
                    .as_bytes(),
            )?;
            Ok(exit::OK)
        }
        AppsCommand::Apply(args) => {
            let context = one_context(&contexts)?;
            let plan = super::apply::Plan::parse(
                &std::fs::read_to_string(&args.plan).context("reading --plan")?,
            )?;
            let operator = match &args.policy {
                Some(path) => junction_policy::Policy::parse(
                    &std::fs::read_to_string(path).context("reading --policy")?,
                )?,
                None => junction_policy::Policy::default(),
            };
            // Policy first: a deny rule fails before any tenant call.
            let policy = super::apply::effective_policy(&operator, &plan)?;
            let inventory = collect(context, &args.source, Some(env), None).await?;
            let now = match &args.source.fixtures {
                Some(_) => Instant::parse(&inventory.captured_at)?,
                None => Instant::now(),
            };
            let (valid, refused) = super::apply::check_fresh(&plan, &inventory, now)?;
            if args.dry_run || valid.is_empty() {
                let report = json!({
                    "status": if args.dry_run { "dry_run" } else { "nothing_to_apply" },
                    "would_send": valid.iter().map(|i| json!({"id": i.id, "app": i.app,
                        "operation": i.operation, "input": i.input})).collect::<Vec<_>>(),
                    "refused": refused,
                });
                out.write_all((serde_json::to_string_pretty(&report)? + "\n").as_bytes())?;
                return Ok(if refused.is_empty() {
                    exit::OK
                } else {
                    exit::PARTIAL
                });
            }
            let approver = env.approver(context)?;
            let (sender, endpoint, audience) = env.sender(context, policy)?;
            let outcomes = super::apply::run(
                &valid,
                &refused,
                approver.as_ref(),
                sender.as_ref(),
                &endpoint,
                &audience,
            )
            .await?;
            let all_applied = outcomes.iter().all(|o| o.status == "applied");
            out.write_all(
                (serde_json::to_string_pretty(&json!({"outcomes": outcomes}))? + "\n").as_bytes(),
            )?;
            Ok(if all_applied { exit::OK } else { exit::PARTIAL })
        }
        AppsCommand::Inventory(args) => {
            let context = one_context(&contexts)?;
            let inventory = collect(context, &args.source, Some(env), None).await?;
            let text = render(&inventory, args.format, &args.view())?;
            match &args.output {
                Some(path) => write_output(path, text.as_bytes())?,
                None => out.write_all(text.as_bytes())?,
            }
            Ok(if breached(&inventory, args.fail_on.as_deref()) {
                exit::THRESHOLD
            } else {
                exit::OK
            })
        }
        AppsCommand::Baseline {
            command: BaselineCommand::Save(args),
        } => {
            let context = one_context(&contexts)?;
            let inventory = collect(context, &args.source, Some(env), None).await?;
            let baseline = super::baseline::Baseline::from_inventory(&inventory)?;
            write_output(
                &args.output,
                (serde_json::to_string_pretty(&baseline)? + "\n").as_bytes(),
            )?;
            out.write_all(
                (serde_json::to_string_pretty(&json!({
                    "status": "saved",
                    "tenant_id": baseline.tenant_id,
                    "apps": baseline.apps.len(),
                    "digest": baseline.digest,
                }))? + "\n")
                    .as_bytes(),
            )?;
            Ok(exit::OK)
        }
        AppsCommand::Diff(args) => {
            let context = one_context(&contexts)?;
            let baseline = read_baseline(&args.baseline)?;
            let inventory = collect(context, &args.source, Some(env), None).await?;
            let drift = super::baseline::diff(&baseline, &inventory)?;
            let text = match args.format {
                DiffFormat::Json => serde_json::to_string_pretty(&drift)? + "\n",
                DiffFormat::Markdown => super::baseline::markdown(&drift),
            };
            match &args.output {
                Some(path) => write_output(path, text.as_bytes())?,
                None => out.write_all(text.as_bytes())?,
            }
            Ok(if args.fail_on_drift && drift.widened() {
                exit::THRESHOLD
            } else {
                exit::OK
            })
        }
        AppsCommand::Export(args) => {
            let context = one_context(&contexts)?;
            // Read the baseline first so a bad file fails before any tenant call.
            let baseline = args.baseline.as_deref().map(read_baseline).transpose()?;
            let inventory = collect(context, &args.source, Some(env), None).await?;
            let drift = baseline
                .map(|b| super::baseline::diff(&b, &inventory))
                .transpose()?;
            let manifest = super::export::write(&args.output, &inventory, drift.as_ref())?;
            out.write_all((serde_json::to_string_pretty(&manifest)? + "\n").as_bytes())?;
            Ok(exit::OK)
        }
        AppsCommand::Flags { format } => {
            let text = match format {
                ListFormat::Json => serde_json::to_string_pretty(super::flags::FLAGS)? + "\n",
                ListFormat::Table => super::flags::FLAGS
                    .iter()
                    .map(|f| {
                        format!(
                            "{} ({})\n  {}\n  Reads: {}\n  Why:   {}\n  Fix:   {}\n\n",
                            f.id,
                            f.severity.as_str(),
                            f.title,
                            f.reads,
                            f.why,
                            f.fix
                        )
                    })
                    .collect(),
            };
            out.write_all(text.as_bytes())?;
            Ok(exit::OK)
        }
        AppsCommand::Permissions { format } => {
            let rows = permissions();
            let text = match format {
                ListFormat::Json => serde_json::to_string_pretty(&rows)? + "\n",
                ListFormat::Table => rows
                    .iter()
                    .map(|r| {
                        format!(
                            "{:<40} {}\n",
                            r["permission"].as_str().unwrap_or_default(),
                            r["operations"]
                                .as_array()
                                .into_iter()
                                .flatten()
                                .filter_map(|o| o.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    })
                    .collect(),
            };
            out.write_all(text.as_bytes())?;
            Ok(exit::OK)
        }
    }
}
