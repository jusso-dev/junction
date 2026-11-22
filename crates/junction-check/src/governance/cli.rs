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
  junction apps flags
  junction apps permissions

Reads run under Junction's read-only policy, whatever policy the context uses.
Exit codes: 0 done, 1 --fail-on threshold breached, 2 error.")]
pub struct AppsArgs {
    #[command(subcommand)]
    pub command: AppsCommand,
}

#[derive(Subcommand, Debug)]
pub enum AppsCommand {
    /// Inventory enterprise apps, OAuth clients, permissions, consent grants and owners, with risk flags.
    Inventory(Box<InventoryArgs>),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Table,
    Json,
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

pub(crate) fn write_output(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let temp = parent.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("apps")
    ));
    std::fs::write(&temp, bytes)?;
    std::fs::rename(&temp, path)?;
    Ok(())
}

fn render(inventory: &Inventory, format: Format, view: &View) -> Result<String> {
    Ok(match format {
        Format::Table => report::table(inventory, view),
        Format::Json => serde_json::to_string_pretty(inventory)? + "\n",
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
    env: &dyn Environment,
    out: &mut dyn Write,
) -> Result<i32> {
    match args.command {
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
