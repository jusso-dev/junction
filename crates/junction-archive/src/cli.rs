//! `junction archive ...` commands.
use crate::{
    catalog,
    checkpoint::Checkpoint,
    collect,
    config::{ArchiveConfig, write_new_private},
    evidence, forward, search,
    store::{DeleteProbe, ObjectStore, PutOutcome},
};
use anyhow::Result;
use clap::Subcommand;
use junction_watch::clock::Instant;
use junction_watch::upstream::LiveUpstream;
use serde_json::{Value, json};
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct ArchiveArgs {
    /// Secret-free archive configuration file.
    #[arg(long, default_value = ".junction/archive/config.toml")]
    pub config: PathBuf,
    #[command(subcommand)]
    pub command: ArchiveCommand,
}

#[derive(Subcommand)]
pub enum ArchiveCommand {
    /// Write a configuration file (create-only) and print the next steps.
    Init {
        #[arg(long)]
        tenant_id: String,
    },
    /// List every tenant permission and storage role the archive uses, and why.
    Permissions,
    /// Check the configured store: create-only writes, refused deletion and the
    /// retention the service reports. Writes one small canary object.
    Doctor,
    /// Run one collection pass over every configured source.
    Collect,
    /// Show checkpoints, paused sources and why a source is unavailable.
    /// Gaps are in the manifests and in every evidence bundle.
    Status,
    /// Search archived records. Output is redacted unless --full is given.
    Search(SearchArgs),
    /// Place, list or release legal holds.
    Hold {
        #[command(subcommand)]
        command: HoldCommand,
    },
    /// Write an evidence bundle (records, manifest with hashes, README) to a new directory.
    Export(ExportArgs),
    /// Recompute every hash in an evidence bundle directory.
    Verify { bundle: PathBuf },
    /// Forward only high-value events to Sentinel or Bower (off unless run).
    Forward(ForwardArgs),
}

#[derive(clap::Args)]
pub struct ForwardArgs {
    /// Print the built-in high-value selector and exit.
    #[arg(long, exclusive = true)]
    pub list: bool,
    /// `sentinel` or `bower`.
    #[arg(long, value_parser = ["sentinel", "bower"], required_unless_present = "list")]
    pub to: Option<String>,
    /// Start of the range to forward (RFC 3339).
    #[arg(long, required_unless_present = "list")]
    pub from: Option<String>,
    /// End of the range to forward (RFC 3339).
    #[arg(long, required_unless_present = "list")]
    pub until: Option<String>,
    /// Narrow the selector to these rule ids (repeatable). It cannot be widened.
    #[arg(long = "only")]
    pub only: Vec<String>,
    /// Sentinel: Logs Ingestion endpoint and rule (see examples/archive/archive-forward-table.bicep).
    #[command(flatten)]
    pub push: junction_check::cli::PushArgs,
    /// Bower: the collector base URL (token from JUNCTION_BOWER_INGEST_TOKEN).
    #[arg(long)]
    pub endpoint: Option<String>,
    /// Bower: application environment label sent with each event.
    #[arg(long, default_value = "production")]
    pub environment: String,
}

#[derive(Subcommand)]
pub enum HoldCommand {
    /// Hold every object holding a record that matches the filters.
    Create {
        /// Hold id: 1-64 letters, digits, - or _.
        #[arg(long)]
        name: String,
        /// Why the hold is needed (case or matter reference).
        #[arg(long)]
        reason: String,
        #[command(flatten)]
        filter: FilterArgs,
    },
    /// List holds and their state.
    List,
    /// Release a hold (recorded; never deletes anything).
    Release {
        #[arg(long)]
        name: String,
        #[arg(long)]
        reason: String,
    },
}

#[derive(clap::Args)]
pub struct ExportArgs {
    #[command(flatten)]
    pub filter: FilterArgs,
    /// New directory to write the bundle into.
    #[arg(long)]
    pub output: PathBuf,
    /// Why the bundle is being exported (assessment, incident reference).
    #[arg(long)]
    pub purpose: String,
    /// Include UPNs, IP addresses and raw records.
    #[arg(long)]
    pub full: bool,
    /// Confirm --full without a terminal prompt.
    #[arg(long, requires = "full")]
    pub yes: bool,
}

#[derive(clap::Args, Clone)]
pub struct FilterArgs {
    /// Start of the time range (RFC 3339, inclusive).
    #[arg(long)]
    pub from: String,
    /// End of the time range (RFC 3339, exclusive).
    #[arg(long)]
    pub to: String,
    /// Limit to a source (repeatable), for example graph:signIns.
    #[arg(long = "source")]
    pub sources: Vec<String>,
    /// Exact operation, case-insensitive.
    #[arg(long)]
    pub operation: Option<String>,
    /// Actor UPN, case-insensitive.
    #[arg(long)]
    pub actor: Option<String>,
    /// Exact IP address.
    #[arg(long)]
    pub ip: Option<String>,
    /// Case-insensitive text anywhere in the record.
    #[arg(long)]
    pub contains: Option<String>,
}

impl FilterArgs {
    pub fn query(&self) -> search::Query {
        search::Query {
            from: self.from.clone(),
            to: self.to.clone(),
            sources: self.sources.clone(),
            operation: self.operation.clone(),
            actor: self.actor.clone(),
            ip: self.ip.clone(),
            contains: self.contains.clone(),
        }
    }
}

#[derive(clap::Args)]
pub struct SearchArgs {
    #[command(flatten)]
    pub filter: FilterArgs,
    /// Most records to return.
    #[arg(long, default_value_t = search::DEFAULT_LIMIT)]
    pub limit: usize,
    /// Show full records, including UPNs, IP addresses and raw payloads.
    #[arg(long)]
    pub full: bool,
    /// Confirm --full without a terminal prompt.
    #[arg(long, requires = "full")]
    pub yes: bool,
}

/// Ask before showing personal data. Refuses without a terminal unless `yes`.
pub fn confirm_full(yes: bool, what: &str) -> Result<()> {
    use std::io::{BufRead, IsTerminal, Write};
    if yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        anyhow::bail!("{what} shows personal data; pass --yes to confirm when not at a terminal");
    }
    eprint!("{what} shows user names, IP addresses and raw audit records. Continue? [y/N] ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    if !matches!(line.trim(), "y" | "Y" | "yes") {
        anyhow::bail!("cancelled");
    }
    Ok(())
}

pub async fn run(args: ArchiveArgs, env: &dyn junction_check::cli::Environment) -> Result<Value> {
    match args.command {
        ArchiveCommand::Forward(forward_args) => run_forward(&args.config, forward_args, env).await,
        ArchiveCommand::Init { tenant_id } => init(&args.config, &tenant_id),
        ArchiveCommand::Permissions => Ok(permissions()),
        ArchiveCommand::Doctor => {
            let config = ArchiveConfig::load(&args.config)?;
            let store = config.open_store()?;
            doctor(&config, store.as_ref(), Instant::now()).await
        }
        ArchiveCommand::Collect => {
            let config = ArchiveConfig::load(&args.config)?;
            let store = config.open_store()?;
            let up = live_upstream(&config)?;
            let mut checkpoint = Checkpoint::open(&config.state_directory, &config.tenant_id)?;
            let outcomes = collect::collect_all(
                &up,
                store.as_ref(),
                &mut checkpoint,
                &config.sources,
                Instant::now(),
                &collect::CollectOptions::default(),
            )
            .await;
            Ok(json!({"store": store.describe(), "sources": outcomes}))
        }
        ArchiveCommand::Search(search_args) => {
            let config = ArchiveConfig::load(&args.config)?;
            if search_args.full {
                confirm_full(search_args.yes, "--full")?;
            }
            let store = config.open_store()?;
            run_search(store.as_ref(), &config.tenant_id, &search_args).await
        }
        ArchiveCommand::Hold { command } => {
            let config = ArchiveConfig::load(&args.config)?;
            let store = config.open_store()?;
            let tenant = &config.tenant_id;
            match command {
                HoldCommand::Create {
                    name,
                    reason,
                    filter,
                } => {
                    let m = evidence::create_hold(
                        store.as_ref(),
                        tenant,
                        &name,
                        &reason,
                        &filter.query(),
                        Instant::now(),
                    )
                    .await?;
                    Ok(
                        json!({"hold": name, "records": m.records.len(), "objects": m.objects, "resultSetSha256": m.result_set_sha256}),
                    )
                }
                HoldCommand::List => {
                    Ok(json!({"holds": evidence::list_holds(store.as_ref(), tenant).await?}))
                }
                HoldCommand::Release { name, reason } => {
                    let m = evidence::release_hold(
                        store.as_ref(),
                        tenant,
                        &name,
                        &reason,
                        Instant::now(),
                    )
                    .await?;
                    Ok(json!({"hold": name, "released_objects": m.objects.len(),
                        "note": "Releasing never deletes. On R2 and local stores the copies under holds/ stay until an administrator changes the lock rule."}))
                }
            }
        }
        ArchiveCommand::Export(export_args) => {
            let config = ArchiveConfig::load(&args.config)?;
            if export_args.full {
                confirm_full(export_args.yes, "export --full")?;
            }
            let store = config.open_store()?;
            let out = evidence::export(
                store.as_ref(),
                &config.tenant_id,
                &export_args.filter.query(),
                export_args.full,
                &export_args.purpose,
                &export_args.output,
                Instant::now(),
            )
            .await?;
            Ok(json!({
                "bundle": export_args.output.display().to_string(),
                "records": out.manifest["recordCount"],
                "resultSetSha256": out.manifest["resultSetSha256"],
                "gaps": out.manifest["gaps"].as_array().map_or(0, Vec::len),
                "redacted": out.manifest["redacted"],
                "audit_written": out.audit_written,
                "audit_note": out.audit_error.map(|e| format!(
                    "the export audit entry was not written to the store ({e}); a read-only searcher identity cannot write it. Record this export in your case notes."
                )),
            }))
        }
        ArchiveCommand::Verify { bundle } => {
            let problems = evidence::verify(&bundle)?;
            Ok(
                json!({"bundle": bundle.display().to_string(), "valid": problems.is_empty(), "problems": problems}),
            )
        }
        ArchiveCommand::Status => {
            let config = ArchiveConfig::load(&args.config)?;
            let checkpoint = Checkpoint::open(&config.state_directory, &config.tenant_id)?;
            Ok(status(&config, &checkpoint))
        }
    }
}

pub async fn run_search(store: &dyn ObjectStore, tenant: &str, args: &SearchArgs) -> Result<Value> {
    let query = args.filter.query();
    let results = search::search(store, tenant, &query, args.limit).await?;
    let view = if args.full {
        search::full
    } else {
        search::redacted
    };
    Ok(json!({
        "query": if args.full { serde_json::to_value(&query)? } else { query.redacted() },
        "records": results.records.iter().map(view).collect::<Vec<_>>(),
        "count": results.records.len(),
        "truncated": results.truncated,
        "duplicates_removed": results.duplicates_removed,
        "objects_read": results.objects_read.len(),
        "problems": results.problems,
        "redacted": !args.full,
    }))
}

async fn run_forward(
    config_path: &std::path::Path,
    args: ForwardArgs,
    env: &dyn junction_check::cli::Environment,
) -> Result<Value> {
    if args.list {
        return Ok(
            json!({"selector_version": forward::SELECTOR_VERSION, "rules": forward::SELECTOR}),
        );
    }
    forward::validate_only(&args.only)?;
    let config = ArchiveConfig::load(config_path)?;
    let store = config.open_store()?;
    let query = search::Query {
        from: args.from.clone().unwrap_or_default(),
        to: args.until.clone().unwrap_or_default(),
        ..search::Query::default()
    };
    query.range()?;
    let mut checkpoint = Checkpoint::open(&config.state_directory, &config.tenant_id)?;
    let retry = crate::store::Retry::default();
    let backoff = junction_watch::backoff::Backoff::default();
    let summary = match args.to.as_deref() {
        Some("sentinel") => {
            if !args.push.push_sentinel {
                anyhow::bail!(
                    "--to sentinel needs --push-sentinel with --dce, --dcr, --stream and --push-context"
                );
            }
            let target = junction_check::push::PushTarget::parse(
                args.push.dce.as_deref().unwrap_or_default(),
                args.push.dcr.as_deref().unwrap_or_default(),
                args.push.stream.as_deref().unwrap_or_default(),
            )?;
            let context = args.push.push_context.clone().ok_or_else(|| {
                anyhow::anyhow!("--push-context names the context whose credential sends the rows")
            })?;
            let base = match &args.push.push_policy {
                Some(path) => junction_policy::Policy::parse(&std::fs::read_to_string(path)?)?,
                None => junction_policy::Policy::default(),
            };
            let policy =
                junction_check::push::effective_policy(true, &base, args.push.approve_push)?;
            if args.push.approve_push && !junction_check::push::policy_allows(&base) {
                env.confirm_push(&context, target.dce.as_str(), &format!(
                    "Forward selected high-value archive events (redacted summary columns; no raw records) to stream {} via DCR {}?",
                    target.stream, target.dcr_immutable_id
                ))?;
            }
            let live = env.live_target(&context)?;
            if !live.tenant_id.eq_ignore_ascii_case(&config.tenant_id) {
                // Allowed (a security workspace can live in another tenant) but noted.
                eprintln!(
                    "note: the Sentinel workspace context is in a different tenant from the archive"
                );
            }
            let sender =
                junction_check::push::ExecutorSender::new(&target, live, env.tokens(), policy)?;
            let key = forward::destination_id(
                "sentinel",
                &format!("{}{}{}", target.dce, target.dcr_immutable_id, target.stream),
            );
            forward::forward(
                store.as_ref(),
                &mut checkpoint,
                &key,
                &query,
                &args.only,
                forward::Destination::Sentinel {
                    target: &target,
                    sender: &sender,
                },
                retry,
                backoff,
            )
            .await?
        }
        Some("bower") => {
            let endpoint = args
                .endpoint
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--to bower needs --endpoint"))?;
            let sender = forward::LiveBower::new(endpoint)?;
            let key = forward::destination_id("bower", endpoint);
            forward::forward(
                store.as_ref(),
                &mut checkpoint,
                &key,
                &query,
                &args.only,
                forward::Destination::Bower {
                    sender: &sender,
                    environment: &args.environment,
                },
                retry,
                backoff,
            )
            .await?
        }
        _ => anyhow::bail!("--to must be sentinel or bower"),
    };
    Ok(json!({"to": args.to, "selector_version": forward::SELECTOR_VERSION, "summary": summary}))
}

fn live_upstream(config: &ArchiveConfig) -> Result<LiveUpstream> {
    let mut policy = junction_policy::Policy::default();
    policy.limits.max_requests_per_minute = config.max_requests_per_minute;
    let governor = junction_policy::RequestGovernor::new(&policy)?;
    let transport = junction_http::HttpTransport::new(
        governor,
        std::time::Duration::from_secs(60),
        64 * 1024 * 1024,
    )?;
    LiveUpstream::new(&config.tenant_id, config.cloud, config.auth, transport)
}

fn status(config: &ArchiveConfig, checkpoint: &Checkpoint) -> Value {
    let sources: Vec<Value> = config
        .sources
        .iter()
        .map(|source| {
            let state = checkpoint.get(source);
            json!({
                "source": source,
                "watermark": state.and_then(|s| s.watermark.clone()),
                "paused_until": state.and_then(|s| s.retry_after.clone()),
                "unavailable": state.and_then(|s| s.unavailable.clone()),
                "last_manifest_sha256": state.and_then(|s| s.last_manifest_sha256.clone()),
            })
        })
        .collect();
    json!({
        "tenant_id": config.tenant_id,
        "sources": sources,
        "exactness": "at-least-once into storage; search and export deduplicate on record id",
    })
}

fn init(path: &std::path::Path, tenant_id: &str) -> Result<Value> {
    junction_watch::store::validate_tenant(tenant_id)?;
    write_new_private(
        path,
        &ArchiveConfig::example(&tenant_id.to_ascii_lowercase()),
    )?;
    Ok(json!({
        "config": path.display().to_string(),
        "next_steps": [
            "1. Create the storage: deploy examples/archive/archive-storage.bicep (Azure) or follow docs/ARCHIVE.md for an R2 bucket with lock rules.",
            "2. Edit the [storage] section of the configuration. It must never contain a key, SAS token or secret.",
            "3. Grant the tenant permissions from `junction archive permissions` to the collector app and give admin consent.",
            "4. Export the credential environment (AZURE_TENANT_ID, AZURE_CLIENT_ID and certificate paths; for R2 also JUNCTION_ARCHIVE_R2_ACCESS_KEY_ID and JUNCTION_ARCHIVE_R2_SECRET_ACCESS_KEY).",
            "5. Run `junction archive doctor` to confirm the store is create-only and immutable."
        ]
    }))
}

fn permissions() -> Value {
    json!({
        "tenant": catalog::SOURCES,
        "storage": catalog::STORAGE_ROLES,
        "note": "Tenant permissions are application permissions and read-only. The archive never starts audit subscriptions; use `junction watch subscribe` or your existing feed."
    })
}

/// Doctor's verdict for one property of the store.
fn check(name: &str, ok: Option<bool>, detail: impl Into<String>) -> Value {
    json!({
        "check": name,
        "status": match ok { Some(true) => "pass", Some(false) => "fail", None => "unknown" },
        "detail": detail.into(),
    })
}

pub async fn doctor(
    config: &ArchiveConfig,
    store: &dyn ObjectStore,
    now: Instant,
) -> Result<Value> {
    let key = format!(
        "v1/tenant={}/doctor/{}.txt",
        config.tenant_id,
        now.to_rfc3339().replace([':', '.'], "-")
    );
    let body = format!("junction archive doctor canary {}\n", now.to_rfc3339()).into_bytes();
    let mut checks = Vec::new();
    let first = store.put_new(&key, body.clone(), "text/plain").await;
    checks.push(check(
        "write",
        Some(matches!(first, Ok(PutOutcome::Created))),
        match &first {
            Ok(_) => "canary object created".to_owned(),
            Err(e) => format!("{e:#}"),
        },
    ));
    if first.is_ok() {
        let second = store
            .put_new(&key, b"overwrite attempt".to_vec(), "text/plain")
            .await;
        let kept = store
            .get(&key)
            .await
            .ok()
            .flatten()
            .is_some_and(|b| b == body);
        checks.push(check(
            "create_only",
            Some(matches!(second, Ok(PutOutcome::AlreadyExists)) && kept),
            "a second put to the same key must not replace the object",
        ));
        let probe = store.delete_probe(&key).await;
        let (ok, detail) = match probe {
            Ok(DeleteProbe::RefusedByImmutability) => (
                Some(true),
                "the storage service refused to delete the canary because of retention".to_owned(),
            ),
            Ok(DeleteProbe::Deleted) => (
                Some(false),
                "the canary could be deleted: the store is NOT immutable".to_owned(),
            ),
            // A role without delete proves nothing about immutability; the
            // retention check below then decides.
            Ok(DeleteProbe::NotPermitted(why)) => (
                None,
                format!(
                    "this identity may not delete ({why}); immutability is shown by the retention check"
                ),
            ),
            Ok(DeleteProbe::Other(why)) => (Some(false), why),
            Err(e) => (Some(false), format!("{e:#}")),
        };
        let delete_proven = ok == Some(true);
        checks.push(check("delete_refused", ok, detail));
        if let Some(days) = config.retention_days() {
            match store.retention_until(&key).await {
                Ok(Some(until)) => {
                    let ok = httpdate::parse_http_date(&until).ok().map(|t| {
                        let wanted = std::time::SystemTime::UNIX_EPOCH
                            + std::time::Duration::from_millis(now.0 as u64)
                            + std::time::Duration::from_secs(u64::from(days) * 86_400 - 86_400);
                        t >= wanted
                    });
                    checks.push(check(
                        "retention",
                        Some(ok.unwrap_or(false)),
                        format!("service reports retention until {until}; configured {days} days"),
                    ));
                }
                // Azure always reports retention on a protected blob, so its
                // absence means the container has no immutability policy.
                Ok(None) if config.reports_retention() => checks.push(check(
                    "retention",
                    Some(false),
                    "the container reports no immutability policy on the canary: archived objects are NOT protected",
                )),
                // R2 locks are bucket rules; only a refused delete proves them.
                Ok(None) => checks.push(check(
                    "retention",
                    delete_proven.then_some(true),
                    format!("R2 does not report per-object retention; confirm the v1/ bucket lock rule keeps objects for {days} days"),
                )),
                Err(e) => checks.push(check("retention", Some(false), format!("{e:#}"))),
            }
        }
    }
    // Immutability must be shown by at least one check: a refused delete or a
    // reported retention date. Two "unknown" results are not healthy.
    let proven = checks.iter().any(|c| {
        (c["check"] == "delete_refused" || c["check"] == "retention") && c["status"] == "pass"
    });
    let healthy = proven
        && checks
            .iter()
            .all(|c| c["status"] == "pass" || c["status"] == "unknown");
    Ok(json!({
        "store": store.describe(),
        "healthy": healthy,
        "checks": checks,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::LocalStore;

    #[tokio::test]
    async fn doctor_flags_a_local_store_as_not_immutable() {
        let dir = tempfile::tempdir().unwrap();
        let config: ArchiveConfig = toml::from_str(&format!(
            "tenant_id = \"11111111-1111-4111-8111-111111111111\"\n[storage]\nkind = \"local\"\npath = {}\n",
            crate::config::toml_path(dir.path())
        ))
        .unwrap();
        let store = LocalStore::new(dir.path()).unwrap();
        let report = doctor(
            &config,
            &store,
            Instant::parse("2026-11-22T00:00:00Z").unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(report["healthy"], false);
        let status = |name: &str| {
            report["checks"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["check"] == name)
                .unwrap()["status"]
                .clone()
        };
        assert_eq!(status("write"), "pass");
        assert_eq!(status("create_only"), "pass");
        assert_eq!(status("delete_refused"), "fail");
    }

    #[test]
    fn init_is_create_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        init(&path, "11111111-1111-4111-8111-111111111111").unwrap();
        assert!(init(&path, "11111111-1111-4111-8111-111111111111").is_err());
        assert!(init(&dir.path().join("b.toml"), "not a tenant").is_err());
    }
}
