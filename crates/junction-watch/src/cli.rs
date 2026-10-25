//! `junction watch ...` commands.
use crate::{
    activity::{self, CollectOptions},
    auth::{self, Role},
    catalog,
    clock::Instant,
    config::WatchConfig,
    probe,
    store::Store,
    upstream::LiveUpstream,
    web,
};
use anyhow::{Context, Result, bail};
use clap::Subcommand;
use serde_json::{Value, json};
use std::{path::PathBuf, sync::Arc, time::Duration};

#[derive(clap::Args)]
pub struct WatchArgs {
    /// Secret-free watchdog configuration file.
    #[arg(long, default_value = ".junction/watch/config.toml")]
    pub config: PathBuf,
    #[command(subcommand)]
    pub command: WatchCommand,
}

#[derive(Subcommand)]
pub enum WatchCommand {
    /// Write a configuration file (create-only) and print onboarding steps.
    Init {
        #[arg(long)]
        tenant_id: String,
        #[arg(long)]
        domain: String,
        #[arg(long)]
        client_id: String,
    },
    /// Explain every permission the watchdog asks for.
    Permissions {
        /// Print the app registration `requiredResourceAccess` JSON instead.
        #[arg(long)]
        manifest: bool,
        /// Include the optional Exchange runner permission.
        #[arg(long)]
        include_optional: bool,
    },
    /// Probe Microsoft APIs (read-only) and record what can be monitored.
    Probe,
    /// Start audit feed subscriptions. Enables delivery of audit data Microsoft
    /// already records; changes no tenant settings.
    Subscribe {
        /// Content type to start (repeatable). Defaults to the configured set.
        #[arg(long = "content-type")]
        content_types: Vec<String>,
    },
    /// Run one collection pass over every configured feed.
    Collect,
    /// Collect on the configured schedule and serve the dashboard.
    Run {
        /// Do not serve the dashboard.
        #[arg(long)]
        no_web: bool,
    },
    /// Serve the dashboard only.
    Serve,
    /// Show capabilities, recent runs and gaps.
    Status,
    /// Opt-in live validation against the tenant using a throwaway in-memory store.
    /// Read-only: never starts subscriptions or changes the tenant.
    Validate,
    /// Verify the hash-chained operator audit trail.
    VerifyTrail,
    /// Show versioned detection rules and their coverage requirements.
    Rules,
    /// Process pending events without contacting Microsoft.
    Detect,
    /// Import a read-only configuration snapshot from the optional runner.
    ImportSnapshot { file: PathBuf },
    /// Approve a reviewed complete initial snapshot as the baseline.
    ApproveBaseline { id: String },
    /// Generate a privacy-minimised security report.
    Report {
        #[arg(value_parser=["daily","weekly"])]
        period: String,
    },
    /// Apply configured retention, preserving evidence for open incidents.
    Retain,
    /// Re-list available Management Activity content without rewinding checkpoints.
    Backfill {
        #[arg(long, default_value_t = 6)]
        days: u64,
    },
    /// Manage dashboard accounts. Passwords are read from standard input.
    User {
        #[command(subcommand)]
        command: UserCommand,
    },
}

#[derive(Subcommand)]
pub enum UserCommand {
    Add {
        username: String,
        /// viewer, analyst or admin.
        #[arg(long, default_value = "viewer")]
        role: String,
    },
    Disable {
        username: String,
    },
    Enable {
        username: String,
    },
}

/// Errors from watch commands carry only operator-safe text (no secrets,
/// tokens or response bodies), so the CLI may print them.
#[derive(Debug)]
pub struct WatchError(pub String);
impl std::fmt::Display for WatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for WatchError {}

pub async fn run(args: WatchArgs) -> Result<Value> {
    dispatch(args)
        .await
        .map_err(|e| WatchError(format!("{e:#}")).into())
}

async fn dispatch(args: WatchArgs) -> Result<Value> {
    match args.command {
        WatchCommand::Init {
            tenant_id,
            domain,
            client_id,
        } => init(&args.config, &tenant_id, &domain, &client_id),
        WatchCommand::Permissions {
            manifest,
            include_optional,
        } => Ok(if manifest {
            catalog::required_resource_access(include_optional)
        } else {
            json!({
                "note": "Default application permissions are read-only. Optional Exchange.ManageAsApp access must be restricted with separately assigned, scoped read-only Exchange roles. The watchdog never reads email or file contents and makes no tenant changes except starting the audit feed subscription when you ask it to.",
                "permissions": catalog::PERMISSIONS.iter().filter(|p| include_optional || !p.optional).collect::<Vec<_>>(),
                "exchange_runner_roles": ["View-Only Configuration", "View-Only Recipients"],
            })
        }),
        command => {
            let config = WatchConfig::load(&args.config)?;
            config.check_environment()?;
            let store = Store::open(&config.store, &config.tenant_id)?;
            match command {
                WatchCommand::Probe => {
                    let up = live(&config)?;
                    let report = probe::probe_all(&up, &store).await?;
                    store.audit("cli", "probe", "tenant", "{}")?;
                    Ok(serde_json::to_value(report)?)
                }
                WatchCommand::Subscribe { content_types } => {
                    let up = live(&config)?;
                    let types = if content_types.is_empty() {
                        config.content_types.clone()
                    } else {
                        content_types
                    };
                    let refs: Vec<&str> = types.iter().map(String::as_str).collect();
                    let results = probe::start_subscriptions(&up, &store, "cli", &refs).await?;
                    Ok(
                        json!({"results": results.into_iter().map(|(ct, r)| json!({"content_type": ct, "result": r.err().unwrap_or_else(|| "started".into())})).collect::<Vec<_>>(),
                              "next": "Microsoft can take up to 12 hours to deliver the first content. Run `junction watch probe` later to confirm."}),
                    )
                }
                WatchCommand::Collect => {
                    // No close_abandoned_runs here: a daemon may be mid-run.
                    let up = live(&config)?;
                    collect_once(&up, &store, &config).await
                }
                WatchCommand::Run { no_web } => run_daemon(config, store, !no_web).await,
                WatchCommand::Serve => {
                    let up = live(&config).ok().map(Arc::new);
                    serve(&config, store, up).await?;
                    Ok(json!({"status": "stopped"}))
                }
                WatchCommand::Status => status(&store),
                WatchCommand::Validate => validate(&config).await,
                WatchCommand::VerifyTrail => Ok(match store.verify_audit_trail()? {
                    None => json!({"status": "intact"}),
                    Some(id) => json!({"status": "broken", "first_bad_entry": id}),
                }),
                WatchCommand::User { command } => user(&store, command),
                WatchCommand::Rules => Ok(serde_json::to_value(crate::rules::registry())?),
                WatchCommand::Detect => Ok(
                    json!({"new_alerts":crate::incidents::detect(&store, &rule_settings(&config,&store)?)?}),
                ),
                WatchCommand::ImportSnapshot { file } => {
                    let snapshot = crate::drift::read_snapshot(&file)?;
                    store.audit("cli", "snapshot_import", &snapshot.resource_type, "{}")?;
                    let (id, changes) = store.import_snapshot(&snapshot)?;
                    Ok(
                        json!({"snapshot_id":id,"changes":changes,"baseline":"Review the complete snapshot, then run approve-baseline with this ID."}),
                    )
                }
                WatchCommand::ApproveBaseline { id } => {
                    store.approve_baseline(&id, "cli")?;
                    Ok(json!({"approved":id}))
                }
                WatchCommand::Report { period } => store.report(&period, Instant::now()),
                WatchCommand::Retain => store.retain(Instant::now(), "cli"),
                WatchCommand::Backfill { days } => {
                    if !(1..=6).contains(&days) {
                        bail!("backfill supports 1 to 6 days within the API availability window");
                    }
                    store.audit(
                        "cli",
                        "backfill",
                        "audit_feeds",
                        &json!({"days":days}).to_string(),
                    )?;
                    let up = live(&config)?;
                    let options = CollectOptions {
                        overlap: Duration::from_secs(days * 86400),
                        ..Default::default()
                    };
                    Ok(serde_json::to_value(
                        activity::collect_all(&up, &store, &config.content_types, &options).await,
                    )?)
                }
                WatchCommand::Init { .. } | WatchCommand::Permissions { .. } => unreachable!(),
            }
        }
    }
}

fn init(path: &std::path::Path, tenant_id: &str, domain: &str, client_id: &str) -> Result<Value> {
    let text = WatchConfig::example(tenant_id, domain, client_id);
    let config: WatchConfig = toml::from_str(&text)?;
    config.validate()?;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .context("configuration already exists or cannot be created")?;
    file.write_all(text.as_bytes())?;
    Ok(json!({
        "config": path,
        "steps": [
            "1. In Entra ID > App registrations, create a single-tenant app named 'Junction Watchdog'. Do not add a client secret.",
            "2. Upload the public certificate (Certificates & secrets > Certificates). Keep the private key on this machine only, mode 0600.",
            "3. API permissions: add the application permissions from `junction watch permissions` (or paste `junction watch permissions --manifest` into the manifest's requiredResourceAccess).",
            "4. Grant admin consent: press 'Grant admin consent' on the API permissions page, or open the consent URL below as a Global Administrator.",
            "5. Turn on auditing if it is off: Microsoft Purview portal > Audit. It is OFF by default on Business Basic, Standard and Premium.",
            "6. Export AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_CERTIFICATE_PATH and AZURE_CLIENT_PRIVATE_KEY_PATH, then run `junction watch probe`.",
            "7. Run `junction watch subscribe` to start the audit feeds, then `junction watch user add <name> --role admin`, then `junction watch run`."
        ],
        "admin_consent_url": catalog::admin_consent_url(tenant_id, client_id, &format!("http://{}/", config.web.bind)),
        "admin_consent_note": "The redirect URI must be registered on the app (Authentication > Web). The portal button needs no redirect URI.",
    }))
}

fn live(config: &WatchConfig) -> Result<LiveUpstream> {
    let mut policy = junction_policy::Policy::default();
    policy.limits.max_requests_per_minute = config.max_requests_per_minute;
    let governor = junction_policy::RequestGovernor::new(&policy)?;
    let transport =
        junction_http::HttpTransport::new(governor, Duration::from_secs(60), 64 * 1024 * 1024)?;
    LiveUpstream::new(&config.tenant_id, config.cloud, config.auth, transport)
}

async fn collect_once(
    up: &impl crate::upstream::Upstream,
    store: &Store,
    config: &WatchConfig,
) -> Result<Value> {
    let now = Instant::now();
    if store
        .meta("last_retention")?
        .and_then(|s| Instant::parse(&s).ok())
        .is_none_or(|t| now.since(t) > Duration::from_secs(86400))
    {
        store.retain(now, "scheduler")?;
        store.put_meta("last_retention", &now.to_rfc3339())?;
    }
    let probe = match probe::probe_if_due(up, store).await {
        None => json!("not due"),
        Some(Ok(r)) => {
            json!({"runnable": r.runnable_detections.len(), "blocked": r.blocked_detections.len()})
        }
        Some(Err(e)) => json!({"error": format!("{e:#}")}),
    };
    let feeds =
        activity::collect_all(up, store, &config.content_types, &CollectOptions::default()).await;
    let mut graph = vec![];
    for source in crate::graph::SOURCES {
        graph.push(
            match crate::graph::collect(up, store, source, Instant::now(), Default::default()).await
            {
                Ok(v) => v,
                Err(_) => {
                    json!({"source":source,"status":"failed","reason":"local store unavailable"})
                }
            },
        );
    }
    let settings = rule_settings(config, store)?;
    let snapshot_collection = crate::drift::collect_sharepoint(up, store).await;
    if let Some(directory) = &config.snapshot_directory {
        crate::drift::import_directory(store, directory)?;
    }
    let snapshot_events = store.reconcile_snapshot_events().map(|_| json!("ok")).unwrap_or_else(|_| json!({"status":"failed","reason":"snapshot event reconciliation failed; retry pending"}));
    // A failed detector must not prevent delivery of already queued incidents.
    let alerts = crate::incidents::detect(store, &settings)
        .map(|n| json!(n))
        .unwrap_or_else(
            |_| json!({"status":"failed","reason":"detection failed; pending events retained"}),
        );
    store.escalate(Instant::now())?;
    let notification_config = if store.meta("operational_settings")?.is_some() {
        store.operational_settings()?.notifications
    } else {
        config.notifications.clone()
    };
    let notifications =
        crate::notify::deliver(store, &notification_config, &settings.internal_domains).await?;
    store.scheduled_reports(Instant::now())?;
    Ok(
        json!({"collected_at": Instant::now().to_rfc3339(), "probe": probe, "feeds": feeds, "graph":graph, "new_alerts":alerts, "snapshots":snapshot_collection.ok(), "snapshot_events":snapshot_events, "notifications":notifications}),
    )
}

fn log(value: Value) {
    eprintln!("{value}");
}

async fn run_daemon(config: WatchConfig, store: Store, with_web: bool) -> Result<Value> {
    let up = Arc::new(live(&config)?);
    store.close_abandoned_runs()?;
    if with_web {
        if auth::user_count(&store)? == 0 {
            bail!(
                "create a dashboard account first: junction watch user add <name> --role admin (or pass --no-web)"
            );
        }
        let (c, s, u) = (config.clone(), store.clone(), up.clone());
        tokio::spawn(async move {
            if let Err(e) = serve(&c, s, Some(u)).await {
                log(json!({"event": "dashboard_stopped", "error": format!("{e:#}")}));
            }
        });
    }
    let interval = Duration::from_secs(config.poll_interval_minutes * 60);
    let mut last_run: Option<Instant> = None;
    log(json!({"event": "watch_started", "interval_minutes": config.poll_interval_minutes}));
    loop {
        // Wall-clock scheduling: monotonic timers stop while a laptop sleeps, so a
        // short tick plus a wall-clock comparison resumes promptly after wake.
        let effective_interval = if store.meta("operational_settings")?.is_some() {
            Duration::from_secs(store.operational_settings()?.poll_minutes * 60)
        } else {
            interval
        };
        let due = last_run.is_none_or(|t| Instant::now().since(t) >= effective_interval);
        if due {
            last_run = Some(Instant::now());
            match collect_once(up.as_ref(), &store, &config).await {
                Ok(v) => log(json!({"event": "collected", "result": v})),
                Err(e) => log(json!({"event": "collect_failed", "error": format!("{e:#}")})),
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(60)) => {}
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    Ok(json!({"status": "stopped"}))
}

pub fn allowed_hosts(bind: &str) -> Vec<String> {
    let mut hosts = vec![bind.to_owned()];
    if let Ok(addr) = bind.parse::<std::net::SocketAddr>()
        && addr.ip().is_loopback()
    {
        hosts.push(format!("localhost:{}", addr.port()));
    }
    hosts
}

async fn serve(
    config: &WatchConfig,
    store: Store,
    upstream: Option<Arc<LiveUpstream>>,
) -> Result<()> {
    let state = Arc::new(web::AppState {
        store,
        upstream,
        tenant_domain: config.tenant_domain.clone(),
        content_types: config.content_types.clone(),
        session_lifetime: Duration::from_secs(config.web.session_hours * 3600),
        allowed_hosts: allowed_hosts(&config.web.bind),
        throttle: Default::default(),
    });
    let listener = tokio::net::TcpListener::bind(&config.web.bind)
        .await
        .context("dashboard address unavailable")?;
    log(json!({"event": "dashboard_listening", "url": format!("http://{}/", config.web.bind)}));
    axum::serve(listener, web::router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .context("dashboard failed")
}

fn status(store: &Store) -> Result<Value> {
    let caps = store.capabilities()?;
    let (runnable, blocked) = probe::detection_coverage(&caps);
    Ok(json!({
        "tenant_id": store.tenant_id(),
        "events_stored": store.event_count()?,
        "capabilities": caps,
        "runnable_detections": runnable,
        "blocked_detections": blocked,
        "recent_runs": store.recent_runs(10)?,
        "gaps": store.gaps()?,
    }))
}

async fn validate(config: &WatchConfig) -> Result<Value> {
    let up = live(config)?;
    let scratch = Store::in_memory(&config.tenant_id)?;
    let report = probe::probe_all(&up, &scratch).await?;
    let mut collection = vec![];
    let options = CollectOptions {
        max_blobs_per_run: 5,
        ..Default::default()
    };
    for ct in &config.content_types {
        let source = format!("o365:{ct}");
        // Sample only the last two hours so validation stays quick and light.
        scratch.advance_checkpoint(&source, Instant::now().minus(Duration::from_secs(3600)))?;
        let outcome = activity::collect(&up, &scratch, ct, Instant::now(), &options).await?;
        collection.push(outcome);
    }
    let mut graph_collection = vec![];
    for source in crate::graph::SOURCES {
        scratch.advance_checkpoint(source, Instant::now().minus(Duration::from_secs(3600)))?;
        graph_collection.push(
            crate::graph::collect(&up, &scratch, source, Instant::now(), Default::default())
                .await?,
        );
    }
    let mut operations: Vec<String> = scratch
        .events(&crate::store::EventQuery {
            limit: 500,
            ..Default::default()
        })?
        .into_iter()
        .map(|e| format!("{} {}", e.source, e.operation))
        .collect();
    operations.sort();
    operations.dedup();
    Ok(json!({
        "mode": "read-only validation; nothing was stored or changed",
        "capabilities": report.capabilities,
        "granted_graph_roles": report.granted_graph_roles,
        "granted_management_roles": report.granted_management_roles,
        "runnable_detections": report.runnable_detections,
        "blocked_detections": report.blocked_detections,
        "sample_collection": collection,
        "graph_sample_collection": graph_collection,
        "observed_event_types": operations,
    }))
}

fn user(store: &Store, command: UserCommand) -> Result<Value> {
    match command {
        UserCommand::Add { username, role } => {
            let role = Role::parse(&role)?;
            let password = read_password()?;
            auth::create_user(store, &username, &password, role)?;
            Ok(json!({"status": "created", "username": username, "role": role.as_str()}))
        }
        UserCommand::Disable { username } => {
            auth::set_disabled(store, &username, true)?;
            Ok(json!({"status": "disabled", "username": username}))
        }
        UserCommand::Enable { username } => {
            auth::set_disabled(store, &username, false)?;
            Ok(json!({"status": "enabled", "username": username}))
        }
    }
}

/// Never a command-line argument: prompt without echo on a terminal, otherwise
/// read one line from standard input.
fn read_password() -> Result<String> {
    use std::io::IsTerminal;
    let password = if std::io::stdin().is_terminal() {
        let first =
            rpassword::prompt_password("Password: ").context("password input unavailable")?;
        let again = rpassword::prompt_password("Repeat password: ")
            .context("password input unavailable")?;
        if first != again {
            bail!("passwords do not match");
        }
        first
    } else {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("password input unavailable")?;
        line.trim_end_matches(['\r', '\n']).to_owned()
    };
    Ok(password)
}

fn rule_settings(config: &WatchConfig, store: &Store) -> Result<crate::rules::RuleSettings> {
    let mut settings = config.rules.clone();
    if store.meta("operational_settings")?.is_some() {
        let operational = store.operational_settings()?;
        settings.bulk_threshold = operational.bulk_threshold;
        settings.approved_external_domains = operational.approved_external_domains;
        settings.sensitive_sites = operational.sensitive_sites;
    }
    settings.internal_domains.push(config.tenant_domain.clone());
    if let Some(domains) = store.meta("verified_domains")? {
        settings
            .internal_domains
            .extend(serde_json::from_str::<Vec<String>>(&domains)?);
    }
    Ok(settings)
}
