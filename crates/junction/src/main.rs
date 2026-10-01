mod approval_cli;
mod auth_cli;
mod context_store;
mod credential_lock;
mod input;
mod invocation;
mod mcp_host;
mod mcp_pages;
mod operation_store;
mod output;
mod scope;
use anyhow::Result;
use clap::{Parser, Subcommand};
use junction_core::RegistryManifest;
use junction_registry::Registry;
use std::ffi::OsString;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "junction",
    version,
    about = "Microsoft API operation runtime",
    after_help = "Operations also accept hierarchical spelling: junction graph users list --input '{}'.\nUse hyphens for underscores: junction azure compute virtual-machines list.\nThe shorthand junction azure vm list resolves azure.compute.virtual_machines.list."
)]
struct Cli {
    #[arg(long, default_value = "generated/registry/operations.json")]
    registry: PathBuf,
    /// Trusted TOML file correcting operation risks for all registry consumers.
    #[arg(long, global = true)]
    risk_overrides: Option<PathBuf>,
    /// Select a named local execution context.
    #[arg(long, global = true)]
    context: Option<String>,
    #[arg(long, global = true, default_value = ".junction/contexts")]
    contexts_directory: PathBuf,
    /// Private directory for resumable long-running operation handles.
    #[arg(long, global = true, default_value = ".junction/operations")]
    operations_directory: PathBuf,
    /// Emit compact JSON (the default output is formatted JSON).
    #[arg(long, global = true, conflicts_with_all = ["yaml", "table"])]
    json: bool,
    /// Emit YAML with the same data as JSON output.
    #[arg(long, global = true)]
    yaml: bool,
    /// Emit tab-separated tables with JSON-escaped cells.
    #[arg(long, global = true, conflicts_with = "yaml")]
    table: bool,
    /// Suppress successful output; errors still use stderr and nonzero status.
    #[arg(long, global = true)]
    quiet: bool,
    /// Emit timing diagnostics to stderr without request data or credentials.
    #[arg(long, global = true, conflicts_with = "quiet")]
    verbose: bool,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Explore the API catalog in an interactive Ratatui terminal interface.
    Tui {
        #[arg(long)]
        allow_preview: bool,
    },
    /// Serve the local HTTP API with a fixed context and policy.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: std::net::SocketAddr,
        #[arg(long)]
        allow_external: bool,
        /// Environment variable containing the local server bearer token.
        #[arg(long, default_value = "JUNCTION_SERVER_TOKEN")]
        token_env: String,
        #[arg(long, default_value = "read-only", value_parser = ["read-only", "safe-write", "full"])]
        policy: String,
        #[arg(long, conflicts_with = "policy")]
        policy_file: Option<PathBuf>,
        #[arg(long)]
        context_file: Option<PathBuf>,
    },
    /// Export Junction's own local HTTP API contract without loading a registry.
    Openapi {
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Serve the small native MCP tool surface over stdio.
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
    /// Inspect or resume an operator-owned long-running operation.
    Operations {
        #[command(subcommand)]
        command: OperationsCommand,
    },
    /// Inspect credentials without exposing token values.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// Invoke a canonical operation as space-separated components.
    #[command(external_subcommand)]
    Operation(Vec<OsString>),
    /// Generate Rust/Serde types for selected canonical schemas and their references.
    GenerateRust {
        #[arg(long = "schema", required = true, num_args = 1..=256)]
        schemas: Vec<String>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Refresh an official source into one registry with retained download receipts.
    Refresh {
        source: String,
        /// Narrow the configured source scope; repeat for multiple paths.
        #[arg(long = "path")]
        paths: Vec<String>,
        #[arg(long)]
        revision: Option<String>,
        #[arg(long, default_value = "sources")]
        sources_directory: PathBuf,
        #[arg(long)]
        service: Option<String>,
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long)]
        api_version: Option<String>,
        #[arg(long, default_value_t = 256)]
        max_documents: usize,
        #[arg(long, default_value_t = 536870912)]
        max_bytes: usize,
        /// Overall discovery/download deadline, between 1 and 3600 seconds.
        #[arg(long, default_value_t = 900)]
        timeout_seconds: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Merge imported registries with isolated document schema namespaces.
    Merge {
        #[arg(required = true, num_args = 1..=256)]
        manifests: Vec<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Enumerate candidate documents in an official source at a pinned commit.
    Discover {
        source: String,
        #[arg(long)]
        revision: Option<String>,
        #[arg(long, default_value = "sources")]
        sources_directory: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Download an official OpenAPI source at an immutable revision.
    Fetch {
        source: String,
        #[arg(long)]
        path: String,
        /// Full Git commit identifier; omitted resolves the default branch head.
        #[arg(long)]
        revision: Option<String>,
        #[arg(long, default_value = "sources")]
        sources_directory: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Manage secret-free local execution contexts.
    Context {
        #[command(subcommand)]
        command: ContextCommand,
    },
    /// Execute a discovered operation using environment client-secret credentials.
    Execute {
        operation: String,
        /// Set the operation's declared subscription path parameter.
        #[arg(long)]
        subscription: Option<String>,
        /// Set the operation's declared resource-group path parameter.
        #[arg(long)]
        resource_group: Option<String>,
        #[arg(long, conflicts_with = "input_file")]
        input: Option<String>,
        /// Read bounded JSON from a file, or '-' for stdin.
        #[arg(long)]
        input_file: Option<PathBuf>,
        /// JSON file containing endpoint and token_request; never store secrets here.
        #[arg(long)]
        context_file: Option<PathBuf>,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        api_version: Option<String>,
        #[arg(long)]
        allow_preview: bool,
        /// Retrieve bounded Graph/ARM pages instead of a single response.
        #[arg(long, requires = "continuation_file")]
        all: bool,
        #[arg(long, requires = "all", default_value_t = 100)]
        max_items: usize,
        #[arg(long, requires = "all", default_value_t = 5)]
        max_pages: usize,
        /// New private file for any unconsumed records and next-page state.
        #[arg(long, requires = "all")]
        continuation_file: Option<PathBuf>,
        /// Resume an operator-owned continuation using the same operation/input/context.
        #[arg(long, requires = "all")]
        resume: Option<PathBuf>,
        /// Start and wait for a declared Azure long-running operation.
        #[arg(long, conflicts_with = "all")]
        wait: bool,
        #[arg(long, requires = "wait", default_value_t = 300)]
        timeout_seconds: u64,
        #[arg(long, requires = "wait", default_value_t = 100)]
        max_polls: usize,
        /// Review and approve one destructive or privileged request on the
        /// controlling terminal. Piped input and agents cannot answer it.
        #[arg(long, conflicts_with = "all")]
        approve: bool,
    },
    /// Execute a bounded dependency-aware batch in one trusted context.
    Batch {
        #[arg(
            long,
            required_unless_present = "input_file",
            conflicts_with = "input_file"
        )]
        input: Option<String>,
        /// Read bounded batch JSON from a file, or '-' for stdin.
        #[arg(long)]
        input_file: Option<PathBuf>,
        #[arg(long)]
        context_file: Option<PathBuf>,
        #[arg(long)]
        policy: Option<PathBuf>,
    },
    /// Inspect and validate official source configuration without fetching.
    Sources {
        #[arg(long, default_value = "sources")]
        directory: PathBuf,
    },
    /// Inspect the catalog hierarchy and available versions.
    Api {
        #[command(subcommand)]
        command: ApiCommand,
    },
    /// Normalize a JSON schema, retaining original constraints and extensions.
    Schema { input: PathBuf },
    /// Normalize OpenAPI JSON/YAML or OData CSDL XML into an operation manifest.
    Import {
        spec: PathBuf,
        #[arg(long)]
        product: String,
        #[arg(long)]
        service: String,
        #[arg(long)]
        source: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "openapi", value_parser = ["openapi", "odata"])]
        format: String,
        /// Trusted HTTPS service root for CSDL metadata.
        #[arg(long, required_if_eq("format", "odata"))]
        endpoint: Option<String>,
        /// Service API version; the EDMX format version is not an API version.
        #[arg(long, required_if_eq("format", "odata"))]
        api_version: Option<String>,
    },
    /// Evaluate local authorization without making an API request.
    PolicyCheck {
        operation: String,
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        policy: PathBuf,
    },
    Search {
        query: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        product: Option<String>,
        #[arg(long)]
        service: Option<String>,
        #[arg(long)]
        allow_preview: bool,
    },
    Describe {
        operation: String,
        #[arg(long)]
        api_version: Option<String>,
        #[arg(long)]
        allow_preview: bool,
    },
    /// Inspect imported scope requirements without acquiring credentials.
    Permissions {
        operation: String,
        #[arg(long)]
        api_version: Option<String>,
        #[arg(long)]
        allow_preview: bool,
    },
}
#[derive(Subcommand)]
enum ContextCommand {
    Add {
        name: String,
        #[arg(long)]
        file: PathBuf,
    },
    List,
    Show {
        name: String,
    },
    Remove {
        name: String,
    },
}

#[derive(Subcommand)]
enum AuthCommand {
    /// Sign in using a device code and save the access credential in the OS store.
    Login {
        #[arg(long)]
        context_file: Option<PathBuf>,
        /// Client ID of an operator-owned Entra public-client application.
        #[arg(long)]
        client_id: String,
        #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u64).range(1..=3600))]
        timeout_seconds: u64,
    },
    /// Remove the saved credential for the exact selected acquisition context.
    Logout {
        #[arg(long)]
        context_file: Option<PathBuf>,
    },
    /// Inspect saved credentials without contacting Microsoft.
    Status {
        #[arg(long)]
        context_file: Option<PathBuf>,
    },
    /// Inspect interactive credentials referenced by named local contexts.
    Accounts,
    /// Acquire or validate a token and print only safe metadata.
    TokenInfo {
        #[arg(long)]
        context_file: Option<PathBuf>,
    },
}
#[derive(Subcommand)]
enum OperationsCommand {
    /// Show the last saved state without contacting Microsoft.
    Get { id: String },
    /// Resume polling with the original tenant, audience, endpoint and API version.
    Wait {
        id: String,
        #[arg(long)]
        context_file: Option<PathBuf>,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long, default_value_t = 300)]
        timeout_seconds: u64,
        /// Retrieve the final response after successful completion.
        #[arg(long)]
        result: bool,
    },
}
#[derive(Subcommand)]
enum McpCommand {
    Serve {
        #[arg(long, default_value = "read-only", value_parser = ["read-only", "safe-write", "full"])]
        policy: String,
        #[arg(long, conflicts_with = "policy")]
        policy_file: Option<PathBuf>,
        #[arg(long)]
        context_file: Option<PathBuf>,
    },
}
#[derive(Subcommand)]
enum ApiCommand {
    /// Compare operation and schema metadata with an earlier manifest.
    Changes {
        previous: PathBuf,
    },
    Stats,
    Products,
    Services {
        #[arg(long)]
        product: Option<String>,
    },
    Versions {
        operation: String,
    },
}
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ExecutionConfig {
    endpoint: String,
    token_request: junction_auth::TokenRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    subscription: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default_resource_group: Option<String>,
    /// Known only for cloud-resolved contexts; explicit endpoints are custom.
    #[serde(skip)]
    cloud: Option<junction_core::cloud::MicrosoftCloud>,
}
impl ExecutionConfig {
    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 64 * 1024 {
            anyhow::bail!("context size limit exceeded");
        }
        let config: Self = serde_json::from_slice(bytes)
            .map_err(|_| anyhow::anyhow!("invalid execution context"))?;
        let endpoint = url::Url::parse(&config.endpoint)
            .map_err(|_| anyhow::anyhow!("invalid context endpoint"))?;
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            anyhow::bail!("invalid context endpoint");
        }
        if !matches!(
            config.token_request.flow,
            junction_auth::AuthFlow::ClientCredentials
                | junction_auth::AuthFlow::DeviceCode
                | junction_auth::AuthFlow::ManagedIdentity
                | junction_auth::AuthFlow::Certificate
                | junction_auth::AuthFlow::WorkloadIdentity
                | junction_auth::AuthFlow::ExternalBearer
                | junction_auth::AuthFlow::OnBehalfOf
        ) {
            anyhow::bail!("unsupported CLI authentication flow");
        }
        config.token_request.validate()?;
        scope::validate(
            config.subscription.as_deref(),
            config.default_resource_group.as_deref(),
        )?;
        Ok(config)
    }
}
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct CloudExecutionConfig {
    cloud: junction_core::cloud::MicrosoftCloud,
    tenant: String,
    service: junction_core::cloud::CloudService,
    credential_profile: String,
    #[serde(default = "default_auth_flow")]
    flow: junction_auth::AuthFlow,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    endpoint_variables: std::collections::BTreeMap<String, String>,
    custom_endpoints: Option<junction_core::cloud::CloudEndpoints>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    subscription: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default_resource_group: Option<String>,
}
fn default_auth_flow() -> junction_auth::AuthFlow {
    junction_auth::AuthFlow::ClientCredentials
}
impl CloudExecutionConfig {
    fn validate(&self) -> Result<()> {
        scope::validate(
            self.subscription.as_deref(),
            self.default_resource_group.as_deref(),
        )?;
        if !matches!(
            self.flow,
            junction_auth::AuthFlow::ClientCredentials
                | junction_auth::AuthFlow::DeviceCode
                | junction_auth::AuthFlow::ManagedIdentity
                | junction_auth::AuthFlow::Certificate
                | junction_auth::AuthFlow::WorkloadIdentity
                | junction_auth::AuthFlow::ExternalBearer
                | junction_auth::AuthFlow::OnBehalfOf
        ) {
            anyhow::bail!("unsupported CLI authentication flow");
        }
        use junction_core::cloud::MicrosoftCloud;
        let endpoints = match (&self.cloud, &self.custom_endpoints) {
            (MicrosoftCloud::Custom, Some(endpoints)) => endpoints.clone(),
            (MicrosoftCloud::Custom, None) => anyhow::bail!("custom endpoints required"),
            (_, Some(_)) => anyhow::bail!("endpoint overrides require custom cloud"),
            (cloud, None) => cloud.endpoints()?,
        };
        endpoints.validate()?;
        let target = endpoints.target(self.service)?;
        let audience = target
            .audience
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("service audience requires explicit configuration"))?;
        junction_auth::TokenRequest {
            tenant: self.tenant.clone(),
            authority: endpoints.authority.clone(),
            audience: audience.into(),
            scopes: self.scopes.clone(),
            credential_profile: self.credential_profile.clone(),
            flow: self.flow,
        }
        .validate()
    }
    fn resolve(self, operation: &junction_core::JunctionOperation) -> Result<ExecutionConfig> {
        self.validate()?;
        use junction_core::cloud::MicrosoftCloud;
        let endpoints = match (self.cloud, self.custom_endpoints) {
            (MicrosoftCloud::Custom, Some(endpoints)) => endpoints,
            (MicrosoftCloud::Custom, None) => anyhow::bail!("custom endpoints required"),
            (_, Some(_)) => anyhow::bail!("endpoint overrides require custom cloud"),
            (cloud, None) => cloud.endpoints()?,
        };
        let upstream = match &operation.endpoint_template {
            Some(template) => template.resolve(&self.endpoint_variables)?,
            None if self.endpoint_variables.is_empty() => operation.base_url.clone(),
            None => anyhow::bail!("operation has no endpoint variables"),
        };
        let target = endpoints.resolve(self.service, &upstream)?;
        let config = ExecutionConfig {
            cloud: Some(self.cloud),
            endpoint: target.endpoint,
            subscription: self.subscription,
            default_resource_group: self.default_resource_group,
            token_request: junction_auth::TokenRequest {
                tenant: self.tenant,
                authority: endpoints.authority.clone(),
                audience: target
                    .audience
                    .ok_or_else(|| anyhow::anyhow!("missing audience"))?,
                scopes: self.scopes,
                credential_profile: self.credential_profile,
                flow: self.flow,
            },
        };
        config.token_request.validate()?;
        Ok(config)
    }
}
fn load_execution_config(
    bytes: &[u8],
    operation: &junction_core::JunctionOperation,
) -> Result<ExecutionConfig> {
    if bytes.len() > 64 * 1024 {
        anyhow::bail!("context size limit exceeded");
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("invalid execution context"))?;
    if value.get("cloud").is_some() {
        let config: CloudExecutionConfig = serde_json::from_value(value)
            .map_err(|_| anyhow::anyhow!("invalid cloud execution context"))?;
        config.resolve(operation)
    } else {
        ExecutionConfig::parse(bytes)
    }
}
fn validated_context(bytes: &[u8]) -> Result<serde_json::Value> {
    if bytes.len() > 64 * 1024 {
        anyhow::bail!("context size limit exceeded");
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("invalid execution context"))?;
    if value.get("cloud").is_some() {
        let config: CloudExecutionConfig =
            serde_json::from_value(value).map_err(|_| anyhow::anyhow!("invalid cloud context"))?;
        config.validate()?;
        Ok(serde_json::to_value(config)?)
    } else {
        Ok(serde_json::to_value(ExecutionConfig::parse(bytes)?)?)
    }
}
fn context_token_request(bytes: &[u8]) -> Result<junction_auth::TokenRequest> {
    let value = validated_context(bytes)?;
    if value.get("cloud").is_none() {
        return Ok(ExecutionConfig::parse(bytes)?.token_request);
    }
    let config: CloudExecutionConfig =
        serde_json::from_value(value).map_err(|_| anyhow::anyhow!("invalid cloud context"))?;
    let endpoints = match (&config.cloud, &config.custom_endpoints) {
        (junction_core::cloud::MicrosoftCloud::Custom, Some(endpoints)) => endpoints.clone(),
        (cloud, _) => cloud.endpoints()?,
    };
    let target = endpoints.target(config.service)?;
    let request = junction_auth::TokenRequest {
        tenant: config.tenant,
        authority: endpoints.authority.clone(),
        audience: target
            .audience
            .clone()
            .ok_or_else(|| anyhow::anyhow!("service audience unavailable"))?,
        scopes: config.scopes,
        credential_profile: config.credential_profile,
        flow: config.flow,
    };
    request.validate()?;
    Ok(request)
}
fn parse_input(input: &str) -> Result<serde_json::Value> {
    if input.len() > 16 * 1024 * 1024 {
        anyhow::bail!("input size limit exceeded");
    }
    serde_json::from_str(input).map_err(|_| anyhow::anyhow!("invalid execution input"))
}
fn atomic_write(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|_| anyhow::anyhow!("could not publish output file"))?;
    Ok(())
}
struct OutputOptions {
    table: bool,
    yaml: bool,
    compact: bool,
    quiet: bool,
}
impl OutputOptions {
    fn emit(&self, value: &impl serde::Serialize) -> Result<()> {
        if !self.quiet {
            let text = if self.table {
                output::table(&serde_json::to_value(value)?)
            } else if self.yaml {
                serde_saphyr::to_string(&serde_json::to_value(value)?)?
            } else if self.compact {
                serde_json::to_string(value)?
            } else {
                serde_json::to_string_pretty(value)?
            };
            println!("{text}");
        }
        Ok(())
    }
}
async fn run() -> Result<()> {
    let arguments: Vec<_> = std::env::args_os().collect();
    let mut cli = Cli::parse_from(&arguments);
    if let Command::Operation(ref operation) = cli.command {
        cli = Cli::parse_from(invocation::rewrite(&arguments, operation)?);
    }
    let _diagnostics = Diagnostics::start(cli.verbose);
    let output_options = OutputOptions {
        table: cli.table,
        yaml: cli.yaml,
        compact: cli.json,
        quiet: cli.quiet,
    };
    if let Command::Openapi { output } = &cli.command {
        let contract = junction_server::openapi();
        if let Some(path) = output {
            atomic_write(path, &serde_json::to_vec_pretty(&contract)?)?;
        } else {
            output_options.emit(&contract)?;
        }
        return Ok(());
    }
    if let Command::Operations {
        command: OperationsCommand::Get { id },
    } = &cli.command
    {
        let handle = operation_store::load(&cli.operations_directory, id)?;
        output_options.emit(&handle.snapshot())?;
        return Ok(());
    }
    if let Command::Auth { command } = &cli.command {
        auth_cli::run(&cli, command, &output_options).await?;
        return Ok(());
    }
    if let Command::Refresh {
        source,
        paths,
        revision,
        sources_directory,
        service,
        endpoint,
        api_version,
        max_documents,
        max_bytes,
        timeout_seconds,
        output,
    } = &cli.command
    {
        let sources = junction_discovery::sources::load_sources(sources_directory)?;
        let source = sources
            .iter()
            .find(|candidate| &candidate.id == source)
            .ok_or_else(|| anyhow::anyhow!("unknown source identifier"))?;
        let options = junction_discovery::refresh::RefreshOptions {
            service: service.clone(),
            endpoint: endpoint.clone(),
            api_version: api_version.clone(),
            max_documents: *max_documents,
            max_bytes: *max_bytes,
            timeout_seconds: *timeout_seconds,
        };
        let manifest = junction_discovery::fetch::OfficialFetcher::new(128 * 1024 * 1024)?
            .refresh_scoped(source, paths, revision.as_deref(), options)
            .await?;
        Registry::load(manifest.clone())?;
        atomic_write(output, &serde_json::to_vec_pretty(&manifest)?)?;
        output_options.emit(
            &serde_json::json!({"status":"refreshed","operations":manifest.operations.len()}),
        )?;
        return Ok(());
    }
    if let Command::Merge { manifests, output } = &cli.command {
        use std::io::Read;
        let mut inputs = Vec::new();
        let mut total_bytes = 0usize;
        for path in manifests {
            let mut bytes = Vec::new();
            std::fs::File::open(path)?
                .take(128 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            total_bytes = total_bytes.saturating_add(bytes.len());
            if bytes.len() > 128 * 1024 * 1024 || total_bytes > 512 * 1024 * 1024 {
                anyhow::bail!("manifest merge input limit exceeded");
            }
            inputs.push(
                serde_json::from_slice(&bytes)
                    .map_err(|_| anyhow::anyhow!("invalid registry manifest"))?,
            );
        }
        let manifest = junction_discovery::merge::merge(inputs)?;
        Registry::load(manifest.clone())?;
        atomic_write(output, &serde_json::to_vec_pretty(&manifest)?)?;
        output_options
            .emit(&serde_json::json!({"status":"merged","operations":manifest.operations.len()}))?;
        return Ok(());
    }
    if let Command::Discover {
        source,
        revision,
        sources_directory,
        output,
    } = &cli.command
    {
        let sources = junction_discovery::sources::load_sources(sources_directory)?;
        let source = sources
            .iter()
            .find(|candidate| &candidate.id == source)
            .ok_or_else(|| anyhow::anyhow!("unknown source identifier"))?;
        let inventory = junction_discovery::fetch::OfficialFetcher::new(128 * 1024 * 1024)?
            .discover(source, revision.as_deref())
            .await?;
        if let Some(output) = output {
            atomic_write(output, &serde_json::to_vec_pretty(&inventory)?)?;
        }
        output_options.emit(&inventory)?;
        return Ok(());
    }
    if let Command::Fetch {
        source,
        path,
        revision,
        sources_directory,
        output,
    } = &cli.command
    {
        let sources = junction_discovery::sources::load_sources(sources_directory)?;
        let source = sources
            .iter()
            .find(|candidate| &candidate.id == source)
            .ok_or_else(|| anyhow::anyhow!("unknown source identifier"))?;
        let fetched = junction_discovery::fetch::OfficialFetcher::new(128 * 1024 * 1024)?
            .fetch(source, path, revision.as_deref())
            .await?;
        match source.source_type {
            junction_discovery::sources::SourceType::OData => {
                junction_discovery::odata::validate_document(&fetched.bytes)?
            }
            _ => {
                let document = junction_discovery::parse_document(&fetched.bytes)?;
                if document.get("openapi").is_none() && document.get("swagger").is_none() {
                    anyhow::bail!("downloaded document is not OpenAPI or Swagger");
                }
            }
        }
        atomic_write(output, &fetched.bytes)?;
        let mut receipt_path = output.as_os_str().to_os_string();
        receipt_path.push(".receipt.json");
        atomic_write(
            std::path::Path::new(&receipt_path),
            &serde_json::to_vec_pretty(&fetched.receipt)?,
        )?;
        output_options.emit(&fetched.receipt)?;
        return Ok(());
    }
    if let Command::Context { command } = &cli.command {
        let output = match command {
            ContextCommand::Add { name, file } => {
                let value = validated_context(&context_store::read_file(file)?)?;
                context_store::add(
                    &cli.contexts_directory,
                    name,
                    &serde_json::to_vec_pretty(&value)?,
                )?;
                serde_json::json!({"status":"added","context":name})
            }
            ContextCommand::List => {
                serde_json::json!({"contexts":context_store::list(&cli.contexts_directory)?})
            }
            ContextCommand::Show { name } => {
                validated_context(&context_store::read(&cli.contexts_directory, name)?)?
            }
            ContextCommand::Remove { name } => {
                context_store::remove(&cli.contexts_directory, name)?;
                serde_json::json!({"status":"removed","context":name})
            }
        };
        output_options.emit(&output)?;
        return Ok(());
    }
    if let Command::Sources { directory } = &cli.command {
        let sources = junction_discovery::sources::load_sources(directory)?;
        output_options.emit(&serde_json::json!({"sources":sources}))?;
        return Ok(());
    }
    if let Command::Schema { input } = &cli.command {
        let value = serde_json::from_slice(&std::fs::read(input)?)?;
        let schema = junction_schema::CanonicalSchema::normalize(&value)?;
        output_options.emit(&schema)?;
        return Ok(());
    }
    if let Command::Import {
        spec,
        product,
        service,
        source,
        output,
        format,
        endpoint,
        api_version,
    } = cli.command
    {
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(spec)?
            .take(128 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        let manifest = if format == "odata" {
            junction_discovery::odata::ingest(
                &bytes,
                &product,
                &service,
                &source,
                endpoint
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("OData service root required"))?,
                api_version
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("OData API version required"))?,
            )?
        } else {
            if endpoint.is_some() || api_version.is_some() {
                anyhow::bail!("endpoint and API version options require OData format");
            }
            let document = junction_discovery::parse_document(&bytes)?;
            junction_discovery::ingest(&document, &product, &service, &source)?
        };
        Registry::load(manifest.clone())?;
        atomic_write(&output, &serde_json::to_vec_pretty(&manifest)?)?;
        return Ok(());
    }
    let http_server = if let Command::Serve {
        listen,
        allow_external,
        token_env,
        ..
    } = &cli.command
    {
        let token =
            std::env::var(token_env).map_err(|_| junction_server::ServerError::TokenMissing)?;
        Some(junction_server::ServerConfig::new(
            *listen,
            *allow_external,
            junction_auth::Secret::new(token)
                .map_err(|_| junction_server::ServerError::TokenInvalid)?,
        )?)
    } else {
        None
    };
    let manifest: RegistryManifest = serde_json::from_slice(&std::fs::read(cli.registry)?)?;
    let registry = Registry::load(manifest.clone())?;
    let registry = if let Some(path) = cli.risk_overrides {
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        let text =
            std::str::from_utf8(&bytes).map_err(|_| anyhow::anyhow!("invalid risk overrides"))?;
        registry.with_risk_overrides(junction_registry::overrides::RiskOverrides::parse(text)?)?
    } else {
        registry
    };
    let output = match cli.command {
        Command::Tui { allow_preview } => {
            junction_tui::run(&registry, allow_preview)?;
            return Ok(());
        }
        Command::GenerateRust { schemas, output } => {
            let canonical = serde_json::from_value::<
                std::collections::BTreeMap<String, junction_schema::CanonicalSchema>,
            >(manifest.schemas["canonical"].clone())
            .map_err(|_| anyhow::anyhow!("invalid canonical schema metadata"))?;
            let module = junction_generator::generate_selected(&canonical, &schemas)?;
            atomic_write(&output, module.source.as_bytes())?;
            serde_json::json!({"status":"generated","types":module.types,"dynamic":module.dynamic})
        }

        Command::Mcp {
            command:
                McpCommand::Serve {
                    policy,
                    policy_file,
                    context_file,
                },
        }
        | Command::Serve {
            policy,
            policy_file,
            context_file,
            ..
        } => {
            let policy = match policy_file {
                Some(path) => junction_policy::Policy::parse(&std::fs::read_to_string(path)?)?,
                None => junction_policy::Policy::parse(&format!("[agent]\nmode = '{policy}'\n"))?,
            };
            let context = match (context_file, cli.context.as_deref()) {
                (Some(file), None) => Some(context_store::read_file(&file)?),
                (None, Some(name)) => Some(context_store::read(&cli.contexts_directory, name)?),
                (None, None) => None,
                _ => anyhow::bail!("select at most one named context or context file"),
            };
            if let Some(bytes) = &context {
                validated_context(bytes)?;
            }
            let host = mcp_host::Host::new(
                registry,
                policy,
                context,
                cli.contexts_directory,
                cli.operations_directory,
            )?;
            if let Some(config) = http_server {
                junction_server::serve(std::sync::Arc::new(host), config).await?;
            } else {
                host.serve().await?;
            }
            return Ok(());
        }
        Command::Batch {
            input,
            input_file,
            context_file,
            policy,
        } => {
            let value = parse_input(&input::load(input.as_deref(), input_file.as_deref())?)?;
            let request: junction_runtime::batch::BatchRequest = serde_json::from_value(value)
                .map_err(|_| anyhow::anyhow!("invalid batch request"))?;
            let policy = match policy {
                Some(path) => junction_policy::Policy::parse(&std::fs::read_to_string(path)?)?,
                None => junction_policy::Policy::default(),
            };
            let mut plan = junction_runtime::batch::BatchPlan::build(request, &policy.limits)?;
            let bytes = match (context_file, cli.context.as_deref()) {
                (Some(file), None) => context_store::read_file(&file)?,
                (None, Some(name)) => context_store::read(&cli.contexts_directory, name)?,
                _ => anyhow::bail!("select exactly one named context or context file"),
            };
            let first = &plan.request.operations[0];
            let selected = registry.resolve(
                &first.operation,
                first.api_version.as_deref(),
                first.allow_preview,
            )?;
            let context = load_execution_config(&bytes, selected)?;
            for operation in &mut plan.request.operations {
                let selected = registry.resolve(
                    &operation.operation,
                    operation.api_version.as_deref(),
                    operation.allow_preview,
                )?;
                let other = load_execution_config(&bytes, selected)?;
                if serde_json::to_value(&other)? != serde_json::to_value(&context)? {
                    anyhow::bail!("batch requires one endpoint and credential context");
                }
                scope::apply(
                    selected,
                    &mut operation.input,
                    None,
                    None,
                    (
                        other.subscription.as_deref(),
                        other.default_resource_group.as_deref(),
                    ),
                )?;
            }
            let plan = junction_runtime::batch::BatchPlan::build(plan.request, &policy.limits)?;
            let executor = junction_runtime::Executor::new(registry, policy)?;
            executor.preflight_batch(&plan, &context.token_request.tenant, &context.endpoint)?;
            let token = auth_cli::acquire(&context.token_request).await?;
            let result = executor
                .execute_batch(
                    plan.request,
                    junction_runtime::ExecutionContext {
                        tenant: &context.token_request.tenant,
                        audience: &context.token_request.audience,
                        endpoint: &context.endpoint,
                        token: &token,
                    },
                )
                .await?;
            serde_json::to_value(result)?
        }
        Command::Execute {
            operation,
            subscription,
            resource_group,
            input,
            input_file,
            context_file,
            policy,
            api_version,
            allow_preview,
            all,
            max_items,
            max_pages,
            continuation_file,
            resume,
            wait,
            timeout_seconds,
            max_polls,
            approve,
        } => {
            let mut input = parse_input(&input::load(input.as_deref(), input_file.as_deref())?)?;
            let selected = registry.resolve(&operation, api_version.as_deref(), allow_preview)?;
            let is_lro = selected.long_running.is_some() && !all;
            if wait
                && (selected.long_running.is_none()
                    || !(1..=3600).contains(&timeout_seconds)
                    || !(1..=10_000).contains(&max_polls))
            {
                anyhow::bail!("wait requires a declared LRO and valid timeout/poll bounds");
            }
            let bytes = match (context_file, cli.context.as_deref()) {
                (Some(file), None) => context_store::read_file(&file)?,
                (None, Some(name)) => context_store::read(&cli.contexts_directory, name)?,
                _ => anyhow::bail!("select exactly one named context or context file"),
            };
            let context = load_execution_config(&bytes, selected)?;
            scope::apply(
                selected,
                &mut input,
                subscription.as_deref(),
                resource_group.as_deref(),
                (
                    context.subscription.as_deref(),
                    context.default_resource_group.as_deref(),
                ),
            )?;
            let policy = match policy {
                Some(path) => junction_policy::Policy::parse(&std::fs::read_to_string(path)?)?,
                None => junction_policy::Policy::default(),
            };
            let approval_reason = match (
                policy.authorize_operation(selected, &context.token_request.tenant),
                approve,
            ) {
                (junction_policy::Decision::ApprovalRequired { reason, .. }, true) => Some(reason),
                (junction_policy::Decision::Allowed, true) => {
                    return Err(approval_cli::failure("approval_not_required"));
                }
                // Policy rejections keep their structured preflight error.
                _ => None,
            };
            let reviewed = selected.clone();
            let executor = junction_runtime::Executor::new(registry, policy)?;
            let approval_context = match &approval_reason {
                Some(_) => Some(junction_policy::approval::ApprovalContext::new(
                    context
                        .cloud
                        .unwrap_or(junction_core::cloud::MicrosoftCloud::Custom),
                    &context.endpoint,
                    &context.token_request.audience,
                    &context.token_request.credential_profile,
                )?),
                None => {
                    executor.preflight(
                        &operation,
                        &input,
                        &context.token_request.tenant,
                        &context.endpoint,
                        api_version.as_deref(),
                        allow_preview,
                    )?;
                    None
                }
            };
            let approval_options = || junction_runtime::ApprovalOptions {
                api_version: api_version.as_deref(),
                allow_preview,
                lifetime: std::time::Duration::from_secs(300),
            };
            let grant = match (&approval_reason, &approval_context) {
                (Some(reason), Some(approval_context)) => {
                    // Validate the complete request before asking a human, then
                    // issue the real single-use grant only after confirmation.
                    drop(executor.issue_approval(
                        &operation,
                        &input,
                        &context.token_request.tenant,
                        approval_context,
                        approval_options(),
                    )?);
                    approval_cli::confirm(&approval_cli::Summary {
                        operation: &reviewed,
                        reason,
                        tenant: &context.token_request.tenant,
                        cloud: &context
                            .cloud
                            .unwrap_or(junction_core::cloud::MicrosoftCloud::Custom),
                        endpoint: approval_context.endpoint(),
                        audience: approval_context.audience(),
                        credential_profile: &context.token_request.credential_profile,
                        input: &input,
                    })?;
                    Some(executor.issue_approval(
                        &operation,
                        &input,
                        &context.token_request.tenant,
                        approval_context,
                        approval_options(),
                    )?)
                }
                _ => None,
            };
            let page_options = junction_runtime::PageOptions {
                max_items,
                max_pages,
                api_version: api_version.clone(),
                allow_preview,
            };
            if all {
                executor.preflight_pages(
                    &operation,
                    &input,
                    &context.token_request.tenant,
                    &context.endpoint,
                    &page_options,
                )?;
                if continuation_file.as_ref().is_some_and(|path| path.exists()) {
                    anyhow::bail!("continuation output already exists");
                }
            }
            let continuation = resume
                .as_deref()
                .map(junction_runtime::pagination::Continuation::load)
                .transpose()?;
            if is_lro {
                operation_store::prepare(&cli.operations_directory)?;
            }
            let token = auth_cli::acquire(&context.token_request).await?;
            let execution_context = junction_runtime::ExecutionContext {
                tenant: &context.token_request.tenant,
                audience: &context.token_request.audience,
                endpoint: &context.endpoint,
                token: &token,
            };
            if is_lro {
                let options = junction_runtime::lro::LroStartOptions {
                    api_version: api_version.clone(),
                    allow_preview,
                    max_polls,
                };
                let handle = match (grant, &approval_context) {
                    (Some(grant), Some(approval_context)) => {
                        executor
                            .start_lro_with_approval(
                                &operation,
                                input,
                                execution_context,
                                options,
                                junction_runtime::ApprovedExecution {
                                    context: approval_context,
                                    grant,
                                },
                            )
                            .await?
                    }
                    _ => {
                        executor
                            .start_lro(&operation, input, execution_context, options)
                            .await?
                    }
                };
                operation_store::save_initial(&cli.operations_directory, &handle)?;
                if wait {
                    let id = handle.snapshot().operation_id.to_owned();
                    let mut stored =
                        operation_store::LockedHandle::acquire(&cli.operations_directory, &id)?;
                    let checkpoint_path = stored.checkpoint_path();
                    let result = executor
                        .wait_lro_checkpointed(
                            &mut stored.handle,
                            execution_context,
                            timeout_seconds,
                            |handle| operation_store::persist_at(&checkpoint_path, handle),
                        )
                        .await
                        .and_then(|snapshot| Ok(serde_json::to_value(snapshot)?));
                    stored.persist()?;
                    result?
                } else {
                    serde_json::to_value(handle.snapshot())?
                }
            } else if all {
                let result = executor
                    .execute_pages_resuming(
                        &operation,
                        input,
                        execution_context,
                        page_options,
                        continuation,
                    )
                    .await?;
                let continuation_path = if let Some(continuation) = result.continuation {
                    let path = continuation_file
                        .ok_or_else(|| anyhow::anyhow!("continuation output required"))?;
                    continuation.save(&path)?;
                    Some(path)
                } else {
                    None
                };
                serde_json::json!({"items":result.items,"continuation":continuation_path,"pages":result.pages})
            } else {
                let response = match (grant, &approval_context) {
                    (Some(grant), Some(approval_context)) => {
                        executor
                            .execute_with_approval(
                                &operation,
                                input,
                                execution_context,
                                api_version.as_deref(),
                                allow_preview,
                                junction_runtime::ApprovedExecution {
                                    context: approval_context,
                                    grant,
                                },
                            )
                            .await?
                    }
                    _ => {
                        executor
                            .execute(
                                &operation,
                                input,
                                execution_context,
                                api_version.as_deref(),
                                allow_preview,
                            )
                            .await?
                    }
                };
                serde_json::json!({"status":response.status,"body":response.body,"correlation":response.correlation})
            }
        }
        Command::Operations { command } => match command {
            OperationsCommand::Get { .. } => unreachable!(),
            OperationsCommand::Wait {
                id,
                context_file,
                policy,
                timeout_seconds,
                result: retrieve_result,
            } => {
                if !(1..=3600).contains(&timeout_seconds) {
                    anyhow::bail!("invalid operation wait timeout");
                }
                let mut stored =
                    operation_store::LockedHandle::acquire(&cli.operations_directory, &id)?;
                let selected = registry.resolve(
                    stored.handle.snapshot().operation,
                    stored.handle.api_version(),
                    stored.handle.allows_preview(),
                )?;
                let bytes = match (context_file, cli.context.as_deref()) {
                    (Some(file), None) => context_store::read_file(&file)?,
                    (None, Some(name)) => context_store::read(&cli.contexts_directory, name)?,
                    _ => anyhow::bail!("select exactly one named context or context file"),
                };
                let context = load_execution_config(&bytes, selected)?;
                let policy = match policy {
                    Some(path) => junction_policy::Policy::parse(&std::fs::read_to_string(path)?)?,
                    None => junction_policy::Policy::default(),
                };
                let executor = junction_runtime::Executor::new(registry, policy)?;
                executor.preflight_lro(
                    &stored.handle,
                    &context.token_request.tenant,
                    &context.token_request.audience,
                    &context.endpoint,
                )?;
                let token = auth_cli::acquire(&context.token_request).await?;
                let checkpoint_path = stored.checkpoint_path();
                let result = executor
                    .wait_lro_checkpointed(
                        &mut stored.handle,
                        junction_runtime::ExecutionContext {
                            tenant: &context.token_request.tenant,
                            audience: &context.token_request.audience,
                            endpoint: &context.endpoint,
                            token: &token,
                        },
                        timeout_seconds,
                        |handle| operation_store::persist_at(&checkpoint_path, handle),
                    )
                    .await
                    .and_then(|snapshot| Ok(serde_json::to_value(snapshot)?));
                stored.persist()?;
                let snapshot = result?;
                if retrieve_result {
                    let response = executor
                        .final_lro_result(
                            &stored.handle,
                            junction_runtime::ExecutionContext {
                                tenant: &context.token_request.tenant,
                                audience: &context.token_request.audience,
                                endpoint: &context.endpoint,
                                token: &token,
                            },
                        )
                        .await?;
                    serde_json::json!({"operation":snapshot,"status":response.status,
                        "body":response.body,"correlation":response.correlation})
                } else {
                    snapshot
                }
            }
        },
        Command::Api { command } => match command {
            ApiCommand::Changes { previous } => {
                let before = serde_json::from_slice(&std::fs::read(previous)?)?;
                serde_json::to_value(junction_registry::changes(&before, &manifest)?)?
            }
            ApiCommand::Stats => serde_json::to_value(registry.stats())?,
            ApiCommand::Products => serde_json::json!({"products": registry.products()}),
            ApiCommand::Services { product } => {
                serde_json::json!({"services": registry.services(product.as_deref()).into_iter().map(|(product, service)| serde_json::json!({"product":product,"service":service})).collect::<Vec<_>>()})
            }
            ApiCommand::Versions { operation } => {
                serde_json::json!({"versions":registry.versions(&operation)?.iter().map(|op| serde_json::json!({"api_version":op.api_version,"maturity":op.maturity,"preview":op.preview})).collect::<Vec<_>>()})
            }
        },
        Command::PolicyCheck {
            operation,
            tenant,
            policy,
        } => {
            let policy = junction_policy::Policy::parse(&std::fs::read_to_string(policy)?)?;
            let op = registry.resolve(&operation, None, false)?;
            serde_json::to_value(policy.authorize_operation(op, &tenant))?
        }
        Command::Search {
            query,
            limit,
            product,
            service,
            allow_preview,
        } => {
            let options = junction_registry::SearchOptions {
                product: product.as_deref(),
                service: service.as_deref(),
                allow_preview,
            };
            serde_json::json!({"matches":registry.discover_filtered(&query, limit, &options)})
        }
        Command::Permissions {
            operation,
            api_version,
            allow_preview,
        } => serde_json::to_value(registry.permissions(
            &operation,
            api_version.as_deref(),
            allow_preview,
        )?)?,
        Command::Describe {
            operation,
            api_version,
            allow_preview,
        } => {
            let mut description = serde_json::to_value(registry.resolve(
                &operation,
                api_version.as_deref(),
                allow_preview,
            )?)?;
            description["input_schema"] =
                registry.input_schema(&operation, api_version.as_deref(), allow_preview)?;
            description["required_permissions"] = serde_json::to_value(
                registry
                    .permissions(&operation, api_version.as_deref(), allow_preview)?
                    .required_permissions,
            )?;
            description
        }
        Command::Refresh { .. }
        | Command::Merge { .. }
        | Command::Discover { .. }
        | Command::Fetch { .. }
        | Command::Openapi { .. }
        | Command::Auth { .. }
        | Command::Operation(_)
        | Command::Import { .. }
        | Command::Schema { .. }
        | Command::Sources { .. }
        | Command::Context { .. } => unreachable!(),
    };
    output_options.emit(&output)?;
    Ok(())
}

struct Diagnostics(Option<std::time::Instant>);
impl Diagnostics {
    fn start(enabled: bool) -> Self {
        if enabled {
            eprintln!("{{\"event\":\"command_started\"}}");
        }
        Self(enabled.then(std::time::Instant::now))
    }
}
impl Drop for Diagnostics {
    fn drop(&mut self) {
        if let Some(start) = self.0 {
            eprintln!(
                "{}",
                serde_json::json!({"event":"command_finished","elapsed_ms":start.elapsed().as_millis()})
            );
        }
    }
}
#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        // Only explicitly safe structured errors are exposed; parser errors may contain secrets.
        if let Some(busy) = error.downcast_ref::<credential_lock::CredentialBusy>() {
            eprintln!("{}", busy.response());
        } else if let Some(server) = error.downcast_ref::<junction_server::ServerError>() {
            eprintln!(
                "{}",
                serde_json::json!({"status":"server_failed","reason":server.to_string()})
            );
        } else if let Some(approval) = error.downcast_ref::<approval_cli::ApprovalFailure>() {
            eprintln!(
                "{}",
                serde_json::to_string(approval).expect("approval failures serialize")
            );
        } else if let Some(denied) = error.downcast_ref::<junction_runtime::ExecutionDenied>() {
            eprintln!(
                "{}",
                serde_json::to_string(&denied.0).expect("policy decisions serialize")
            );
        } else if let Some(timeout) = error.downcast_ref::<junction_runtime::lro::LroWaitTimeout>()
        {
            eprintln!(
                "{}",
                serde_json::to_string(timeout).expect("wait timeout serializes")
            );
        } else if let Some(result) = error.downcast_ref::<junction_runtime::lro::LroResultError>() {
            eprintln!(
                "{}",
                serde_json::to_string(result).expect("result error serializes")
            );
        } else if let Some(failure) =
            error.downcast_ref::<junction_runtime::authorization::AuthorizationFailure>()
        {
            eprintln!(
                "{}",
                serde_json::to_string(failure).expect("authorization failures serialize")
            );
        } else if let Some(failure) =
            error.downcast_ref::<junction_discovery::refresh::RefreshFailure>()
        {
            let mut diagnostic =
                serde_json::json!({"error":"source_refresh_failed","stage":failure.stage});
            if let Some(fetch) = error.downcast_ref::<junction_discovery::fetch::FetchFailure>() {
                diagnostic["download"] =
                    serde_json::to_value(fetch).expect("safe download diagnostics serialize");
            }
            if let Some(limit) =
                error.downcast_ref::<junction_discovery::refresh::RefreshLimitExceeded>()
            {
                diagnostic["limit"] =
                    serde_json::to_value(limit.limit).expect("refresh limits serialize");
            }
            eprintln!("{diagnostic}");
        } else if let Some(fetch) = error.downcast_ref::<junction_discovery::fetch::FetchFailure>()
        {
            eprintln!(
                "{}",
                serde_json::json!({"error":"source_download_failed","download":fetch})
            );
        } else {
            eprintln!(
                "{{\"error\":\"command_failed\",\"message\":\"Check command arguments, context, credentials and manifest validity\"}}"
            );
        }
        std::process::exit(1);
    }
}

#[cfg(test)]
mod execution_tests {
    #[test]
    fn certificate_contexts_select_headless_auth_in_public_and_sovereign_clouds() {
        let bytes = include_bytes!("../../../examples/certificate-context.json");
        for cloud in ["public", "us_government", "china"] {
            let mut value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
            value["cloud"] = cloud.into();
            let request =
                super::context_token_request(&serde_json::to_vec(&value).unwrap()).unwrap();
            assert_eq!(request.flow, junction_auth::AuthFlow::Certificate);
            assert_eq!(request.tenant, "replace-with-tenant-id");
        }
        let mut explicit: serde_json::Value =
            serde_json::from_slice(include_bytes!("../../../examples/execution-context.json"))
                .unwrap();
        explicit["token_request"]["flow"] = "certificate".into();
        let request =
            super::context_token_request(&serde_json::to_vec(&explicit).unwrap()).unwrap();
        assert_eq!(request.flow, junction_auth::AuthFlow::Certificate);
    }
    use super::*;
    #[test]
    fn managed_identity_contexts_reach_the_headless_flow_selector() {
        let cloud = include_bytes!("../../../examples/managed-identity-context.json");
        let request = context_token_request(cloud).unwrap();
        assert_eq!(request.flow, junction_auth::AuthFlow::ManagedIdentity);
        assert_eq!(request.tenant, "replace-with-tenant-id");
        let mut explicit: serde_json::Value =
            serde_json::from_slice(include_bytes!("../../../examples/execution-context.json"))
                .unwrap();
        explicit["token_request"]["flow"] = "managed_identity".into();
        let request = context_token_request(&serde_json::to_vec(&explicit).unwrap()).unwrap();
        assert_eq!(request.flow, junction_auth::AuthFlow::ManagedIdentity);
    }
    #[test]
    fn batch_requires_one_input_source_and_execute_keeps_empty_default() {
        assert!(Cli::try_parse_from(["junction", "batch"]).is_err());
        assert!(Cli::try_parse_from(["junction", "batch", "--input-file", "-"]).is_ok());
        assert!(Cli::try_parse_from(["junction", "execute", "graph.users.list"]).is_ok());
        assert!(
            Cli::try_parse_from([
                "junction",
                "execute",
                "azure.compute.vm.start",
                "--wait",
                "--timeout-seconds",
                "1",
                "--max-polls",
                "1"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "junction",
                "execute",
                "graph.users.list",
                "--wait",
                "--all",
                "--continuation-file",
                "state.json"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "junction",
                "execute",
                "graph.users.list",
                "--timeout-seconds",
                "1"
            ])
            .is_err()
        );
        for command in ["batch", "execute"] {
            let mut args = vec!["junction", command];
            if command == "execute" {
                args.push("graph.users.list");
            }
            args.extend(["--input", "{}", "--input-file", "-"]);
            assert!(Cli::try_parse_from(args).is_err());
        }
    }
    fn config(endpoint: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"endpoint":endpoint,"token_request":{
            "tenant":"customer-a","authority":"https://login.example.com","audience":"https://resource.example.com",
            "scopes":[],"credential_profile":"default","flow":"client_credentials"
        }})).unwrap()
    }
    #[test]
    fn explicit_context_accepts_workload_identity_and_rejects_unimplemented_flows() {
        let mut value: serde_json::Value =
            serde_json::from_slice(&config("https://resource.example.com")).unwrap();
        value["token_request"]["flow"] = serde_json::json!("workload_identity");
        assert!(ExecutionConfig::parse(&serde_json::to_vec(&value).unwrap()).is_ok());
        value["token_request"]["flow"] = serde_json::json!("on_behalf_of");
        value["token_request"]["scopes"] = serde_json::json!(["https://resource.example.com/read"]);
        assert!(ExecutionConfig::parse(&serde_json::to_vec(&value).unwrap()).is_ok());
        value["token_request"]["flow"] = serde_json::json!("device_code");
        assert!(ExecutionConfig::parse(&serde_json::to_vec(&value).unwrap()).is_ok());
        value["token_request"]["flow"] = serde_json::json!("certificate");
        assert!(ExecutionConfig::parse(&serde_json::to_vec(&value).unwrap()).is_ok());
    }
    #[test]
    fn context_scope_defaults_roundtrip_and_build_validated_arm_requests() {
        let operation: junction_core::JunctionOperation = serde_json::from_value(serde_json::json!({
            "id":"azure.resources.groups.list","product":"azure","service":"resources","resource":"groups",
            "operation":"list","description":"","method":"GET","base_url":"https://management.azure.com",
            "path":"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}",
            "parameters":[{"name":"subscriptionId","location":"path","required":true,"schema":{"type":"string"}},
                {"name":"resourceGroupName","location":"path","required":true,"schema":{"type":"string","pattern":"^group-"}}],
            "responses":{},"security":[],"risk":"read_only","preview":false,
            "source":{"id":"official","upstream":"official","operation_id":"Groups_List"}
        })).unwrap();
        for value in [
            serde_json::json!({"cloud":"us_government","tenant":"customer-a","service":"arm","credential_profile":"environment",
                "subscription":"sub-default","default_resource_group":"group-default"}),
            {
                let mut value: serde_json::Value =
                    serde_json::from_slice(&config("https://management.usgovcloudapi.net"))
                        .unwrap();
                value["subscription"] = "sub-default".into();
                value["default_resource_group"] = "group-default".into();
                value
            },
        ] {
            let normalized = validated_context(&serde_json::to_vec(&value).unwrap()).unwrap();
            assert_eq!(normalized["subscription"], "sub-default");
            assert_eq!(normalized["default_resource_group"], "group-default");
            let context =
                load_execution_config(&serde_json::to_vec(&normalized).unwrap(), &operation)
                    .unwrap();
            let mut input = serde_json::json!({});
            scope::apply(
                &operation,
                &mut input,
                Some("sub-cli"),
                None,
                (
                    context.subscription.as_deref(),
                    context.default_resource_group.as_deref(),
                ),
            )
            .unwrap();
            let request = junction_runtime::prepare(
                &operation,
                &input,
                &context.token_request.tenant,
                &context.endpoint,
                &Default::default(),
            )
            .unwrap();
            assert_eq!(
                request.url.as_str(),
                "https://management.usgovcloudapi.net/subscriptions/sub%2Dcli/resourceGroups/group%2Ddefault"
            );
            input["parameters"]["resourceGroupName"] = "invalid-group".into();
            assert!(
                junction_runtime::prepare(
                    &operation,
                    &input,
                    &context.token_request.tenant,
                    &context.endpoint,
                    &Default::default()
                )
                .is_err()
            );
            let mut invalid = value;
            invalid["subscription"] = "secret\nvalue".into();
            assert!(validated_context(&serde_json::to_vec(&invalid).unwrap()).is_err());
        }
        let cli = Cli::try_parse_from([
            "junction",
            "execute",
            "azure.resources.groups.list",
            "--subscription",
            "sub-cli",
            "--resource-group",
            "group-cli",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Execute {
                subscription: Some(_),
                resource_group: Some(_),
                ..
            }
        ));
    }
    #[test]
    fn cloud_context_resolves_dod_and_rejects_cross_service() {
        let operation: junction_core::JunctionOperation = serde_json::from_value(serde_json::json!({
            "id":"graph.users.list","product":"graph","service":"users","resource":"users",
            "operation":"list","description":"","method":"GET","base_url":"https://graph.microsoft.com/v1.0",
            "path":"/users","parameters":[],"responses":{},"security":[],"risk":"read_only","preview":false,
            "source":{"id":"official","upstream":"official","operation_id":"Users_List"}
        })).unwrap();
        let mut value = serde_json::json!({"cloud":"us_government_dod","tenant":"customer-a","service":"graph","credential_profile":"environment"});
        let resolved =
            load_execution_config(&serde_json::to_vec(&value).unwrap(), &operation).unwrap();
        assert_eq!(resolved.endpoint, "https://dod-graph.microsoft.us/v1.0");
        assert_eq!(
            resolved.token_request.authority,
            "https://login.microsoftonline.us"
        );
        assert_eq!(
            resolved.token_request.audience,
            "https://dod-graph.microsoft.us"
        );
        value["service"] = "arm".into();
        assert!(load_execution_config(&serde_json::to_vec(&value).unwrap(), &operation).is_err());
        value["service"] = "graph".into();
        value["custom_endpoints"] = serde_json::to_value(
            junction_core::cloud::MicrosoftCloud::Public
                .endpoints()
                .unwrap(),
        )
        .unwrap();
        assert!(load_execution_config(&serde_json::to_vec(&value).unwrap(), &operation).is_err());
    }

    #[test]
    fn operator_endpoint_bindings_require_the_configured_service_origin() {
        let spec = serde_json::json!({"swagger":"2.0","basePath":"/v1",
            "x-ms-parameterized-host":{"hostTemplate":"{account}.vault.azure.net","parameters":[
                {"name":"account","in":"path","type":"string"}]},
            "paths":{"/items":{"get":{"operationId":"Items_List"}}}});
        let operation = junction_discovery::ingest(&spec, "azure", "vault", "official")
            .unwrap()
            .operations
            .remove(0);
        let mut endpoints = junction_core::cloud::MicrosoftCloud::Public
            .endpoints()
            .unwrap();
        endpoints.arm = Some(junction_core::cloud::ServiceEndpoint {
            endpoint: "https://customer-a.vault.azure.net".into(),
            audience: Some("https://vault.azure.net".into()),
        });
        let mut context = serde_json::json!({"cloud":"custom","tenant":"customer-a","service":"arm",
            "credential_profile":"automation","custom_endpoints":endpoints,
            "endpoint_variables":{"account":"customer-a"}});
        let config =
            load_execution_config(&serde_json::to_vec(&context).unwrap(), &operation).unwrap();
        assert_eq!(config.endpoint, "https://customer-a.vault.azure.net/v1");
        assert_eq!(config.token_request.audience, "https://vault.azure.net");
        let openapi = serde_json::json!({"openapi":"3.0.3","servers":[{
            "url":"https://{account}.vault.azure.net/v1","variables":{"account":{"default":"default-account"}}}],
            "paths":{"/items":{"get":{"operationId":"Items_List"}}}});
        let openapi_operation = junction_discovery::ingest(&openapi, "azure", "vault", "official")
            .unwrap()
            .operations
            .remove(0);
        let openapi_config =
            load_execution_config(&serde_json::to_vec(&context).unwrap(), &openapi_operation)
                .unwrap();
        assert_eq!(openapi_config.endpoint, config.endpoint);
        let request = junction_runtime::prepare(
            &operation,
            &serde_json::json!({}),
            "customer-a",
            &config.endpoint,
            &Default::default(),
        )
        .unwrap();
        assert_eq!(
            request.url.as_str(),
            "https://customer-a.vault.azure.net/v1/items"
        );
        assert!(
            junction_runtime::prepare(
                &operation,
                &serde_json::json!({"parameters":{"account":"attacker"}}),
                "customer-a",
                &config.endpoint,
                &Default::default()
            )
            .is_err()
        );
        context["endpoint_variables"]["account"] = "customer-b".into();
        assert!(load_execution_config(&serde_json::to_vec(&context).unwrap(), &operation).is_err());
        context["endpoint_variables"] = serde_json::json!({});
        assert!(load_execution_config(&serde_json::to_vec(&context).unwrap(), &operation).is_err());
    }

    #[test]
    fn devops_example_context_resolves_imported_operation_and_bound_audience() {
        let bytes = include_bytes!("../../../examples/devops-cloud-context.json");
        let cloud: CloudExecutionConfig = serde_json::from_slice(bytes).unwrap();
        cloud.validate().unwrap();
        let spec = serde_json::json!({"swagger":"2.0","info":{"version":"7.1"},
        "host":"dev.azure.com","basePath":"/","paths":{
            "/{organization}/_apis/projects":{"get":{"operationId":"Projects_List",
                "parameters":[{"name":"organization","in":"path","required":true,"type":"string"},
                    {"name":"api-version","in":"query","required":true,"type":"string"}],"responses":{}}}
        }});
        let manifest =
            junction_discovery::ingest(&spec, "azure-devops", "core", "official").unwrap();
        let operation = &manifest.operations[0];
        let config = cloud.resolve(operation).unwrap();
        assert_eq!(
            config.token_request.audience,
            "499b84ac-1321-427f-aa17-267ca6975798"
        );
        assert_eq!(
            config.token_request.scopes,
            vec!["499b84ac-1321-427f-aa17-267ca6975798/.default"]
        );
        assert_eq!(
            config.token_request.authority,
            "https://login.microsoftonline.com"
        );
        let request = junction_runtime::prepare(
            operation,
            &serde_json::json!({"parameters":{"organization":"customer-a"}}),
            &config.token_request.tenant,
            &config.endpoint,
            &Default::default(),
        )
        .unwrap();
        assert_eq!(request.url.host_str(), Some("dev.azure.com"));
        assert!(
            request
                .url
                .query_pairs()
                .any(|(name, value)| name == "api-version" && value == "7.1")
        );
        let mut wrong_service = operation.clone();
        wrong_service.base_url = "https://graph.microsoft.com/v1.0".into();
        let cloud: CloudExecutionConfig = serde_json::from_slice(bytes).unwrap();
        assert!(cloud.resolve(&wrong_service).is_err());
    }
    #[test]
    fn context_rejects_credentials_and_unsafe_endpoints() {
        assert!(ExecutionConfig::parse(&config("https://resource.example.com/v1.0")).is_ok());
        for endpoint in [
            "http://resource.example.com",
            "https://user:secret@resource.example.com",
            "https://resource.example.com?secret=value",
            "https://resource.example.com#token",
        ] {
            assert!(ExecutionConfig::parse(&config(endpoint)).is_err());
        }
        assert!(ExecutionConfig::parse(br#"{"client_secret":"secret"}"#).is_err());
        assert!(
            !parse_input("secret-input")
                .unwrap_err()
                .to_string()
                .contains("secret-input")
        );
    }
}
