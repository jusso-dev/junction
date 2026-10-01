Build Junction

Build an open-source, production-grade Rust project called Junction.

Junction is a single Rust binary that provides a unified interface to Microsoft’s public APIs, initially covering:

* Microsoft Azure
* Azure Resource Manager
* Microsoft Graph
* Microsoft 365
* Microsoft Entra ID
* Microsoft Defender XDR
* Defender for Endpoint
* Defender for Cloud
* Defender for Identity where publicly exposed
* Defender for Office 365 where publicly exposed
* Microsoft Sentinel
* Microsoft Intune
* Microsoft Purview
* Exchange Online APIs exposed through Graph or documented REST APIs
* SharePoint APIs
* OneDrive
* Teams
* Planner
* Outlook / Exchange workloads exposed through Graph
* Azure DevOps
* Power Platform public APIs
* Power BI / Fabric public APIs
* Windows 365
* Azure Arc
* Azure Lighthouse
* Azure Monitor
* Log Analytics
* Azure Resource Graph
* Cost Management
* Microsoft Security APIs
* adjacent Microsoft cloud products with documented public APIs

The objective is NOT to manually implement thousands of endpoints.

Instead, Junction must be a self-updating Microsoft API runtime.

It discovers Microsoft’s machine-readable API definitions, converts them into a canonical internal API model, generates Rust metadata/types where appropriate, and exposes every discovered operation through:

1. Rust library APIs
2. Junction CLI
3. JSON input/output
4. MCP server
5. agent-oriented tool discovery
6. local HTTP API
7. structured operation manifests
8. optional OpenAPI export
9. shell-friendly invocation

The compiled executable should remain:

junction

Do not require Python, Node.js, PowerShell, Azure CLI or Microsoft Graph CLI at runtime.

The final runtime must be pure Rust wherever reasonably possible.

⸻

Core Design Principle

Do NOT create a gigantic handwritten SDK.

Create:

Microsoft API Sources
        ↓
Discovery
        ↓
Spec ingestion
        ↓
Normalization
        ↓
Canonical Junction API Model
        ↓
Validation
        ↓
Rust/code/metadata generation
        ↓
Operation Registry
        ↓
Junction Runtime
        ↓
CLI / MCP / Agent / HTTP / Rust

Junction should behave more like an API operating layer than an SDK.

Every Microsoft operation should ultimately become a canonical Junction operation such as:

azure.compute.virtual_machines.list
azure.compute.virtual_machines.start
azure.compute.virtual_machines.restart
azure.resources.resource_groups.list
graph.users.list
graph.users.get
graph.groups.list
m365.teams.list
m365.sharepoint.sites.list
defender.incidents.list
defender.incidents.update
defender.hunting.run_query
sentinel.incidents.list
sentinel.incidents.update
intune.devices.list
purview.audit.search

Operation naming must be deterministic and stable across generator runs.

⸻

Source Discovery

Create a pluggable discovery framework.

Start with official Microsoft sources only.

Examples include Microsoft’s public Azure REST API specification repositories, Microsoft Graph metadata/specification sources, Microsoft Learn REST documentation, Graph metadata, Defender API documentation/specifications and other official machine-readable Microsoft API definitions.

Prefer, in order:

1. official OpenAPI
2. official TypeSpec
3. official OData metadata
4. official service metadata
5. official Microsoft-maintained API manifests
6. structured Microsoft Learn metadata
7. documented endpoint extraction as a LAST resort

Never scrape arbitrary blogs or third-party API lists.

Maintain:

sources/
    azure.toml
    graph.toml
    defender.toml
    m365.toml
    sentinel.toml
    intune.toml
    purview.toml
    power-platform.toml
    fabric.toml
    azure-devops.toml

Each source definition contains:

pub struct ApiSource {
    pub id: String,
    pub product: String,
    pub source_type: SourceType,
    pub upstream: String,
    pub paths: Vec<String>,
    pub authority: Authority,
    pub clouds: Vec<Cloud>,
    pub enabled: bool,
}

Support:

enum SourceType {
    OpenApi,
    TypeSpec,
    OData,
    Metadata,
    Documentation,
}

⸻

Canonical API Model

Everything gets normalized into an internal representation.

Create something conceptually similar to:

pub struct JunctionOperation {
    pub id: OperationId,
    pub product: Product,
    pub service: String,
    pub resource: String,
    pub operation: String,
    pub method: HttpMethod,
    pub base_url: BaseUrlStrategy,
    pub path: String,
    pub api_version: Option<String>,
    pub parameters: Vec<Parameter>,
    pub request_body: Option<SchemaRef>,
    pub response: Option<SchemaRef>,
    pub authentication: AuthenticationRequirement,
    pub permissions: Vec<PermissionRequirement>,
    pub pagination: Option<PaginationStrategy>,
    pub throttling: Option<ThrottleMetadata>,
    pub maturity: ApiMaturity,
    pub destructive: bool,
    pub idempotent: bool,
    pub documentation_url: Option<String>,
    pub source: SourceMetadata,
}

Also normalize schemas.

Create a common type system supporting:

* strings
* integers
* floating point
* booleans
* dates
* timestamps
* durations
* UUIDs
* URIs
* byte arrays
* enums
* arrays
* maps
* objects
* unions
* nullable values
* discriminated unions
* references
* arbitrary JSON where unavoidable

Do not force every API into compile-time Rust structs when doing so makes API ingestion brittle.

Use a hybrid model:

common/stable API
    → generated strongly typed structures
long-tail/dynamic API
    → validated serde_json::Value + schema metadata

This is essential to keeping Junction maintainable.

⸻

API Version Handling

Azure contains enormous numbers of API versions.

Junction must understand:

stable
preview
beta
deprecated
retired

Users can request:

junction azure compute virtual-machines list \
  --api-version latest

or:

junction azure compute virtual-machines list \
  --api-version 2026-XX-XX

Default selection:

latest stable supported API

Preview APIs must require:

--allow-preview

unless configured globally.

Never silently switch a stable operation to preview.

⸻

Authentication Engine

Authentication is one of Junction’s most important components.

Create:

junction-auth

It must support Microsoft’s required authentication patterns without every API implementing auth independently.

Support Microsoft Entra OAuth 2.0 / OIDC flows including:

* authorization code
* authorization code + PKCE
* client credentials
* device authorization/device code
* managed identity
* workload identity
* federated workload credentials
* service principals
* certificates
* client secrets
* delegated user tokens
* application permissions
* on-behalf-of flow where applicable
* multi-tenant applications
* tenant-specific authentication
* Azure CLI credential import as optional convenience
* environment credentials
* externally supplied bearer tokens

Where Azure services use non-Entra authentication, support documented mechanisms including:

* API keys
* shared keys
* SAS tokens
* signed requests
* service-specific credentials

Do NOT assume every Microsoft API uses:

https://graph.microsoft.com/.default

Model resource/audience explicitly.

For example:

pub struct TokenRequest {
    tenant: Tenant,
    authority: AuthorityHost,
    audience: Audience,
    scopes: Vec<String>,
    flow: AuthFlow,
}

The authentication engine must understand different audiences/resources.

Examples include Graph, ARM, Defender and service-specific data-plane resources.

⸻

Sovereign Microsoft Clouds

Sovereign cloud support is mandatory.

Model:

enum MicrosoftCloud {
    Public,
    UsGovernment,
    UsGovernmentDod,
    China,
    Custom,
}

Do NOT hardcode public-cloud endpoints throughout the application.

Centralize:

authority host
Graph endpoint
ARM endpoint
Defender endpoint
service endpoint suffixes
storage suffixes
Key Vault suffixes
resource audiences

Design the abstraction so additional Microsoft cloud environments can be added without touching API execution logic.

⸻

Credential Security

Never print:

* access tokens
* refresh tokens
* client secrets
* certificates/private keys
* SAS tokens
* API keys

Implement secret redaction throughout tracing.

Use secure OS credential storage when available.

Provide:

junction auth login
junction auth logout
junction auth status
junction auth accounts
junction auth token-info

token-info may display SAFE metadata such as:

tenant
audience
expiry
scopes
roles
account

but never output the raw token unless the user explicitly invokes a dedicated command designed for that purpose.

Support headless agent environments using environment variables, workload identity, managed identity and injected credentials.

⸻

Permission Intelligence

Junction should know what permissions an operation requires whenever authoritative metadata exists.

Example:

junction describe graph.users.list

Output:

{
  "operation": "graph.users.list",
  "authentication": "entra",
  "supports": [
    "delegated",
    "application"
  ],
  "permissions": {
    "delegated": [...],
    "application": [...]
  }
}

Do not automatically grant permissions.

Junction tells the operator or agent what is required.

If execution receives HTTP 401/403, enrich the error with:

operation
audience
authentication mode
required permissions
currently detectable token permissions
documentation
possible remediation

without exposing secrets.

⸻

Multi-Tenant Support

Junction must work extremely well for MSPs and enterprise automation.

Allow:

junction context add customer-a
junction context add customer-b
junction --context customer-a graph users list

Context can contain:

tenant
subscription
cloud
credential profile
default scopes
default resource group
Defender tenant
Graph endpoint
custom endpoints

Never allow credentials to accidentally cross tenant boundaries.

Tenant isolation must be enforced inside the credential/token cache.

⸻

Universal Executor

Implement:

async fn execute(
    operation: OperationId,
    input: Value,
    context: ExecutionContext,
) -> Result<ExecutionResult>

The executor handles:

* endpoint construction
* parameter serialization
* authentication
* token acquisition
* API versions
* headers
* query parameters
* request bodies
* retries
* throttling
* pagination
* continuation tokens
* OData
* Graph $select
* $filter
* $expand
* $orderby
* $top
* $skip
* ARM continuation links
* long-running Azure operations
* asynchronous operations
* polling
* regional endpoints
* correlation IDs
* retry-after
* transient failures

Use:

tokio
reqwest
serde
serde_json
tracing
clap

where appropriate.

⸻

Pagination

Agents should not need to understand Microsoft’s different pagination systems.

Expose:

junction graph users list --all

and:

{
  "items": [...],
  "continuation": null
}

Internally support:

* @odata.nextLink
* nextLink
* continuationToken
* skipToken
* service-specific pagination

Agents can choose bounded retrieval:

{
  "max_items": 100,
  "max_pages": 5
}

Hard limits must prevent accidental unbounded agent loops.

⸻

Long-Running Operations

Azure operations frequently return asynchronous operation handles.

Normalize this.

Example:

junction azure compute virtual-machines start ...

Junction returns:

{
  "operation_id": "...",
  "state": "running"
}

Support:

junction operations wait <id>
junction operations get <id>
junction operations cancel <id>

where cancellation is supported.

Agents should be able to invoke:

{
  "wait": true,
  "timeout_seconds": 300
}

⸻

Agent-First Design

Junction is explicitly intended to be consumed by AI agents.

Agents should NOT need the entire Microsoft API catalog loaded into their context.

Implement hierarchical discovery.

Example:

junction search "list defender incidents"

Response:

{
  "matches": [
    {
      "operation": "defender.incidents.list",
      "description": "...",
      "risk": "read",
      "required_permissions": [...]
    }
  ]
}

Then:

junction describe defender.incidents.list --json

returns the exact JSON schema expected.

Then:

junction execute defender.incidents.list \
  --input '{}'

This implements:

search
  ↓
describe
  ↓
execute

and prevents an agent from consuming hundreds of thousands of tokens of API schemas.

⸻

MCP Server

Junction must have native MCP support.

Run:

junction mcp serve

Do NOT expose tens of thousands of MCP tools individually.

Expose a small stable MCP surface:

junction_search
junction_describe
junction_execute
junction_batch
junction_permissions
junction_context

Example:

junction_search({
  "query": "find defender incidents"
})

then:

junction_describe({
  "operation": "defender.incidents.list"
})

then:

junction_execute({
  "operation": "defender.incidents.list",
  "input": {}
})

This makes Junction suitable for:

* OpenAI agents
* Claude
* Hermes
* OpenClaw
* Codex
* custom agents
* IDE agents
* MCP-compatible clients
* autonomous security agents

⸻

Agent Safety

Classify operations automatically and allow manual overrides:

enum OperationRisk {
    ReadOnly,
    Write,
    Destructive,
    Privileged,
}

Examples:

list users
→ ReadOnly
create VM
→ Write
delete subscription resource
→ Destructive
modify Conditional Access
→ Privileged

Agents can run in:

read-only
safe-write
full

mode.

Example:

junction mcp serve --policy read-only

Attempting a write returns a machine-readable policy rejection.

For destructive operations support approval workflows.

Example:

{
  "status": "approval_required",
  "operation": "azure.compute.virtual_machines.delete",
  "reason": "destructive operation"
}

Never allow an LLM to bypass configured Junction policies.

⸻

Policy Engine

Implement a local policy layer.

Example:

[agent]
mode = "safe-write"
[deny]
operations = [
    "*.delete",
    "graph.identity.conditional_access.*"
]
[allow]
tenants = [
    "..."
]
[limits]
max_requests_per_minute = 100
max_pages = 20
max_parallel_requests = 10

Eventually this should support OPA/Cedar-style external authorization, but do not make an external engine mandatory for v1.

⸻

Batch Execution

Agents often need multiple calls.

Provide:

{
  "operations": [
    {
      "id": "users",
      "operation": "graph.users.list",
      "input": {}
    },
    {
      "id": "incidents",
      "operation": "defender.incidents.list",
      "input": {}
    }
  ]
}

Support:

* controlled concurrency
* dependencies
* references to previous results
* fail-fast
* continue-on-error
* maximum operation count
* timeouts

Never allow uncontrolled recursive execution.

⸻

CLI

Create a polished CLI.

Examples:

junction search "virtual machines"
junction describe azure.compute.virtual_machines.list
junction execute azure.compute.virtual_machines.list \
  --subscription xxx
junction graph users list
junction defender incidents list
junction azure vm list
junction auth login
junction context list
junction api stats
junction api products
junction api services
junction api changes

CLI aliases can provide ergonomic commands, but the canonical operation registry remains the source of truth.

Support:

--json
--yaml
--table
--quiet
--verbose

JSON output must be deterministic and agent-friendly.

⸻

Local API Server

Support:

junction serve

Expose:

GET  /health
GET  /v1/search
GET  /v1/operations
GET  /v1/operations/{id}
POST /v1/execute/{id}
POST /v1/batch
GET  /v1/contexts
GET  /v1/permissions/{id}

Generate an OpenAPI description for Junction itself.

This allows other systems to use Junction without spawning CLI processes.

Bind to localhost by default.

External listening must be explicit.

⸻

Rust Workspace

Structure the repository approximately as:

junction/
├── Cargo.toml
├── crates/
│   ├── junction/
│   ├── junction-core/
│   ├── junction-auth/
│   ├── junction-http/
│   ├── junction-runtime/
│   ├── junction-registry/
│   ├── junction-schema/
│   ├── junction-discovery/
│   ├── junction-generator/
│   ├── junction-policy/
│   ├── junction-mcp/
│   ├── junction-server/
│   └── junction-cli/
│
├── generators/
│   ├── azure/
│   ├── graph/
│   ├── odata/
│   ├── defender/
│   └── docs/
│
├── sources/
├── generated/
│   ├── registry/
│   ├── schemas/
│   └── manifests/
│
├── overrides/