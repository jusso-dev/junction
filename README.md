# Junction

A Rust operation runtime for Microsoft's public APIs. Junction normalizes upstream specifications into a versioned operation registry rather than hand-writing an SDK.

Licensed under [MIT](LICENSE). Public repository: [jusso-dev/junction](https://github.com/jusso-dev/junction). See [contributor instructions](CONTRIBUTING.md) and [automated releases](docs/RELEASING.md).

The daily GitHub Actions workflow refreshes every catalog below from official Microsoft sources, increments the patch version, and publishes native Rust binaries for Linux, macOS and Windows as GitHub prereleases with SHA-256 checksums.

## API coverage

The default registry holds **19,462 operations across 10 products**, all refreshed live from official Microsoft sources. Each catalog keeps per-document receipts (repository revision or Learn page, SHA-256 and byte count) in `generated/manifests/`.

| Product area | Operation IDs | Source | Operations |
| --- | --- | --- | --- |
| Microsoft Graph (v1.0; beta opt-in) | `graph.*` | [msgraph-metadata](https://github.com/microsoftgraph/msgraph-metadata) OpenAPI | 17,870 (beta 29,581) |
| Microsoft 365, Entra ID, Intune, Windows 365, Teams, SharePoint, OneDrive, Planner, Outlook/Exchange | `m365.*`, `entra.*`, `intune.*`, `windows365.*` aliases over `graph.*` | Graph | see `junction api aliases` |
| Azure Resource Manager: Resources, Compute, Monitor, Resource Graph, Cost Management, Log Analytics, Arc, Lighthouse | `azure.*` | [azure-rest-api-specs](https://github.com/Azure/azure-rest-api-specs) OpenAPI | 520 |
| Log Analytics query (data plane) | `azure.log_analytics_query.*` | azure-rest-api-specs data-plane OpenAPI | 7 |
| Microsoft Sentinel | `sentinel.*` | azure-rest-api-specs | 95 |
| Microsoft Purview (accounts; audit, eDiscovery, labels via Graph) | `purview.*` | azure-rest-api-specs + Graph aliases | 26 + aliases |
| Defender for Cloud | `defender.cloud.*` | azure-rest-api-specs | 29 |
| Defender XDR (incidents, advanced hunting) | `defender.xdr.*`, plus `defender.incidents.*`/`defender.hunting.*` Graph aliases | Microsoft Learn reference | 4 |
| Defender for Endpoint | `defender.endpoint.*` | Microsoft Learn reference | 100 |
| Defender for Cloud Apps | `defender.cloud_apps.*` | Microsoft Learn reference | 29 |
| Defender for Identity, Defender for Office 365 | `defender.identity.*`, `defender.threat_intelligence.*`, `defender.attack_simulation.*` | Graph security API aliases | aliases |
| Power Platform | `power_platform.*` | Microsoft Learn REST reference | 214 |
| Power BI | `power_bi.rest.*` | [PowerBI-CSharp](https://github.com/microsoft/PowerBI-CSharp) swagger | 287 |
| Microsoft Fabric | `fabric.*` | [fabric-rest-api-specs](https://github.com/microsoft/fabric-rest-api-specs) | 256 |
| Office 365 Management Activity API | `m365.office_365_management.*` | Microsoft Learn reference | 6 |
| Azure DevOps Core | `azure_devops.*` | [vsts-rest-api-specs](https://github.com/MicrosoftDocs/vsts-rest-api-specs) | 19 |

### Documented endpoints (Microsoft Learn)

Defender for Endpoint, Defender XDR, Defender for Cloud Apps, Power Platform and the Office 365 Management Activity API publish no official OpenAPI document. For these, Junction uses the specification's last-resort documented endpoint extraction. It reads only the pages listed in each product's official Learn `toc.json` under a configured prefix (see `sources/*.toml` with `source_type = "documentation"`). Pages are fetched as Markdown (`Accept: text/markdown`), paced and retried under Learn throttling, with a SHA-256 receipt for each page.

From each page Junction extracts:

- the documented HTTP request templates;
- URI/query parameters, including the OData options when the page documents OData support;
- request-body tables, with their required fields;
- Application/Delegated permission tables and OAuth scopes;
- `@odata.nextLink` pagination.

It then synthesizes an OpenAPI 3 document and imports it through the same normalizer as other sources. Naming, risk classification and policy therefore behave identically. Only Microsoft-operated API hosts are accepted; sample hosts such as `contoso` are ignored. Defender for Cloud Apps' tenant-specific host becomes an endpoint template (`tenant_id`, `tenant_region`).

Response shapes from documentation are unvalidated JSON. Execution validates the documented request inputs.

### Product aliases

Intune, Windows 365, Teams, SharePoint, OneDrive, Planner, Outlook, Entra ID, Purview audit/eDiscovery/labels and the Graph-based Defender capabilities have no separate public API: their documented endpoints are Graph operations. `junction api aliases` lists stable product names that resolve to the canonical Graph operation:

```sh
junction describe intune.devices.list          # graph.device_management.managed_devices.list
junction defender incidents list --input '{}'  # graph.security.incidents.list
junction describe purview.audit.queries.list   # graph.security.audit_log.queries.list
```

Aliases never create or modify operations. The canonical ID, risk and policy rules (including deny patterns) apply unchanged, and a real operation ID always wins over an alias.

### Cloud contexts

Cloud contexts resolve endpoints and token audiences for `graph`, `arm`, `defender_xdr`, `defender_endpoint`, `azure_devops`, `fabric`, `power_platform`, `power_bi`, `log_analytics` and `office365_management`. Sovereign values are included where Microsoft documents them. Services without a documented sovereign endpoint require a custom cloud.

Development status: foundational implementation. Bounded CLI/library execution, native MCP stdio serving, and authenticated local HTTP serving are implemented. Full API coverage and additional authentication flows remain in development. Do not use this version for production automation.

## Build

```sh
cargo build --release
cargo test --workspace
```

The executable is `target/release/junction`. No Python, Node.js, PowerShell, Azure CLI, or Graph CLI is required.

## Terminal interface

Launch the Ratatui catalog explorer with `junction tui`. Press `?` for keyboard help. It uses a dark theme,
a product sidebar, searchable operation list, and tabs for overview, input schema,
and permission requirements. Press `/` to search, arrows or `j`/`k` to browse,
`[`/`]` to filter products, `{`/`}` to filter services, `Tab` to change details, `PageUp`/`PageDown` to scroll,
`n`/`b` for next/previous catalog pages, `p` to toggle preview visibility, and `q` to quit. The unfiltered catalog is browsable in pages of 100. Search results are capped at
100; searches cover the selected product's full catalog. Resize to at least
70 columns × 16 rows; the sidebar hides below 110 columns.

```sh
junction tui
junction --registry generated/registry/graph-beta.json tui --allow-preview
```

The interface uses the same version selection, schema metadata and trusted
`--risk-overrides` as CLI discovery. It browses the local catalog without loading
credentials or making API calls. Execution continues through `junction execute`.

## Current workflow

```sh
junction import specification.json --product azure --service compute \
  --source https://github.com/Azure/azure-rest-api-specs \
  --output generated/registry/operations.json
junction search 'virtual machines'
junction describe azure.compute.virtual_machines.list
junction permissions azure.compute.virtual_machines.list --json
junction policy-check azure.compute.virtual_machines.list \
  --tenant customer-a --policy examples/policy.toml
```

Import accepts OpenAPI 3 or Swagger 2 JSON/YAML, with a 128 MiB input limit. Rust 1.89 or newer is required. References in schemas are preserved. Local parameter references are resolved with cycle detection; external parameter references are rejected until document loading is implemented. Imported manifests include canonical schema definitions alongside original schema metadata. Colliding operation/version names are rejected before the manifest is written. Version resolution defaults to latest non-preview; preview requires explicit opt-in. Catalog search is capped at 100 results.

## Sources

Canonical operations also accept space-separated invocation, with the same flags and execution checks:

```sh
junction --context customer-a graph users list --input '{}'
junction --context customer-a azure compute virtual-machines list --api-version latest
junction --context customer-a azure vm list --api-version latest
```

Hyphens in components map to underscores. `azure vm` expands to `azure.compute.virtual_machines`; the selected registry must contain the canonical operation. Supply request parameters in `--input` as with `execute`.

`junction permissions <canonical-operation>` inspects imported scope requirements without acquiring credentials or making API requests. It supports `--api-version` and `--allow-preview`, and returns the selected version, source provenance, and a metadata status. Requirements also appear in `describe`. Imported OpenAPI `externalDocs` links appear as `documentation_url` in descriptions, permission summaries, and 401/403 diagnostics. Operation-level documentation takes precedence over document-level documentation. Only plain HTTPS links without user-info, query strings, or fragments are retained; absent or unsafe links are `null`. Links are metadata and are never used as execution endpoints. These summaries do not infer delegated/application support or grant permissions; `unavailable` requires consulting the service's authoritative permission documentation.

Use official Microsoft sources:

- [Azure REST specifications](https://github.com/Azure/azure-rest-api-specs)
- [Microsoft Graph metadata](https://github.com/microsoftgraph/msgraph-metadata)

The full requested design is preserved in [docs/SPECIFICATION.md](docs/SPECIFICATION.md). Implementation tracking is in [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md).

Policy defaults to read-only. Deny rules and tenant restrictions take precedence over modes. Destructive and privileged operations produce `approval_required`; agent input cannot approve them. Every physical API request, including retries and page fetches, passes through shared request admission.

Version lifecycle: `latest` selects stable before preview even with `--allow-preview`. Deprecated versions require an exact version; retired versions never resolve. Numeric versions use natural ordering. Lifecycle metadata defaults to stable for older manifests; authoritative retirement metadata integration is pending.

Catalog inspection: `junction api stats`, `junction api products`, `junction api services --product graph`, and `junction api versions graph.users.list`. Search returns compact summaries including `required_permissions` from imported OpenAPI scope groups. Outer groups are alternatives; scopes within each group are jointly required. Missing or scope-free metadata is `null`, not a declaration of unrestricted access. Delegated/application permission enrichment and service RBAC metadata remain pending. Describe returns full operation metadata and a JSON input schema for the execution envelope.

Review catalog updates with `junction --registry new.json api changes old.json`. Both manifests are validated. Reports list added/removed operation versions, changed field names, and whether schemas changed; they omit changed values. Daily Graph catalog refreshes are configured in the release workflow; compatibility gates remain pending.

`junction-auth` provides secret-safe values, isolated token caching, client-secret and RSA certificate client credentials, workload/external credentials, VM managed identity, OBO, device-code and authorization-code providers. Device-code CLI login uses native macOS Keychain storage. See [authentication](docs/AUTHENTICATION.md) and [certificate credentials](docs/CERTIFICATE-AUTHENTICATION.md) for supported formats, platform limits and remaining verification. Flow enum variants alone do not establish implemented acquisition.

Client-credentials implementation follows [Microsoft documentation](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow). Authority and audience come from trusted caller configuration. Local HTTP tests cover form encoding, success, redirect rejection, oversized responses and safe failure messages. Live tenant testing remains pending.

`junction-runtime::prepare` builds requests from an operation and trusted endpoint after a local policy check. It accepts an input envelope with `parameters` and `body`. Scalar parameters and JSON bodies are validated against retained registry schemas. Declared headers, query arrays and flat query objects are supported. Cookie/form serialization, complex path styles and broader dialect support remain pending; this planner is not yet a complete universal executor.

`junction-http` provides bounded HTTPS JSON transport and shared request admission. The executor must still enforce authorization, token audience/tenant binding, and complete input validation before calling it. Bounded read retries honor Retry-After; enriched authorization errors and transport integration tests remain pending.

The runtime library now exposes a single-request `Executor::execute` accepting trusted endpoint/audience context and an acquired token. It rejects credential context mismatches and expired tokens before sending. Schema validation, bounded read retries, next-link pagination and client-secret CLI execution are connected. Central cloud endpoints, bounded pagination, saved LRO polling and explicit final-result retrieval are implemented. Live Microsoft integration and broader execution coverage remain unfinished.

`Executor::execute_pages` retrieves Graph/ARM next-link pages within policy item/page limits, retaining excess page items in a continuation. The Rust `execute_pages_resuming` API consumes opaque in-memory continuations, drains buffered records before network access, and rechecks request/context binding, credentials, and policy. Relative links resolve against the current page. CLI pagination and private-file continuation storage are available below; declared query continuation tokens and Azure DevOps header tokens are supported. Additional body-token and service-specific strategies remain unfinished.

## Execute with environment credentials

Set `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and `AZURE_CLIENT_SECRET` through your secret manager or environment. Copy [examples/execution-context.json](examples/execution-context.json) and configure the tenant, authority, resource audience, and endpoint for the target API. The environment tenant must match the context tenant. Context files contain no credentials. Endpoint and authority configuration is trusted operator configuration; do not accept these files from untrusted agents.

```sh
junction execute graph.users.list --context-file context.json --input '{}'
```

Execution uses read-only policy by default. Supply `--policy examples/policy.toml` to select local policy, and `--api-version` / `--allow-preview` for explicit version selection. Policy and schema validation run before token acquisition. Policy rejection and approval requirements produce structured JSON on stderr with nonzero exit status. Successful calls return JSON containing HTTP `status` and `body`. Tenant, audience and expiry are checked before API requests. The shared credential selector supports client-secret, certificate, workload, managed-identity, external-bearer, OBO and stored device-code credentials. Live Microsoft tenant verification remains pending.

## Named contexts and clouds

```sh
junction context add customer-a --file examples/us-government-context.json
junction context list
junction context show customer-a
junction --context customer-a execute graph.users.list --input '{}'
junction context remove customer-a
```

Replace the example tenant before use. Contexts are stored under `.junction/contexts` in the working directory; use global `--contexts-directory` to select another store. Names cannot contain paths. Adding a context never overwrites an existing one. Files contain validated configuration only and are created with owner-only permissions on Unix. Credentials remain in the environment. Context commands do not require an operation registry.

Cloud contexts accept `public`, `us_government` (GCC High), `us_government_dod`, `china`, or `custom`, and select a service (`graph`, `arm`, `defender_xdr`, `defender_endpoint`, `azure_devops`, `fabric`). Graph and ARM authority/endpoint/audience mappings are centralized; remapping preserves the upstream base path and rejects a mismatched service. Custom clouds require a full `custom_endpoints` object containing explicit authority, service endpoints/audiences, and optional storage/Key Vault suffixes. Missing services never fall back to public endpoints. Existing explicit endpoint/token_request context files remain supported for operator-configured targets.

Endpoint references: [Microsoft Graph national clouds](https://learn.microsoft.com/en-us/graph/deployments), [Azure cloud definitions](https://github.com/Azure/azure-cli/blob/dev/src/azure-cli-core/azure/cli/core/cloud.py), [Defender XDR government endpoints](https://learn.microsoft.com/en-us/defender-xdr/usgov), and [Defender for Endpoint government endpoints](https://learn.microsoft.com/en-us/defender-endpoint/gov). Government Defender endpoint metadata is retained, but built-in execution requires authoritative audience metadata that is still pending; use an explicitly configured context after verifying your service audience. China Defender mappings are unavailable. These endpoint mappings do not establish operation availability or feature parity in sovereign clouds. Live cloud execution remains unverified.

Parameter serialization metadata is retained during import. Query arrays support OpenAPI form (repeated or comma-separated), non-exploded space/pipe styles, and Swagger csv/ssv/tsv/pipes/multi. Flat form/deepObject query objects are supported; nested objects and allowReserved currently fail explicitly. Values are encoded independently from array delimiters. Expanded object keys cannot override other declared query parameters or the selected API version. Declared scalar/array headers are validated, bounded and marked sensitive; credential and transport headers remain controlled by the runtime.

Swagger JSON body parameters and local OpenAPI requestBody references normalize into the same request-body envelope. Body schema references remain symbolic and are validated against retained definitions. Explicit non-JSON Swagger body media types are rejected. Serialization follows the supported portions of [OpenAPI 3 parameter rules](https://spec.openapis.org/oas/v3.0.4.html#parameter-object) and [Swagger 2 parameter rules](https://spec.openapis.org/oas/v2.0.html#parameter-object); this is not complete OpenAPI serialization coverage.

## Retrieve an official definition

```sh
junction fetch graph --path openapi/v1.0/openapi.yaml \
  --output .junction/upstream/graph-v1.0.yaml
junction import .junction/upstream/graph-v1.0.yaml --product graph \
  --service directory --source https://github.com/microsoftgraph/msgraph-metadata \
  --output .junction/registry/graph-v1.0.json
junction --registry .junction/registry/graph-v1.0.json api stats
```

Fetch resolves the repository's default-branch commit using the [GitHub commits API](https://docs.github.com/en/rest/commits/commits#list-commits), then downloads a commit-pinned raw URL. Pass a full `--revision` commit ID for reproducible retrieval. Repository ownership and configured path scope are checked before requests. Downloads use unauthenticated HTTPS, reject redirects, and enforce a 60-second request timeout and 128 MiB response limit. A SHA-256 receipt is saved alongside the raw specification as `<output>.receipt.json`. Files are individually published by atomic rename after parsing; the specification/receipt pair is not transactional. The receipt records provenance and content identity; it is not a signature verification claim.

The real Graph v1.0 definition at revision `7b2914c8ad1340129f52aa785f13c074cb46fd7c` was fetched, parsed, imported, loaded, and searched through the CLI: 17,870 operations. The [verification receipt](docs/verification/graph-v1.0-receipt.json) records the 44,334,960-byte document and digest. The Graph naming adapter now produces canonical names such as `graph.users.list`; all 17,870 imported operation names are unique. Complete execution of this catalog is not verified. Directory enumeration, multi-document/schema merging, external references, TypeSpec, complete OData coverage, update compatibility gates and other source catalogs remain pending.

YAML parsing uses strict boolean inference and bounded catalog-sized node/event limits. Resource limits remain enforced, and parser diagnostics containing input text are suppressed. Catalog import validates the registry before atomically replacing its output.

## Open source and automated builds

Junction is licensed under [MIT](LICENSE). The intended public repository is `jusso-dev/junction`; repository publication must be completed before its workflows can run.

The [daily release workflow](.github/workflows/daily-release.yml) refreshes official Graph v1.0/beta, Azure DevOps Core, Resources, Compute VM, Sentinel, Purview Accounts, Cost Management, Azure Resource Graph resource/saved queries, Monitor Metrics, Activity Logs, Activity Log Alerts, Metric Alerts and Scheduled Query Rules and Fabric Platform, Admin, Lakehouse and Notebook definitions at 02:17 UTC, increments the patch version, tests and builds native Rust binaries for Linux, macOS, and Windows, and publishes archives with SHA-256 checksums as workflow artifacts and GitHub prereleases. See [release instructions](docs/RELEASING.md) for packaging, installation, and coverage.

## Bounded pagination

```sh
junction execute graph.users.list --context-file context.json --all \
  --max-items 100 --max-pages 5 --continuation-file page-2.json
junction execute graph.users.list --context-file context.json --all \
  --resume page-2.json --continuation-file page-3.json
```

`--all` retrieves Graph/ARM `value` arrays with `@odata.nextLink` or `nextLink` within policy limits. Defaults are 100 items and five pages per invocation. Output contains `items`, `pages`, and `continuation` (a file path or null). A new `--continuation-file` destination is required; it is written only if more records remain and never overwrites a file. Resume requires the same operation, API version, input, tenant, audience, and endpoint, and rechecks current policy and credentials. Buffered records are returned before further requests.

Declared `x-ms-pageable` operations may start with POST and a validated JSON
body. Continuation links use GET by default. A named next-page operation can use
GET or POST; its current policy, source identity, version and body schema are
checked before credential acquisition. Named POST continuations reuse the
original JSON body only when that operation declares a body; bodyless operations
receive none. This follows the [AutoRest paging contract](https://github.com/Azure/autorest/blob/main/docs/extensions/readme.md#x-ms-pageable).
POST requests retain the policy method floor and are not automatically retried.
Named operations with service headers/cookies and pagination that changes a body
continuation-token field remain unsupported.

Paired official [`x-ms-list-continuation-token` markers](https://github.com/microsoft/OpenAPI/blob/main/extensions/x-ms-list-continuation-token.md)
declare a string query parameter and a string response property. Junction supports
custom parameter names and nested response properties, including local schema
references. Tokens become encoded query values on the existing endpoint; marked
POST continuations preserve the original method and JSON body. Unpaired or
ambiguous markers are rejected. Missing, null or empty tokens finish retrieval.
Marked response schema traversal is bounded; live service execution remains unverified.
Document-level reference indexing keeps unrelated schemas outside that traversal,
including catalogs mixing ordinary operations with marked token operations.

Resumes bind the full initial and named-operation metadata, as well as the exact
input and acquisition bindings. Changed metadata and checkpoints from the older
input/version-only binding format are rejected; restart retrieval instead of
reusing those checkpoints. Request history persists across resumptions, so a
resume cannot repeat the initial POST. A continuation chain is capped at 10,000
distinct page requests in addition to each invocation's item/page limits.
GET transport retries are admitted separately by policy and are not additional
logical page submissions. Local tests cover POST selection/body validation,
resumption, metadata changes and policy bounds; live POST pagination remains
unverified.

Checkpoint files contain sensitive response records, input, and continuation URLs. Treat them as trusted operator state, keep them private, and remove them when finished. Unix files are created with mode 0600 and loading rejects group/world-accessible files. On Windows, access follows the destination directory's ACL; choose a private directory. Checkpoints are bounded to 32 MiB and are not printed as JSON tool output. Live paginated Microsoft execution remains unverified.

## Focused operation discovery

```sh
junction search "list users" --product graph --service users --limit 5
junction search "incidents" --product defender
junction search "users" --allow-preview
```

Search ranks canonical action/resource matches above description-only matches and prefers shorter operation paths when relevance is equal. Results use deterministic ordering and remain capped at 100 compact entries. Product and service filters narrow the catalog hierarchy. Preview-only operations require `--allow-preview`; stable versions remain preferred. Queries are limited to 1,024 bytes and 32 distinct terms; empty or over-limit queries return no matches. The cached 17,870-operation Graph catalog returns `graph.users.list` first for `list users`. Search does not acquire credentials or infer undocumented permissions.

`junction describe <operation>` now includes `input_schema`, a JSON Schema for the executor's `parameters`/`body` envelope. It retains required fields, local recursive references, and upstream constraints, adapts OpenAPI nullable/numeric-exclusive keywords, binds optional `api-version` to the selected version, and includes only reachable definitions. Unknown envelope/parameter fields are rejected. Runtime policy and parameter serialization checks still apply separately; unsupported body formats or missing/external references fail explicitly.

Global `--json` emits compact deterministic JSON; formatted JSON remains the default. `--quiet` suppresses successful command output while retaining error diagnostics and exit status. Both flags work before or after subcommands, including `junction describe graph.users.list --json`. `--yaml` emits equivalent YAML; `--table` emits tab-separated rows with JSON-escaped cells, deterministic columns, and preserved nested values. Format flags are mutually exclusive. Verbose tracing remains pending.

## Batch calls

```sh
junction batch --context-file context.json --input '{"operations":[{"id":"users","operation":"graph.users.list","input":{}},{"id":"groups","operation":"graph.groups.list","input":{}}],"max_parallel":2,"timeout_seconds":300,"fail_fast":false}'
```

Batch requests support `depends_on` IDs and input references such as `{"$result":"users","pointer":"/body/value/0/id"}`. References imply dependencies. Calls use one trusted endpoint, tenant, audience, and credential configuration; mixed contexts are rejected. Every operation's policy is checked before token acquisition. Inputs without result references are also preflighted; referenced inputs are validated after substitution. Concurrency and operation count follow policy caps. Results remain in submission order with succeeded, failed, skipped, or timed_out status. Fail-fast stops new calls while started calls finish; `fail_fast:false` continues independent work. An overall deadline stops local waiting; it does not prove an upstream mutation was cancelled. Live batch calls and MCP batch integration remain unverified/incomplete.

## Workload identity from environment

Set context `flow` to `workload_identity` (inside `token_request` for explicit contexts, or at the top level for cloud contexts). Supply `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and `AZURE_FEDERATED_TOKEN_FILE` through the trusted workload environment. Junction reads the externally issued assertion file anew for each acquisition, then exchanges it against the context's Entra authority and audience. The file is bounded to 1 MiB and never logged. Tenant and flow must match; there is no fallback to a client secret. Both execute and batch use this provider after policy preflight. The identity host must rotate its assertion file as needed. Junction does not configure federation trust or sign assertions; live federation exchange remains unverified.

## Injected bearer credentials

Set context `flow` to `external_bearer` and inject `JUNCTION_ACCESS_TOKEN`, `JUNCTION_TOKEN_TENANT`, `JUNCTION_TOKEN_AUDIENCE`, and `JUNCTION_TOKEN_EXPIRES_AT` (Unix epoch seconds) through the trusted credential broker/environment. Token values never belong in context files or command arguments. Tenant and audience must match the execution context, and at least 60 seconds of lifetime must remain. No token endpoint call is made.

The broker/operator must supply correct metadata: Junction does not validate token signatures or derive authorization from unverified JWT claims. Environment injection records no granted scopes or roles; use empty context scopes. The Rust `ExternalBearerProvider` can accept broker-attested permissions and rejects requested scopes absent from that metadata. Execution policy remains authoritative. Live injected-token API calls remain unverified.

Manual risk corrections use the global `--risk-overrides` flag and a trusted TOML file. See [override configuration](overrides/README.md). Corrections apply to every version and registry consumer; policy and HTTP method risk floors still apply.

## On-behalf-of library authentication

`junction_auth::on_behalf_of::OnBehalfOfProvider` exchanges a validated incoming user access token for a downstream token using a confidential client's secret. The embedding middle-tier service must authenticate the incoming token's signature, issuer, tenant, and audience before constructing its `AccessToken`; Junction does not treat unverified JWT claims as trusted metadata. Entra validates the assertion during exchange.

Construct one provider per user assertion, supply the middle-tier audience, and acquire with `AuthFlow::OnBehalfOf` and explicit downstream audience-qualified scopes. Tenant mismatch, near expiry, flow mismatch, and scopes for a different audience are rejected before transport. The shared HTTPS transport rejects redirects and bounds responses. Refresh tokens are not retained and granted permissions are not inferred from requested scopes. The application-wide `TokenCache` rejects OBO insertion because it has no user/assertion key; callers must use a correctly user-bound cache. CLI/environment selection is available as described below; live tenant verification remains pending.

Protocol: [Microsoft's on-behalf-of flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow).


For CLI OBO execution, select `flow: "on_behalf_of"` and explicit downstream scopes in a trusted context, such as [examples/obo-cloud-context.json](examples/obo-cloud-context.json). Supply the following through a trusted credential broker or environment:

- `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`: the confidential middle-tier application.
- `JUNCTION_OBO_ASSERTION`: its validated incoming user access token.
- `JUNCTION_OBO_TENANT`: the assertion's broker-verified tenant, matching `AZURE_TENANT_ID` and the execution context.
- `JUNCTION_OBO_MIDDLE_TIER_AUDIENCE`: its broker-verified audience for the middle-tier application, distinct from the downstream context audience.
- `JUNCTION_OBO_EXPIRES_AT`: its broker-verified expiry as Unix seconds.

These metadata values are operator/broker attestations; Junction does not decode an unsigned JWT to establish trust. Context files contain downstream settings, never assertion values or client secrets. The incoming assertion is held only for the invocation, and the acquired downstream token is used by the existing executor, pagination, or batch path. Refresh and reauthentication remain the broker's responsibility.

```sh
junction context add customer-a --file examples/obo-cloud-context.json
junction --context customer-a graph users list --input '{}'
```


## Safe token metadata

```sh
junction auth token-info --context-file context.json --json
junction --context customer-a auth token-info
```

This command acquires or validates a credential for the selected context and emits only tenant, audience, expiry, detected scopes/roles, and account metadata. It works without a registry and uses the same explicit environment credential flow as execution. Client-secret, certificate, workload, and OBO acquisition may contact the trusted token authority; managed identity contacts IMDS and injected external bearer validation stays local. Tokens and client secrets are never printed. Requested scopes are not reported as granted permissions. `--quiet` suppresses output while still validating/acquiring the credential. Device-code login and private persistence are implemented on macOS; browser login and Windows/Linux persistence remain unfinished.


## JSON input files and stdin

Execution and batch accept `--input-file <path>` or `--input-file -` for stdin, as an alternative to inline `--input`. Reads are capped at 16 MiB and must contain UTF-8 JSON. File paths must resolve to regular files. Omitting input on execute retains `{}`; batch requires one input source. The same flags work with hierarchical invocation.

```sh
junction --context customer-a graph users list --input-file request.json
junction --context customer-a batch --input-file batch.json
junction --context customer-a graph users list --input-file - < request.json
```

Use file/stdin input for sensitive request bodies to avoid putting payloads in process arguments. Policy, schema, tenant, and credential checks are identical across input sources. Protect files containing sensitive data using your normal filesystem access controls.


## Request correlation

Each physical execution attempt receives a generated UUID v4 in `client-request-id` and `x-ms-client-request-id`, including retries and page requests. Declared operation headers cannot replace these identifiers. Single-call and successful batch results include a `correlation` object; library HTTP responses and 401/403 diagnostics retain it too. Upstream `request-id` and `x-ms-request-id` values are retained only when UUID-shaped; other formats are omitted. Pagination success currently returns its aggregate records rather than per-page IDs. Request URLs, bearer credentials, arbitrary response headers, and failed response bodies are not included in correlation metadata.

Reference: [Microsoft Graph troubleshooting guidance](https://learn.microsoft.com/en-us/microsoft-cloud/dev/dev-proxy/concepts/how-to-debug-microsoft-graph-calls).


## Long-running operation metadata

Azure OpenAPI imports retain `x-ms-long-running-operation` as `long_running`, including optional declared `final_state_via` and local `final_state_schema` references. Supported declared hints are Azure-AsyncOperation, Location, original URI, and Operation-Location. Invalid markers/options fail import without echoing source values. Existing manifests without this metadata remain compatible.

Library HTTP responses retain opaque `async_links` from Azure-AsyncOperation, Operation-Location, and Location headers. Relative links resolve against the request URL; only HTTPS links on the same origin, without user-info or fragments, are retained. These links have no Debug/Serialize implementation because polling URLs may contain sensitive data. They are not included in CLI output. The executor uses these links for bounded polling and private operation checkpoints.

Reference: [Azure AutoRest LRO extensions](https://github.com/Azure/autorest/blob/main/docs/extensions/readme.md#x-ms-long-running-operation-options).

Fabric imports retain `x-ms-fabric-sdk-long-running-operation` and select Fabric's
Location polling protocol. An HTTP 200 poll with `status: Running` remains pending.
When no safe Location is available, a validated UUID in `x-ms-operation-id` supplies
a same-origin `/v1/operations/{id}` polling URL. A successful poll's distinct,
same-origin Location is retained for `operations wait --result` and checkpoint
resumption. Operations without a safe result URL report result retrieval as
unavailable. Live Fabric polling remains unverified. See [Microsoft's Fabric LRO
protocol](https://learn.microsoft.com/en-us/rest/api/fabric/articles/long-running-operation).



The runtime library's `lro` module normalizes Azure async status responses into running/succeeded/failed/canceled states. Azure-AsyncOperation and Operation-Location polling require explicit `status`; resource polling uses `properties.provisioningState` or `provisioningState`, and Location polling recognizes pending 202 and completed 200/204 responses. Provider-specific nonterminal state names remain running. `LroTracker` bounds observations, preserves terminal states, and emits only state/poll count, excluding upstream error payloads. Use `Executor::start_lro` to start a declared LRO and `Executor::poll_lro` to make bounded status requests. These return an opaque in-memory handle and safe snapshots.

Protocol reference: [Track asynchronous Azure operations](https://learn.microsoft.com/azure/azure-resource-manager/management/async-operations).


LRO handles bind to the original tenant, audience, endpoint, operation, and selected API version. Each poll rechecks current operation policy and credential validity. Azure-AsyncOperation takes priority over Operation-Location and Location; PUT/PATCH resource polling can fall back to the original URI. Pending POST/DELETE responses require a safe status link. Polling never resubmits the initial mutation. Callers must wait the handle's `retry_after()` delay before polling again; exhausted limits, invalid context, and early polls fail before transport. Network errors consume a logical poll attempt; HTTP read retries also pass through shared physical-request admission. Safe snapshots contain only the generated operation ID, canonical operation, state, and poll count. Explicit final-state result retrieval is implemented through operations wait --result; supported remote cancellation remains pending. Live Azure polling has not been verified.


For a declared LRO, `execute --wait` (including hierarchical invocation) starts the operation and waits for a terminal state:

```sh
junction --context customer-a azure vm start --input-file request.json \
  --policy operator-policy.toml --wait --timeout-seconds 300 --max-polls 100
```

The wait timeout is 1–3600 seconds, default 300; logical polls are capped at 1–10000, default 100. Poll limits and shared policy request limits both apply. Waiting conflicts with `--all` pagination. These bounds and declared LRO support are checked before credential acquisition. The deadline covers polling delays, status requests, and read retries after the initial mutation is accepted. Success output is a safe operation-state snapshot, not the final service resource payload. A local timeout reports `operation_wait_timed_out` with the operation ID and last known state and does not cancel the remote operation. Library callers retain their in-memory handle, and the CLI saves a private checkpoint for later polling. Failed/canceled remote states are reported explicitly in the snapshot; applications must inspect `state`.


Library LRO handles support `save(path)` and `LroHandle::load(path)` for operator-owned private checkpoints. Saving creates a new file and never overwrites an existing checkpoint. Files are bounded to 64 KiB, retain selected version/context/poll counts and the next allowed polling time, and contain no access tokens, client secrets, input bodies, or upstream error payloads. Polling URLs may contain sensitive query data, so Unix checkpoints are created with mode 0600 and public/group permissions are rejected on load. Other platforms require a private directory protected by appropriate ACLs. Loaded handles still pass executor policy, credential, context, and same-origin checks before polling. Checkpoints are trusted mutable operator files, not signed agent-provided authorizations. CLI execution stores these checkpoints in its private operation store.


## Persistent operation handles

Declared long-running operations automatically return a safe operation snapshot and save a checkpoint in `.junction/operations`, even without `--wait`. Use the global `--operations-directory` flag to select another operator-owned directory. Storage is checked before the initial mutation, and the first checkpoint is saved before waiting begins.

```sh
junction --context customer-a azure vm start --input-file request.json --policy operator-policy.toml
junction operations get 00000000-0000-4000-8000-000000000001
junction --context customer-a operations wait 00000000-0000-4000-8000-000000000001 \
  --policy operator-policy.toml --timeout-seconds 300
```

Replace the example ID with the returned `operation_id`. `operations get` displays the last saved state without acquiring credentials or loading a registry. `operations wait` selects the original operation/version, requires the same tenant/audience/endpoint, rechecks policy before credential acquisition, and resumes the remaining logical poll budget. It saves updated state after completion, timeout, or polling error using an atomic file replacement. A terminal handle returns its existing state without sending an HTTP request. Failed/canceled states remain explicit snapshot states.

Add `--result` to `operations wait` to retrieve the final response after the
operation succeeds. The response includes the saved operation snapshot, HTTP
status, body and correlation IDs. The explicit retrieval uses a governed GET;
failed/canceled operations cannot retrieve a successful result. PUT/PATCH results
use the original resource URL. POST results follow the declared final-state hint,
or use Location when available. Status-endpoint result retrieval repeats a GET
rather than caching private response bodies in checkpoints. Final-state hints do
not change status polling, following the
[AutoRest final-state rules](https://github.com/Azure/autorest/blob/main/docs/extensions/readme.md#x-ms-long-running-operation-options).

Final destinations stay bound to the original HTTPS origin and are stored only
in private checkpoints. Old checkpoints without a final-result binding still
support polling; result retrieval fails explicitly. A missing required final
header also leaves polling usable, with result retrieval unavailable. This path
has local metadata, isolation and checkpoint tests; live Azure result retrieval
has not been verified.

An exclusive `<id>.lock` prevents concurrent waiters from updating the same checkpoint. Read-only inspection can continue while waiting. A process crash can leave a lock; remove it only after confirming no process is still using that handle. Each logical poll is reserved and persisted before transport; observed state and retry readiness are persisted after the response, with another save when waiting returns. If saving fails, polling stops. An interrupted in-flight request remains counted, so resuming cannot recover its consumed logical poll budget. A crash between receiving a response and saving it can still leave the last observed state stale. Protect the directory with filesystem permissions/ACLs: checkpoints contain private polling URLs and are trusted operator state. Remote cancellation and live Azure validation remain pending.

## Subscription and resource-group scope

Both explicit-endpoint and cloud contexts accept optional `subscription` and `default_resource_group` fields. Execution and batch fill missing declared subscription/resource-group path parameters from these defaults. Existing input parameters take precedence; unrelated operations receive no extra parameters. These defaults do not change tenant, cloud, audience, or credentials.

```sh
junction context add customer-a --file examples/arm-cloud-context.json
junction --context customer-a azure compute virtual-machines list \
  --subscription your-subscription-id --resource-group your-resource-group
```

Replace the example context's tenant/subscription values before use and load an ARM operation registry for the desired service. The bundled default catalog currently covers Graph. Explicit CLI scope flags take precedence over context defaults, but conflicting values already supplied in `input.parameters` cause an error. Flags require exactly one matching declared path parameter; context defaults are ignored when the operation has none. Canonical parameter names, schema validation, and URL encoding still come from the registry. Batch input values and result references remain authoritative over context defaults.


## Native MCP over stdio

```sh
junction mcp serve --policy read-only
junction --context customer-a mcp serve --policy safe-write
junction --context customer-a mcp serve --policy-file examples/policy.toml
```

The server exposes exactly `junction_search`, `junction_describe`, `junction_execute`, `junction_batch`, `junction_permissions`, and `junction_context`. Search/describe/permissions work without an execution context; execution and batch require one named context or `--context-file` selected by the operator at startup. Policy mode or a policy file is also fixed at startup. Tool arguments cannot supply credentials, endpoints, tenant switches, or policy overrides. Context tools list/show secret-free operator contexts without modifying them.

The host uses the same registry, risk overrides, context defaults, schema checks, credential flows, authorization diagnostics, and executor as CLI execution. One executor and request governor remain shared across calls. Declared LRO execution saves private handles and accepts `wait`/`timeout_seconds`; batch retains bounded concurrency, dependencies, references, fail-fast, and deadlines. Policy rejections and approval requirements appear as structured MCP tool errors. Unknown errors omit request values and raw exception details.

Configure an MCP client's stdio command as `junction` with arguments such as `["--context", "customer-a", "mcp", "serve", "--policy", "read-only"]`. JSON-RPC initialization negotiates protocol `2025-11-25`, and tool use begins after `notifications/initialized`. Stdout contains only newline-delimited protocol messages; CLI display flags do not change protocol output. Incoming/outgoing frames are limited to 16 MiB. The host permits one active tool call; ping and cancellation remain responsive while it awaits I/O. Additional tool calls receive a busy error and can be retried after completion. Streamable HTTP and external-client/live Microsoft interoperability remain pending.

Protocol references: [MCP lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle), [stdio transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports), and [tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).


MCP `junction_execute` accepts `all: true`, `max_items` (default 100), and `max_pages` (default 5) for bounded Graph/ARM pagination. Responses contain `items`, `pages`, and either an opaque `continuation` ID or null. To resume, repeat the same operation, input, API version and preview selection with `all: true` and the returned ID. Runtime context/request binding still applies. Successful resumption consumes the old ID and returns a replacement if more records remain; failed calls retain the previous checkpoint. Polling/waiting cannot be combined with pagination, and pagination controls require `all: true`.

Continuation files remain private to the MCP host and never expose filesystem paths or upstream next-link URLs. Each host retains at most 64 active handles, with the runtime's 32-MiB limit per checkpoint. Handles expire when that host process exits. The host does not add bearer credentials to checkpoints; they can contain sensitive input and returned records. Live Graph/ARM page retrieval through an external MCP client remains unverified.


Oversized MCP responses now return a correlated `response_too_large` JSON-RPC error instead of terminating the host or writing partial payloads. Response serialization stops at the frame limit, and subsequent requests remain usable. The error includes `execution_may_have_completed: true`: a rejected response does not undo an executed request. Use smaller pagination bounds or narrower API projections when applicable. String JSON-RPC IDs are limited to 256 UTF-8 bytes so error responses remain bounded. Outgoing limits include the newline delimiter. Output I/O failures still terminate serving.


Paginated MCP results are checked against the full tool-response size before continuation rotation, including both text and structured content. If a result is too large, the tool returns `response_too_large` and leaves the caller's existing continuation available for retry with a smaller `max_items` or narrower projection. Initial requests rejected this way create no hidden continuation handle; repeat the initial read with smaller bounds. An individual record that cannot fit requires a narrower projection. Output delivery failures after a successful size check are still transport failures rather than acknowledged resumptions.


MCP clients can send `notifications/cancelled` with the active call's exact `requestId`. The host drops that local call, releases its resources, and sends no response for the canceled request. Unknown, completed, malformed, or mismatched IDs are ignored; cancellation reasons are not logged. Cancellation does not undo a Microsoft request already sent or cancel a remote Azure operation. Existing pagination checkpoints remain available, and LRO poll reservations/state already saved stay on disk. Cancellation during initial remote mutation/token acquisition may leave remote work accepted before a handle could be saved. A canceled call frees the single active-call slot so subsequent tools can run.

Reference: [MCP cancellation](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/cancellation).

## Junction HTTP contract export

```sh
junction openapi --json
junction openapi --output junction-openapi.json
```

This exports Junction's own OpenAPI 3.1.1 contract without loading a Microsoft registry or acquiring credentials. It describes `/health`, search, bounded operation listing, describe, execute, batch, contexts, permissions, and `/openapi.json`, with `http://127.0.0.1:8080` as the default server. Execution body schemas share the MCP tool definitions and exclude host policy, endpoint, and credential overrides. Successful result schemas remain broad where the selected Microsoft operation determines the payload. Release archives include the contract with their compiled binary version. Exporting the contract does not start a server.

## Local HTTP server

Supply a randomly generated server token through `JUNCTION_SERVER_TOKEN` (32–256 characters: ASCII letters, digits, `-_.~`), then start the server:

```sh
junction serve
junction --context customer-a serve --policy read-only
junction serve --context-file examples/execution-context.json --listen 127.0.0.1:8080
```

Every route requires `Authorization: Bearer <server-token>`, including health and OpenAPI retrieval. This token is separate from Microsoft credentials and never printed. Use `--token-env NAME` to select another environment variable. The server defaults to loopback; non-loopback addresses require `--allow-external`. The listener uses HTTP; use a TLS reverse proxy for remote access. Requests with browser Origin headers are rejected, and CORS is not enabled.

HTTP uses the same registry, context, credential binding, policy, pagination, LRO, and batch executor as MCP. Context and policy are fixed at startup; request bodies cannot override them. POST bodies require `application/json`. Request and response bodies are limited to 16 MiB, body reads time out after 10 seconds, and at most 16 requests enter the body/dispatch stage. One top-level tool call runs at a time; additional tool calls receive 429 while health, OpenAPI, and bounded operation listing remain available. Batch retains its configured internal request concurrency. Oversized responses return a safe 413 error indicating that execution may already have completed. Ctrl-C starts graceful shutdown and waits for active requests.

## Native OData metadata import

```sh
junction fetch graph-odata --path schemas/v1.0-USNat.csdl --output graph.csdl
junction import graph.csdl --format odata \
  --product graph --service directory \
  --source https://github.com/microsoftgraph/msgraph-metadata \
  --endpoint https://graph.microsoft.com/v1.0 --api-version v1.0 \
  --output generated/registry/graph-odata.json
```

Use the fetch receipt's commit-pinned `upstream` URL as `--source` for exact provenance. Fetch validates the bounded XML document envelope and retains revision/digest receipts. Import requires an explicit HTTPS service root and API version; the EDMX version describes the metadata format. The adapter generates collection reads, singleton reads, and unbound action/function imports. Schemas preserve structural/navigation properties, aliases, inheritance, enums, type definitions, nullability and facets. Inline and externally targeted `Readable=false` restrictions suppress read routes. Action bodies use closed parameter schemas and mutations retain write classification.

XML parsing runs natively in Rust with a 128-MiB byte limit, 200,000-node limit, depth limit of 128, and 64 attributes per element. DTDs, custom entities, unsupported encodings/declarations, malformed namespaces and ambiguous definitions are rejected. XML references are never fetched. Complex-property/alternate keys, bound-operation routes, deeper navigation, container inheritance, complete capability/permission vocabularies and complete facet enforcement remain pending. Synthetic metadata and CLI import/schema validation are tested; live Graph CSDL retrieval/import remains unverified. Daily updates continue to use Graph OpenAPI catalogs.

References: [OData CSDL XML](https://docs.oasis-open.org/odata/odata-csdl-xml/v4.01/odata-csdl-xml-v4.01.html), [OData JSON representation](https://docs.oasis-open.org/odata/odata-json-format/v4.01/odata-json-format-v4.01.html), [official Graph CSDL source](https://github.com/microsoftgraph/msgraph-metadata/blob/master/schemas/v1.0-USNat.csdl).

Function inputs use declared parameter aliases, for example `{"parameters":{"@term":"O'Brien","@year":2026}}`. Junction quotes OData strings, doubles embedded apostrophes, encodes URI values, and serializes structured aliases as JSON. Primitive, enum and underlying type definitions select literal encoding from trusted metadata. Functions use GET and retain read policy classification. Parameter names determine stable overload suffixes; overloads with identical parameter-name sets are rejected. Parameters annotated with `Core.OptionalParameter` may be omitted; Junction leaves their defaults to the service and removes omitted aliases from the function URL. Bound functions, unsupported spatial literals and full overload resolution remain pending.

CSDL entity sets also expose reads by declared key, including inherited and composite keys. For example, `graph.users.get` accepts `{"parameters":{"@id":"123e4567-e89b-12d3-a456-426614174000"}}` when the metadata declares a GUID key. Key values use typed, URI-encoded aliases; single keys use `/users(@id)` and composite keys use named predicates. `ReadByKeyRestrictions.Readable` overrides collection readability for key routes. Complex property key aliases, alternate keys and full capability interpretation remain pending.

CSDL navigation properties generate one-hop read operations from singletons and keyed entities, such as `graph.me.manager.get` and `graph.users.reports.list`. Keyed navigation accepts the same required aliases as the entity read. Collection navigation retains bounded OData pagination/query options; nullable single-valued navigation declares a 204 response. Inherited navigation properties are included without recursively expanding entity relationships. Unqualified inline and externally targeted read restrictions apply to the declaring type/property; qualified annotations remain separate. Deeper navigation, navigation bindings/restrictions, external type resolution and bound operations remain pending.

CSDL query schemas honor unqualified inline and externally targeted capability flags for `$select`, `$expand`, `$filter`, `$orderby`, `$top` and `$skip`. Disabled options are absent from the closed input schema; `FilterRestrictions.RequiresFilter` makes a nonempty filter mandatory. Singleton and key reads expose entity query options. Navigation query options use the property's own annotations. Container defaults, nested-expression/property restrictions and the remaining capability vocabulary are still pending.

CSDL collection reads also accept `$count` as a JSON boolean and `$search` as a string, subject to `CountRestrictions.Countable` and `SearchRestrictions.Searchable`. Both are URI-encoded query values on collection and collection-navigation operations. Collection response schemas retain nonnegative `@odata.count` values, including the string representation used for 64-bit counts. Search-expression restrictions, standalone `/$count` routes and live-service verification remain pending.

Enumerate candidate files in an enabled official OpenAPI/OData repository with `junction discover azure --output azure-inventory.json`. Pass `--revision` with a full commit identifier for reproducibility. The inventory sorts configured-scope files and includes pinned raw URLs, blob identifiers and declared sizes; file extensions identify candidates, which still require fetch validation and import. Enumeration falls back to scoped subtree traversal when GitHub truncates the recursive tree, and excludes symlinks/submodules. The fallback is bounded to 1,024 subtree requests, 128 MiB of responses, 200,000 entries and 64 path levels, with a five-minute elapsed-time check between bounded requests. Any incomplete or over-budget traversal fails without publishing an inventory. Live large-repository verification and broader product coverage remain pending.

Combine imported catalogs with `junction merge graph-registry.json azure-registry.json --output combined-registry.json`. Each document receives an isolated content-derived schema namespace, keeping same-named schemas from different APIs/versions separate. Operations retain their canonical IDs and API versions; exact repeated imports deduplicate, while conflicting operation/version pairs reject the merge. Output is written atomically after registry validation. Repository-relative references are resolved during refresh; broader daily product coverage remains pending.

Refresh a configured source directly with `junction refresh azure --path specification/compute --revision <full-commit> --output compute-registry.json`. Repeat `--path` to select additional configured paths or descendants; scope expansion is rejected. Refresh discovers pinned candidates, enforces document/byte limits, imports and merges definitions, and retains fetch receipts in the resulting manifest. Repository-relative JSON-pointer dependencies are fetched automatically inside the configured source scope at the same pinned revision; advanced schema URI/anchor semantics remain unsupported. The daily Graph updater uses this pipeline for stable and beta at one shared revision, stages both catalogs before publication, and retains refresh reports alongside source receipts.

Merging refreshed catalogs retains their refresh reports and other `x-*` metadata under `schemas.x-junction-import-metadata`, keyed by each input manifest's content hash. Nested merges retain the earlier provenance tree.

Refresh dependency downloads count toward `--max-documents` and `--max-bytes`. `--path` narrows API discovery while shared definitions may come from elsewhere within the original configured source scope. Dependency receipts appear in `schemas.x-junction-refresh.dependencies`; dependency files contribute schemas without automatically adding their API operations.

Use `--timeout-seconds` to bound refresh work (default 900 seconds; maximum 3,600). The deadline covers discovery and dependency fetching and prevents publishing a registry completed after expiry. Synchronous parsing may finish before the timeout can be reported.

Generate a Rust/Serde module from selected canonical schema references with `junction --registry registry.json generate-rust --schema '<canonical-reference>' --output types.rs`. References are included automatically. The command reports canonical-reference-to-Rust-name mappings and dynamic JSON fallbacks. Generated modules require `serde` with its derive feature and `serde_json`; `SCHEMAS_JSON` retains constraints for full schema validation. Optional fields preserve omission, required nullable fields remain required, and recursive references use boxed generated types. Daily updates include a starter selection of common Graph types; broader typed API coverage remains in development.

The Rust authentication library supports explicitly initiated device authorization through `DeviceCodeProvider::begin` and `poll`. Sessions bind tenant, audience, scopes, authority and client identity, keep the device credential private, and enforce polling intervals and expiry. The CLI now provides device-code `auth login`, `logout`, `status`, `accounts` and `token-info`, backed by native macOS Keychain storage. Stored credentials are reused by CLI, MCP and HTTP execution. Rust callers can exchange bound refresh credentials and persist rotated access/refresh pairs; device login retains refresh credentials when `offline_access` was requested. Saved device-code credentials renew automatically under a shared transaction lock. Windows/Linux secure storage and live sign-in verification remain pending. See [interactive authentication](docs/AUTHENTICATION.md) for setup and current limits.

Rust callers can use `PkceProvider::begin` to obtain a browser authorization URL and `exchange` to validate a callback and acquire an access token. Sessions enforce S256 PKCE, state, exact redirect matching, expiry and single use. HTTPS redirects or HTTP loopback callbacks are supported. CLI browser login, persistent accounts and OIDC identity verification remain in development.

For confidential web clients, `PkceProvider::with_client_secret` supports `AuthFlow::AuthorizationCode` and authenticates the token exchange with the client secret while retaining S256 PKCE. Public-client and confidential-client sessions cannot be exchanged through each other's provider mode.

Operators approve one destructive or privileged request with
`junction execute <operation> --approve ...`. Junction validates the complete
request first, then shows the operation, risk, method/path, tenant, cloud,
endpoint, audience, credential profile and exact input on the controlling
terminal (`/dev/tty`, or the Windows console), never stdin. The operator must
retype the operation identifier and a fresh random code. Only then is a
single-use five-minute grant issued in-process and consumed by that one request
(including starting a declared long-running operation). Deny rules and read-only
mode still reject; piped or agent-run processes without a terminal receive
`{"status":"approval_failed","reason":"operator_terminal_unavailable"}`. MCP and
HTTP hosts have no approval input. See [approvals](docs/APPROVALS.md).

Trusted Rust callers can use `Executor::prepare_with_approval` to consume an
operator-issued grant and prepare the request against the loaded registry's
referenced schemas without acquiring credentials or sending it. Grant issuance
must stay outside agent tools.

`Executor::issue_approval` resolves the selected registry operation, checks that
current policy requires approval, and validates the full request against registry
schemas before issuing a short-lived grant. `ApprovalOptions` carries API version,
preview opt-in and lifetime (at most five minutes). This API belongs inside a
trusted operator host; it is not exposed through agent tools.
