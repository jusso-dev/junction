# Implementation audit

The original specification remains the completion criterion. This checklist describes current evidence, not a narrowed scope.

Paired Microsoft `x-ms-list-continuation-token` annotations now normalize into
query-continuation metadata. The runtime validates the declared request parameter,
reads nested response pointers, encodes token values, preserves marked POST bodies
and rejects ambiguous link/token responses. Import traversal is bounded for marked
documents and skipped for documents without annotations. The cached Graph catalog
regression imports 17,870 operations. Body-token mutation and header-based paging
remain unfinished; no live token-pagination verification is claimed.
An index propagates marker reachability backwards through local references, so
aliases and cycles are handled without expanding every unrelated response schema.
The mixed cached-Graph regression adds one synthetic marked operation and imports
17,871 operations with exactly one token strategy.

## Implemented foundation

- Rust workspace and single `junction` executable.
- Shared HTTPS transport with redirect rejection, sensitive bearer headers, global request admission, configurable timeout and response size limits, and safe upstream errors. Executor integration and transport integration tests remain pending.
- Runtime request planner with pre-construction policy checks, explicit trusted endpoint, scalar path/query encoding, OData query names, selected API version enforcement and basic body presence checks. Network execution and schema validation remain pending.
- Authentication foundation: zeroizing redacted secrets, explicit token requests, safe metadata, tenant/audience/profile/authority/flow/scope cache isolation, expiry skew and scoped logout. Client-secret client-credentials acquisition is implemented as a Rust library provider with HTTPS-only transport, redirect rejection, timeout, response size/lifetime bounds, and safe errors. Other acquisition flows remain pending.
- Ten typed official-source configuration files, deterministic loading, exact origin validation and `junction sources` inspection.
- Serializable operation metadata, raw schema retention, source provenance.
- Canonical schema type normalization for primitives/formats, nullable types, enums, arrays, maps, objects, unions, intersections, discriminators and references, retaining original metadata. CLI `schema` exposes normalization.
- JSON/YAML OpenAPI 3 / Swagger 2 ingestion with deterministic names and collision rejection.
- Local parameter reference resolution, cycle rejection, parameter overrides, and canonical schema definitions in imported manifests.
- Manifest change reports for added/removed/modified operation versions and schema changes, independent of ordering.
- Compact agent search summaries and product/service/version hierarchy with catalog statistics.
- Registry search and describe with bounded search, natural version ordering, stable-first defaults, explicit deprecated selection, preview/beta opt-in and retired exclusion.
- Local TOML policy parsing with strict fields, tenant restrictions, wildcard denies, three modes and machine-readable decisions.
- Shared rate/concurrency admission primitives with RAII permit release; CLI policy-check for review before execution.

## Still required

- Broader source/product verification, source-specific filtering, pluggable adapters and automatic discovery/update.
- External/local reference resolution, TypeSpec, OData, metadata and documentation adapters.
- Complete canonical schema integration, constraint validation, reference resolution, stable naming overrides, generated Rust types, manifests and OpenAPI export.
- All specified API products, authoritative maturity/retirement metadata, and product-specific supported-version rules.
- Authentication flows, cloud endpoints, secure credential storage, redaction, permission intelligence and isolated tenant contexts.
- Universal executor, serialization, retries, throttling, pagination limits, continuation handling and asynchronous operations.
- Wire policy and request admission into every executor surface; trusted approvals, pagination/item/batch limit enforcement and dependent batches.
- Ergonomic CLI aliases, auth/context/API commands, JSON/YAML/table output.
- MCP transport and six stable tools; local HTTP server and its OpenAPI contract.
- Production security testing, mock-service integration tests, real official-spec ingestion tests, CI, release packaging, operational documentation and licensing.

## Known foundation limitations

- Operation IDs depend on upstream operationId, with no persisted compatibility map yet.
- API version comes from info.version; this is not correct for every Microsoft source.
- Base URLs are retained from specifications; endpoint security and sovereign-cloud resolution must be implemented before execution.
- Schema reference validation and external reference document loading are not implemented. Local parameter references and overrides are implemented.
- Risk inference is preliminary and must not be used as the final execution authorization boundary.

- Policy primitives are implemented but no API request execution exists yet, so runtime enforcement is not complete. Destructive/privileged operations always require approval; trusted approval storage is still required.

- Schema normalization preserves validation constraints in original metadata but does not yet enforce them; canonical schemas are included in imported registry schema definitions; executable validation and reference resolution are still required.

- Shared JSON/YAML document parsing has a 128 MiB input limit and suppresses parser errors containing input text. Further streaming and memory-budget tests remain required for large upstream catalogs.

- Client-credentials HTTP tests verify encoded secret/scope form fields, successful acquisition parsing, redirect rejection, safe HTTP failure messages, and oversized declared response rejection using local mock sockets. Live tenant testing and chunked-limit/timeout cases remain pending.

- Runtime library Executor connects registry resolution, policy checks, tenant/audience/expiry token binding, request planning and bounded transport for one HTTP request. Method-based minimum risk blocks malformed risk downgrades. Context endpoint/audience selection remains trusted caller responsibility; endpoint mapping, schema validation, CLI execution, retries, pagination and LROs remain pending.

- JSON Schema validation enforces constraints and formats with local references, without external network/file resolution, and safe errors. Request planning validates scalar parameters and inline application/json body schemas. OpenAPI nullable/exclusive dialect adaptation and registry-wide reference binding remain pending.

- OpenAPI validation adaptation now translates nullable/x-nullable and boolean exclusive numeric bounds recursively through schema-bearing keywords, while preserving literal annotations. Registry-wide reference binding and other dialect differences remain pending.

- Registry retains original schemas and execution binds parameter/body validation to local Swagger definitions and OpenAPI components. Recursive definitions are validated symbolically rather than inlined. External document references and multi-source/version schema namespacing remain pending.

- Bounded Graph/ARM page accumulator handles value arrays and nextLink/@odata.nextLink, checks continuation origin, detects cycles, enforces policy page/item bounds and preserves buffered records. Executor fetching/resumption and token-based service adapters remain pending.

- Executor execute_pages now retrieves bounded Graph/ARM value/nextLink pages through the governed transport, with policy/schema checks before first fetch and token expiry checks before every page. GET bodies are rejected. Resume support, token-based adapters and mock paginated HTTP integration tests remain pending.

- Read requests now retry HTTP 408/429/500/502/503/504 through the shared governor, with at most four attempts and a ten-second elapsed retry budget. Retry-After accepts numeric seconds or HTTP dates and is retained as typed duration metadata; arbitrary header text and failed response bodies are suppressed. Mutations, redirects, authentication failures, transport failures and admission failures are not retried. Each attempt retains the existing transport timeout; this is not an aggregate execution deadline. Mock retry integration tests and jitter remain pending. All 44 workspace tests and strict Clippy pass.

- Added CLI `execute` using an explicit secret-free context JSON file and AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET environment credentials. Environment credential rejects cross-tenant use before acquisition. Executor preflight enforces policy and schema before token requests. Typed execution denials preserve structured policy_rejected/approval_required across CLI stderr. Subprocess tests verify method risk floors, deny-before-input/credentials ordering and secret-safe errors. Context storage/management, broader credential providers, CLI pagination, successful live end-to-end execution and enriched upstream errors remain pending.

- Centralized MicrosoftCloud and Graph/ARM/Defender endpoint metadata in junction-core, reusing the same cloud enum in source discovery. Public, GCC High, DoD and China Graph/ARM remapping preserves base paths and separates API endpoint from token audience. Storage and Key Vault suffixes are centralized. Custom clouds require validated explicit endpoints; unavailable service/audience metadata and cross-service endpoints fail closed. CLI supports cloud context JSON and named contexts with add/list/show/remove and global --context/--contexts-directory. Context files are bounded, secret-free, create-only and owner-only on Unix. Tests cover cloud isolation, custom mappings, traversal, overwrite prevention, context CRUD without registry, secret-field rejection and named execution policy enforcement. Sovereign operation availability, government Defender audiences, regional/data-plane mapping, further context defaults and live cloud verification remain pending.

- Import now retains parameter style/explode/collectionFormat/allowReserved metadata with defaults compatible with older manifests, resolves local requestBody objects, and normalizes Swagger JSON body parameters. Runtime handles encoded query arrays and flat objects, declared scalar/array headers, schema-bound JSON body references and explicit rejection of unsupported strategies. Delimiters are separate from encoded array values. Expanded query objects cannot replace declared parameters or api-version. Header limits, injection checks and reserved credential/framing names are enforced by transport for every attempt, including retries and pagination. Import-to-preflight tests verify required/ref-resolved Swagger body schemas. Path parameters marked `x-ms-skip-url-encoding` keep scope separators while each segment is encoded and traversal segments are rejected. Cookie/form bodies, complex path/header objects, allowReserved and full serialization coverage remain pending; successful transport-level header tests still require an HTTPS mock harness.

- Added OfficialFetcher and CLI fetch for enabled OpenAPI GitHub sources, enforcing approved owners/configured path scopes, full immutable revision URLs, HTTPS/no redirects, bounded unauthenticated responses and SHA-256 provenance receipts. Latest default-branch revision resolution is supported. Fetch/import files are individually published atomically after successful validation. Local mock tests cover headers, response size/chunk bounds, redirects and safe errors; invalid import preserves prior registry output. Real Graph v1.0 download exposed default YAML node-budget and YAML 1.1 boolean-coercion failures; bounded catalog budgets and strict boolean inference fix both, with regression tests. Full pinned Graph v1.0 imports 17,870 operations (17,785 stable, 85 deprecated) and is discoverable through CLI. Receipt is recorded in docs/verification/graph-v1.0-receipt.json. Generic Graph naming remains incompatible with the requested canonical examples and must be replaced by a dedicated adapter. External schema references, multi-document merging, source tree enumeration, other source adapters/catalogs, generator tooling and scheduled/self-updating compatibility gates remain required.

## Pagination resume

The Rust executor now supports `execute_pages_resuming` with an opaque continuation with explicit private-file save/load APIs. Continuations preserve unconsumed records, the original request URL, visited page URLs, and operation/tenant/audience/input binding. Resume revalidates current policy, input, and credential expiry/isolation before returning buffered data or fetching more pages. Each invocation has explicit item/page limits constrained by policy; buffered-only resumes report zero fetched pages. Relative next links resolve against the current page URL. CLI pagination and persistent continuation storage are implemented in the following section; service-specific token strategies remain incomplete.

Pagination options now deserialize strict JSON with defaults of 100 items and five pages. `preflight_pages` checks registry selection, policy, schema, GET/body restrictions, and policy bounds before credential acquisition. Callers should invoke it before acquiring tokens; execution also enforces these checks.

## CLI pagination and checkpoint files

`execute --all` now invokes the shared bounded pagination executor after pagination preflight and credential acquisition. `--max-items` and `--max-pages` default to 100 and five. An explicit new `--continuation-file` path preserves any overflow records and next link; JSON returns only that path, items, and page count. `--resume` loads trusted operator-owned state and enforces the executor's original request/context/version binding. Checkpoints have a versioned strict format, a 32 MiB cap, same-origin URL validation, create-only writes, and Unix 0600 permissions. Windows relies on the parent directory ACL. Round-trip, unsafe-link, permission, overwrite, and CLI argument tests pass. End-to-end live Microsoft retrieval and other pagination strategies remain unverified/incomplete.

## Ranked hierarchical discovery

Registry search now ranks exact IDs, canonical actions and resource tokens ahead of description-only matches, then orders ties by path depth and canonical ID. Shared `SearchOptions` adds product/service filters and explicit preview opt-in; stable remains preferred. CLI search exposes the same filters. Result counts and query complexity are bounded. Tests cover ranking, filters, preview gating, exact-ID lookup, input-order independence, and invalid/empty queries. A CLI search against the cached full Graph v1.0 catalog confirms `graph.users.list` ranks first for `list users`.

## Agent input schemas

Registry `input_schema` produces a strict JSON Schema envelope for a selected operation; CLI describe adds it alongside retained operation metadata. Required parameters/body and version constraints match the executor envelope. Referenced OpenAPI/Swagger definitions are adapted and included transitively with cycle deduplication and depth/reference limits. Unused catalog definitions are omitted. Tests validate accepted/rejected envelopes, nullable values, recursive bodies, version pinning, and unknown fields. Full cached Graph users-list description was checked through the CLI. This schema describes input shape; runtime policy, endpoint, and supported serialization checks remain authoritative.

Input-schema reference traversal now follows schema positions rather than arbitrary JSON keys, preserving references beneath properties named `default` or other annotation keywords. It validates full nested reference targets and preserves escaped JSON Pointer names. Regression tests cover annotation data, escaped names, missing nested targets, and actual instance validation. Global CLI `--json` selects compact JSON and `--quiet` suppresses successful output; failure diagnostics/status remain intact. Subprocess tests verify placement and behavior.

## YAML and table output

Global `--yaml` uses Rust serde serialization of the same JSON data model, preserving scalar types, nulls, arrays, and nested data. `--table` renders tab-separated rows for object collections, indexed values for scalar collections, and field/value rows for other output. Column ordering is deterministic; JSON cells escape terminal control characters and retain nested values. Format flags are mutually exclusive. Quiet mode still suppresses successful output, and errors remain JSON on stderr. Tests compare normalized YAML with JSON and verify ambiguous strings and table escaping.

## Batch dependency planning

`junction_runtime::batch` now defines strict request/operation models and a bounded `BatchPlan`. Plans validate policy operation/concurrency caps, a one-hour maximum timeout, a 16 MiB request cap, unique safe IDs, known dependencies, self-reference rejection, depth limits, and acyclic dependency waves before work is scheduled. Inputs use `{"$result":"prior-id","pointer":"/body/value/0/id"}` references; these infer dependencies and resolve only from supplied successful results. Replacement data is never recursively interpreted. Tests cover wave ordering, result substitution, recursive-instruction prevention, missing results, cycles, malformed pointers, duplicates, unknown dependencies, and limits. This is the planning layer; concurrent execution, failure handling, CLI batch, and MCP batch remain incomplete.

## Shared batch execution

`Executor::execute_batch` now executes validated dependency waves in one trusted tenant/audience context through the shared executor. Admission is bounded by request concurrency and policy; successful results follow submission order and can feed later inputs. Fail-fast stops new work while already-started calls finish. Continue-on-error skips failed dependencies and continues independent operations. A single batch deadline cancels local waiting and distinguishes started timeouts from unsubmitted skips; timeout cannot establish whether an upstream mutation completed. Accumulated successful result data is capped at 64 MiB. Policy denials remain structured; arbitrary error strings are omitted. Mock-future tests verify peak concurrency, ordering, result references, failure modes, secret-safe errors, and deadline behavior. CLI/MCP batch and live multi-service execution remain pending.

## CLI batch integration

`junction batch --input <json>` now supports named or explicit execution contexts, local policy, environment credentials, shared batch execution, and all output formats. It rejects heterogeneous endpoint/credential configuration before acquiring tokens. `preflight_batch` checks every operation's registry selection and method risk floor, then validates independent input before acquisition; reference-dependent input is validated when resolved. The Rust batch entry point enforces the same preflight. Existing subprocess denial tests now also cover batch POST/DELETE policy outcomes and secret-safe errors with credentials absent. Live Microsoft batch execution and MCP integration remain pending.

## Workload assertion exchange

The authentication library now exposes `ClientCredentialsProvider::with_workload_assertion`, accepting a secret-wrapped externally issued assertion and requiring `AuthFlow::WorkloadIdentity`. The shared transport posts client_assertion and the JWT bearer assertion type, with client_credentials grant and explicit audience default scope. Client-secret fields are excluded from assertion requests. Entra verifies federation trust; Junction does not interpret the assertion as evidence of granted permissions. HTTPS-only transport, redirect rejection, bounded responses, expiry checks, and redaction are shared with client-secret exchange. Unit tests verify form selection and flow mismatch rejection. Environment assertion-file selection, CLI connection, assertion refresh, and live federation verification remain pending. Protocol reference: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow

Workload identity is now wired through environment credentials and CLI execute/batch. Explicit and cloud contexts accept the workload_identity flow. Provider selection is explicit; AZURE_FEDERATED_TOKEN_FILE is reread per acquisition, bounded to 1 MiB, held in zeroizing memory, and checked for regular file/UTF-8/whitespace validity. Tenant and flow binding run before file access or network calls. Tests verify file replacement, bounds, malformed values, context flow acceptance, and tenant isolation. Hosting-platform assertion rotation is external; live federation exchange remains unverified.

## Workload exchange verification

A network-free test now builds the actual reqwest form request and decodes its wire body, verifying assertion/scope encoding, preserved ARM-style double-slash default scopes, the JWT bearer assertion type, and absence of client_secret. A local TCP mock exchange test verifies federated response metadata and redaction and will run in normal CI. TCP listener tests remain excluded locally because this sandbox denies binding; no live federation claim is made.

## Externally supplied bearer credentials

`ExternalBearerProvider` accepts secret-wrapped opaque credentials and trusted broker metadata, enforcing flow, tenant, audience, expiry, and requested-scope binding without decoding unverified JWTs. Environment injection uses explicit JUNCTION_ACCESS_TOKEN/TOKEN_TENANT/TOKEN_AUDIENCE/TOKEN_EXPIRES_AT values and advertises no permissions. Explicit/cloud contexts accept external_bearer, and execute/batch share provider selection after preflight. Tests cover valid acquisition, context/flow/scope mismatches, expired tokens, and Debug redaction. Live API acceptance and JWT signature validation are not claimed.

## Authorization diagnostics

The executor now enriches transport HTTP 401/403 errors with safe operation/audience/bearer metadata, imported OAuth scope requirement alternatives, detected broker/provider scopes and roles, and static remediation. Missing scope metadata stays null. Scope alternatives preserve OpenAPI OR grouping; these do not establish complete delegated/application permissions or RBAC requirements. Error bodies, request URLs, and token values remain excluded. CLI stderr and batch errors retain this typed diagnostic; pagination uses it too. Tests verify alternatives, absent metadata, non-authorization error preservation, and secret omission. Live service-specific diagnostics and complete permission intelligence remain pending.

## Operator risk overrides

The registry and CLI now accept bounded strict TOML risk overrides with exact operation IDs and required review reasons. Corrections apply to all catalog versions and flow through search, describe, policy checks, execution, and batch. Unknown IDs, duplicate corrections, and malformed/excessive input fail. The executor still enforces its independent HTTP method risk floor. Overrides are trusted operator configuration, not an approval channel. Library tests cover all-version application, discovery visibility, and validation failures. Release packaging includes override documentation.


## On-behalf-of acquisition

Added a Rust-library client-secret OBO provider using the Microsoft JWT bearer grant, incoming assertion, and requested_token_use=on_behalf_of. It requires a caller-validated incoming user token and trusted middle-tier audience; validates tenant/expiry, exact flow, and audience-qualified scopes before sending; and shares bounded, redacted HTTPS response handling with client credentials. No refresh tokens or requested-scope-derived grants are retained. OBO tokens cannot enter the application cache until a user/assertion dimension exists. Protocol/form, context rejection, and cache isolation tests pass. CLI/environment wiring, certificate OBO, user-bound persistence, and live verification remain pending.


## OBO environment and CLI connection

Explicit and sovereign-cloud contexts now accept on_behalf_of. Environment selection reads separate incoming assertion, verified tenant/audience/expiry attestations, and confidential application credentials, with no fallback to client credentials or external bearer. Incoming tenant must match both environment and execution context; OBO provider validates expiry and downstream scopes before HTTP. Execution, pagination, and batch use the existing credential acquisition path, preserving policy preflight before credentials. Added secret-free cloud context example and environment-provider/context parser tests. Live tenant exchange, certificate OBO, and user-bound cache/persistence remain pending.


## Safe auth token-info command

Added auth token-info with named or explicit context selection, no operation registry dependency, centralized cloud authority/audience resolution, and existing environment acquisition. Output serializes only TokenMetadata, never the AccessToken. Injected-token integration tests verify safe output, missing registry independence, context storage, quiet output, cross-tenant rejection, and conflicting context selection. CLI tests and strict Clippy pass. Network acquisition remains subject to previously documented live verification gaps; login/logout/status/accounts and OS storage remain pending.


## Transport correlation IDs

API HTTP attempts generate OS-random UUID v4 client request IDs, attaching both Graph and Azure header spellings with transport ownership. Responses retain generated ID and only UUID-shaped request-id/x-ms-request-id fields. Single-call/batch success envelopes and typed authorization errors expose correlation without arbitrary header/body/URL data. Each retry/page has its own physical-attempt ID. Tests verify UUID format/uniqueness, unsafe upstream header omission, input override rejection, and authorization diagnostic preservation. Live Microsoft header roundtrip and per-page aggregate diagnostics remain pending.


## Azure LRO ingestion and transport links

Canonical operations now preserve optional LRO metadata with typed final-state hint and local final-result schema reference from official x-ms extensions. Missing hints remain unspecified rather than inventing behavior; unknown hint values and malformed markers/options fail safely. HTTP success responses capture opaque Azure-AsyncOperation/Operation-Location/Location links with relative resolution, same-origin HTTPS and user-info/fragment checks, and bounded header length. No automatic follow or output serialization occurs. Tests cover all declared strategies, marker/options errors, compatibility with absent metadata, relative links, and cross-origin/credential link rejection. Runtime polling/state management, CLI operations, cancellation, and live Azure verification remain pending.


## Azure async state normalization

Added runtime lro state classification for Azure-AsyncOperation, Operation-Location, Location, and resource provisioningState responses. Explicit succeeded/failed/canceled states are terminal; provider-specific values stay running. Status endpoints fail on missing/malformed state instead of falsely claiming success. Location/resource fallback handles 202 pending and successful completion. LroTracker bounds observations (including malformed observations), makes terminal states absorbing, and stores no response bodies or error messages. Unit tests cover provider states, malformed response preservation, request limits, and safe progress serialization. Network polling/handles/wait/cancel remain pending.


## Executor LRO start and poll

Connected declared LRO start and single-step polling to the shared executor/transport. Opaque handles retain polling URL and exact tenant/audience/endpoint/version bindings without Debug/Serialize; safe snapshots expose generated correlation operation ID, canonical operation, state, and poll count. Polling rechecks original operation policy and current credentials, observes Retry-After readiness, counts logical poll attempts even on failures, and avoids replaying mutations. Header priority and PUT/PATCH original-resource fallback are implemented. Guard tests prove cross-context rejection, policy rechecks, early poll rejection, terminal short-circuit, bounds, and URL/body omission. Final-state result fetches, wait deadline, persistence, cancellation, CLI, and live network verification remain pending.


## Deadline-bound LRO wait and execute --wait

Added Executor::wait_lro with a 1–3600-second deadline covering sleeps, HTTP polls, and retries. Local timeout produces a structured safe error carrying last known state and does not mark remote cancellation; the library handle remains usable. CLI execute/hierarchical --wait accepts bounded --max-polls/--timeout-seconds, rejects pagination conflicts and invalid/unsupported LRO requests before credentials, and preserves policy preflight. Tests cover Retry-After exceeding deadline without a poll, terminal completion without network, timeout redaction/state preservation, parser constraints, and policy denial before missing credentials. Final-state resource fetch, durable CLI handles, operations get/wait/cancel, and live polling remain pending.


## Private LRO checkpoint persistence

Added create-new private LroHandle save/load APIs, strict bounded versioned JSON storage, selected context/version/state/poll-limit preservation, and wall-clock conversion of retry readiness. URLs remain absent from safe snapshots but are retained in operator-owned mode-0600 Unix files; load rejects permissive files, malformed metadata, excess sizes/counts, credentials/fragments in URLs, and cross-origin poll targets. Files contain no token/input/error bodies. Tests verify roundtrip, overwrite refusal, poll-count preservation, cross-context rejection, origin tampering, and Unix permission enforcement. Windows relies on parent ACLs. Checkpoints remain trusted mutable operator state, not authenticated authorization objects; durable CLI storage, concurrent update handling, operations commands, final resource payloads, and live verification remain pending.


## Durable CLI operations

Declared LRO execution now starts through the LRO executor by default, saves a private checkpoint before optional waiting, and emits an operation snapshot. Added global operations-directory selection, operations get without registry/credentials, and operations wait with original version/preview selection, context binding, policy checks before credentials, deadline limits, and unchanged remaining poll budget. Exclusive create-new locks prevent competing waiters; updated checkpoints replace atomically on success, timeout, or polling error. Existing locks are never stolen, and failed loads release only locks created by the current process. Integration coverage verifies terminal resume without network, deadline preservation, private permissions, safe output, policy/context rejection, ID binding/traversal checks, contention, and lock cleanup. Abrupt termination can leave a lock and lose progress since the last saved checkpoint. Final resource retrieval, cancellation, live Azure polling, and other full-specification work remain pending.


## Checkpointed polling reservations

Added checkpoint callbacks to library wait/poll APIs while retaining the existing in-memory interfaces. The executor reserves and persists each logical poll before transport, then persists observed progress and retry readiness after each response, including malformed status observations. CLI initial waiting and operations wait use these callbacks under their exclusive handle lock and still save on return/error. A checkpoint failure before transport aborts the poll; interruption during transport leaves its logical attempt consumed on disk. Runtime tests verify the persisted reservation and that callback failure prevents transport, while CLI resume/timeout/lock tests continue to pass. A response received immediately before process termination may leave saved state stale, and an interrupted process may leave its lock. Live Azure roundtrips remain unverified.

## Context subscription and resource-group defaults

Explicit/cloud execution contexts retain and validate optional subscription/default_resource_group fields. Execute and hierarchical invocation support --subscription/--resource-group, resolving only matching declared path parameters with conflict rejection. Missing batch and execution parameters inherit context defaults without overriding explicit input or result references. Batch plans are rebuilt after default application before executor preflight. Tests verify context roundtrip, sovereign ARM URL construction, input precedence, unsupported-operation rejection, unsafe values, parser flags, and schema enforcement on inherited values. Added a secret-free ARM context example. Live ARM discovery/execution remains pending.


## Native MCP protocol core

Added junction-mcp with a JSON-RPC session lifecycle for protocol 2025-11-25, initialization negotiation, initialized-notification gating, ping, tools/list, and tools/call. Exactly six stable tool definitions expose search/describe/execute/batch/permissions/context rather than per-endpoint tools. Input schemas validate before host dispatch and exclude host credentials/policy; execution and batch annotations conservatively permit destructive behavior. Host callbacks return explicitly structured success/error results with matching text and structuredContent. Bounded 16-MiB newline framing limits input allocation and prevents partial oversized output writes. Tests cover handshake ordering, protocol negotiation, duplicate initialization, exact surface, argument/unknown-tool rejection without value echoes, structured policy errors, invalid request IDs, and frame limits. CLI stdio serving, registry/executor/context host adapters, concurrent request cancellation, and client interoperability are not yet connected or verified.

Protocol references: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports, https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle, https://modelcontextprotocol.io/specification/2025-11-25/server/tools.


## MCP stdio host integration

Added junction mcp serve with startup-only policy mode/file and optional named/file execution context. Native Rust stdio reads bounded frames, drives the MCP lifecycle, dispatches all six tools, and emits only protocol responses on stdout. Search/describe/permissions share registry selection/input schemas; context list/show validates secret-free context files. Execute and batch use the shared executor, persistent governor, environment credentials, scope defaults, fail-closed preflight, risk overrides, structured safe diagnostics, and private LRO handles/waiting. No agent-supplied policy/context/endpoint/credentials are accepted. Added a read-only registry accessor to Executor to avoid duplicating a large catalog in the MCP host. Process-level stdio tests verify initialization, tool listing, search/schema/permission/context results, write/delete rejection before missing credentials, batch preflight, argument injection rejection, parse-error recovery, and stdout purity. Sequential top-level requests, active-call cancellation, pagination controls, streamable HTTP, live Microsoft calls, and external-client interoperability remain pending.


## Bounded MCP pagination

Connected junction_execute all/max_items/max_pages/continuation options to the existing Graph/ARM executor. Pagination preflight enforces GET/body, policy, input/schema and bound checks before credentials; LRO/wait conflicts and controls without all are rejected. Private session-local continuation files are indexed by 256-bit random opaque IDs, with no agent-controlled paths, a 64-handle cap, and the runtime's checkpoint size/binding limits. Successful resumes rotate or consume handles; failed calls leave the previous checkpoint available, and host exit cleans up temporary storage. Tests verify buffering, failed-resume preservation, rotation/reuse rejection, traversal rejection, capacity, Unix privacy, and tool-schema bounds/URL-token rejection. Live MCP paginated transport and external-client interoperability remain unverified.


## MCP response-size recovery

Added a bounded serialization buffer for frame output and a host response writer that replaces oversized results with a correlated, payload-free response_too_large JSON-RPC error. It reserves space for the newline delimiter, caps string request IDs at 256 bytes, and keeps subsequent requests usable. Output I/O failures do not attempt another frame after partial writes. Protocol tests verify payload omission/correlation and subsequent framing; process-level tests use an oversized registry description then ping to prove the actual stdio host survives. Executed requests are not undone by response rejection; pagination recovery after an oversized result and broader cancellation/concurrency support remain pending.


## MCP pagination response-size recovery

Pagination now validates the full MCP tool-result representation before committing continuation changes. The check includes both text/structuredContent and reserved JSON-RPC envelope/request-ID space. Oversized results yield a safe typed response_too_large tool error and preserve an existing checkpoint/token; initial oversized reads do not allocate inaccessible handles. A smaller retry can consume the same saved buffered records and then rotate/finish normally. Tests prove oversized delivery leaves the previous handle usable, smaller delivery succeeds and consumes it, and no stale active handle remains. Output I/O failure after continuation commit still lacks delivery acknowledgment; live paginated MCP calls and cancellation/concurrency remain pending.


## Responsive MCP control messages and local cancellation

Separated synchronous protocol routing from host execution and added a bounded message driver with one active call. A dedicated stdio reader feeds a capacity-one channel; the driver polls active work alongside incoming control messages. Ping and protocol responses remain available while a tool awaits I/O; additional tool calls receive bounded busy errors. Matching notifications/cancelled drops the local future without a canceled-request response; unknown/mismatched/malformed notifications are ignored and reasons are not echoed. Existing continuation checkpoints and per-poll durable LRO reservations survive dropped futures, while remote mutations are not rolled back. Tests prove pending work is dropped, ping remains responsive, mismatched IDs do not cancel, capacity is released, subsequent calls succeed, and existing stdio integration/size-recovery behavior passes. Remote cancellation, external-client/live-service behavior, and parallel top-level tool calls remain pending.

## Local HTTP OpenAPI contract

Added junction-server with a deterministic OpenAPI 3.1.1 description of the requested local routes plus contract retrieval, localhost default, bounded query/body schemas, safe structured errors, and shared MCP execution/batch input definitions. Added junction openapi for JSON/YAML/table/file export without registry or credentials. File export uses the existing atomic output writer; release packaging generates a contract from the packaged binary to keep versions aligned. Tests verify required routes/path parameters, unique operation IDs, local reference closure, canonical ingestion/registry acceptance, input bounds and configuration injection rejection, and registry-free CLI stdout/file output. Successful dynamic result schemas remain broad. This is a contract only; HTTP listening/routing, connection authentication, external bind controls, live networking, and external validator interoperability remain pending.


## Local HTTP request routing

Added transport-independent routing for all documented local API paths. Query and body values validate against the generated contract, with explicit boolean/integer conversion, required-query enforcement, duplicate/unknown-field rejection, strict percent/UTF-8 decoding, canonical operation path-ID checks, an 8-KiB target limit, and a 16-MiB body limit. Execute obtains its canonical operation from the path and rejects body-level operation/policy/token/endpoint overrides. Routes produce shared tool invocations or health/OpenAPI/bounded-list actions without Debug/Serialize on sensitive inputs. Safe errors carry HTTP status and fixed reasons, never raw request values. Tests cover every route, selection/pagination options, encoded identifiers, configuration injection, malformed URLs, duplicates, method/route errors, and body-size rejection. HTTP listening, host adapter dispatch, request authentication, and live endpoint verification remain pending.

## Local HTTP dispatch and bounded catalog listing

Added a transport-neutral async dispatcher with a shared host-tool callback. Health, contract export, and operation listing avoid credential acquisition; tool routes forward validated arguments to the host's existing policy/context/execution machinery. Typed policy, authorization, size, and wait-timeout failures map to HTTP status codes. Registry listing selects one supported version per canonical ID in deterministic order, applies product/service/preview filters before offsets, and collects at most 101 references. Responses include at most 100 compact operation records with descriptions limited to 1024 characters and a next offset. Tests cover stable preference, preview-only gating, retired exclusion, filtered pagination, extreme offsets, closed bounds, callback forwarding, and rejection before callback invocation. Listener wiring, connection authentication, response transport bounds, and live networking remain pending.

## Authenticated local HTTP serving

Added `junction serve` using a Rust HTTP listener and the shared executor host. Default binding is 127.0.0.1:8080; external addresses require explicit opt-in. Every request authenticates with a separately configured, zeroizing server token before reading its body or invoking the host. Browser origins and duplicate authorization headers are rejected. POST requires JSON. Incoming and serialized outgoing bodies are bounded at 16 MiB; stalled body reads time out after 10 seconds, and a 16-request admission limit bounds body/dispatch work. Oversized responses are replaced before transport output and indicate that execution may already have completed. HTTP tool calls serialize with immediate 429 rejection while health/contract/listing remain responsive; batch retains internal executor concurrency. Context, policy and endpoint configuration remain operator-owned. Ctrl-C initiates graceful shutdown. Fixed typed CLI startup errors exclude credential values and paths. The generated contract declares server bearer authentication.

In-memory transport tests cover authentication, origins, duplicate headers, content types, body bounds/timeouts, safe response overflow and headers. Shared-host tests exercise real registry metadata and write/destructive batch/execution preflight before credentials, plus busy admission and recovery. A real-socket CLI test covers every documented route, missing server authentication, policy rejection and continued service availability; local sandbox validation excludes it because listener binding is denied, while CI runs it. Live Microsoft-service HTTP execution, TLS termination, browser clients, client-disconnect cancellation and production load verification remain unverified or pending.

## Native OData CSDL ingestion

Added bounded Rust XML ingestion for OData 4.x EDMX, reusing canonical OpenAPI ingestion and registry validation. It preserves aliases, structural/navigation schemas, recursive references, inheritance, enums, type definitions and CSDL facets/nullability. Collection reads, singleton reads and unbound action imports become canonical operations. Inline and externally targeted read restrictions suppress explicitly unreadable resources. Primitive/collection action responses use JSON value envelopes; actions without results declare 204. Added the official Graph CSDL source, format-specific fetch scope/extension guards, bounded XML envelope validation before fetch output, and CLI import with explicit endpoint/API version and bounded file reads. Tests exercise routes, schema validation, preview gates, source scope, CLI import/describe, malformed XML, DTD/custom entities, nesting limits and unsafe endpoints. Live Graph CSDL download did not complete; no live import or daily CSDL coverage is claimed. Bound/navigation routes, container inheritance, complete facets/capability interpretation and authoritative permission vocabularies remain pending.

## OData function imports and literal serialization

Added unbound function imports with deterministic parameter-name signatures, Graph root-function naming and canonical names for other products. Declared function parameters become typed query aliases, required unless annotated with `Core.OptionalParameter`. The runtime supports OData literal serialization for strings, booleans, numeric types, GUID/date/time values, binary values, durations, enums, and structured JSON aliases. Strings and prefixed literals escape embedded apostrophes before URI encoding, and structured values remain one encoded alias value. Underlying type aliases are resolved with cycle bounds. Function responses share action representation handling. Identical parameter-name overloads are rejected rather than silently choosing one. Tests run CSDL ingestion through registry schema closure and real request planning, checking encoded URL/query values, inherited/recursive types, injection-shaped values, numeric rejection, zero-argument functions, Graph/generic-product overload names, duplicate signatures and unsupported literal metadata. Optional parameters preserve omission: function signatures omit their alias clauses, action bodies omit their properties, and service defaults remain metadata rather than locally injected values. Explicit null still follows declared nullability. Mandatory parameters after optional parameters and duplicate optional annotations are rejected. An end-to-end request-planning test covers omission, explicit zero/null, service-default metadata and policy checks. Spatial literals, bound-function routes and complete overload resolution remain pending.


### OData entity key reads

CSDL entity sets now expose canonical `get` operations alongside collection `list`. Keys resolve through bounded entity inheritance, require unique non-nullable structural properties, and preserve scalar schemas/facets and underlying literal types. Single-key routes use the unnamed canonical predicate; composite keys retain declaration order and named predicates. Both use required query aliases and the shared runtime literal encoder, leaving caller values out of path expressions. Graph and generic product names remain deterministic. Inline and external `ReadByKeyRestrictions.Readable` override collection readability for key reads, including key-only readable collections. Discovery tests cover inherited/composite keys, GUID schemas, naming, missing/duplicate/nullable keys, inheritance cycles and all readability combinations. Runtime planning tests validate omission/null/type/length failures and encode an injection-shaped string key as one query value. Complex-property/alternate keys, remaining key capabilities, navigation routes, bound operations and live service verification remain pending.


### OData navigation reads

Added one-hop GET operations for declared navigation properties on singletons and keyed entity sets. Bounded entity inheritance resolution is shared with key discovery. Target types must be locally declared entities, inherited navigation names must be unique, and inline unreadable navigation is omitted. Collection navigation returns the OData value/nextLink envelope and accepts collection query options; single-valued navigation returns its entity schema and declares 204 when nullable. Required typed aliases from the parent key remain required for navigation requests. Canonical Graph and generic product names include the parent resource and navigation property. Discovery tests cover singleton/keyed/inherited routes, cardinality, nullability, readability and invalid targets/duplicate inherited names. Runtime request planning checks encoded key literals, required keys and collection limits. Recursive/deeper routes, navigation bindings/restrictions, external target resolution and live execution remain pending. Container inheritance still requires referenced-document resolution and has not been implemented.


### Externally targeted CSDL navigation restrictions

Navigation route generation now applies unqualified externally targeted read restrictions to the property on its declaring entity type, including inherited declarations. Alias and namespace-qualified target spellings resolve identically. Qualified annotation groups and qualified capability annotations do not override the unqualified capability. Entity inheritance retains qualified declaring names to avoid matching restrictions against the resource's derived type. Tests cover both target spellings, inherited restrictions, unaffected sibling/entity routes, group/term qualifiers and safe malformed-expression errors. This covers separate annotation targeting within an imported document; external document fetching and the broader NavigationRestrictions vocabulary remain pending.


### CSDL query capability flags

Read input schemas now derive query options from explicit `SelectSupport.Supported`, `ExpandRestrictions.Expandable`, `FilterRestrictions.Filterable`, `SortRestrictions.Sortable`, `TopSupported` and `SkipSupported` annotations. Inline and externally targeted annotations resolve vocabulary aliases and ignore qualifiers. `RequiresFilter` adds a required nonempty filter; inconsistent non-filterable/required-filter metadata is rejected. Boolean literals use strict bounded XML expression parsing with safe errors for malformed/ambiguous values. Singleton and key reads expose only entity query options, while navigation reads consult their own property annotations and retain parent key aliases. Tests cover removed options in closed schemas, inline/external annotations, required filters, navigation flags, malformed/duplicate/contradictory declarations and runtime planning before transport. Container default/override semantics, nested expression constraints and complete vocabulary interpretation remain pending.


### OData count and search collection queries

Added typed `$count` (boolean) and `$search` (string) query parameters to collection and collection-navigation reads. Capability gates use unqualified inline/external `CountRestrictions.Countable` and `SearchRestrictions.Searchable` records, including aliases and literal defaults. Entity/singleton reads omit these collection options. Collection response schemas retain optional nonnegative numeric or string `@odata.count` metadata. Tests cover enabled/disabled options, collection navigation, non-collection exclusion, JSON type rejection, count response representations and URI encoding of injection-shaped search values. Full search-expression capability interpretation, standalone count routes and live-service validation remain pending.


### Official source file enumeration

Added Rust `OfficialFetcher::discover` and `junction discover <source>` with optional immutable revision and atomic JSON inventory output. Repository identity validation is shared with fetch, preserving enabled/adapter/approved-owner guards. Discovery resolves the default branch once, reads a bounded recursive Git tree, requires an explicit untruncated result, filters configured path boundaries and format extensions, excludes symlinks/submodules, validates blob identifiers/sizes/paths, sorts candidates and constructs commit-pinned raw URLs instead of trusting upstream URL fields. Tests cover deterministic scopes, prefix confusion, formats, links, malformed paths/identifiers/sizes, duplicate files, safe errors and missing/truncated completeness. Inventories identify candidate files; their contents must still pass fetch/import validation. Large-tree subtree traversal, bulk import, full product catalog refresh and hosted/live enumeration remain pending.


### Bounded large-repository subtree enumeration

Truncated recursive Git tree responses now trigger breadth-first traversal of immutable subtree identifiers. Only branches that intersect configured scopes are followed; upstream URL fields are ignored. Nonrecursive responses must match requested tree identifiers, declare completeness and contain valid single-segment paths/entry kinds. Ancestor SHA tracking rejects cycles while allowing the same tree object under separate valid paths. Traversal bounds are 1,024 subtree requests, 128 MiB of aggregate response bytes, 200,000 entries, 1,024 queued branches, 4,096 path bytes, 64 levels and a five-minute elapsed-time check before/after individual requests (each request retains its 60-second transport timeout). Pending responses and unfinished queues cannot produce inventories. Tests cover scope intersections and prefix confusion, shared trees, completed output, truncation, identifier mismatch, cycles, unsafe paths, active-response state and request/byte limits. This supersedes the earlier missing subtree-traversal limitation. Live large-repository traversal, rate-limit recovery, bulk importing and expanded daily catalogs remain pending.


### Multi-document registry merging

Added discovery-library `merge` and CLI `junction merge` for up to 256 imported manifests. Documents sort/deduplicate by full SHA-256 content identifiers; local schema/component/Swagger definition references receive per-document namespaces. Canonical schema metadata is regenerated from rewritten raw schemas. Canonical operation IDs, API versions and source metadata remain attached to operations, while duplicate operation/version pairs fail. References in parameters, bodies, default/named responses and discriminator mappings are rewritten without rewriting literal defaults/examples. CLI input bounds are 128 MiB per file and 512 MiB aggregate; merged operations are bounded at one million. Output uses atomic writes after registry validation. Tests cover order independence, version-specific same-name schema isolation, properties named example, default-response references, escaped Swagger definition names, deduplication/conflicts and CLI preservation of previous output on conflicts/malformed inputs. External references and advanced schema URI/anchor semantics remain pending, as do automatic bulk retrieval/import and daily multi-product integration.

Bulk source refresh now connects pinned source discovery, bounded sequential fetching,
OpenAPI/OData ingestion and registry merging through `junction refresh <source>
--output <manifest>`. The resulting manifest includes an `x-junction-refresh`
report with the inventory, individual fetch receipts, imported document count and
byte count. Non-specification OpenAPI candidates are recorded and skipped; invalid
specifications, receipt mismatches and version conflicts abort publication. CLI
output uses the existing atomic writer. Defaults allow 256 documents and 512 MiB;
`--max-documents` permits up to 4,096. OData requires `--endpoint` and
`--api-version`, validated before discovery. Unit tests cover merging, receipts,
limits, incomplete imports and conflicts. Full Azure repository refresh still
requires external-reference resolution and deliberate source scoping; the daily
release workflow currently refreshes Graph rather than every configured source.

Scoped refresh and daily integration now support repeated `--path` arguments within
the configured source scope. The daily updater resolves Graph's commit once, refreshes
stable and beta at that revision, and stages registries/statistics/refresh reports
before copying the completed catalogs. A network-free orchestration test exercises
shared revision binding, retained receipts, failed-beta preservation and staging
cleanup; CI and daily source checks run it. CLI tests cover rejection of scope
expansion, traversal, invalid limits/services and unsafe OData roots before network
work. Hosted execution remains unverified pending repository publication.

Merged registries now retain root `x-*` metadata, including refresh inventories
and fetch receipts, plus component-level extensions. These remain literal values
under `schemas.x-junction-import-metadata`, keyed by the input manifest's SHA-256
namespace. A subsequent merge retains the earlier metadata tree, so provenance
survives composition of independently refreshed catalogs. Tests cover merge order,
repeated-input deduplication, literal reference preservation, nested merges and
registry loading. Retention preserves supplied metadata; it does not authenticate
receipts from manually supplied manifests.

External-reference groundwork now includes a native discovery-library
`bundle::bundle(entry, documents)` for explicitly supplied repository-relative
OpenAPI documents. It resolves relative paths and JSON pointers, namespaces
external schemas/reference objects by target hash, and preserves recursive types
symbolically. Unsupported URI/anchor semantics, missing documents, malformed
fragments, remote URLs and repository-root escapes fail with fixed errors. Literal
examples/defaults/extensions are not followed. Limits bound documents, bytes,
reference targets and traversal. Tests ingest a bundled Swagger API with external
parameters, escaped schema names, transitive references and recursive objects,
then validate typed inputs through the actual registry. The bundler performs no
filesystem/network access; connecting dependency discovery and fetching to refresh
is still required before claiming live Azure external-reference support.

Refresh now retains parsed OpenAPI candidates and bundles each API entry against
all fetched documents before ingestion. Shared definition files need no OpenAPI
header to serve as dependencies; their receipts remain in the refresh report.
Missing references reject the completed refresh instead of leaving unresolved
schema metadata. A test exercises external request-body schemas through refresh,
merge, registry loading and typed input validation, and verifies missing-dependency
failure. This covers dependencies already present in the pinned inventory;
on-inventory dependency discovery/fetching remains pending.

The bundler was additionally run against the cached 44,334,960-byte official Graph
v1.0 OpenAPI document at revision `7b2914c8ad1340129f52aa785f13c074cb46fd7c`;
all 11,546 paths bundled successfully. This verifies the bundling stage against
the existing real catalog, not a new network download or a hosted daily run.

Pinned dependency fetching is now connected to refresh. `refresh_scoped` narrows
API inventory discovery but uses the original configured source scope to fetch
missing repository-relative documents. Dependency discovery follows transitive
references through supplied documents, preserves recursive types and ignores
literal defaults/examples/extensions. Every extra download uses the inventory's
immutable revision and existing unauthenticated official transport; remote URLs,
repository escapes and paths outside the configured source are rejected.
Dependencies count against the same document/byte limits and appear separately
in the refresh report, without importing their API operations automatically.
Tests cover missing/transitive document discovery, fragment errors, pinned receipt
validation, scope rejection, duplicates and document limits. Live Azure refresh
and complete external URI/anchor semantics remain unverified or incomplete.

A live scoped Azure Resource Manager refresh was attempted for
`specification/resources/resource-manager/Microsoft.Resources/stable/2021-04-01/resources.json`.
It failed at the source-download stage; no registry was published, and live Azure
verification remains incomplete. Refresh now accepts `--timeout-seconds` (default
900, valid range 1–3,600) alongside its document/byte limits. The deadline cancels
pending asynchronous work and rejects late completion of synchronous bundling or
import before output publication. Unit tests cover pending-work timeout, successful
completion, late completion and invalid settings; CLI preflight tests cover invalid
deadlines without replacing existing output. Synchronous parsing is not preempted
mid-call, so actual return time can exceed the deadline while publication is still
rejected.

The new `junction-generator` crate emits deterministic standalone Rust/Serde
modules from selected canonical schemas. `junction generate-rust --schema
<canonical-reference> --output types.rs` selects schemas and recursively includes
local reference dependencies. Generated identifiers are hashes of canonical
references, reported by the CLI; JSON field names use Serde renames and indexed
Rust fields to avoid keyword/name collisions. References use boxed generated
newtypes, supporting recursive objects. Objects, typed additional-property maps,
arrays, primitives, string enums and nullable values are represented directly.
Required nullable fields stay required, optional nullable fields distinguish absent
from explicit null, and closed objects reject unknown fields. Complex composition,
numeric enums and unrestricted shapes remain dynamic JSON, explicitly reported.
`SCHEMAS_JSON` retains original constraints for complete Junction validation;
Serde alone does not enforce every numeric bound, format or composition rule.
Tests compile and execute the generated module in an isolated offline Cargo crate,
check recursion/presence/nullability/enums/unknown fields, and verify deterministic
output, safe literals and reference closure. A CLI test checks atomic output and
preservation after an invalid selection. Daily type generation and curated common
API type selections remain pending.

Daily catalog preparation now generates a starter selection of stable Graph
emailAddress, recipient, phone and dateTimeTimeZone schemas plus their references.
The selection file is maintained under generators/graph, and canonical names must
resolve uniquely after document namespace merging. Generated source and the
reference-name/dynamic-fallback report are staged with catalogs before publication;
generation failure preserves previous catalogs and types. Native release packaging
already includes the generated directory, so these files enter the versioned
archives. The orchestration test covers successful generation and failed-generation
preservation. Actual CLI generation against the cached official Graph registry
produced five schema types, and the emitted module compiled in an isolated offline
Cargo crate. Hosted publication and broader curated typed API coverage remain
unverified or incomplete.

The current native release binary was rebuilt offline and packaged as
`dist/junction-v0.1.0-aarch64-apple-darwin.tar.gz` with a SHA-256 sidecar. The previous
package was preserved separately. The fresh archive is 12,782,934 bytes. Checksum
verification passed; an extracted copy reports Junction 0.1.0 and loads 17,870
cached stable/deprecated Graph operations across 77 services. Verification also
checked five generated common schema types, byte-identical generated Rust source,
the type mapping report, matching OpenAPI contract version, VERSION and TARGET.
This is a local macOS ARM64 artifact using the existing cached Graph catalog;
Linux/Windows builds and GitHub publication remain unverified.

The authentication library now provides `DeviceCodeProvider::begin` and `poll` for
explicitly initiated device authorization. A session fixes concrete tenant,
authority, audience, scopes and client identity. The device credential uses the
redacted zeroizing Secret type; only the user-facing verification URI/code prompt
is serializable. HTTPS-only transport rejects redirects and bounds each response
to 1 MiB. Monotonic expiry and next-poll reservations prevent early network polls;
pending/slow-down responses preserve or increase the interval, transport errors
back off, and terminal responses stop the session. Successful access tokens reuse
the existing safe decoder and request-bound metadata; refresh/ID tokens are not
persisted or exposed. Tests cover pending/slow-down/success/terminal transitions,
expiry, client binding, scope isolation, malformed prompts and redaction. Library
integration is implemented; CLI login/account management, secure persistent token
storage, refresh-token handling and real Entra authorization remain pending.
Protocol sources: Microsoft's device-code documentation and RFC 8628.

Device-code polling now backs off on response-read failures as well as request
failures. Retry advice is capped by session expiry and rounded up only for partial
seconds, avoiding waits past the remaining session lifetime. The no-network tests
check backoff and expiry-capped waits. Two additional socket transport tests assert
form encoding of reserved credential characters, the concrete tenant token path,
absence of an Authorization header and rejection of redirect/private error data.
These socket tests compile under the workspace checks but are excluded locally;
the existing unfiltered CI command will run them in the hosted environment.

The authentication library now includes `PkceProvider` for public-client OAuth
code exchange. Each session generates independent 256-bit verifier/state values,
uses an S256 challenge, fixes concrete tenant/audience/scopes/client/redirect, and
expires after 15 minutes. Callback parsing checks exact redirect identity, state,
duplicate parameters, percent encoding and query-only response mode. Valid codes
consume the session before exchange; rejected or replayed sessions cannot mint
another token. Verifiers and accepted codes use redacted zeroizing secrets;
authorization URLs are exposed explicitly for browser navigation. Token transport
uses HTTPS, disables redirects, bounds responses to 1 MiB and reuses the safe
access-token decoder. Tests cover the standard S256 vector, random uniqueness,
callback confusion/replay, expiry, audience/tenant validation and error redaction.
CLI browser/listener orchestration, confidential-client code flow, persistent
accounts, refresh-token exchange and OIDC ID-token/nonce verification remain
pending. Protocol references: Microsoft authorization-code documentation and
RFC 7636; no live Entra login was performed.

Code exchange now supports confidential clients through
`PkceProvider::with_client_secret` using `AuthFlow::AuthorizationCode`. Public
clients retain `AuthFlow::Pkce`; both use S256. Confidential secrets enter only the
token exchange form, never the browser authorization URL. Sessions bind the
public/confidential mode in addition to client and redirect; mismatched providers
fail before callback consumption or network work. Tests cover mode isolation,
secret encoding/placement and PKCE retention. Redirect validation continues to
allow HTTPS and explicit HTTP loopback callbacks, including development web-app
callbacks. Certificate-based client authentication, CLI login, persistent accounts,
refresh exchange and live Entra verification remain pending. Microsoft's
client-secret authorization-code documentation was checked for the request fields.

Device-code CLI login now uses the native macOS Keychain adapter in
`junction-auth::storage`. Stored access credentials bind every normalized token
cache dimension, reject mismatched records and unsupported lifetimes, and keep
serialized buffers and token strings zeroizing. Unsupported platforms return
an error without a plaintext persistence fallback. The CLI adds login, logout,
status and accounts; token-info, execution, batch, LRO waiting, MCP and HTTP
hosting share credential acquisition that reads stored interactive tokens without
initiating login. Explicit login has bounded polling and Ctrl-C cancellation.
Storage isolation/corruption tests use an in-memory backend rather than modifying
the operator's Keychain. Auth CLI tests verify no-registry status/account listing,
safe metadata, timeout argument bounds and rejecting incompatible login contexts.
Refresh-token exchange, Windows/Linux native storage, browser login, profile-wide
logout and live Entra/Keychain round-trip validation remain pending. See
`docs/AUTHENTICATION.md` for the current behavior and setup instructions.

Interactive sessions now retain separately redacted refresh credentials when
`offline_access` was requested. The HTTPS-only, nonredirecting refresh provider
binds the original client application and complete acquisition context. Public
and confidential clients require matching provider modes. It returns a rotated
access/refresh pair, retaining the prior refresh credential if no replacement
is returned. Keychain records can persist the pair together and load renewal
credentials after access expiry; existing access-only records remain readable.
CLI device login saves returned refresh credentials. Tests cover grant encoding,
client/mode isolation, rotation, secret redaction, expiry, tenant isolation and
paired logout. Automatic CLI renewal still requires coordination with concurrent
refresh/logout, and live Entra refresh verification remains pending. Protocol
behavior was checked against Microsoft's authorization-code/refresh documentation.

Automatic device-code credential renewal now runs through the shared CLI/MCP/HTTP
acquisition path. Login, acquisition/renewal and logout acquire a stable OS file
lock for the exact normalized credential context before reading or modifying
Keychain. The lock remains held through network exchange and paired persistence;
contenders fail with a safe busy error instead of waiting indefinitely. Lock files
are empty, never unlinked, and shared under the operator home across working
directories. Unix ownership, private permissions, file type/link count and
no-follow opening are checked. Independent-process tests verify exclusion and
release; separate tenant contexts remain independent. Native Keychain and live
Entra renewal acceptance testing remain pending. Standalone Rust callers must
coordinate their own writes with the same credential lifecycle.

The automatic acquisition path now has injectable renewal/storage tests covering
cache hits, absent refresh grants, renewal rejection, failed persistence, foreign
tenant access/refresh pairs and successful rotation. Failure paths retain the
existing saved record and return an error rather than an execution credential.
These tests exercise the same helper used under the production credential lock,
without modifying native Keychain or contacting Microsoft. Live integration
verification is still required.

CLI credential lock contention now returns a typed, secret-free
`credential_busy` JSON error with `retryable: true`. Only the OS lock's actual
WouldBlock result receives that classification; other locking errors remain
unavailable errors. The CLI formats this known-safe type directly rather than
exposing arbitrary provider/parser errors. Native lock tests verify the typed
classification using genuinely overlapping file handles.

The MCP/HTTP host now preserves the same typed credential contention as a safe
tool error with `status: credential_busy` and `retryable: true`. HTTP maps it to
429. Tests run the actual MCP result serializer and HTTP dispatcher and confirm
that private outer error-chain details are never echoed; unknown errors retain
the generic safe failure response.

Junction's exported local OpenAPI error schema now declares optional `error`,
`message` and boolean `retryable` fields alongside `status` and `reason`.
Contract tests validate the credential-contention response against the HTTP 429
schema and reject incorrectly typed retry flags. Extended authorization/policy
metadata remains allowed for forward-compatible structured error responses.

Daily catalog refresh now stages and validates Junction's own OpenAPI export
alongside Microsoft catalogs and common Rust types. Export failure or malformed
contract output aborts before replacing published local files. After allocating
the next patch version, the release workflow rebuilds Junction, regenerates the
local contract and checks its version before committing release manifests and
staging the catalog bundle. Network-free orchestration tests cover failed and
malformed exports while preserving the prior catalog/contract. Hosted GitHub
execution remains unverified under the existing publication blocker.

OpenAPI ingestion now preserves Azure DevOps operation-level API versions from
`x-ms-docs-override-version` and conservatively marks `x-ms-preview` operations
as preview even when the document version is stable. Mixed-version regression
tests check stable/preview separation and reject malformed operation versions;
all 13 ingestion tests and discovery Clippy pass. This addresses version
normalization, not full Azure DevOps coverage: native upstream discovery still
fails in this environment, and no complete DevOps catalog has been imported.

A runtime integration test now imports a DevOps-shaped Swagger definition,
checks registry preview gating, prepares the selected API-version query and
rejects attempts to replace that version through agent input. It exposed and
fixed Swagger parameter conversion retaining boolean `required` inside the
JSON Schema; parameter requiredness remains on the canonical parameter while
the boolean is removed from its validation schema. The integration test and
13 ingestion tests pass, as does Clippy for both affected crates. This verifies
request preparation without claiming a live Azure DevOps API call.

Automatically injected API-version query values now undergo the endpoint's
parameter schema validation, matching explicit input validation. A selected
registry version that conflicts with a declared version enum is rejected before
request execution. All 30 runtime unit tests, the DevOps request preparation
integration test and runtime Clippy pass after this change.

Daily refresh now also stages official Azure DevOps Core 7.1 at an independent
immutable source revision, records refresh receipts/statistics and merges it
with stable Graph into the default registry. Graph beta remains separate;
preview DevOps operations retain registry opt-in gating. Network-free script
tests verify both products enter the merged registry and failed DevOps refresh
or merge leaves previous published catalogs/contracts untouched. Native live
DevOps ingestion and hosted release execution remain unverified. This adds Core
to scheduled refresh configuration, not coverage of every DevOps service.

A cross-product integration test now merges independently ingested Swagger
documents with conflicting schema names and verifies the resulting DevOps
input contract. Required organization/body fields, body property constraints,
unknown-property rejection and selected API-version constraints survive the
merge. The other document's incompatible same-name definition does not leak
into DevOps validation. Both DevOps integration tests and runtime Clippy pass;
these fixtures do not substitute for a complete live catalog ingestion.

The native macOS ARM64 release binary and version 0.1.0 archive were rebuilt
after the DevOps importer and selected-version validation changes. The packaged
binary matches the release build, the archive checksum passes, and the packaged
CLI loads the existing 17,870-operation Graph catalog. Its catalog remains
Graph-only until a real DevOps refresh succeeds; scheduled refresh configuration
does not imply additional operations are already present in this local archive.

OpenAPI imports now retain Swagger security definitions or OpenAPI security
schemes under `x-junction-security-schemes`, which survives merge in document
provenance metadata. A DevOps-shaped OAuth integration fixture verifies inherited
scope requirements, operation overrides and retained authorization/token URLs
through import, merge and registry permission inspection. Scope-free metadata
continues to report unavailable rather than infer unrestricted access. All 14
ingestion tests and discovery Clippy pass. Retaining scheme metadata does not
implement legacy DevOps OAuth authentication or infer Entra permissions.

The pagination accumulator now supports explicit continuation-token query
parameters through `accept_continuation_token`. Opaque tokens are URL encoded,
existing copies of that parameter are replaced, other query values and the
request origin are preserved, and bounded buffering/resume/cycle detection
remain shared with next-link pagination. Tests cover query injection strings,
invalid control characters, buffering and repeated-token cycles. This is a
Rust accumulator API; automatic executor selection and response-header token
extraction are still required before CLI/MCP token pagination is complete.

The bounded executor now selects Azure DevOps header-token pagination for
operations whose product canonicalizes to `azure_devops` and whose specification
declares the `continuationToken` query parameter. Transport captures the
`x-ms-continuationtoken` response header as a redacted, zeroizing Secret and
rejects duplicate, malformed or oversized token headers. The shared accumulator
retains item/page limits, context-bound private continuation storage and cycle
detection. Seven HTTP tests, 31 runtime unit tests and two runtime integration
tests pass; live multi-page DevOps calls remain unverified. Other services'
token field/header conventions still need explicit adapters.

Pagination strategy selection now runs through the same response-acceptance
method used by the executor and its regression test. Two-page fixtures verify
DevOps declared-token precedence, Graph next-link behavior despite a token
header, and next-link fallback for DevOps operations without a declared token
parameter. Page results preserve both pages' items. All 32 runtime unit tests,
two integration tests and runtime Clippy pass. These response fixtures do not
verify live service transport or authentication.

Bounded execution also accepts top-level JSON `continuationToken` and `skipToken`
fields when an operation declares the matching query parameter. String tokens
are encoded as opaque query values; null ends pagination. Non-string tokens
and simultaneous token/next-link metadata are rejected, and undeclared token
fields cannot change requests. Existing DevOps header selection takes precedence.
All 33 runtime unit tests, two integration tests and runtime Clippy pass. Other
field names, nested tokens and token pagination through POST bodies still need
service metadata/adapters; live service calls remain unverified.

After the combined discovery, catalog orchestration and token-pagination
changes, the offline locked workspace test run passed with seven socket-based
`transport_tests` excluded under the sandbox. This includes CLI authentication,
MCP, HTTP contracts, generator compilation, registry and runtime tests. Workspace
Clippy with warnings denied, formatting and network-free catalog-refresh
orchestration also passed. These checks do not verify upstream live catalogs,
actual Microsoft authorization or GitHub-hosted releases.

Public cloud execution contexts now support `service: azure_devops`, resolving
`https://dev.azure.com` with Entra audience
`499b84ac-1321-427f-aa17-267ca6975798`. Cloud audience validation accepts strict
UUID application identifiers alongside HTTPS resource URIs. Government/China
clouds have no implicit DevOps mapping, and unrelated operation origins remain
rejected. A service-principal context example is included; Microsoft documents
the resource and organization access prerequisites at
https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/service-principal-managed-identity.
Four cloud unit tests and workspace Clippy pass. This adds public DevOps Core
endpoint resolution; live token acquisition, organization authorization and
other DevOps hosts still require verification/support.

A CLI regression test now loads the supplied DevOps cloud context, imports a
Swagger operation, resolves its endpoint and exact application-ID audience/scope,
then prepares the organization path and API-version query. Cross-service Graph
origins are rejected. The example's tenant placeholder uses the same valid
hyphenated format as other context examples. The regression test and CLI Clippy
pass; this verifies context/request planning without obtaining a live token.

OpenAPI server URLs now resolve declared variable defaults and honor
operation/path server overrides ahead of document defaults. Default values
must be strings and satisfy declared enums; unresolved templates, oversized
URLs, userinfo and query/fragment-bearing endpoints are rejected with fixed
errors. Fifteen ingestion tests and discovery Clippy pass. This selects the
first server's defaults; operator selection of alternate servers/regions and
relative server URLs still require additional endpoint-model support.

CLI `--verbose` now emits JSON command-start/finish timing diagnostics on stderr
and conflicts with `--quiet`. Diagnostics deliberately contain no command
arguments, URLs, context names, request payloads or raw errors. JSON stdout
remains independently parseable. A process integration test checks successful
OpenAPI export and failed registry loading without echoing a private file-name
argument; the test and CLI Clippy pass. Timing diagnostics are initial verbose
support; per-stage discovery/execution timing is not yet instrumented.

Non-Azure OpenAPI/Swagger imports without explicit server/host metadata now fail
instead of inheriting the ARM management hostname. Graph fixtures declare their
own endpoint, and a regression test covers Graph, DevOps, Defender and Fabric
missing endpoints. Discovery unit/integration tests pass with its one socket
transport test excluded; discovery Clippy and formatting pass. The legacy ARM
fallback still applies to `product: azure`; distinguishing incomplete ARM
documents from Azure data-plane documents remains additional work.

The remaining implicit ARM hostname fallback has now been removed. Every
imported operation requires a document host/server or a path/operation server
override. Documents with only local server overrides work without a root
endpoint, and schema-only documents can still be imported without inventing a
host. Fixtures for actual ARM operations now declare the ARM hostname. Discovery
tests (one socket test excluded), 23 CLI unit tests and runtime tests pass after
fixture updates; discovery Clippy passes. Relative and parameterized Swagger
hosts still need their own explicit endpoint-resolution support.

Swagger endpoint construction now honors declared HTTP/HTTPS schemes, preferring
HTTPS when available instead of rewriting HTTP-only sources. Hosts reject
userinfo, embedded paths/query/fragment delimiters, templates and whitespace;
base paths require an absolute path and reject query/fragment data. OpenAPI
server validation also rejects backslashes and whitespace normalization.
Discovery tests pass with one socket transport test excluded, including 18
ingestion cases; discovery Clippy passes. HTTP metadata preservation does not
enable insecure credential transport: execution still requires HTTPS.

Release packaging now validates the exported local API contract's version and
loads the packaged default registry before creating its archive, recording
catalog statistics from that binary. A fresh native macOS ARM64 version 0.1.0
archive includes the recent endpoint, DevOps context, token-pagination and
verbose CLI changes. Its checksum, packaged CLI stats/verbose smoke check and
workflow lint pass. The local catalog still contains only the existing 17,870
Graph operations; no live DevOps refresh or hosted release is implied.

Swagger ingestion now honors Azure's `x-ms-parameterized-host` ahead of the
standard host, including referenced parameters, string defaults, declared enum
validation, base paths and `useSchemePrefix: false`. The implementation follows
the [official AutoRest extension specification](https://github.com/Azure/autorest/blob/main/docs/extensions/readme.md#x-ms-parameterized-host).
Resolved endpoints pass the same absolute URL checks as OpenAPI servers; errors
do not echo host values. Definitions with missing host-variable defaults still
fail explicitly: operator-configured dynamic host parameters remain unfinished.
The ingestion suite has 19 passing cases, including extension precedence and
malformed-host rejection. The packaged release predates this importer change.

Follow-up: canonical operations now retain an optional endpoint template with
declared defaults and choices. Swagger host variables without defaults can be
imported and survive manifest serialization. Trusted cloud context files bind
them through `endpoint_variables`; resolution rejects missing/unknown bindings,
invalid values and undeclared choices. The resolved origin must still match the
configured service, so a custom data-plane service requires an explicit custom
endpoint and audience. Host bindings are not execution input parameters. Tests
cover registry persistence, operator binding, rejection of a different account
origin and agent attempts to set the host, alongside bounded/redacted errors.
This supersedes the missing-default limitation above for Swagger hosts; unresolved
OpenAPI server variables still require further work. No live data-plane request
or new release archive has been verified for this change.

Verification for the template model: all 24 CLI unit tests pass, all 33 runtime
unit tests and both runtime integration tests pass, and the discovery suite
passes with one socket transport test excluded (20 ingestion cases). Workspace
Clippy passes for all targets. Existing manifests omit the new optional field
and remain compatible.

OpenAPI server variables now use the same canonical endpoint template and trusted
context bindings as Swagger hosts. Selected document, path and operation servers
retain defaults and declared choices; static overrides clear inherited variables.
OpenAPI defaults remain required by the source specification. Empty string
defaults are allowed when the resolved URL is valid. All 21 ingestion cases and
24 CLI unit tests pass, including regional overrides, server precedence and
matching a bound OpenAPI host against the explicitly configured origin. Workspace
Clippy passes. Operator instructions are in `docs/ENDPOINTS.md`.

Daily publication now validates its complete three-platform archive/checksum set
before creating a release tag. Tests cover checksum tampering, missing files,
path substitution, extra archives and Windows line endings. A publication retry
can reuse an existing remote tag only when it points to the prepared commit.
Both workflow definitions pass actionlint. These are local checks; repository
publication and actual hosted release recovery remain unverified.

Release asset validation additionally rejects mixed-version downloads, extra
files (including hidden files), and symbolic-link archives/checksums. It checks
the whole publication directory, matching the workflow's `dist/*` upload scope.
Regression fixtures pass for mixed versions, hidden extras and symbolic links,
followed by another valid-set check; both workflow definitions still pass lint.

Daily refresh now includes the scoped `azure-resources` official source. The
updater pins its repository revision, selects the newest stable date-versioned
Resources definition from that inventory, writes refresh receipts/statistics and
merges it with stable Graph and DevOps Core. Orchestration fixtures verify that
a newer preview path is not selected and that failed Azure refresh or missing
stable inventory preserves the prior default catalog and API contract. This
extends scheduled source coverage; full Azure coverage remains unfinished.
The local packaged/default registry still has the existing Graph catalog. Live
Resources retrieval, hosted execution and actual Microsoft API execution are
unverified; mock orchestration does not establish those outcomes.

Scheduled refresh now requires each selected Graph, DevOps Core and Resources
catalog to contain operations and exactly one imported entry receipt matching
its expected pinned revision and path. Schema-only documents cannot silently
replace service coverage. Orchestration fixtures for an empty Azure catalog and
a wrong-revision receipt abort before changing the previous default catalog or
API contract; the successful refresh fixture still passes.

Integration verification after the endpoint-template and scheduled Resources
changes: `cargo test --workspace --offline --locked -q -- --skip transport_tests`
completed successfully, with seven socket transport tests excluded. Workspace
format checking and Clippy for all targets pass. Catalog orchestration, release
asset validation and both workflow lint checks pass together. This establishes
local integration compatibility, not live provider coverage or hosted releases.

OpenAPI/Swagger ingestion now includes operations under Azure `x-ms-paths`.
Following the [official AutoRest extension semantics](https://github.com/Azure/autorest/blob/main/docs/extensions/readme.md#x-ms-paths),
query suffixes distinguish source overloads but do not supply request values;
only declared query parameters are serialized by the executor. Canonical paths
retain the path portion, including overload-only documents with empty `paths`.
All 22 ingestion cases pass and discovery Clippy passes. A runtime integration
case verifies query encoding, omission of source-only query text and rejection
of missing required query input. These importer changes are not yet packaged.

The native scoped Resources refresh attempt terminated with a generic safe
command failure; no verified catalog was produced. Its root cause is not proven
by that error. The live-retrieval limitation therefore remains.

Azure `x-ms-pageable` now normalizes item-field, next-link-field and optional
next-operation metadata. The executor uses declared response fields, supports
null next-link declarations and retains bounded buffering and same-origin link
checks. Named next-page operations are retained but explicitly unsupported when
a next page is present. Discovery/runtime suites pass (23 ingestion cases,
34 runtime unit cases and three runtime integration cases), excluding one
discovery socket transport test. Workspace Clippy passes. Tests cover custom
fields, origin rejection, malformed links, single-page bounded buffering and
named-operation rejection. The release archive predates these changes.

Named next-page GET operations can now pass executor preflight when their source
operation ID resolves uniquely within the same product, service, source document
and API version. The next operation's policy and preview/retirement eligibility
are checked before credentials. GET links retain origin/cycle/page/item guards.
POST/body continuations and named operations declaring service headers or cookies
remain unsupported. An integration test checks valid GET selection and rejection
of denied, missing, cross-document, cross-version, preview, POST, body and header
relationships; runtime/registry Clippy passes. Live next-page dispatch remains
unverified. This supersedes the blanket named-operation limitation above for the
supported GET case, without claiming complete service-specific pagination.

Related-operation lookup now retains exact versionless identity even if a newer
version exists under the same canonical ID. It no longer interprets an absent
related API version as `latest`. Tests cover versionless selection, ambiguous
source relationships, preview/beta opt-in and retirement rejection.

The native macOS ARM64 0.1.0 archive has now been rebuilt with the extended-path,
pageable-field and named-GET pagination changes. Its SHA-256 checksum passes and
the packaged binary loads the bundled 17,870-operation Graph catalog. A separate
temporary fixture imported through the packaged CLI verifies stripped extended
path queries, retained pageable fields and described input parameters. This is
an offline executable smoke check; it does not prove Azure catalog retrieval,
live pagination, hosted native builds or GitHub publication.

Refresh errors now carry typed safe stages for configuration, inventory,
download, document validation, dependency resolution, normalization and deadline.
The CLI emits `source_refresh_failed` plus a stage, without source URLs, parser
contents or underlying error text. Unit and CLI integration checks verify safe
formatting and that invalid configuration creates no output catalog. A native
debug-binary Resources retry identifies the current failure as `inventory`,
before spec download/import; the network-level cause remains unproven. These
diagnostics are not yet in the release archive.

Source download failures now retain safe typed diagnostics through refresh-stage
context: transport, timeout, HTTP status, response read, or size limit. CLI refresh
errors include the category and, only for an HTTP response rejection, its numeric
status. The diagnostic retains no URL, response body, or underlying reqwest error.
Focused context-preservation and CLI configuration-error tests passed. A native
debug Azure Resources refresh returned inventory/transport, establishing that this
attempt failed before an HTTP response; DNS, proxy, TLS, and connection causes are
not distinguished. No refreshed Azure catalog was produced. These changes are not
yet included in the packaged release archive.

The standalone `discover` and `fetch` commands also emit safe typed download
failures, so inventory failures in the daily updater no longer collapse into a
generic command error. The hosted socket test now checks exact numeric HTTP
statuses (including redirects) and both declared-length and streamed size-limit
failures, while ensuring rejected bodies remain absent from errors. Local
non-socket discovery unit tests passed (18 tests); the socket case remains for
hosted verification.

Refresh budget errors now carry a safe `documents` or `bytes` limit category
through stage context to CLI JSON. Dependency-expansion budget failures retain
the dependency-resolution stage rather than becoming generic command failures.
Tests verify typed inventory budget rejection and that rejected dependencies
remain absent from refresh state and cannot yield a completed catalog. Seven
refresh unit tests passed. CLI/discovery Clippy passed for the implementation.

Added a Rust Azure VM IMDS managed identity provider with a fixed endpoint,
proxy bypass, no redirects, bounded zeroized response handling, exact resource
binding and expiry checks. Two focused unit tests passed. This is library support;
CLI integration, retries and live Azure VM verification remain outstanding.
See docs/MANAGED-IDENTITY.md for trusted tenant-binding requirements and scope.

Junction now includes `junction tui`, backed by Ratatui 0.29 and Crossterm in the
same executable. The catalog explorer has a dark teal theme, responsive product
sidebar, bounded full-catalog search, keyboard selection, preview gating, and
scrollable overview/input-schema/permissions tabs. It reuses the caller's
validated registry and trusted risk overrides. No credential acquisition or
remote execution is performed by this catalog surface. Terminal restoration on
ordinary errors and panic uses Ratatui's initialization/restoration behavior.
Three TUI tests cover rendering at multiple sizes, navigation/search/preview
behavior and terminal control sanitization. Native PTY startup against the
17,870-operation catalog, search, schema-tab switching and Ctrl+C restoration
were verified. A minimal vendored official Ratatui dependency patch resolves a
unicode-width constraint conflict with existing YAML diagnostics; provenance and
scope are recorded in vendor/README.md. This UI is not yet in the older dist archive.

The native macOS release archive was rebuilt after the TUI, managed-identity
library and safe refresh diagnostic changes. Packaging now requires `tui --help`
before creating files and includes RATATUI-LICENSE.txt. The prior binary was
rejected before package creation. Release-asset validation tests and shell syntax
checks passed. The new aarch64-apple-darwin archive's SHA-256 passed. An extracted
archive loaded the bundled 17,870-operation Graph catalog, rendered the TUI in a
PTY, exited successfully on Ctrl+C, restored the alternate screen and exactly
restored terminal attributes. Linux/Windows artifacts and public GitHub publication
remain unverified. Managed identity is still library-only, and Azure/DevOps
catalogs are not present in this local default bundle.

Managed identity is now wired into the shared headless environment credential
selector and accepted by both cloud and explicit execution contexts. Trusted
context selection therefore reaches the Azure VM provider from CLI/MCP/HTTP
execution. AZURE_TENANT_ID must match the configured concrete tenant; optional
AZURE_CLIENT_ID selects a UUID user-assigned identity. There is no credential
fallback. Three focused auth tests verify provider semantics and rejection before
network, and one CLI test verifies both context formats reach the managed identity
flow. CLI/auth Clippy passed. Live VM acquisition and service execution remain
unverified; these integration changes postdate the current dist archive.

Managed identity token decoding now enforces RFC 6750 bearer-value syntax before
constructing a secret for request dispatch. Tests cover whitespace, delimiters,
non-ASCII text and misplaced/empty padding, as well as valid opaque token syntax.
All 31 non-socket auth unit tests passed; six transport tests were excluded.
A new compiled IMDS transport test checks required Metadata header, acquisition
without Authorization, redirect rejection and both declared/streamed response
limits. Hosted execution of that socket test remains outstanding. These changes
postdate the packaged release archive.

Workspace verification after TUI and managed identity integration completed successfully: 232 tests passed, with 8 socket tests excluded under local restrictions. Workspace all-target Clippy, formatting, workflow lint, catalog-update orchestration, release-asset validation and public-repository validation passed. A subsequent TUI rendering fix sanitizes method/version metadata as well as other labels; its four focused tests and Clippy passed. These source changes postdate the current packaged archive. Public GitHub and hosted transport/build verification remain outstanding.

The TUI's empty-search catalog now supports next/previous pages with n/b,
retaining at most 100 operation references per page. Product and preview changes,
search edits and clearing the search reset the page offset and selection.
A test traverses all 205 fixture operations across three pages without duplicates,
checks terminal-page behavior, backward navigation and filter reset, and finds
an operation beyond the first page using search. All five TUI tests and Clippy
passed. Search ranking remains capped at 100; paging applies to catalog browsing.
This change postdates the packaged archive.

The TUI now adds service filters with { / } and a scrolling service sidebar
scoped to the selected product. Service selection filters both paged listing
and ranked search. Changing product rebuilds available services and resets
service selection and page position. Both sidebar selections scroll into view.
Six TUI tests and Clippy passed, including service-specific listing/search,
product changes and responsive rendering. These changes postdate dist artifacts.

Daily patch allocation now uses a tested shell helper with decimal digit carry,
so versions do not overflow signed shell arithmetic. It accepts stable semantic
versions without leading zeroes, enforces Rust semver's u64 component range and
rejects an exhausted patch. Tests cover decimal carry, the signed-integer boundary,
maximum supported patch, invalid/prerelease/build versions and argument counts.
They run in push/PR CI and daily preparation. Tests, shell syntax and workflow
lint passed. Hosted automatic version commits and releases remain unverified.

Long TUI search queries now scroll horizontally to retain the typed tail and
cursor inside the search field. Cursor placement uses terminal cell width, so
wide Unicode queries work as well as ASCII. Rendering tests verify the tail,
interior cursor bounds and backspace editing at 80 columns. Seven TUI tests and
Clippy passed. This change postdates the packaged archive.

The Ratatui explorer now offers a modal `?` keyboard guide and a compact footer. Help preserves catalog selection and filters; search accepts a literal question mark. All eight TUI tests pass, including rendering the complete guide at the minimum supported 70 × 16 terminal size. Focused all-target Clippy passes. The existing packaged binary predates this refinement.

The native v0.1.0 aarch64-apple-darwin release archive has been rebuilt with current managed identity integration, token validation and TUI paging, service filters, long-search scrolling and keyboard help. SHA-256 verification passes. An extracted-package pseudo-terminal check verifies the 17,870-operation catalog, integrated help display, clean Ctrl+C exit, alternate-screen restoration and exact terminal attribute restoration. The previous archive is preserved locally. GitHub publication and hosted Linux/Windows builds remain unverified.

Managed identity acquisition now retries documented temporary IMDS statuses with at most five attempts and a 120-second total deadline. Retry-After numeric delays are honored within a 70-second bound; unsupported or excessive values fail without early retry. Redirects/authentication errors and transport failures remain terminal. Four focused managed identity tests pass, including status classification, retry exhaustion and server delays. Live transient IMDS behavior remains unverified. The native release archive predates this retry change.

Two managed identity HTTP transport regression tests now cover transient recovery with unchanged identity headers and five-attempt exhaustion. All-target auth Clippy and 32 non-socket tests pass; eight auth socket tests are excluded locally. Attempting the recovery test failed at localhost TcpListener::bind with PermissionDenied before acquisition. Both CI workflows include the full workspace test command; no hosted result is available.

ManagedIdentityProvider now caches one token within its fixed request/identity instance and serializes refresh with an async mutex. Cached credentials require more than 60 seconds remaining; expired entries are cleared before refresh. The existing 120-second deadline includes lock waiting. All 33 non-socket auth tests and all-target Clippy pass. Environment execution still creates per-acquisition instances, so shared CLI/MCP/HTTP caching remains unfinished. The release archive predates this change.

Managed identity caching is now integrated into the shared environment acquisition path used by CLI/MCP/HTTP execution. A process-wide pool retains at most 64 fixed-request providers, with keys covering the existing tenant/authority/audience/scopes/profile/flow cache boundary plus selected client ID. Environment tenant/flow and identity validation precede lookup. Pool tests verify reuse, context/identity isolation, invalid request rejection and retention bounds. All 34 non-socket auth tests pass; live and hosted socket verification remain outstanding.

Workspace integration verification after managed identity retry/cache/pool changes completed successfully: 240 tests pass with 10 restricted-environment socket tests filtered. Workspace all-target Clippy and formatting checks pass. Vendored Ratatui emits existing lifetime warnings during tests; the workspace lint command succeeds. This does not verify live Azure, GitHub publication or hosted platform builds.

Added enabled official Azure Compute source scoped to Microsoft.Compute/Compute and documented pinned virtual machine ingestion. The native sources command validates and reports the new configuration. Upstream virtualMachine.json path was verified against the official Azure repository. Daily updater integration and live Compute ingestion remain unfinished; no Compute coverage is claimed for the local default registry.

The daily catalog updater now imports latest stable Azure Compute virtualMachine.json from a scoped inventory pinned to the same Azure commit as Resources, validates imported operations and receipt, and merges Compute into the staged default. The 18-call mock orchestration passes, covering preview/example exclusion, revision mismatch, no stable definition, failed refresh, empty operations and wrong receipt, with prior default/Compute/OpenAPI catalogs preserved on failure. Bash syntax and explicit CI/daily workflow actionlint checks pass. Live Compute refresh and hosted publication remain unverified; local generated catalogs are unchanged.

Strengthened updater provenance checks for every Graph/DevOps/Resources/Compute refresh: expected source ID, exact pinned official download URL, SHA-256 shape and positive bounded integer byte count. Eight additional malformed-receipt cases abort and preserve previous default/Compute catalogs. Orchestration, Bash syntax and workflow actionlint pass. The existing real Graph receipt satisfies the additional consistency checks. These checks do not replace the Rust fetcher's digest computation or prove live ingestion of other sources.

Verified Azure Compute naming against official virtualMachine.json metadata and added an offline ingestion regression for VM list/start/restart. The test checks canonical IDs, API versions, required subscription input, paging, write/read risks, async action metadata and deterministic manifests. All 24 ingestion tests pass. It does not prove full live Compute refresh or operation execution.

LRO poll reservations now persist a one-second fallback readiness delay before status transport. On HTTP failure, an available Retry-After updates the handle and is checkpointed before the enriched error returns. Interruption/checkpoint regression verifies delayed readiness survives save/load and immediate re-poll rejection while retaining consumed poll budget. All 38 runtime unit/integration tests and all-target runtime Clippy pass. Live HTTP-error Retry-After behavior remains unverified; final resource fetching and remote cancellation remain unfinished. The packaged binary predates this fix.

The saved-operation CLI integration test passes after LRO readiness changes, exercising private checkpoint resumption, terminal completion, timeout progress, tenant/policy rejection, exclusive locks and safe output. Reviewed the CLI checkpoint replacement path and updated STATUS.md to reflect managed identity pooling, Compute/Resources/DevOps daily configuration, Ratatui integration and remaining full-spec requirements. Hosted refresh and live LRO error handling are still unverified.

Added the Rust trusted approval capability foundation. Grants bind full operation/policy metadata, tenant, exact input and operator-supplied execution context, expire within five minutes and are consumed by value without Clone/Debug/serialization. Tests cover input/context/tenant/metadata/policy changes, expiry and current deny/read-only rules. Runtime integration and trusted CLI/private durable issuance remain unfinished; agent surfaces still reject approval-required calls.

Approval grants now use a typed ApprovalContext requiring explicit cloud, canonical plain-HTTPS endpoint, audience and credential profile instead of an opaque context string. Constructor validation rejects embedded credentials/query/fragment and empty bindings; issuance rejects non-concrete tenant aliases and oversized input. Independent cloud/endpoint/audience/profile changes invalidate grants. Six policy tests and all-target policy Clippy pass. Runtime/CLI approval workflow integration remains unfinished.

Added runtime prepare_with_approval: consumes a trusted bound grant, enforces the approval decision, and uses a shared private preparation routine for identical input/path/parameter/schema validation. Approved destination comes from ApprovalContext. Tests verify ordinary deletion stays approval-required, approved deletion prepares correctly, an approved input containing an approval flag still fails input validation, and changed input is rejected. All 39 runtime tests and runtime/policy all-target Clippy pass. Credential acquisition/HTTP execution integration and trusted CLI durable issuance remain unfinished.

Added trusted Rust Executor::execute_with_approval with single-use grant consumption, current policy and registry schema validation, endpoint/audience binding checks and token validation before governed transport. Regressions reject changed endpoint, audience, tenant and input before transport; a valid grant progresses to token validation and rejects a mismatched token. All 40 runtime tests and six policy tests pass, and all-target Clippy passes. Cloud and credential profile remain trusted caller assertions; CLI issuance, private durable storage and agent-surface integration remain unfinished. The packaged binary predates this change.

Added explicit final Azure LRO response retrieval through Executor::final_lro_result and operations wait --result. Final targets follow POST final-state metadata/default Location and PUT/PATCH original resource URLs without changing status polling. New private checkpoints retain same-origin final destinations and protocols; old checkpoints continue polling but report operation_result_unavailable for retrieval. Missing required final headers preserve polling handles. Retrieval rechecks current policy, tenant/audience/endpoint, token validity and successful state, uses governed GET transport, and rejects non-successful final state. Response bodies are returned explicitly and never checkpointed; status-endpoint retrieval repeats GET rather than caching a terminal body. Regression coverage checks target selection, checkpoint compatibility/tampering, context/state rejection, missing-header preservation and safe CLI diagnostics/lock cleanup. All 41 runtime tests, seven HTTP tests and the CLI operations integration test pass, with all-target Clippy and formatting passing. Live Azure final retrieval, remote cancellation and the full specification remain unverified/unfinished. The release archive predates this change.

Implemented headless Entra RSA certificate client credentials with ring PS256 signing, DER SHA-256 thumbprints, fresh UUID JWT IDs and five-minute endpoint-bound assertions. The shared environment selector checks tenant/flow before file access, reads bounded regular DER files, rejects Unix key permissions accessible to group/other and symlinks, and preserves certificate request bindings during bounded HTTPS token exchange. CLI explicit/cloud contexts accept certificate flow, including sovereign authorities. Input DER/signature/assertion buffers are zeroizing; signing-library internal allocation wiping is not guaranteed. Full X.509 chain/expiry/key correspondence is delegated to Entra, not parsed locally. Tests verify cryptographic signatures/tampering, assertion fields/freshness, token form/resource scope, tenant/flow isolation, file bounds/permissions and safe errors. Certificate-backed OBO/authorization-code, other formats/signers and live Entra acceptance remain pending. All 39 non-socket auth tests and 26 CLI unit tests pass. The full workspace has 252 passing tests with 10 locally restricted socket tests filtered; workspace all-target Clippy and formatting pass. Fixed the stale bundled-source count assertion by checking required source IDs and deterministic ordering. Rebuilt the optimized macOS ARM64 binary with managed identity pooling, trusted approved execution, LRO final retrieval and certificate auth. GitHub publication and full-spec completion remain unverified/unfinished.

Repackaged the rebuilt macOS ARM64 release binary as dist/junction-v0.1.0-aarch64-apple-darwin.tar.gz (13,235,619 bytes), preserving the previous package. SHA-256 verification passes. Extracted-archive checks verify the 17,870-operation catalog, Ratatui notice, certificate context selection without acquisition, operations wait --result help, native TUI/keyboard-guide rendering and terminal restoration on Ctrl-C. New certificate docs/context and Azure Compute source are present; test private-key fixtures are absent. This is a verified local package, not a hosted/public GitHub release or live cloud acceptance result.

Added declared POST list pagination and named GET/POST continuation methods following the AutoRest x-ms-pageable contract. Initial POST input/body uses ordinary preparation; default continuations use bodyless GET, while named POST continuations reuse the original body only when declared and validate its schema before credential acquisition. Both selected operations remain subject to current policy/source/version checks, and authorization errors identify the actual named operation. POST keeps the transport no-retry rule. Continuations now bind full initial/named operation metadata and retain nonempty request history across resumes, preventing replay of the initial POST; legacy input/version-only bindings fail closed. Added a 10,000 distinct-page limit across a continuation chain. Regressions exercise imported POST body references, next-body mismatch, denied/unsupported methods, bodyless continuation selection, buffering/resume, changed operation metadata and empty/exhausted history. All 45 runtime tests, five CLI execution tests and two MCP integration tests pass; runtime/CLI all-target Clippy and formatting pass. Rebuilt the optimized macOS ARM64 binary. Body-token mutation, named service headers, further service-specific strategies, live POST paging and the full specification remain unfinished.

Repackaged the optimized macOS ARM64 binary with declared POST pagination, preserving the previous certificate-era archive. SHA-256 verification and extracted-package checks pass: catalog size, certificate context selection, LRO result flag, Ratatui notice, TUI/keyboard-help rendering and exact terminal restoration on Ctrl-C. This remains a local development artifact; hosted publication, live Microsoft paging and the full requested end state remain unverified.
