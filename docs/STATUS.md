# Junction delivery status

Junction is under development. The full specification in
[SPECIFICATION.md](SPECIFICATION.md) has not been completed. A working local
binary and release automation are available; this is not yet a verified
production release.

Latest local pagination work adds authoritative paired
`x-ms-list-continuation-token` query/response metadata, nested JSON pointers and
encoded query tokens. Marked POST pages retain their original body. Unmarked
documents bypass continuation-schema traversal; the cached official Graph v1.0
document still imports all 17,870 operations. Live token pagination is unverified.
The updated ingestion, core, registry and runtime suites passed 95 tests;
changed-crate Clippy and workspace formatting checks passed. One discovery
download test requiring a local socket could not run under this sandbox.
Continuation marker reachability is indexed once per document, including schema
aliases and recursive reference cycles. A mixed-catalog regression using the
cached Graph document plus one synthetic marked operation imports 17,871
operations and identifies exactly one query-continuation strategy. Large unrelated
response schemas remain importable when other operations carry markers.
The complete discovery suite passes 66 tests with its single socket-dependent
download test filtered under the sandbox; changed-crate Clippy and workspace
formatting checks pass.

## Current evidence (2026-10-01)

A live run of `scripts/update-catalogs.sh` against official upstream
repositories completed successfully, staging and publishing 18,815 default
operations across seven products (Graph, Azure, Azure DevOps, Sentinel,
Purview, Defender, Fabric). Per-catalog receipts and stats are in
`generated/manifests/`:

| Catalog | Operations |
| --- | --- |
| Graph v1.0 (default) / beta (opt-in) | 17,870 / 29,581 |
| Azure Compute (consolidated `ComputeRP.json` 2026-04-01) | 206 |
| Azure Resources | 40 |
| Azure Cost Management | 75 |
| Azure Monitor (metrics, activity logs, alerts, scheduled queries) | 27 |
| Azure Resource Graph | 8 |
| Azure Log Analytics | 85 |
| Azure Arc (Hybrid Compute) | 65 |
| Azure Lighthouse | 14 |
| Defender for Cloud (alerts, assessments, pricings, secure score) | 29 |
| Sentinel | 95 |
| Purview Accounts | 26 |
| Azure DevOps Core | 19 |
| Fabric Platform / Admin / Lakehouse / Notebook | 168 / 53 / 23 / 12 |

Live ingestion fixes made to reach this: scoped recursive GitHub tree listing
for repositories whose recursive tree exceeds 8 MiB, optional `GITHUB_TOKEN`
for API metadata, an 8M-node bundle traversal bound (Graph beta exceeds 1.4M
nodes), JSON-family request media types (`application/json-patch+json`),
references inside Azure `x-ms-paths`, and case-variant shared-directory
references in Fabric definitions.

`junction execute --approve` now provides the operator approval flow:
complete request validation, terminal-only review and confirmation, then a
single-use in-process grant consumed by one request or LRO start. It was
verified through a pseudo-terminal for accept and decline paths and by an
integration test for terminal-less, deny, read-only and not-required cases.

The full workspace suite now runs without sandbox socket restrictions.
Remaining gaps are listed in the tables below; live Microsoft tenant execution
is still unverified.

## Release and open source

| Requirement | Current evidence | Remaining work |
| --- | --- | --- |
| Open source | MIT license, contribution guide, public repository `jusso-dev/junction` | Keep repository settings verified by the release workflow. |
| Daily endpoint updates | `.github/workflows/daily-release.yml` and `scripts/update-catalogs.sh` | Run successfully on GitHub. Daily refresh is configured for Graph stable/beta, Azure DevOps Core, Azure Resources, Azure Compute VM, Sentinel SecurityInsights, Purview Accounts, Cost Management, Azure Resource Graph resource/saved queries, Monitor Metrics, Activity Logs, Activity Log Alerts, Metric Alerts and Scheduled Query Rules and Fabric Platform, Admin, Lakehouse and Notebook. It still needs broader product coverage and live verification. |
| Automatic versioning | Release workflow updates Cargo versions and lockfile; decimal patch increment validates Rust semver u64 bounds | Verify a hosted daily run, resulting commit and release tag. |
| Native artifacts | Workflow builds Linux, macOS and Windows packages with checksums; local macOS ARM64 package exists | Verify all hosted platform builds and published release assets. |

## Product implementation

Fabric's `x-ms-fabric-sdk-long-running-operation` boolean marker selects a distinct
Location polling protocol that requires an explicit response `status`. Running
responses with HTTP 200 remain running. Successful polls retain a distinct same-origin completion `Location` for explicit
result retrieval and checkpoint resumption. Missing or unsafe result URLs remain
unavailable. A validated UUID in `x-ms-operation-id` supplies a same-origin `/v1/operations/{id}`
polling fallback when Location is unavailable. Live Fabric LRO verification remains unfinished.

Fabric discovery now uses Microsoft's official `fabric-rest-api-specs` OpenAPI
repository for platform, admin, lakehouse, notebook and shared definitions. Native refresh and execution
remain unverified, while Fabric Platform, Admin, Lakehouse and Notebook is now configured in the staged daily catalog merge.
Fabric has a central public-cloud endpoint/audience mapping and an example cloud
context. Sovereign configurations require explicit Fabric service metadata instead
of falling back to public-cloud endpoints. Live Fabric authentication is unverified.

Directly loaded manifests require exactly one matching query parameter for a
declared continuation strategy. Registry tests cover duplicate/missing parameters,
header/query mismatches and invalid JSON-pointer escapes.

Compute, Resources and Sentinel source scopes allow shared ARM schema dependencies.
Daily validation checks dependency receipts in addition to the imported document;
orchestration tests cover rejecting a dependency from a different revision.

The Ratatui Overview pane displays declared pagination fields, query-token
response pointers, continuation methods and asynchronous polling support alongside
the selected operation's version, risk and source.

| Area | Implemented locally | Still required |
| --- | --- | --- |
| Discovery | Official pinned GitHub inventories, scoped downloads, bounded refresh, OpenAPI and OData ingestion, local external-reference bundling | TypeSpec, service metadata and structured documentation adapters; broader live Microsoft catalogs. |
| Canonical model and versions | Schema normalization, deterministic operation IDs, stable/preview selection, registry validation | Validate coverage against real catalogs for all requested products. |
| Rust generation | Deterministic compilable types, recursive references, nullable fields, enums, canonical metadata and dynamic fallback | Broader curated common API types and richer typed unions/discriminators. |
| Authentication | Client secrets, RSA certificate client credentials, workload assertions, external bearer credentials, OBO, public/confidential authorization-code providers; device-code CLI login/logout/status/accounts with native macOS Keychain storage; bound refresh exchange, rotated-pair persistence and automatic CLI renewal coordinated with login/logout; VM managed identity with bounded IMDS retries and identity-isolated in-process token pooling | Windows/Linux secure storage, CLI browser login, non-VM managed identity adapters, broader certificate formats/signers and non-Entra signing mechanisms; live login and native storage verification. |
| Clouds and contexts | Central cloud endpoints/audiences, explicit availability, tenant-bound credential caches, private context files | Live sovereign-cloud and multi-tenant integration verification. |
| Execution | Typed input checks, HTTPS execution, retry/throttle handling, correlation IDs, bounded next-link/declared query continuation-token pagination, declared POST list/named-next-page methods and bodies and saved LRO polling with persisted readiness delays and explicit final-result retrieval | Body continuation-token mutation, named service-header pagination and additional service-specific pagination, supported remote cancellation and live final-result verification. |
| Interfaces | CLI, Rust crates, six-tool MCP surface, local HTTP API, OpenAPI export and integrated Ratatui catalog explorer | Complete authentication command UX and live end-to-end acceptance tests. The TUI supports inspection; execution controls remain future work. |
| Policy and batch | Risk classification, policy rejection, approval-required responses, single-use trusted Rust approval grants, CLI `--approve` terminal review for requests and LRO starts, bounded dependency batches | Durable/cross-process approvals, batch approvals and remote approval UX remain future work. |

Tests provide evidence for the implemented behavior, not completion of the
remaining requirements. Local socket-based transport tests are excluded where
the sandbox prevents binding; CI is configured to run the unfiltered suite.
The available local catalog contains 17,870 Graph operations from cached stable
source data. That count does not establish support for every requested Microsoft
product or prove the daily refresh has run on GitHub.

The remaining delivery milestones include verified authentication across supported
platforms, broader catalog ingestion, complete approval/LRO workflows and hosted
release verification.
Full-spec completion remains substantially beyond that milestone. See
[AUTHENTICATION.md](AUTHENTICATION.md) for the current CLI storage and expiry limits.

Recent verification: the earlier workspace run passed 252 tests with 10 locally
restricted socket tests filtered. After POST pagination changes, all 45 runtime
tests, five CLI execution tests and two MCP integration tests pass, with runtime/CLI
all-target Clippy and formatting passing. The optimized
macOS ARM64 binary has been rebuilt with Ratatui, managed identity pooling,
trusted approved execution, LRO final-result retrieval, certificate credentials and declared POST pagination.
Hosted results and live cloud execution are still missing.

Fabric imports recognize the official leading Microsoft Learn preview-release note
as operation-level preview maturity, in addition to version and `x-ms-preview`
markers. Ordinary preview mentions do not change maturity. Live Fabric catalog
retrieval and execution remain unverified.

OpenAPI operation-level `x-ms-preview` and `deprecated` markers must be booleans.
Malformed markers abort import with a fixed error, preserving existing catalogs
instead of silently treating unknown maturity as stable.

After Fabric workload scopes and maturity validation, the discovery suite passes
69 tests with one sandbox-restricted download test filtered. Workspace compilation
passes. Re-importing the cached official Graph v1.0 document retains all 17,870
operations; the mixed pagination fixture retains 17,871 with exactly one marked
query-continuation operation. These checks establish local compatibility, not a
live upstream refresh or cloud execution result.

OpenAPI mutation actions beginning with delete/remove/purge/erase/drop/truncate
(or bulk followed by one of those verbs) receive destructive risk even when they
use POST. Read methods remain read-only; Conditional Access retains privileged
risk. Trusted operator overrides remain available for semantic corrections.

A runtime integration regression imports Fabric POST bulk removal, round-trips its
manifest, loads the registry and confirms safe-write/full modes require approval
before request preparation. Read-only and explicit deny policies reject it. The
regression passes without credentials or network requests.

Graph OpenAPI risk classification uses its normalized dotted action name, including
explicit `invoke_delete` aliases, so POST removal/deletion actions retain
destructive risk. Focused ingestion regressions and discovery Clippy pass; the
latest Graph risk change is included in the verified local macOS release archive.

OData CSDL action risk uses the declared action name rather than its public import
alias. A runtime regression imports `PurgeItems` exposed as `/run`, round-trips
and loads the manifest for Graph and Purview, and verifies request preparation
returns approval-required under full policy. The runtime regressions and Clippy
pass without acquiring credentials or sending requests.

The bundled Graph catalogs were re-imported locally from the cached official
source after verifying its recorded SHA-256 and byte count. All 17,870 operation
IDs remain. The update promotes 85 POST actions from write to destructive, retains
2,774 declared pageable strategies, corrects six parameter schema requiredness
markers and retains security-scheme metadata. Canonical/component schemas are
unchanged. `generated/manifests/graph-local-reimport.json` records the receipt and
counts. This is a local re-import, not a live refresh; the verified macOS archive includes these catalogs.

The daily updater now stages Purview Accounts from the newest stable ARM
Swagger path at the shared pinned Azure revision, accepting both legacy and nested
Purview layouts. Its source scope includes shared ARM resource-management types.
Mock updater regressions verify stable selection, shared dependency receipts,
rejection of empty catalogs and mismatched receipts/inventories, and preservation
of previous Purview and default catalogs on failure. The updater suite, shell
syntax checks and workflow actionlint pass. Live Purview refresh, data-plane
coverage and hosted publication remain unfinished. This source configuration
change is included in the rebuilt local macOS archive after package verification.

Purview receipt validation also enforces its configured product and shared ARM
paths. Regression cases reject unrelated Azure/OpenAPI paths, storage shared
types, misleading prefixes, parent traversal and empty path components while
preserving published catalogs. The updater suite and workflow lint pass.

Azure Monitor now has a dedicated enabled OpenAPI source for Insights ARM
definitions and shared resource-management types. Its scoped-source regressions
pass, accepting the documented Metrics definition while rejecting storage and
Monitor data-plane paths. Daily Monitor refresh now selects stable Metrics and Activity Logs; live catalog
imports remain unfinished. This configuration is included in the rebuilt local macOS archive after verification.

Monitor daily orchestration regressions pass: the combined mock catalog includes
both Metrics and Activity Logs, chooses stable definitions independently, and
rejects missing stable definitions, wrong inventory revisions and refresh
failures while preserving previous catalogs. Shell syntax and actionlint pass.

Additional Monitor publication regressions pass for empty catalogs, mismatched
source receipts, unrelated or malformed dependency paths, and Activity Logs
failure after Metrics succeeds. Both Monitor catalogs and the combined catalog
retain their previous contents. Shared ARM dependency receipts pass validation.
The release build and workflow lint pass. Live imports remain unverified.

The daily Monitor merge now adds stable Activity Log Alerts, Metric Alerts and
Scheduled Query Rules alongside Metrics and Activity Logs. Microsoft’s Insights
README lists these emitted definitions. The mock updater suite passes with all
five Monitor catalogs; a final Scheduled Query Rules failure preserves all
previous Monitor catalogs and the combined catalog. Shell syntax and actionlint
pass. No live alert import or execution has been verified. Updated release
documentation is included in the rebuilt local macOS archive after verification.

Monitor stable selection now groups emitted filenames with and without `_API`
suffixes before comparing versions. The updater regressions pass with both
modern Metrics/Metric Alerts definitions and an older pinned inventory containing
only `metrics_API.json` and `metricAlert_API.json`. Preview/example paths remain
excluded and catalog output names remain fixed. Workflow lint and shell syntax
pass; this does not establish live import or execution coverage.

Azure Resource Graph has an enabled scoped OpenAPI source for its official
ResourceGraph directory and shared ARM types. Source tests accept the stable
resourcegraph/graphquery definitions and reject unrelated paths. Daily updates
select each newest stable definition at the pinned Azure revision, validate
scoped receipts, and merge both staged catalogs. The mock orchestration suite
and actionlint pass. Live ingestion, query execution and hosted publishing
remain unverified; this source configuration is included in the rebuilt local macOS archive after verification.

Resource Graph publication regressions pass for missing stable definitions,
revision mismatches, empty catalogs, invalid source receipts, and saved-query
refresh failure after resource queries succeed. Both previous catalogs and the
default merged catalog are preserved. Release build and actionlint pass. Live
imports, hosted release and execution remain unverified.

Cost Management now has a scoped enabled OpenAPI source for the official
CostManagement directory and shared ARM types, excluding unrelated Billing
definitions. Source regressions pass. Daily orchestration selects the newest
stable consolidated `openapi.json` and adds its catalog to the staged merge.
The mock updater suite, shell syntax and workflow lint pass. Live imports,
execution and hosted publication remain unverified; the source configuration
is included in the rebuilt local macOS archive after verification.

Cost Management publication regressions pass: newest stable selection and shared
ARM dependency receipts validate; missing stable definitions, wrong revisions
or source receipts, empty catalogs, refresh failures and out-of-scope dependency
paths reject publication and preserve the previous Cost Management and combined
catalogs. The release build and actionlint pass. Live ingestion remains unverified.

The Rust executor now offers registry-backed `prepare_with_approval`, consuming
a trusted grant and validating the exact input against loaded referenced schemas
without credentials or transport. Regression tests accept a valid referenced
body and reject missing required fields, incorrect types and extra properties.
Both approved-preparation tests and runtime all-target Clippy pass. CLI/durable
approval issuance and approved LRO/pagination flows remain unfinished. The source
change is newer than the current local binary/archive.

Registry-backed approval preparation also rejects changed tenants, exact input,
explicit operation denies, read-only policy and policy limits. The three
approved-preparation regressions pass, runtime all-target Clippy passes and the
workspace check passes. These are Rust preparation checks, not proof of a CLI
operator approval flow or live approved execution.

Trusted hosts can now issue validated grants through `Executor::issue_approval`.
Registry selection, current policy and request construction/schema validation
precede grant issuance. The referenced-body regression verifies malformed bodies
reject issuance and still reject preparation with lower-level grants. All three
approved-preparation tests and runtime all-target Clippy pass. CLI confirmation,
durable approval storage and approved LRO execution remain unfinished.
