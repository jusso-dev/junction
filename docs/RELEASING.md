# Automated releases

The project uses the MIT license and targets the public personal repository `jusso-dev/junction`. This workspace has not yet been published to GitHub.

`.github/workflows/ci.yml` checks pushes and pull requests. `daily-release.yml` runs daily at 02:17 UTC and can be started manually. Its repository guard restricts release writes to `jusso-dev/junction`. Before preparing a version and again before publishing, the workflow queries GitHub and requires a public, active, MIT-licensed repository owned by the personal `jusso-dev` user. Missing or mismatched metadata stops the release. This check does not create the repository or change its visibility. GitHub scheduling can be delayed.

The daily job fetches commit-pinned Microsoft Graph v1.0 and beta OpenAPI documents, validates and imports them, and records source revisions, SHA-256 digests, and catalog statistics. It also generates common Graph email-address, recipient, phone and date/time Rust/Serde types, including referenced schemas. Generation failure aborts catalog publication. The bundled default merges stable Graph with Azure DevOps Core 7.1, Azure Resources and Azure Compute virtual machine operations and Sentinel SecurityInsights. Each Microsoft repository is pinned independently; Compute, Resources and Sentinel share the same Azure commit. Resources selects the newest stable date-versioned resources.json from its scoped inventory; Compute selects the newest stable virtualMachine.json and excludes example paths. DevOps operation-level preview versions remain gated by `--allow-preview`; Graph beta is a separate registry. DevOps, Azure Resources, Compute, Sentinel and merge failures abort before publication; an inventory without a stable Resources definition also aborts. Broader Azure and other product catalogs still need expansion. DevOps Core and Azure Resources refreshes are configured and orchestration-tested, but live native retrieval remains unverified in this environment.

After validation, the workflow increments the workspace patch version and commits Cargo.toml, Cargo.lock, and source manifests to the default branch. Linux, macOS, and Windows runners test and build the prepared commit. Each archive includes the native binary with `junction tui`, the Ratatui copyright/license notice, catalogs, generated/types/graph-common.rs, the type-name/fallback report, source receipts, license, documentation, examples, VERSION, and TARGET files. Packaging also exports generated/manifests/junction-openapi.json from that binary so the local API contract version matches the release. The binary includes authenticated localhost HTTP serving; its separate server token is supplied through an environment variable. Archives and SHA-256 checksums are uploaded as Actions artifacts with 30-day retention. Successful builds are tagged and attached to a GitHub prerelease for persistent downloads. These releases reflect the implementation in development, not completion of the full specification.

The repository must allow the workflow token to write contents and push the default branch; branch rules must permit these automated commits. A failed build after the version commit leaves that version consumed, so later releases may have patch-number gaps. Tags are never overwritten.

Extract an archive and run the binary from its root so the default `generated/registry/operations.json` resolves. On Unix:

```sh
./junction api stats
./junction search users
./junction --registry generated/registry/graph-beta.json describe graph.users.list --allow-preview
```

On Windows use `junction.exe`. This workflow produces each runner's native Rust target; the TARGET file and archive name identify the architecture.

To prepare a local package:

```sh
cargo build --release --locked -p junction
bash scripts/update-catalogs.sh
bash scripts/package-release.sh 0.1.0 "$(rustc -vV | sed -n 's/^host: //p')" macos
```

Use `linux` or `windows` for other platforms. The Windows workflow creates ZIPs with PowerShell after the packaging script prepares the directory. Updating catalogs requires GitHub network access. Local release compilation, stable Graph import, packaging, workflow syntax, formatting, Clippy, and sandbox-compatible tests were verified; live beta retrieval and GitHub-hosted matrix execution remain unverified.

Packaging checks that the binary reports the requested version and refuses an existing package directory, preventing stale files from entering a release. For a repeated local build, move the earlier package directory out of `dist` first.

Before publishing, the daily workflow requires one native archive per platform
and verifies each SHA-256 checksum. Checksums must name the exact archive basename;
Linux/macOS LF and Windows CRLF checksum files are accepted. A retry after tag
creation reuses the remote tag only when it resolves to the prepared commit.
A tag pointing to another commit stops publication. Published releases and assets
are not overwritten by this workflow. The asset validation tests run in both CI
and daily preparation; tag recovery still needs GitHub-hosted verification.

The common schema selection is maintained in `generators/graph/common-schema-names.txt`. Names must resolve uniquely in the stable catalog. Generated modules require Serde's derive feature and serde_json; the report maps canonical references to generated Rust identifiers and lists dynamic JSON fallbacks. Complete validation still uses retained schema constraints. Generation and offline compilation were verified against the existing cached official Graph catalog; the hosted daily pipeline remains unverified.

Daily receipt validation also requires the expected source ID and exact official raw GitHub URL containing the pinned commit and selected path. SHA-256 must be 64 lowercase hexadecimal characters, and download size must be a positive integer within the fetcher's 128 MiB bound. These are receipt consistency checks; the Rust fetcher computes the digest from downloaded bytes. Tests reject altered source/URL, malformed or missing digest, zero/oversized/fractional/string sizes, and preserve prior catalogs before publication.

Sentinel selects the newest stable date from split `Incidents.json` or generated
`SecurityInsights/stable/<date>/openapi.json` definitions in its official scoped
inventory. Selection excludes preview and example paths and verifies the shared
Azure revision. Receipts must match the selected path and commit; empty catalogs
or failed refreshes abort before publishing staged outputs. The generated layout
is documented in the [official Microsoft specification](https://github.com/Azure/azure-rest-api-specs/tree/main/specification/securityinsights/resource-manager/Microsoft.SecurityInsights/SecurityInsights/stable/2025-09-01).
Orchestration is tested locally; live native Sentinel retrieval remains unverified.
The Sentinel source explicitly permits `specification/common-types/resource-management`
for its shared ARM parameter/schema dependencies. Unrelated service paths stay outside
that source's permitted scope.

Compute and Resources likewise permit shared ARM schemas under
`specification/common-types/resource-management`. Refresh reports retain dependency
receipts separately from imported API documents. The daily updater validates both:
dependency receipts must retain the pinned revision, source, immutable upstream,
SHA-256 digest and bounded integer byte count. A bad dependency receipt aborts
publication and preserves the previous catalogs.
Receipt collections must be arrays with unique paths; dependency counts are
bounded to 255 per imported document. Paths reject empty, dot and parent segments,
backslashes, query/fragment delimiters and control characters. Orchestration tests
also reject corrupted dependency sources, upstream URLs, hashes and byte counts
before any existing catalog is replaced.

Fabric Platform, Admin, Lakehouse and Notebook daily refresh pins `microsoft/fabric-rest-api-specs` independently
and imports the Platform, Admin, Lakehouse and Notebook `swagger.json` documents
from the same commit,
with permitted platform/admin/common schema dependencies. Each catalog gets separate
statistics and a refresh report before all four are merged into the default registry. Failed refreshes, empty catalogs and invalid receipts abort staged
publication. Live native Fabric retrieval and execution remain unverified.

Fabric receipt paths must stay inside the configured Platform, Admin, Lakehouse,
Notebook or Common directories. A matching upstream URL does not permit a receipt
from an unrelated directory. Orchestration tests reject out-of-scope and malformed
Notebook dependency paths before replacing any of the four Fabric catalogs.

Purview Accounts control-plane refresh selects the newest stable `purview.json`
from the pinned Azure inventory, supporting both legacy and nested Purview paths.
Preview definitions remain excluded. Data-plane Purview catalogs and live refresh
verification remain outstanding.

The daily updater also imports Azure Monitor Metrics and Activity Logs from the
newest stable definition of each workload at the pinned Azure revision. It
excludes preview and example paths, validates scoped receipts, and stages both
catalogs before the combined catalog is published. Additional Monitor workloads
and live/hosted verification remain unfinished.

Monitor daily coverage also includes Activity Log Alerts (`activityLogAlerts_API.json`),
Metric Alerts (`metricAlert.json`) and Scheduled Query Rules
(`scheduledQueryRule_API.json`). Each workload selects its newest stable version across emitted Swagger
filenames with and without the `_API` suffix, retaining fixed output catalog names. Live imports remain unverified.

Azure Resource Graph daily coverage includes resource queries (`resourcegraph.json`)
and saved queries (`graphquery.json`), selecting each newest stable version at
the shared Azure revision. Preview resource history/change definitions remain
outside this stable update stage. Live ingestion and execution remain unverified.

Cost Management daily updates select the newest stable consolidated `openapi.json`
at the pinned Azure revision, validate product-scoped receipts and stage its
catalog in the default merge. Older split-file packages remain available for
manual scoped refresh; they are not the daily selection. Live ingestion and
execution remain unverified.
