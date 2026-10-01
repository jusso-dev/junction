# Official source catalog

Fabric uses the [official Microsoft Swagger repository](https://github.com/microsoft/fabric-rest-api-specs)
with enabled Platform, Admin, Lakehouse, Notebook and common scopes. Shared
references resolve inside those scopes at the same pinned revision. Daily refresh
includes all four workload catalogs; live ingestion and execution remain unverified.

Source configuration is validated with `junction sources`. These records identify upstream definitions, not complete ingestion coverage. Official GitHub OpenAPI and OData documents can be fetched at immutable revisions. `graph-odata.toml` points to Graph's stable CSDL metadata; its native adapter currently imports schemas, collection reads, singleton reads, and unbound action/function imports. Documentation sources remain disabled until a structured adapter exists.

`clouds` lists verified availability of this source configuration, not a declaration that the product is unavailable in other clouds. Sovereign source availability still requires verification.

Origin validation checks exact HTTPS hosts and approved Microsoft GitHub owners. The fetcher rejects redirects, enforces size/time limits, and records source revision and SHA-256 receipts. CSDL XML references are never fetched. Origin ownership does not guarantee that every operation in a repository is a public Microsoft API; ingestion must also filter public Microsoft endpoints.

Azure and Graph repositories supply multiple product catalogs. Product-specific filtering and canonical aliases remain to be implemented so M365/Intune do not duplicate the entire Graph catalog.

Fabric discovery includes the official Platform, Admin, Lakehouse and Notebook
OpenAPI directories and their common schemas. Daily refresh imports all four catalogs from one pinned Fabric revision. Live
retrieval and execution remain unverified.

Purview's source scope includes its official service directory and shared ARM
resource-management definitions so control-plane references can be resolved.
Unrelated Azure service directories remain outside that source scope. Daily refresh selects the newest stable Purview control-plane definition from
the pinned Azure inventory. Live retrieval remains unverified.

`azure-monitor.toml` scopes manual discovery/refresh to the official
[Monitor Insights ARM definitions](https://github.com/Azure/azure-rest-api-specs/tree/main/specification/monitor/resource-manager/Microsoft.Insights/Insights)
and shared ARM types. Metrics, activity logs, alerts and other emitted Swagger
files can be selected beneath that scope. Monitor data-plane APIs are outside
this configuration. Daily refresh independently selects the newest stable Metrics, Activity Logs, Activity Log Alerts, Metric Alerts and
Scheduled Query Rules definitions at the shared Azure revision. Live ingestion remains pending.

`azure-resource-graph.toml` enables scoped discovery/refresh of Microsoft's
[Resource Graph ARM definitions](https://github.com/Azure/azure-rest-api-specs/tree/main/specification/resourcegraph/resource-manager/Microsoft.ResourceGraph/ResourceGraph)
and shared ARM types. The upstream stable configuration includes
`resourcegraph.json` and `graphquery.json`; its preview history/change definitions
are not stable catalog coverage. Daily updates select each stable query definition at the shared Azure revision;
live ingestion remains pending.

`azure-cost-management.toml` scopes discovery/refresh to Microsoft's
[Cost Management ARM definitions](https://github.com/Azure/azure-rest-api-specs/tree/main/specification/cost-management/resource-manager/Microsoft.CostManagement/CostManagement)
and shared ARM types. The upstream stable 2025/2026 packages emit a consolidated
`openapi.json`; earlier packages use multiple Swagger files. Daily updates select the newest stable consolidated definition at the shared
Azure revision; live ingestion remains pending. Billing is outside this source scope.

`azure-log-analytics.toml`, `azure-arc.toml`, `azure-lighthouse.toml` and
`defender-for-cloud.toml` scope Microsoft's Log Analytics
(`Microsoft.OperationalInsights`), Azure Arc Hybrid Compute
(`Microsoft.HybridCompute`), Lighthouse (`Microsoft.ManagedServices`) and
Defender for Cloud (`Microsoft.Security`) ARM definitions plus shared ARM types.
The daily updater selects the newest stable document per workload at the shared
Azure revision (Defender for Cloud: alerts, assessments, pricings, secure score)
and rejects receipts outside each provider scope. Operation IDs use
`azure.log_analytics.*`, `azure.arc.*`, `azure.lighthouse.*` and
`defender.cloud.*`.

Large repositories are enumerated by listing each configured scope with one
recursive GitHub tree request (falling back to level-by-level listing when
GitHub truncates or the response exceeds 8 MiB). An optional `GITHUB_TOKEN`
environment variable is sent only to `api.github.com` metadata requests to avoid
anonymous rate limits; raw document downloads remain unauthenticated.

Some official definitions reference shared directories with the wrong letter
case (Fabric's `../../Common/definitions.json` for `common/`). Refresh maps such a
reference onto exactly one configured scope by ASCII case and records the
receipt under the canonical path.
