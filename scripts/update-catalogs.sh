#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
binary="${JUNCTION_BINARY:-target/release/junction}"
mkdir -p .junction generated/registry generated/manifests generated/types
staging="$(mktemp -d .junction/catalog-refresh.XXXXXX)"
trap 'rm -rf "$staging"' EXIT
mkdir -p "$staging/registry" "$staging/manifests" "$staging/types"
validate_catalog() {
  jq -e --arg revision "$2" --arg path "$3" --arg source "$4" --arg repository "$5" --arg scope "${6:-}" '
    (.operations | type == "array" and length > 0) and
    (.schemas["x-junction-refresh"] |
      .imported == 1 and
      (.documents | type == "array") and
      ((.dependencies // []) | type == "array" and length <= 255) and
      (.documents | length == 1 and .[0].status == "imported" and .[0].receipt.path == $path) and
      ([((.documents + (.dependencies // []))[] | .receipt.path)] | length == (unique | length)) and
      all((.dependencies // [])[]; .status == "dependency") and
      all((.documents + (.dependencies // []))[];
        (.status == "imported" or .status == "dependency") and
        .receipt.revision == $revision and .receipt.source == $source and
        (.receipt.path | type == "string" and
          (if $scope != "" then
            (startswith($scope + "/") or startswith("specification/common-types/resource-management/") or (($source == "azure-log-analytics-query" or $source == "azure-key-vault-data") and startswith("specification/common-types/data-plane/")))
          elif $source == "fabric" then
            (startswith("platform/") or startswith("admin/") or startswith("common/") or startswith("lakehouse/") or startswith("notebook/") or startswith("policySet/"))
          elif $source == "azure-cost-management" then
            (startswith("specification/cost-management/resource-manager/Microsoft.CostManagement/CostManagement/") or startswith("specification/common-types/resource-management/"))
          elif $source == "azure-resource-graph" then
            (startswith("specification/resourcegraph/resource-manager/Microsoft.ResourceGraph/ResourceGraph/") or startswith("specification/common-types/resource-management/"))
          elif $source == "azure-monitor" then
            (startswith("specification/monitor/resource-manager/Microsoft.Insights/Insights/") or startswith("specification/common-types/resource-management/"))
          elif $source == "purview" then
            (startswith("specification/purview/") or startswith("specification/common-types/resource-management/"))
          else (startswith("specification/") or startswith("openapi/")) end) and
          (contains("\\") or contains("?") or contains("#") | not) and
          (explode | all(. > 31 and . != 127)) and
          (split("/") | all(. != "" and . != "." and . != ".."))) and
        .receipt.upstream == ("https://raw.githubusercontent.com/" + $repository + "/" + $revision + "/" + .receipt.path) and
        (.receipt.sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
        (.receipt.bytes | type == "number" and . > 0 and . <= 134217728 and floor == .)))
  ' "$1" >/dev/null || return 1
}
# Resolve the default branch once so stable and beta share immutable provenance.
"$binary" discover graph --output "$staging/inventory.json"
revision="$(jq -er '.revision | select(test("^[0-9a-f]{40}$"))' "$staging/inventory.json")"
for api_version in v1.0 beta; do
  registry="$staging/registry/graph-${api_version}.json"
  "$binary" refresh graph --revision "$revision" \
    --path "openapi/${api_version}/openapi.yaml" --service graph \
    --max-documents 1 --output "$registry"
  validate_catalog "$registry" "$revision" "openapi/${api_version}/openapi.yaml" graph microsoftgraph/msgraph-metadata
  "$binary" --registry "$registry" api stats > "$staging/manifests/graph-${api_version}-stats.json"
  jq -e '.schemas["x-junction-refresh"]' "$registry" > "$staging/manifests/graph-${api_version}-refresh.json"
  jq -e '.schemas["x-junction-refresh"].documents[0].receipt' "$registry" > "$staging/manifests/graph-${api_version}-source.json"
done
# Azure DevOps Core is not refreshed: its upstream, MicrosoftDocs/vsts-rest-api-specs,
# was removed from GitHub (404 at every revision) and has no official replacement.
# Select the newest stable Resources definition from one pinned Azure inventory.
"$binary" discover azure-resources --output "$staging/azure-resources-inventory.json"
azure_revision="$(jq -er '.revision | select(test("^[0-9a-f]{40}$"))' "$staging/azure-resources-inventory.json")"
resources_path="$(jq -er '
  [.documents[].path | select(test("^specification/resources/resource-manager/Microsoft\\.Resources/resources/stable/[0-9]{4}-[0-9]{2}-[0-9]{2}/resources\\.json$"))]
  | sort | last | strings
' "$staging/azure-resources-inventory.json")"
resources_registry="$staging/registry/azure-resources.json"
"$binary" refresh azure-resources --revision "$azure_revision" \
  --path "$resources_path" --service resources --max-documents 256 --output "$resources_registry"
validate_catalog "$resources_registry" "$azure_revision" "$resources_path" azure-resources Azure/azure-rest-api-specs
"$binary" --registry "$resources_registry" api stats > "$staging/manifests/azure-resources-stats.json"
jq -e '.schemas["x-junction-refresh"]' "$resources_registry" > "$staging/manifests/azure-resources-refresh.json"
# Compute uses the same immutable Azure commit as Resources.
"$binary" discover azure-compute --revision "$azure_revision" --output "$staging/azure-compute-inventory.json"
if [[ "$(jq -er '.revision' "$staging/azure-compute-inventory.json")" != "$azure_revision" ]]; then
  echo 'Compute inventory revision does not match the pinned Azure commit.' >&2
  exit 1
fi
# Newer Compute versions consolidate VM operations into ComputeRP.json; older
# revisions only publish virtualMachine.json. Prefer the newest stable version.
compute_path="$(jq -er '
  [.documents[].path
   | select(test("^specification/compute/resource-manager/Microsoft\\.Compute/Compute/stable/[0-9]{4}-[0-9]{2}-[0-9]{2}/(ComputeRP|virtualMachine)\\.json$"))
   | {path: ., version: capture("/stable/(?<version>[0-9]{4}-[0-9]{2}-[0-9]{2})/").version, consolidated: endswith("/ComputeRP.json")}]
  | sort_by(.version, .consolidated) | last | .path | strings
' "$staging/azure-compute-inventory.json")"
compute_registry="$staging/registry/azure-compute.json"
"$binary" refresh azure-compute --revision "$azure_revision" \
  --path "$compute_path" --service compute --max-documents 256 --output "$compute_registry"
validate_catalog "$compute_registry" "$azure_revision" "$compute_path" azure-compute Azure/azure-rest-api-specs
"$binary" --registry "$compute_registry" api stats > "$staging/manifests/azure-compute-stats.json"
jq -e '.schemas["x-junction-refresh"]' "$compute_registry" > "$staging/manifests/azure-compute-refresh.json"
# Sentinel supports both the original split Swagger files and generated OpenAPI.
"$binary" discover sentinel --revision "$azure_revision" --output "$staging/sentinel-inventory.json"
if [[ "$(jq -er '.revision' "$staging/sentinel-inventory.json")" != "$azure_revision" ]]; then
  echo 'Sentinel inventory revision does not match the pinned Azure commit.' >&2
  exit 1
fi
sentinel_path="$(jq -er '
  [.documents[].path
   | select(test("^specification/securityinsights/resource-manager/Microsoft\\.SecurityInsights/(SecurityInsights/)?stable/[0-9]{4}-[0-9]{2}-[0-9]{2}/(Incidents|openapi)\\.json$"))
   | {path: ., version: capture("/stable/(?<version>[0-9]{4}-[0-9]{2}-[0-9]{2})/").version}]
  | sort_by(.version, .path) | last | .path | strings
' "$staging/sentinel-inventory.json")"
sentinel_registry="$staging/registry/sentinel.json"
"$binary" refresh sentinel --revision "$azure_revision" \
  --path "$sentinel_path" --service securityinsights --max-documents 256 --output "$sentinel_registry"
validate_catalog "$sentinel_registry" "$azure_revision" "$sentinel_path" sentinel Azure/azure-rest-api-specs
"$binary" --registry "$sentinel_registry" api stats > "$staging/manifests/sentinel-stats.json"
jq -e '.schemas["x-junction-refresh"]' "$sentinel_registry" > "$staging/manifests/sentinel-refresh.json"
# Purview control-plane definitions use the same pinned Azure commit.
"$binary" discover purview --revision "$azure_revision" --output "$staging/purview-inventory.json"
if [[ "$(jq -er '.revision' "$staging/purview-inventory.json")" != "$azure_revision" ]]; then
  echo 'Purview inventory revision does not match the pinned Azure commit.' >&2
  exit 1
fi
purview_path="$(jq -er '
  [.documents[].path
   | select(test("^specification/purview/resource-manager/Microsoft\\.Purview/(Purview/)?stable/[0-9]{4}-[0-9]{2}-[0-9]{2}/purview\\.json$"))
   | {path: ., version: capture("/stable/(?<version>[0-9]{4}-[0-9]{2}-[0-9]{2})/").version}]
  | sort_by(.version, .path) | last | .path | strings
' "$staging/purview-inventory.json")"
purview_registry="$staging/registry/purview-accounts.json"
"$binary" refresh purview --revision "$azure_revision" --path "$purview_path" \
  --service accounts --max-documents 256 --output "$purview_registry"
validate_catalog "$purview_registry" "$azure_revision" "$purview_path" purview Azure/azure-rest-api-specs
"$binary" --registry "$purview_registry" api stats > "$staging/manifests/purview-accounts-stats.json"
jq -e '.schemas["x-junction-refresh"]' "$purview_registry" > "$staging/manifests/purview-accounts-refresh.json"
# Cost Management control-plane definitions use the same pinned Azure commit.
"$binary" discover azure-cost-management --revision "$azure_revision" --output "$staging/cost_management-inventory.json"
if [[ "$(jq -er '.revision' "$staging/cost_management-inventory.json")" != "$azure_revision" ]]; then
  echo 'Cost Management inventory revision does not match the pinned Azure commit.' >&2
  exit 1
fi
cost_management_path="$(jq -er '
  [.documents[].path
   | select(test("^specification/cost-management/resource-manager/Microsoft\\.CostManagement/CostManagement/stable/[0-9]{4}-[0-9]{2}-[0-9]{2}/openapi\\.json$"))
   | {path: ., version: capture("/stable/(?<version>[0-9]{4}-[0-9]{2}-[0-9]{2})/").version}]
  | sort_by(.version, .path) | last | .path | strings
' "$staging/cost_management-inventory.json")"
cost_management_registry="$staging/registry/azure-cost-management.json"
"$binary" refresh azure-cost-management --revision "$azure_revision" --path "$cost_management_path" \
  --service cost_management --max-documents 256 --output "$cost_management_registry"
validate_catalog "$cost_management_registry" "$azure_revision" "$cost_management_path" azure-cost-management Azure/azure-rest-api-specs
"$binary" --registry "$cost_management_registry" api stats > "$staging/manifests/azure-cost-management-stats.json"
jq -e '.schemas["x-junction-refresh"]' "$cost_management_registry" > "$staging/manifests/azure-cost-management-refresh.json"
# Monitor definitions evolve independently: choose latest stable per workload.
"$binary" discover azure-monitor --revision "$azure_revision" --output "$staging/monitor-inventory.json"
if [[ "$(jq -er '.revision' "$staging/monitor-inventory.json")" != "$azure_revision" ]]; then
  echo 'Monitor inventory revision does not match the pinned Azure commit.' >&2
  exit 1
fi
monitor_registries=()
for monitor_document in metrics activityLogs activityLogAlerts_API metricAlert scheduledQueryRule_API; do
  monitor_path="$(jq -er --arg document "$monitor_document" '
    [.documents[].path
     | select(test("^specification/monitor/resource-manager/Microsoft\\.Insights/Insights/stable/[0-9]{4}-[0-9]{2}-[0-9]{2}/" + ($document | sub("_API$"; "")) + "(_API)?\\.json$"))
     | {path: ., version: capture("/stable/(?<version>[0-9]{4}-[0-9]{2}-[0-9]{2})/").version}]
    | sort_by(.version, .path) | last | .path | strings
  ' "$staging/monitor-inventory.json")"
  monitor_registry="$staging/registry/azure-monitor-${monitor_document}.json"
  "$binary" refresh azure-monitor --revision "$azure_revision" --path "$monitor_path" \
    --service monitor --max-documents 256 --output "$monitor_registry"
  validate_catalog "$monitor_registry" "$azure_revision" "$monitor_path" azure-monitor Azure/azure-rest-api-specs
  "$binary" --registry "$monitor_registry" api stats > "$staging/manifests/azure-monitor-${monitor_document}-stats.json"
  jq -e '.schemas["x-junction-refresh"]' "$monitor_registry" > "$staging/manifests/azure-monitor-${monitor_document}-refresh.json"
  monitor_registries+=("$monitor_registry")
done
# Resource Graph stable query and saved-query catalogs share the Azure revision.
"$binary" discover azure-resource-graph --revision "$azure_revision" --output "$staging/resource_graph-inventory.json"
if [[ "$(jq -er '.revision' "$staging/resource_graph-inventory.json")" != "$azure_revision" ]]; then
  echo 'Resource Graph inventory revision does not match the pinned Azure commit.' >&2
  exit 1
fi
resource_graph_registries=()
for resource_graph_document in resourcegraph graphquery; do
  resource_graph_path="$(jq -er --arg document "$resource_graph_document" '
    [.documents[].path
     | select(test("^specification/resourcegraph/resource-manager/Microsoft\\.ResourceGraph/ResourceGraph/stable/[0-9]{4}-[0-9]{2}-[0-9]{2}/" + ($document | sub("_API$"; "")) + "(_API)?\\.json$"))
     | {path: ., version: capture("/stable/(?<version>[0-9]{4}-[0-9]{2}-[0-9]{2})/").version}]
    | sort_by(.version, .path) | last | .path | strings
  ' "$staging/resource_graph-inventory.json")"
  resource_graph_registry="$staging/registry/azure-resource-graph-${resource_graph_document}.json"
  "$binary" refresh azure-resource-graph --revision "$azure_revision" --path "$resource_graph_path" \
    --service resource_graph --max-documents 256 --output "$resource_graph_registry"
  validate_catalog "$resource_graph_registry" "$azure_revision" "$resource_graph_path" azure-resource-graph Azure/azure-rest-api-specs
  "$binary" --registry "$resource_graph_registry" api stats > "$staging/manifests/azure-resource-graph-${resource_graph_document}-stats.json"
  jq -e '.schemas["x-junction-refresh"]' "$resource_graph_registry" > "$staging/manifests/azure-resource-graph-${resource_graph_document}-refresh.json"
  resource_graph_registries+=("$resource_graph_registry")
done
# Additional ARM workloads: source|service|provider scope|stable document names.
# Each document independently selects its newest stable version at the shared
# Azure revision; receipts must stay inside the provider scope or shared types.
arm_workloads=(
  "azure-log-analytics|log_analytics|specification/operationalinsights/resource-manager/Microsoft.OperationalInsights/OperationalInsights|openapi"
  "azure-arc|arc|specification/hybridcompute/resource-manager/Microsoft.HybridCompute/HybridCompute|openapi"
  "azure-lighthouse|lighthouse|specification/managedservices/resource-manager/Microsoft.ManagedServices/ManagedServices|managedservices"
  "defender-for-cloud|cloud|specification/security/resource-manager/Microsoft.Security/Security|alerts assessments pricings secureScore"
  "azure-storage|storage|specification/storage/resource-manager/Microsoft.Storage/Storage|openapi"
  "azure-key-vault|key_vault|specification/keyvault/resource-manager/Microsoft.KeyVault/KeyVault|openapi"
  "azure-network|network|specification/network/resource-manager/Microsoft.Network/Network|virtualNetwork loadBalancer firewall applicationGateway networkWatcher"
  "azure-application-insights|application_insights|specification/applicationinsights/resource-manager/Microsoft.Insights/ApplicationInsights|components_API workbooks_API"
  "azure-key-vault-data|key_vault_keys|specification/keyvault/data-plane/Keys|keys|azure-key-vault-keys"
  "azure-key-vault-data|key_vault_secrets|specification/keyvault/data-plane/Secrets|secrets|azure-key-vault-secrets"
  "azure-key-vault-data|key_vault_certificates|specification/keyvault/data-plane/Certificates|certificates|azure-key-vault-certificates"
)
arm_registries=()
for workload in "${arm_workloads[@]}"; do
  IFS='|' read -r arm_source arm_service arm_scope arm_documents arm_label <<< "$workload"
  "$binary" discover "$arm_source" --revision "$azure_revision" --output "$staging/${arm_source}-inventory.json"
  if [[ "$(jq -er '.revision' "$staging/${arm_source}-inventory.json")" != "$azure_revision" ]]; then
    echo "${arm_source} inventory revision does not match the pinned Azure commit." >&2
    exit 1
  fi
  for arm_document in $arm_documents; do
    if ! arm_path="$(jq -er --arg scope "$arm_scope" --arg document "$arm_document" '
      [.documents[].path
       | select(startswith($scope + "/stable/") and test("/stable/[0-9]{4}-[0-9]{2}-[0-9]{2}/" + $document + "\\.json$"))
       | {path: ., version: capture("/stable/(?<version>[0-9]{4}-[0-9]{2}-[0-9]{2})/").version}]
      | sort_by(.version, .path) | last | .path | strings
    ' "$staging/${arm_source}-inventory.json")"; then
      echo "No stable ${arm_document}.json for ${arm_source} under ${arm_scope}." >&2
      exit 1
    fi
    arm_name="${arm_label:-$arm_source}"
    [[ "$arm_documents" == "$arm_document" ]] || arm_name="${arm_name}-${arm_document}"
    arm_registry="$staging/registry/${arm_name}.json"
    "$binary" refresh "$arm_source" --revision "$azure_revision" --path "$arm_path" \
      --service "$arm_service" --max-documents 256 --output "$arm_registry"
    validate_catalog "$arm_registry" "$azure_revision" "$arm_path" "$arm_source" Azure/azure-rest-api-specs "$arm_scope"
    "$binary" --registry "$arm_registry" api stats > "$staging/manifests/${arm_name}-stats.json"
    jq -e '.schemas["x-junction-refresh"]' "$arm_registry" > "$staging/manifests/${arm_name}-refresh.json"
    arm_registries+=("$arm_registry")
  done
done
# Log Analytics query data plane shares the pinned Azure revision.
"$binary" discover azure-log-analytics-query --revision "$azure_revision" --output "$staging/azure-log-analytics-query-inventory.json"
log_query_path='specification/monitor/data-plane/OperationalInsights/stable/v1/OperationalInsights.json'
jq -e --arg revision "$azure_revision" --arg path "$log_query_path" \
  '.revision == $revision and any(.documents[]; .path == $path)' \
  "$staging/azure-log-analytics-query-inventory.json" >/dev/null
log_query_registry="$staging/registry/azure-log-analytics-query.json"
"$binary" refresh azure-log-analytics-query --revision "$azure_revision" --path "$log_query_path" \
  --service log_analytics_query --max-documents 256 --output "$log_query_registry"
validate_catalog "$log_query_registry" "$azure_revision" "$log_query_path" azure-log-analytics-query Azure/azure-rest-api-specs specification/monitor/data-plane/OperationalInsights
"$binary" --registry "$log_query_registry" api stats > "$staging/manifests/azure-log-analytics-query-stats.json"
jq -e '.schemas["x-junction-refresh"]' "$log_query_registry" > "$staging/manifests/azure-log-analytics-query-refresh.json"
# Power BI publishes its REST swagger in Microsoft's .NET SDK repository.
"$binary" discover power-bi --output "$staging/power-bi-inventory.json"
power_bi_revision="$(jq -er '.revision | select(test("^[0-9a-f]{40}$"))' "$staging/power-bi-inventory.json")"
power_bi_registry="$staging/registry/power-bi.json"
"$binary" refresh power-bi --revision "$power_bi_revision" --path sdk/swaggers/swagger.json \
  --service rest --max-documents 16 --output "$power_bi_registry"
validate_catalog "$power_bi_registry" "$power_bi_revision" sdk/swaggers/swagger.json power-bi microsoft/PowerBI-CSharp sdk/swaggers
"$binary" --registry "$power_bi_registry" api stats > "$staging/manifests/power-bi-stats.json"
jq -e '.schemas["x-junction-refresh"]' "$power_bi_registry" > "$staging/manifests/power-bi-refresh.json"
# APIs without official OpenAPI are extracted from Microsoft Learn reference
# pages listed in each product's toc.json, with a SHA-256 receipt per page.
docs_registries=()
for docs_source in defender defender-endpoint defender-cloud-apps power-platform office-365-management; do
  docs_registry="$staging/registry/${docs_source}.json"
  "$binary" refresh "$docs_source" --output "$docs_registry"
  upstream="$(jq -er --arg id "$docs_source" '.sources[] | select(.id == $id) | .upstream' <("$binary" sources))"
  jq -e --arg source "$docs_source" --arg upstream "$upstream" '
    (.operations | type == "array" and length > 0) and
    (.schemas["x-junction-refresh"] |
      .kind == "documentation" and (.revision | test("^[0-9a-f]{64}$")) and
      (.documents | type == "array" and length > 0 and length == (map(.receipt.path) | unique | length)) and
      all(.documents[]; .status == "imported" and .receipt.source == $source and
        (.receipt.upstream | startswith($upstream)) and
        (.receipt.sha256 | test("^[0-9a-f]{64}$")) and
        (.receipt.bytes | type == "number" and . > 0 and . <= 4194304)))
  ' "$docs_registry" >/dev/null
  "$binary" --registry "$docs_registry" api stats > "$staging/manifests/${docs_source}-stats.json"
  jq -e '.schemas["x-junction-refresh"]' "$docs_registry" > "$staging/manifests/${docs_source}-refresh.json"
  docs_registries+=("$docs_registry")
done
# Fabric Platform has an independent immutable Microsoft repository revision.
"$binary" discover fabric --output "$staging/fabric-inventory.json"
fabric_revision="$(jq -er '.revision | select(test("^[0-9a-f]{40}$"))' "$staging/fabric-inventory.json")"
fabric_registry="$staging/registry/fabric-platform.json"
"$binary" refresh fabric --revision "$fabric_revision" --path platform/swagger.json \
  --service platform --max-documents 256 --output "$fabric_registry"
validate_catalog "$fabric_registry" "$fabric_revision" platform/swagger.json fabric microsoft/fabric-rest-api-specs
"$binary" --registry "$fabric_registry" api stats > "$staging/manifests/fabric-platform-stats.json"
jq -e '.schemas["x-junction-refresh"]' "$fabric_registry" > "$staging/manifests/fabric-platform-refresh.json"
# Admin is refreshed from the same Fabric commit as Platform.
fabric_admin_registry="$staging/registry/fabric-admin.json"
"$binary" refresh fabric --revision "$fabric_revision" --path admin/swagger.json \
  --service admin --max-documents 256 --output "$fabric_admin_registry"
validate_catalog "$fabric_admin_registry" "$fabric_revision" admin/swagger.json fabric microsoft/fabric-rest-api-specs
"$binary" --registry "$fabric_admin_registry" api stats > "$staging/manifests/fabric-admin-stats.json"
jq -e '.schemas["x-junction-refresh"]' "$fabric_admin_registry" > "$staging/manifests/fabric-admin-refresh.json"
fabric_workload_registries=()
for fabric_service in lakehouse notebook; do
  workload_registry="$staging/registry/fabric-${fabric_service}.json"
  "$binary" refresh fabric --revision "$fabric_revision" --path "${fabric_service}/swagger.json" \
    --service "$fabric_service" --max-documents 256 --output "$workload_registry"
  validate_catalog "$workload_registry" "$fabric_revision" "${fabric_service}/swagger.json" fabric microsoft/fabric-rest-api-specs
  "$binary" --registry "$workload_registry" api stats > "$staging/manifests/fabric-${fabric_service}-stats.json"
  jq -e '.schemas["x-junction-refresh"]' "$workload_registry" > "$staging/manifests/fabric-${fabric_service}-refresh.json"
  fabric_workload_registries+=("$workload_registry")
done
# Generate a bounded selection of stable common Graph structures plus references.
schema_arguments=()
while IFS= read -r schema_name; do
  [[ -n "$schema_name" ]] || continue
  reference="$(jq -er --arg name "$schema_name" '
    [.schemas.canonical | keys[] | select(endswith("/" + $name) or endswith("." + $name))]
    | if length == 1 then .[0] else error("common schema must resolve uniquely") end
  ' "$staging/registry/graph-v1.0.json")"
  schema_arguments+=(--schema "$reference")
done < generators/graph/common-schema-names.txt
"$binary" --registry "$staging/registry/graph-v1.0.json" generate-rust \
  "${schema_arguments[@]}" --output "$staging/types/graph-common.rs" \
  > "$staging/manifests/graph-common-types.json"
"$binary" openapi --output "$staging/manifests/junction-openapi.json"
jq -e '.openapi == "3.1.1" and (.info.version | type == "string") and (.paths | type == "object")' \
  "$staging/manifests/junction-openapi.json" >/dev/null
# Publish only after every refresh and validation succeeds. Beta stays opt-in.
"$binary" merge "$staging/registry/graph-v1.0.json" "$resources_registry" "$compute_registry" "$sentinel_registry" "$purview_registry" "$cost_management_registry" "${monitor_registries[@]}" "${resource_graph_registries[@]}" "${arm_registries[@]}" "$log_query_registry" "$power_bi_registry" "${docs_registries[@]}" "$fabric_registry" "$fabric_admin_registry" "${fabric_workload_registries[@]}" \
  --output "$staging/registry/operations.json"
"$binary" --registry "$staging/registry/operations.json" api stats > "$staging/manifests/operations-stats.json"
cp "$staging/registry/"*.json generated/registry/
cp "$staging/manifests/"*.json generated/manifests/
cp "$staging/types/"*.rs generated/types/
