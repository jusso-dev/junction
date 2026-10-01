#!/usr/bin/env bash
# Exercise orchestration without network access or a prebuilt Rust binary.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
test_directory="$(mktemp -d)"
trap 'rm -rf "$test_directory"' EXIT
mkdir -p "$test_directory/scripts" "$test_directory/generators/graph"
cp "$root/generators/graph/common-schema-names.txt" "$test_directory/generators/graph/"
cp "$root/scripts/update-catalogs.sh" "$test_directory/scripts/"
cat > "$test_directory/mock-junction" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> calls.txt
if [[ "$1" == '--registry' ]]; then
  jq -e '.operations | length > 0' "$2" >/dev/null
  if [[ "$3" == 'generate-rust' ]]; then
    if [[ "${FAIL_GENERATION:-0}" == '1' ]]; then exit 1; fi
    shift 3
    while (( $# )); do
      if [[ "$1" == '--output' ]]; then
        echo 'pub struct Example;' > "$2"
        break
      fi
      shift
    done
    echo '{"status":"generated","types":{},"dynamic":[]}'
  else
    echo '{"operations":1}'
  fi
  exit
fi
command="$1"
source="${2:-}"
shift
output=''
path=''
revision=''
merge_inputs=()
while (( $# )); do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --path) path="$2"; shift 2 ;;
    --revision) revision="$2"; shift 2 ;;
    *) if [[ "$command" == 'merge' ]]; then merge_inputs+=("$1"); fi; shift ;;
  esac
done
if [[ "$command" == 'openapi' ]]; then
  if [[ "${FAIL_OPENAPI:-0}" == '1' ]]; then exit 1; fi
  if [[ "${INVALID_OPENAPI:-0}" == '1' ]]; then echo '{}' > "$output"; exit; fi
  echo '{"openapi":"3.1.1","info":{"version":"0.1.0"},"paths":{}}' > "$output"
elif [[ "$command" == 'merge' ]]; then
  if [[ "${FAIL_MERGE:-0}" == '1' ]]; then exit 1; fi
  jq -s '{operations:map(.operations[]) , schemas:{}}' "${merge_inputs[@]}" > "$output"
elif [[ "$command" == 'discover' ]]; then
  if [[ "$source" == 'azure-compute' ]]; then
    [[ "$revision" == 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ]]
    if [[ "${NO_STABLE_COMPUTE:-0}" == '1' ]]; then
      echo '{"revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","documents":[]}' > "$output"
    else
      echo '{"revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","documents":[{"path":"specification/compute/resource-manager/Microsoft.Compute/Compute/stable/2023-09-01/virtualMachine.json"},{"path":"specification/compute/resource-manager/Microsoft.Compute/Compute/stable/2024-07-01/virtualMachine.json"},{"path":"specification/compute/resource-manager/Microsoft.Compute/Compute/stable/2024-07-01/ComputeRP.json"},{"path":"specification/compute/resource-manager/Microsoft.Compute/Compute/stable/2024-03-01/ComputeRP.json"},{"path":"specification/compute/resource-manager/Microsoft.Compute/Compute/preview/2099-01-01-preview/virtualMachine.json"},{"path":"specification/compute/resource-manager/Microsoft.Compute/Compute/preview/2099-01-01-preview/ComputeRP.json"},{"path":"specification/compute/resource-manager/Microsoft.Compute/Compute/stable/2099-01-01/examples/virtualMachine.json"}]}' > "$output"
    fi
    if [[ "${WRONG_COMPUTE_INVENTORY:-0}" == '1' ]]; then
      jq '.revision = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' "$output" > "$output.changed"
      mv "$output.changed" "$output"
    fi
  elif [[ "$source" == 'sentinel' ]]; then
    [[ "$revision" == 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ]]
    if [[ "${NO_STABLE_SENTINEL:-0}" == '1' ]]; then
      echo '{"revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","documents":[]}' > "$output"
    else
      echo '{"revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","documents":[{"path":"specification/securityinsights/resource-manager/Microsoft.SecurityInsights/stable/2024-03-01/Incidents.json"},{"path":"specification/securityinsights/resource-manager/Microsoft.SecurityInsights/SecurityInsights/stable/2025-09-01/openapi.json"},{"path":"specification/securityinsights/resource-manager/Microsoft.SecurityInsights/SecurityInsights/preview/2099-01-01-preview/openapi.json"},{"path":"specification/securityinsights/resource-manager/Microsoft.SecurityInsights/SecurityInsights/stable/2099-01-01/examples/openapi.json"}]}' > "$output"
    fi
    if [[ "${WRONG_SENTINEL_INVENTORY:-0}" == '1' ]]; then
      jq '.revision = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' "$output" > "$output.changed"
      mv "$output.changed" "$output"
    fi
  elif [[ "$source" =~ ^(azure-log-analytics|azure-arc|azure-lighthouse|defender-for-cloud)$ ]]; then
    [[ "$revision" == 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ]]
    case "$source" in
      azure-log-analytics) scope='specification/operationalinsights/resource-manager/Microsoft.OperationalInsights/OperationalInsights'; names='openapi' ;;
      azure-arc) scope='specification/hybridcompute/resource-manager/Microsoft.HybridCompute/HybridCompute'; names='openapi' ;;
      azure-lighthouse) scope='specification/managedservices/resource-manager/Microsoft.ManagedServices/ManagedServices'; names='managedservices' ;;
      defender-for-cloud) scope='specification/security/resource-manager/Microsoft.Security/Security'; names='alerts assessments pricings secureScore' ;;
    esac
    jq -n --arg scope "$scope" --arg names "$names" '{revision:("a" * 40),documents:([$names | split(" ")[] as $name | ("stable/2020-01-01/" + $name + ".json"), ("stable/2025-01-01/" + $name + ".json"), ("preview/2099-01-01-preview/" + $name + ".json"), ("stable/2099-01-01/examples/" + $name + ".json")] | map({path:($scope + "/" + .)}))}' > "$output"
    if [[ "${NO_STABLE_ARM:-}" == "$source" ]]; then jq '.documents = []' "$output" > "$output.changed"; mv "$output.changed" "$output"; fi
    if [[ "${WRONG_ARM_INVENTORY:-}" == "$source" ]]; then jq '.revision = ("b" * 40)' "$output" > "$output.changed"; mv "$output.changed" "$output"; fi
  elif [[ "$source" == 'azure-cost-management' ]]; then
    [[ "$revision" == 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ]]
    jq -n '{revision:("a" * 40),documents:(["stable/2025-03-01/openapi.json","stable/2026-06-01/openapi.json","preview/2099-01-01-preview/openapi.json"] | map({path:("specification/cost-management/resource-manager/Microsoft.CostManagement/CostManagement/" + .)}))}' > "$output"
    if [[ "${NO_STABLE_COST:-0}" == '1' ]]; then jq '.documents = []' "$output" > "$output.changed"; mv "$output.changed" "$output"; fi
    if [[ "${WRONG_COST_INVENTORY:-0}" == '1' ]]; then jq '.revision = ("b" * 40)' "$output" > "$output.changed"; mv "$output.changed" "$output"; fi
  elif [[ "$source" == 'azure-resource-graph' ]]; then
    [[ "$revision" == 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ]]
    jq -n '{revision:("a" * 40),documents:(["stable/2021-03-01/resourcegraph.json","stable/2024-04-01/resourcegraph.json","stable/2024-04-01/graphquery.json","preview/2099-01-01-preview/resourcegraph.json"] | map({path:("specification/resourcegraph/resource-manager/Microsoft.ResourceGraph/ResourceGraph/" + .)}))}' > "$output"
    if [[ "${NO_STABLE_RESOURCE_GRAPH:-0}" == '1' ]]; then jq '.documents = []' "$output" > "$output.changed"; mv "$output.changed" "$output"; fi
    if [[ "${WRONG_RESOURCE_GRAPH_INVENTORY:-0}" == '1' ]]; then jq '.revision = ("b" * 40)' "$output" > "$output.changed"; mv "$output.changed" "$output"; fi
  elif [[ "$source" == 'azure-monitor' ]]; then
    [[ "$revision" == 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ]]
    jq -n '{revision:("a" * 40),documents:(["stable/2021-05-01/metrics_API.json","stable/2018-03-01/metricAlert_API.json","stable/2023-01-01/metrics.json","stable/2024-02-01/metrics.json","stable/2015-04-01/activityLogs.json","stable/2026-01-01/activityLogAlerts_API.json","stable/2026-01-01/metricAlert.json","stable/2026-03-01/scheduledQueryRule_API.json","preview/2099-01-01-preview/metricAlert.json","preview/2099-01-01-preview/metrics.json","stable/2099-01-01/examples/metrics.json"] | map({path:("specification/monitor/resource-manager/Microsoft.Insights/Insights/" + .)}))}' > "$output"
    if [[ "${LEGACY_MONITOR_ONLY:-0}" == '1' ]]; then
      jq '.documents |= map(select((.path | endswith("/metrics.json") or endswith("/metricAlert.json")) | not))' "$output" > "$output.changed"; mv "$output.changed" "$output"
    fi
    if [[ "${NO_STABLE_MONITOR:-0}" == '1' ]]; then jq '.documents = []' "$output" > "$output.changed"; mv "$output.changed" "$output"; fi
    if [[ "${WRONG_MONITOR_INVENTORY:-0}" == '1' ]]; then jq '.revision = ("b" * 40)' "$output" > "$output.changed"; mv "$output.changed" "$output"; fi
  elif [[ "$source" == 'purview' ]]; then
    [[ "$revision" == 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ]]
    echo '{"revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","documents":[{"path":"specification/purview/resource-manager/Microsoft.Purview/Purview/stable/2021-12-01/purview.json"},{"path":"specification/purview/resource-manager/Microsoft.Purview/Purview/preview/2099-01-01-preview/purview.json"}]}' > "$output"
    if [[ "${NO_STABLE_PURVIEW:-0}" == '1' ]]; then jq '.documents = []' "$output" > "$output.changed"; mv "$output.changed" "$output"; fi
    if [[ "${WRONG_PURVIEW_INVENTORY:-0}" == '1' ]]; then jq '.revision = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' "$output" > "$output.changed"; mv "$output.changed" "$output"; fi
  elif [[ "$source" == 'azure-resources' ]]; then
    if [[ "${NO_STABLE_AZURE:-0}" == '1' ]]; then
      echo '{"revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","documents":[]}' > "$output"
    else
      echo '{"revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","documents":[{"path":"specification/resources/resource-manager/Microsoft.Resources/resources/stable/2019-10-01/resources.json"},{"path":"specification/resources/resource-manager/Microsoft.Resources/resources/stable/2021-04-01/resources.json"},{"path":"specification/resources/resource-manager/Microsoft.Resources/resources/preview/2099-01-01-preview/resources.json"}]}' > "$output"
    fi
  else
    echo '{"revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' > "$output"
  fi
else
  [[ "$revision" == 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ]]
  if [[ "${FAIL_BETA:-0}" == '1' && "$path" == 'openapi/beta/openapi.yaml' ]]; then exit 1; fi
  if [[ "${FAIL_DEVOPS:-0}" == '1' && "$path" == 'specification/core/7.1/core.json' ]]; then exit 1; fi
  if [[ "${FAIL_MONITOR:-0}" == '1' && "$source" == 'azure-monitor' ]]; then exit 1; fi
  if [[ "${FAIL_PURVIEW:-0}" == '1' && "$source" == 'purview' ]]; then exit 1; fi
  if [[ "${FAIL_AZURE:-0}" == '1' && "$source" == 'azure-resources' ]]; then exit 1; fi
  if [[ "${FAIL_COMPUTE:-0}" == '1' && "$source" == 'azure-compute' ]]; then exit 1; fi
  if [[ "${FAIL_SENTINEL:-0}" == '1' && "$source" == 'sentinel' ]]; then exit 1; fi
  if [[ "${FAIL_FABRIC:-0}" == '1' && "$source" == 'fabric' ]]; then exit 1; fi
  case "$source" in
    graph) repository='microsoftgraph/msgraph-metadata' ;;
    fabric) repository='microsoft/fabric-rest-api-specs' ;;
    azure-devops) repository='MicrosoftDocs/vsts-rest-api-specs' ;;
    *) repository='Azure/azure-rest-api-specs' ;;
  esac
  jq -n --arg revision "$revision" --arg path "$path" --arg source "$source" --arg repository "$repository" \
    '{operations:[{id:(if ($path | startswith("platform/")) then "fabric.platform.workspaces.list" elif ($path | startswith("admin/")) then "fabric.admin.tenants.list" elif ($path | startswith("lakehouse/")) then "fabric.lakehouse.items.list" elif ($path | startswith("notebook/")) then "fabric.notebook.items.list" elif ($path | startswith("specification/cost-management/")) then "azure.cost_management.query.usage" elif ($path | startswith("specification/resourcegraph/")) then (if ($path | endswith("/resourcegraph.json")) then "azure.resource_graph.resources.query" else "azure.resource_graph.graph_queries.list" end) elif ($path | startswith("specification/monitor/")) then (if ($path | test("/metrics(_API)?\\.json$")) then "azure.monitor.metrics.list" elif ($path | endswith("/activityLogAlerts_API.json")) then "azure.monitor.activity_log_alerts.list" elif ($path | test("/metricAlert(_API)?\\.json$")) then "azure.monitor.metric_alerts.list" elif ($path | endswith("/scheduledQueryRule_API.json")) then "azure.monitor.scheduled_query_rules.list" else "azure.monitor.activity_logs.list" end) elif ($path | startswith("specification/operationalinsights/")) then "azure.log_analytics.workspaces.list" elif ($path | startswith("specification/hybridcompute/")) then "azure.arc.machines.list" elif ($path | startswith("specification/managedservices/")) then "azure.lighthouse.registration_definitions.list" elif ($path | startswith("specification/security/")) then ("defender.cloud." + ($path | capture("/(?<name>[A-Za-z]+)\\.json$").name | ascii_downcase) + ".list") elif ($path | startswith("specification/compute/")) then "azure.compute.virtual_machines.list" elif ($path | startswith("specification/securityinsights/")) then "sentinel.securityinsights.incidents.list" elif ($path | startswith("specification/purview/")) then "purview.accounts.accounts.list" elif ($path | startswith("specification/resources/")) then "azure.resources.resource_groups.list" elif ($path | startswith("specification/")) then "azure_devops.core.projects.list" else "graph.users.list" end)}],schemas:{canonical:{"#/components/schemas/hash.microsoft.graph.emailAddress":{},"#/components/schemas/hash.microsoft.graph.recipient":{},"#/components/schemas/hash.microsoft.graph.phone":{},"#/components/schemas/hash.microsoft.graph.dateTimeTimeZone":{}},"x-junction-refresh":{imported:1,documents:[{receipt:{revision:$revision,path:$path,source:$source,upstream:("https://raw.githubusercontent.com/" + $repository + "/" + $revision + "/" + $path),sha256:("a" * 64),bytes:123},status:"imported"}]}}}' > "$output"
  if [[ "$source" == 'azure-compute' ]]; then
    if [[ -n "${BAD_RECEIPT_FIELD:-}" ]]; then
      jq --arg field "$BAD_RECEIPT_FIELD" --argjson value "${BAD_RECEIPT_VALUE:-null}" '.schemas["x-junction-refresh"].documents[0].receipt[$field] = $value' "$output" > "$output.changed"
      mv "$output.changed" "$output"
    fi
    if [[ "${EMPTY_COMPUTE:-0}" == '1' ]]; then
      jq '.operations = []' "$output" > "$output.changed"
      mv "$output.changed" "$output"
    fi
    if [[ "${WRONG_COMPUTE_RECEIPT:-0}" == '1' ]]; then
      jq '.schemas["x-junction-refresh"].documents[0].receipt.path = "wrong.json"' "$output" > "$output.changed"
      mv "$output.changed" "$output"
    fi
  fi
  if [[ "$source" == 'azure-cost-management' ]]; then
    if [[ "${FAIL_COST:-0}" == '1' ]]; then exit 1; fi
    if [[ "${EMPTY_COST:-0}" == '1' ]]; then jq '.operations = []' "$output" > "$output.changed"; mv "$output.changed" "$output"; fi
    if [[ "${WRONG_COST_RECEIPT:-0}" == '1' ]]; then jq '.schemas["x-junction-refresh"].documents[0].receipt.source = "azure"' "$output" > "$output.changed"; mv "$output.changed" "$output"; fi
    jq '.schemas["x-junction-refresh"].dependencies = [(.schemas["x-junction-refresh"].documents[0] | .status = "dependency" | .receipt.path = "specification/common-types/resource-management/v5/types.json" | .receipt.upstream = ("https://raw.githubusercontent.com/Azure/azure-rest-api-specs/" + .receipt.revision + "/" + .receipt.path))]' "$output" > "$output.changed"; mv "$output.changed" "$output"
    if [[ -n "${BAD_COST_DEPENDENCY_PATH:-}" ]]; then
      jq --arg path "$BAD_COST_DEPENDENCY_PATH" '.schemas["x-junction-refresh"].dependencies[0].receipt |= (.path = $path | .upstream = ("https://raw.githubusercontent.com/Azure/azure-rest-api-specs/" + .revision + "/" + .path))' "$output" > "$output.changed"; mv "$output.changed" "$output"
    fi
  fi
  if [[ "$source" == 'azure-resource-graph' ]]; then
    if [[ "${FAIL_RESOURCE_GRAPH_SAVED:-0}" == '1' && "$path" == */graphquery.json ]]; then exit 1; fi
    if [[ "${EMPTY_RESOURCE_GRAPH:-0}" == '1' ]]; then jq '.operations = []' "$output" > "$output.changed"; mv "$output.changed" "$output"; fi
    if [[ "${WRONG_RESOURCE_GRAPH_RECEIPT:-0}" == '1' ]]; then jq '.schemas["x-junction-refresh"].documents[0].receipt.source = "azure"' "$output" > "$output.changed"; mv "$output.changed" "$output"; fi
  fi
  if [[ "$source" == 'azure-monitor' ]]; then
    if [[ "${FAIL_MONITOR_FINAL:-0}" == '1' && "$path" == */scheduledQueryRule_API.json ]]; then exit 1; fi
    if [[ "${FAIL_MONITOR_ACTIVITY:-0}" == '1' && "$path" == */activityLogs.json ]]; then exit 1; fi
    if [[ "${EMPTY_MONITOR:-0}" == '1' ]]; then
      jq '.operations = []' "$output" > "$output.changed"; mv "$output.changed" "$output"
    fi
    if [[ "${WRONG_MONITOR_RECEIPT:-0}" == '1' ]]; then
      jq '.schemas["x-junction-refresh"].documents[0].receipt.source = "azure"' "$output" > "$output.changed"; mv "$output.changed" "$output"
    fi
    jq '.schemas["x-junction-refresh"].dependencies = [(.schemas["x-junction-refresh"].documents[0] | .status = "dependency" | .receipt.path = "specification/common-types/resource-management/v5/types.json" | .receipt.upstream = ("https://raw.githubusercontent.com/Azure/azure-rest-api-specs/" + .receipt.revision + "/" + .receipt.path))]' "$output" > "$output.changed"; mv "$output.changed" "$output"
    if [[ -n "${BAD_MONITOR_DEPENDENCY_PATH:-}" ]]; then
      jq --arg path "$BAD_MONITOR_DEPENDENCY_PATH" '.schemas["x-junction-refresh"].dependencies[0].receipt |= (.path = $path | .upstream = ("https://raw.githubusercontent.com/Azure/azure-rest-api-specs/" + .revision + "/" + .path))' "$output" > "$output.changed"; mv "$output.changed" "$output"
    fi
  fi
  if [[ "$source" =~ ^(azure-log-analytics|azure-arc|azure-lighthouse|defender-for-cloud)$ ]]; then
    if [[ "${FAIL_ARM:-}" == "$source" ]]; then exit 1; fi
    if [[ "${EMPTY_ARM:-}" == "$source" ]]; then jq '.operations = []' "$output" > "$output.changed"; mv "$output.changed" "$output"; fi
    jq '.schemas["x-junction-refresh"].dependencies = [(.schemas["x-junction-refresh"].documents[0] | .status = "dependency" | .receipt.path = "specification/common-types/resource-management/v5/types.json" | .receipt.upstream = ("https://raw.githubusercontent.com/Azure/azure-rest-api-specs/" + .receipt.revision + "/" + .receipt.path))]' "$output" > "$output.changed"; mv "$output.changed" "$output"
    if [[ -n "${BAD_ARM_DEPENDENCY_PATH:-}" && "${BAD_ARM_DEPENDENCY_SOURCE:-}" == "$source" ]]; then
      jq --arg path "$BAD_ARM_DEPENDENCY_PATH" '.schemas["x-junction-refresh"].dependencies[0].receipt |= (.path = $path | .upstream = ("https://raw.githubusercontent.com/Azure/azure-rest-api-specs/" + .revision + "/" + .path))' "$output" > "$output.changed"; mv "$output.changed" "$output"
    fi
  fi
  if [[ "$source" == 'purview' ]]; then
    jq '.schemas["x-junction-refresh"].dependencies = [(.schemas["x-junction-refresh"].documents[0] | .status = "dependency" | .receipt.path = "specification/common-types/resource-management/v5/types.json" | .receipt.upstream = ("https://raw.githubusercontent.com/Azure/azure-rest-api-specs/" + .receipt.revision + "/" + .receipt.path))]' "$output" > "$output.changed"
    mv "$output.changed" "$output"
    if [[ -n "${BAD_PURVIEW_DEPENDENCY_PATH:-}" ]]; then
      jq --arg path "$BAD_PURVIEW_DEPENDENCY_PATH" '.schemas["x-junction-refresh"].dependencies[0].receipt |= (.path = $path | .upstream = ("https://raw.githubusercontent.com/Azure/azure-rest-api-specs/" + .revision + "/" + .path))' "$output" > "$output.changed"
      mv "$output.changed" "$output"
    fi
    if [[ "${EMPTY_PURVIEW:-0}" == '1' ]]; then
      jq '.operations = []' "$output" > "$output.changed"
      mv "$output.changed" "$output"
    fi
    if [[ "${WRONG_PURVIEW_RECEIPT:-0}" == '1' ]]; then
      jq '.schemas["x-junction-refresh"].documents[0].receipt.revision = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' "$output" > "$output.changed"
      mv "$output.changed" "$output"
    fi
  fi
  if [[ "$source" == 'sentinel' ]]; then
    jq '.schemas["x-junction-refresh"].dependencies = [(.schemas["x-junction-refresh"].documents[0] | .status = "dependency" | .receipt.path = "specification/common-types/resource-management/v5/types.json" | .receipt.upstream = ("https://raw.githubusercontent.com/Azure/azure-rest-api-specs/" + .receipt.revision + "/" + .receipt.path))]' "$output" > "$output.changed"
    mv "$output.changed" "$output"
    if [[ "${BAD_DEPENDENCY:-0}" == '1' ]]; then
      jq '.schemas["x-junction-refresh"].dependencies[0].receipt.revision = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' "$output" > "$output.changed"
      mv "$output.changed" "$output"
    fi
    if [[ -n "${BAD_DEPENDENCY_FIELD:-}" ]]; then
      jq --arg field "$BAD_DEPENDENCY_FIELD" --argjson value "$BAD_DEPENDENCY_VALUE" '.schemas["x-junction-refresh"].dependencies[0].receipt[$field] = $value' "$output" > "$output.changed"
      mv "$output.changed" "$output"
      if [[ "$BAD_DEPENDENCY_FIELD" == 'path' ]]; then
        jq '.schemas["x-junction-refresh"].dependencies[0].receipt |= (.upstream = ("https://raw.githubusercontent.com/Azure/azure-rest-api-specs/" + .revision + "/" + .path))' "$output" > "$output.changed"
        mv "$output.changed" "$output"
      fi
    fi
    if [[ "${DUPLICATE_DEPENDENCY:-0}" == '1' ]]; then
      jq '.schemas["x-junction-refresh"].dependencies |= (. + .)' "$output" > "$output.changed"
      mv "$output.changed" "$output"
    fi
    if [[ "${MALFORMED_DEPENDENCIES:-0}" == '1' ]]; then
      jq '.schemas["x-junction-refresh"].dependencies = {}' "$output" > "$output.changed"
      mv "$output.changed" "$output"
    fi
    if [[ "${EMPTY_SENTINEL:-0}" == '1' ]]; then
      jq '.operations = []' "$output" > "$output.changed"
      mv "$output.changed" "$output"
    fi
    if [[ "${WRONG_SENTINEL_RECEIPT:-0}" == '1' ]]; then
      jq '.schemas["x-junction-refresh"].documents[0].receipt.revision = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' "$output" > "$output.changed"
      mv "$output.changed" "$output"
    fi
  fi
  if [[ "$source" == 'fabric' ]]; then
    jq '.schemas["x-junction-refresh"].dependencies = [(.schemas["x-junction-refresh"].documents[0] | .status = "dependency" | .receipt.path = "common/definitions.json" | .receipt.upstream = ("https://raw.githubusercontent.com/microsoft/fabric-rest-api-specs/" + .receipt.revision + "/" + .receipt.path))]' "$output" > "$output.changed"
    mv "$output.changed" "$output"
    if [[ "$path" == 'notebook/swagger.json' && -n "${BAD_FABRIC_DEPENDENCY_PATH:-}" ]]; then
      jq --arg path "$BAD_FABRIC_DEPENDENCY_PATH" '.schemas["x-junction-refresh"].dependencies[0].receipt |= (.path = $path | .upstream = ("https://raw.githubusercontent.com/microsoft/fabric-rest-api-specs/" + .revision + "/" + .path))' "$output" > "$output.changed"
      mv "$output.changed" "$output"
    fi
    if [[ "${FAIL_FABRIC_NOTEBOOK:-0}" == '1' && "$path" == 'notebook/swagger.json' ]]; then exit 1; fi
    if [[ "${FAIL_FABRIC_ADMIN:-0}" == '1' && "$path" == 'admin/swagger.json' ]]; then exit 1; fi
    if [[ "${EMPTY_FABRIC:-0}" == '1' ]]; then
      jq '.operations = []' "$output" > "$output.changed"
      mv "$output.changed" "$output"
    fi
    if [[ "${WRONG_FABRIC_RECEIPT:-0}" == '1' ]]; then
      jq '.schemas["x-junction-refresh"].documents[0].receipt.source = "graph"' "$output" > "$output.changed"
      mv "$output.changed" "$output"
    fi
  fi
  if [[ "$source" == 'azure-resources' ]]; then
    if [[ "${EMPTY_AZURE:-0}" == '1' ]]; then
      jq '.operations = []' "$output" > "$output.changed"
      mv "$output.changed" "$output"
    fi
    if [[ "${WRONG_AZURE_RECEIPT:-0}" == '1' ]]; then
      jq '.schemas["x-junction-refresh"].documents[0].receipt.revision = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' "$output" > "$output.changed"
      mv "$output.changed" "$output"
    fi
  fi
fi
MOCK
chmod +x "$test_directory/mock-junction"
export JUNCTION_BINARY="$test_directory/mock-junction"
bash "$test_directory/scripts/update-catalogs.sh"
[[ "$(wc -l < "$test_directory/calls.txt" | tr -d ' ')" == '70' ]]
jq -e '.operations | length == 25' "$test_directory/generated/registry/operations.json" >/dev/null
jq -e '[.operations[].id] | sort == ["azure.arc.machines.list", "azure.compute.virtual_machines.list", "azure.cost_management.query.usage", "azure.lighthouse.registration_definitions.list", "azure.log_analytics.workspaces.list", "azure.monitor.activity_log_alerts.list", "azure.monitor.activity_logs.list", "azure.monitor.metric_alerts.list", "azure.monitor.metrics.list", "azure.monitor.scheduled_query_rules.list", "azure.resource_graph.graph_queries.list", "azure.resource_graph.resources.query", "azure.resources.resource_groups.list", "azure_devops.core.projects.list", "defender.cloud.alerts.list", "defender.cloud.assessments.list", "defender.cloud.pricings.list", "defender.cloud.securescore.list", "fabric.admin.tenants.list", "fabric.lakehouse.items.list", "fabric.notebook.items.list", "fabric.platform.workspaces.list", "graph.users.list", "purview.accounts.accounts.list", "sentinel.securityinsights.incidents.list"]' "$test_directory/generated/registry/operations.json" >/dev/null
[[ -s "$test_directory/generated/manifests/azure-devops-core-refresh.json" ]]
jq -e '.documents[0].receipt.path == "specification/resources/resource-manager/Microsoft.Resources/resources/stable/2021-04-01/resources.json"' "$test_directory/generated/manifests/azure-resources-refresh.json" >/dev/null
jq -e '.revision == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' "$test_directory/generated/manifests/graph-beta-source.json" >/dev/null
[[ -f "$test_directory/generated/manifests/graph-v1.0-refresh.json" ]]
[[ -s "$test_directory/generated/types/graph-common.rs" ]]
jq -e '.status == "generated"' "$test_directory/generated/manifests/graph-common-types.json" >/dev/null
cp "$test_directory/generated/types/graph-common.rs" "$test_directory/previous.rs"
cp "$test_directory/generated/registry/operations.json" "$test_directory/previous.json"
cp "$test_directory/generated/manifests/junction-openapi.json" "$test_directory/previous-openapi.json"
jq -e '.documents[0].receipt.path == "specification/compute/resource-manager/Microsoft.Compute/Compute/stable/2024-07-01/ComputeRP.json"' "$test_directory/generated/manifests/azure-compute-refresh.json" >/dev/null
jq -e '.documents[0].receipt.path == "specification/securityinsights/resource-manager/Microsoft.SecurityInsights/SecurityInsights/stable/2025-09-01/openapi.json"' "$test_directory/generated/manifests/sentinel-refresh.json" >/dev/null
cp "$test_directory/generated/registry/azure-compute.json" "$test_directory/previous-compute.json"
jq -e '.documents[0].receipt.path == "platform/swagger.json" and .documents[0].receipt.source == "fabric"' "$test_directory/generated/manifests/fabric-platform-refresh.json" >/dev/null
jq -e '.documents[0].receipt.path == "admin/swagger.json" and .documents[0].receipt.source == "fabric" and .documents[0].receipt.revision == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' "$test_directory/generated/manifests/fabric-admin-refresh.json" >/dev/null
for catalog in platform admin lakehouse notebook; do
  cp "$test_directory/generated/registry/fabric-${catalog}.json" "$test_directory/previous-fabric-${catalog}.json"
done
for workload in lakehouse notebook; do
  jq -e --arg path "$workload/swagger.json" '.documents[0].receipt.path == $path and .documents[0].receipt.source == "fabric" and .documents[0].receipt.revision == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' "$test_directory/generated/manifests/fabric-${workload}-refresh.json" >/dev/null
done
for document in metrics activityLogs activityLogAlerts_API metricAlert scheduledQueryRule_API; do
  cp "$test_directory/generated/registry/azure-monitor-${document}.json" "$test_directory/previous-monitor-${document}.json"
done
jq -e '.documents[0].receipt.path == "specification/monitor/resource-manager/Microsoft.Insights/Insights/stable/2024-02-01/metrics.json"' "$test_directory/generated/manifests/azure-monitor-metrics-refresh.json" >/dev/null
cp "$test_directory/generated/registry/sentinel.json" "$test_directory/previous-sentinel.json"
jq -e '.documents[0].receipt.path == "specification/purview/resource-manager/Microsoft.Purview/Purview/stable/2021-12-01/purview.json" and .documents[0].receipt.source == "purview" and .documents[0].receipt.revision == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" and .dependencies[0].receipt.path == "specification/common-types/resource-management/v5/types.json"' "$test_directory/generated/manifests/purview-accounts-refresh.json" >/dev/null
cp "$test_directory/generated/registry/purview-accounts.json" "$test_directory/previous-purview.json"
for document in resourcegraph graphquery; do
  cp "$test_directory/generated/registry/azure-resource-graph-${document}.json" "$test_directory/previous-resource-graph-${document}.json"
  jq -e --arg path "specification/resourcegraph/resource-manager/Microsoft.ResourceGraph/ResourceGraph/stable/2024-04-01/${document}.json" '.documents[0].receipt.path == $path and .documents[0].receipt.source == "azure-resource-graph"' "$test_directory/generated/manifests/azure-resource-graph-${document}-refresh.json" >/dev/null
done
cp "$test_directory/generated/registry/azure-cost-management.json" "$test_directory/previous-cost.json"
jq -e '.documents[0].receipt.path == "specification/cost-management/resource-manager/Microsoft.CostManagement/CostManagement/stable/2026-06-01/openapi.json" and .documents[0].receipt.source == "azure-cost-management" and .dependencies[0].receipt.path == "specification/common-types/resource-management/v5/types.json"' "$test_directory/generated/manifests/azure-cost-management-refresh.json" >/dev/null
for failure in FAIL_COST EMPTY_COST WRONG_COST_RECEIPT NO_STABLE_COST WRONG_COST_INVENTORY NO_STABLE_RESOURCE_GRAPH WRONG_RESOURCE_GRAPH_INVENTORY FAIL_RESOURCE_GRAPH_SAVED EMPTY_RESOURCE_GRAPH WRONG_RESOURCE_GRAPH_RECEIPT FAIL_MONITOR_FINAL FAIL_MONITOR_ACTIVITY EMPTY_MONITOR WRONG_MONITOR_RECEIPT FAIL_MONITOR NO_STABLE_MONITOR WRONG_MONITOR_INVENTORY EMPTY_PURVIEW WRONG_PURVIEW_RECEIPT FAIL_PURVIEW NO_STABLE_PURVIEW WRONG_PURVIEW_INVENTORY FAIL_FABRIC_NOTEBOOK FAIL_FABRIC_ADMIN FAIL_FABRIC EMPTY_FABRIC WRONG_FABRIC_RECEIPT DUPLICATE_DEPENDENCY MALFORMED_DEPENDENCIES BAD_DEPENDENCY FAIL_SENTINEL NO_STABLE_SENTINEL WRONG_SENTINEL_INVENTORY EMPTY_SENTINEL WRONG_SENTINEL_RECEIPT WRONG_COMPUTE_INVENTORY FAIL_COMPUTE NO_STABLE_COMPUTE EMPTY_COMPUTE WRONG_COMPUTE_RECEIPT FAIL_DEVOPS FAIL_MERGE FAIL_AZURE NO_STABLE_AZURE EMPTY_AZURE WRONG_AZURE_RECEIPT; do
  if env "$failure=1" bash "$test_directory/scripts/update-catalogs.sh"; then
    echo "Expected $failure to abort publication." >&2
    exit 1
  fi
  cmp "$test_directory/previous.json" "$test_directory/generated/registry/operations.json"
  cmp "$test_directory/previous-cost.json" "$test_directory/generated/registry/azure-cost-management.json"
  for document in resourcegraph graphquery; do
    cmp "$test_directory/previous-resource-graph-${document}.json" "$test_directory/generated/registry/azure-resource-graph-${document}.json"
  done
  cmp "$test_directory/previous-purview.json" "$test_directory/generated/registry/purview-accounts.json"
  for document in metrics activityLogs activityLogAlerts_API metricAlert scheduledQueryRule_API; do
    cmp "$test_directory/previous-monitor-${document}.json" "$test_directory/generated/registry/azure-monitor-${document}.json"
  done
  cmp "$test_directory/previous-compute.json" "$test_directory/generated/registry/azure-compute.json"
  cmp "$test_directory/previous-fabric-admin.json" "$test_directory/generated/registry/fabric-admin.json"
  cmp "$test_directory/previous-sentinel.json" "$test_directory/generated/registry/sentinel.json"
  cmp "$test_directory/previous-openapi.json" "$test_directory/generated/manifests/junction-openapi.json"
done
# New ARM workloads: newest stable per document, scoped receipts, and atomic
# preservation of every published catalog when any stage fails.
jq -e '.documents[0].receipt.path == "specification/operationalinsights/resource-manager/Microsoft.OperationalInsights/OperationalInsights/stable/2025-01-01/openapi.json" and .documents[0].receipt.source == "azure-log-analytics"' "$test_directory/generated/manifests/azure-log-analytics-refresh.json" >/dev/null
jq -e '.documents[0].receipt.path == "specification/managedservices/resource-manager/Microsoft.ManagedServices/ManagedServices/stable/2025-01-01/managedservices.json"' "$test_directory/generated/manifests/azure-lighthouse-refresh.json" >/dev/null
for document in alerts assessments pricings secureScore; do
  jq -e --arg path "specification/security/resource-manager/Microsoft.Security/Security/stable/2025-01-01/${document}.json" '.documents[0].receipt.path == $path and .documents[0].receipt.source == "defender-for-cloud"' "$test_directory/generated/manifests/defender-for-cloud-${document}-refresh.json" >/dev/null
done
cp "$test_directory/generated/registry/azure-arc.json" "$test_directory/previous-arc.json"
for arm_source in azure-log-analytics azure-arc azure-lighthouse defender-for-cloud; do
  for failure in FAIL_ARM EMPTY_ARM NO_STABLE_ARM WRONG_ARM_INVENTORY; do
    if env "$failure=$arm_source" bash "$test_directory/scripts/update-catalogs.sh"; then
      echo "Expected $failure for $arm_source to abort publication." >&2
      exit 1
    fi
    cmp "$test_directory/previous.json" "$test_directory/generated/registry/operations.json"
    cmp "$test_directory/previous-arc.json" "$test_directory/generated/registry/azure-arc.json"
  done
  for bad_path in specification/storage/resource-manager/private.json specification/common-types/data-plane/v1/types.json specification/security/../storage/private.json; do
    if BAD_ARM_DEPENDENCY_SOURCE="$arm_source" BAD_ARM_DEPENDENCY_PATH="$bad_path" bash "$test_directory/scripts/update-catalogs.sh"; then
      echo "Expected $arm_source dependency $bad_path to abort publication." >&2
      exit 1
    fi
    cmp "$test_directory/previous.json" "$test_directory/generated/registry/operations.json"
  done
done
for bad_case in 'source|"graph"' 'upstream|"https://example.com/definition.json"' 'sha256|"bad"' 'sha256|null' 'bytes|0' 'bytes|134217729' 'bytes|1.5' 'bytes|"123"'; do
  field="${bad_case%%|*}"
  value="${bad_case#*|}"
  if BAD_RECEIPT_FIELD="$field" BAD_RECEIPT_VALUE="$value" bash "$test_directory/scripts/update-catalogs.sh"; then
    echo "Expected invalid receipt $field to abort publication." >&2
    exit 1
  fi
  cmp "$test_directory/previous.json" "$test_directory/generated/registry/operations.json"
  cmp "$test_directory/previous-cost.json" "$test_directory/generated/registry/azure-cost-management.json"
  cmp "$test_directory/previous-purview.json" "$test_directory/generated/registry/purview-accounts.json"
  cmp "$test_directory/previous-compute.json" "$test_directory/generated/registry/azure-compute.json"
done
for bad_case in 'source|"graph"' 'upstream|"https://example.com/schema.json"' 'sha256|null' 'bytes|0' 'bytes|1.5' 'path|"specification/../private.json"'; do
  field="${bad_case%%|*}"
  value="${bad_case#*|}"
  if BAD_DEPENDENCY_FIELD="$field" BAD_DEPENDENCY_VALUE="$value" bash "$test_directory/scripts/update-catalogs.sh"; then
    echo "Expected invalid dependency receipt $field to abort publication." >&2
    exit 1
  fi
  cmp "$test_directory/previous.json" "$test_directory/generated/registry/operations.json"
  cmp "$test_directory/previous-cost.json" "$test_directory/generated/registry/azure-cost-management.json"
  cmp "$test_directory/previous-purview.json" "$test_directory/generated/registry/purview-accounts.json"
  cmp "$test_directory/previous-fabric-admin.json" "$test_directory/generated/registry/fabric-admin.json"
  cmp "$test_directory/previous-sentinel.json" "$test_directory/generated/registry/sentinel.json"
done
for bad_path in 'specification/billing/private.json' 'openapi/private.json' 'specification/common-types/storage/types.json' 'specification/cost-management/resource-manager/Microsoft.CostManagement/CostManagement/../private.json'; do
  if BAD_COST_DEPENDENCY_PATH="$bad_path" bash "$test_directory/scripts/update-catalogs.sh"; then
    echo 'Expected an out-of-scope Cost Management dependency to abort publication.' >&2
    exit 1
  fi
  cmp "$test_directory/previous.json" "$test_directory/generated/registry/operations.json"
  cmp "$test_directory/previous-cost.json" "$test_directory/generated/registry/azure-cost-management.json"
  cmp "$test_directory/previous-openapi.json" "$test_directory/generated/manifests/junction-openapi.json"
done
for bad_path in 'specification/compute/private.json' 'openapi/private.json' 'specification/common-types/storage/types.json' 'specification/monitor/data-plane/private.json' 'specification/monitor/resource-manager/Microsoft.Insights/Insights/../private.json'; do
  if BAD_MONITOR_DEPENDENCY_PATH="$bad_path" bash "$test_directory/scripts/update-catalogs.sh"; then
    echo 'Expected an out-of-scope Monitor dependency to abort publication.' >&2
    exit 1
  fi
  cmp "$test_directory/previous.json" "$test_directory/generated/registry/operations.json"
  cmp "$test_directory/previous-cost.json" "$test_directory/generated/registry/azure-cost-management.json"
  for document in metrics activityLogs activityLogAlerts_API metricAlert scheduledQueryRule_API; do
    cmp "$test_directory/previous-monitor-${document}.json" "$test_directory/generated/registry/azure-monitor-${document}.json"
  done
  cmp "$test_directory/previous-openapi.json" "$test_directory/generated/manifests/junction-openapi.json"
done
for bad_path in 'specification/compute/private.json' 'openapi/private.json' 'specification/common-types/storage/types.json' 'specification/purview-other/private.json' 'specification/purview/../private.json' 'specification/purview//types.json'; do
  if BAD_PURVIEW_DEPENDENCY_PATH="$bad_path" bash "$test_directory/scripts/update-catalogs.sh"; then
    echo 'Expected an out-of-scope Purview dependency to abort publication.' >&2
    exit 1
  fi
  cmp "$test_directory/previous.json" "$test_directory/generated/registry/operations.json"
  cmp "$test_directory/previous-cost.json" "$test_directory/generated/registry/azure-cost-management.json"
  cmp "$test_directory/previous-purview.json" "$test_directory/generated/registry/purview-accounts.json"
  cmp "$test_directory/previous-openapi.json" "$test_directory/generated/manifests/junction-openapi.json"
done
for bad_path in 'specification/private.json' 'openapi/private.json' 'warehouse/private.json' 'common/../private.json' 'notebook//definitions.json'; do
  if BAD_FABRIC_DEPENDENCY_PATH="$bad_path" bash "$test_directory/scripts/update-catalogs.sh"; then
    echo 'Expected an out-of-scope Fabric dependency to abort publication.' >&2
    exit 1
  fi
  cmp "$test_directory/previous.json" "$test_directory/generated/registry/operations.json"
  cmp "$test_directory/previous-cost.json" "$test_directory/generated/registry/azure-cost-management.json"
  cmp "$test_directory/previous-purview.json" "$test_directory/generated/registry/purview-accounts.json"
  for catalog in platform admin lakehouse notebook; do
    cmp "$test_directory/previous-fabric-${catalog}.json" "$test_directory/generated/registry/fabric-${catalog}.json"
  done
done
if FAIL_BETA=1 bash "$test_directory/scripts/update-catalogs.sh"; then
  echo 'Expected failed beta refresh to abort publication.' >&2
  exit 1
fi
cmp "$test_directory/previous.json" "$test_directory/generated/registry/operations.json"
if FAIL_GENERATION=1 bash "$test_directory/scripts/update-catalogs.sh"; then
  echo 'Expected failed generation to abort publication.' >&2
  exit 1
fi
cmp "$test_directory/previous.json" "$test_directory/generated/registry/operations.json"
cmp "$test_directory/previous.rs" "$test_directory/generated/types/graph-common.rs"
if FAIL_OPENAPI=1 bash "$test_directory/scripts/update-catalogs.sh"; then
  echo 'Expected failed OpenAPI export to abort publication.' >&2
  exit 1
fi
cmp "$test_directory/previous.json" "$test_directory/generated/registry/operations.json"
cmp "$test_directory/previous.rs" "$test_directory/generated/types/graph-common.rs"
cmp "$test_directory/previous-openapi.json" "$test_directory/generated/manifests/junction-openapi.json"
if INVALID_OPENAPI=1 bash "$test_directory/scripts/update-catalogs.sh"; then
  echo 'Expected malformed OpenAPI export to abort publication.' >&2
  exit 1
fi
cmp "$test_directory/previous.json" "$test_directory/generated/registry/operations.json"
cmp "$test_directory/previous-openapi.json" "$test_directory/generated/manifests/junction-openapi.json"
[[ -z "$(find "$test_directory/.junction" -name 'catalog-refresh.*' -print)" ]]
echo 'Catalog refresh orchestration passed.'

# Older pinned revisions may only emit the legacy suffixed definitions.
LEGACY_MONITOR_ONLY=1 bash "$test_directory/scripts/update-catalogs.sh"
jq -e '.documents[0].receipt.path == "specification/monitor/resource-manager/Microsoft.Insights/Insights/stable/2021-05-01/metrics_API.json"' "$test_directory/generated/manifests/azure-monitor-metrics-refresh.json" >/dev/null
jq -e '.documents[0].receipt.path == "specification/monitor/resource-manager/Microsoft.Insights/Insights/stable/2018-03-01/metricAlert_API.json"' "$test_directory/generated/manifests/azure-monitor-metricAlert-refresh.json" >/dev/null
jq -e '.operations | length == 25' "$test_directory/generated/registry/operations.json" >/dev/null
