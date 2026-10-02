#!/usr/bin/env bash
# Opt-in, read-only smoke test against a real tenant. Prints only statuses and
# counts (never response bodies), uses a read-only policy, and makes no
# changes. Requires an existing Azure CLI sign-in (`az login`) unless the
# context files below are supplied.
#
#   JUNCTION_LIVE_TENANT=<tenant id> JUNCTION_LIVE_SUBSCRIPTION=<subscription id> \
#     bash scripts/live-smoke.sh
#
# Optional: JUNCTION_LIVE_ARM_CONTEXT / JUNCTION_LIVE_GRAPH_CONTEXT point to
# existing context files to test other credential flows.
set -euo pipefail
cd "$(dirname "$0")/.."
binary="${JUNCTION_BINARY:-target/release/junction}"
tenant="${JUNCTION_LIVE_TENANT:?set JUNCTION_LIVE_TENANT}"
subscription="${JUNCTION_LIVE_SUBSCRIPTION:-}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
printf "[agent]\nmode = 'read-only'\n" > "$work/policy.toml"
arm="${JUNCTION_LIVE_ARM_CONTEXT:-$work/arm.json}"
graph="${JUNCTION_LIVE_GRAPH_CONTEXT:-$work/graph.json}"
[[ -f "$arm" ]] || printf '{"cloud":"public","tenant":"%s","service":"arm","credential_profile":"live","flow":"azure_cli"}' "$tenant" > "$arm"
[[ -f "$graph" ]] || printf '{"cloud":"public","tenant":"%s","service":"graph","credential_profile":"live","flow":"azure_cli"}' "$tenant" > "$graph"
failures=0
check() {
  local name="$1" filter="$2"
  shift 2
  local output
  if output="$("$binary" "$@" --policy "$work/policy.toml" --json 2>&1)" && summary="$(jq -c "$filter" <<< "$output" 2>/dev/null)"; then
    echo "ok   $name $summary"
  else
    # Errors are Junction's secret-free structured diagnostics.
    echo "FAIL $name $(jq -c '{status, error, http_status, reason}' <<< "$output" 2>/dev/null || echo unparseable)"
    failures=$((failures + 1))
  fi
}
check graph.organization.list '{status, count:(.body.value|length)}' \
  execute graph.organization.list --context-file "$graph" --input '{}'
check graph.users.list.paged '{items:(.items|length), pages}' \
  execute entra.users.list --all --max-items 20 --max-pages 2 --continuation-file "$work/users.json" \
  --context-file "$graph" --input '{"parameters":{"$top":10,"$select":["id"]}}'
if [[ -n "$subscription" ]]; then
  check azure.resources.resource_groups.list '{status, count:(.body.value|length)}' \
    execute azure.resources.resource_groups.list --subscription "$subscription" --context-file "$arm" --input '{}'
fi
check azure.resource_graph.query.paged '{items:(.items|length), pages}' \
  execute azure.resource_graph.resources.post --all --max-items 10 --max-pages 2 --continuation-file "$work/rg.json" \
  --context-file "$arm" --input '{"body":{"query":"Resources | project id","options":{"$top":5}}}'
echo "live smoke failures: $failures"
exit "$failures"
