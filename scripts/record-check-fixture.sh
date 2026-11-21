#!/usr/bin/env bash
# Record one read-only operation from a test tenant you control as a synthetic
# check fixture. Off by default and refused in CI: set JUNCTION_RECORD_FIXTURES=1.
#
#   JUNCTION_RECORD_FIXTURES=1 scripts/record-check-fixture.sh \
#     --context test-tenant --operation graph.users.list \
#     --input '{"parameters":{"$top":5}}' \
#     --out crates/junction-check/tests/fixtures/identity/my_case/users.json
#
# The response is scrubbed (`junction check scrub-fixture`): GUIDs, UPNs, e-mail
# addresses, domains, IP addresses, names and tokens become consistent synthetic
# values. Read the result before committing; the scrubber is a safety net.
set -euo pipefail
if [[ "${JUNCTION_RECORD_FIXTURES:-}" != "1" ]]; then
  echo "Recording is off. Set JUNCTION_RECORD_FIXTURES=1 to call a test tenant." >&2
  exit 2
fi
if [[ -n "${CI:-}" || -n "${GITHUB_ACTIONS:-}" ]]; then
  echo "Recording never runs in CI." >&2
  exit 2
fi
context="" operation="" input="{}" out="" junction="${JUNCTION:-junction}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --context) context="$2"; shift 2 ;;
    --operation) operation="$2"; shift 2 ;;
    --input) input="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
[[ -n "$context" && -n "$operation" && -n "$out" ]] || { echo "need --context, --operation and --out" >&2; exit 2; }
case "$operation" in
  *.list|*.get|*.run|*.post|*.execute|*.run_hunting_query|*.list_*) ;;
  *) echo "only read operations can be recorded" >&2; exit 2 ;;
esac
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
# The default policy is read-only; recording never passes --approve.
"$junction" --context "$context" --json execute "$operation" --input "$input" > "$tmp"
mkdir -p "$(dirname "$out")"
"$junction" check scrub-fixture --operation "$operation" < "$tmp" > "$out"
echo "wrote $out (scrubbed); review it before committing" >&2
