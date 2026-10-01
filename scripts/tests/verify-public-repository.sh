#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
fixture_root="$(mktemp -d)"
trap 'rm -rf "$fixture_root"' EXIT
metadata="$fixture_root/repository.json"
base='{"full_name":"jusso-dev/junction","owner":{"login":"jusso-dev","type":"User"},"private":false,"visibility":"public","archived":false,"disabled":false,"license":{"spdx_id":"MIT"}}'
printf '%s\n' "$base" > "$metadata"
bash scripts/verify-public-repository.sh "$metadata"
for mutation in '.private=true' '.visibility="private"' '.full_name="another/junction"' '.owner.login="another"' '.owner.type="Organization"' '.archived=true' '.disabled=true' '.license=null' '.license.spdx_id="NOASSERTION"' 'del(.private)' 'del(.visibility)' 'del(.owner)' '[]' 'null'; do
  printf '%s\n' "$base" | jq "$mutation" > "$metadata"
  if bash scripts/verify-public-repository.sh "$metadata" > "$fixture_root/output" 2>&1; then
    echo "Invalid repository metadata was accepted: $mutation" >&2
    exit 1
  fi
done
printf '%s\n' 'invalid-json' > "$metadata"
if bash scripts/verify-public-repository.sh "$metadata" >/dev/null 2>&1; then exit 1; fi
printf '%s\n' 'Public repository validation passed.'
