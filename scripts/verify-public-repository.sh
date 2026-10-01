#!/usr/bin/env bash
set -euo pipefail
# Validate GitHub's repository response without echoing its potentially private fields.
metadata="${1:?repository metadata JSON required}"
jq -e '
  .full_name == "jusso-dev/junction" and
  .owner.login == "jusso-dev" and .owner.type == "User" and
  .private == false and .visibility == "public" and
  .archived == false and .disabled == false and
  .license.spdx_id == "MIT"
' "$metadata" >/dev/null 2>&1 || {
  echo 'Release requires the public, active MIT-licensed personal repository jusso-dev/junction.' >&2
  exit 1
}
