#!/usr/bin/env bash
# Refresh crates/junction-check/data/frameworks from a crownguard checkout.
# Data flows one way: crownguard is the maintained source; edit there, then run
#   scripts/sync-frameworks.sh /path/to/crownguard
# and review the diff. CIS text is never copied (ids only), per CIS licence terms.
set -euo pipefail
crownguard="${1:-../crownguard}"
if [[ ! -d "$crownguard/content/frameworks" ]]; then
  echo "usage: $0 /path/to/crownguard" >&2
  exit 2
fi
exec python3 "$(dirname "$0")/sync-frameworks.py" "$crownguard"
