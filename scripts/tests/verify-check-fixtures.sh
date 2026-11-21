#!/usr/bin/env bash
# Fail if a check fixture holds a JWT or an e-mail address on a real domain.
# The Rust test `committed_fixtures_are_synthetic` applies the full domain rules.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)/crates/junction-check/tests/fixtures"
status=0
if grep -rIl 'eyJ' "$root" >/dev/null 2>&1; then
  echo "check fixtures contain a JWT-like eyJ value:" >&2
  grep -rIl 'eyJ' "$root" >&2
  status=1
fi
# E-mail addresses must use reserved example domains.
if grep -rIhoE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' "$root" \
  | grep -viE '@([a-z0-9-]+\.)*(contoso\.example|fabrikam\.example|example\.(org|com|net))$' \
  | grep -vE '@[A-Za-z0-9.-]+\.(example|test|invalid)$' >/dev/null; then
  echo "check fixtures contain e-mail addresses outside the example domains:" >&2
  grep -rIhoE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' "$root" \
    | grep -viE '@([a-z0-9-]+\.)*(contoso\.example|fabrikam\.example|example\.(org|com|net))$' \
    | grep -vE '@[A-Za-z0-9.-]+\.(example|test|invalid)$' | sort -u >&2
  status=1
fi
exit "$status"
