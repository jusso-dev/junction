#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
for mapping in '0.0.0 0.0.1' '0.1.8 0.1.9' '1.2.9 1.2.10' '1.2.99 1.2.100' '1.2.199 1.2.200' '1.2.9223372036854775807 1.2.9223372036854775808' '1.2.18446744073709551614 1.2.18446744073709551615'; do
  read -r current expected <<< "$mapping"
  [[ "$(bash scripts/next-patch-version.sh "$current")" == "$expected" ]]
done
for invalid in '' '01.2.3' '1.02.3' '1.2.03' '1.2.3-beta' '1.2.3+build' 'v1.2.3' '1.2.-1' '1.2.18446744073709551615' '18446744073709551616.2.0' '1.18446744073709551616.0' '1.2.18446744073709551616' '1.2.3/private-token'; do
  if bash scripts/next-patch-version.sh "$invalid" >/dev/null 2>&1; then
    echo 'Invalid or exhausted version was accepted.' >&2
    exit 1
  fi
done
if bash scripts/next-patch-version.sh >/dev/null 2>&1; then exit 1; fi
if bash scripts/next-patch-version.sh 1.2.3 4.5.6 >/dev/null 2>&1; then exit 1; fi
printf '%s\n' 'Automatic patch version tests passed.'
