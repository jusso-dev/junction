#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
[[ $# == 1 ]] || { echo 'One stable semantic version is required.' >&2; exit 1; }
version="$1"
[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
  echo 'A stable semantic version without leading zeroes is required.' >&2
  exit 1
}
IFS='.' read -r major minor patch <<< "$version"
maximum=18446744073709551615
for component in "$major" "$minor" "$patch"; do
  if [[ ${#component} -gt ${#maximum} ]] ||
     { [[ ${#component} -eq ${#maximum} ]] && [[ "$component" > "$maximum" ]]; }; then
    echo 'Semantic version component exceeds the Rust version range.' >&2
    exit 1
  fi
done
[[ "$patch" != "$maximum" ]] || { echo 'Patch version is exhausted.' >&2; exit 1; }
# Increment decimal digits without signed shell-integer overflow or octal parsing.
next=''
carry=1
for ((index=${#patch}-1; index>=0; index--)); do
  digit="${patch:index:1}"
  if [[ "$carry" == 1 ]]; then
    if [[ "$digit" == 9 ]]; then digit=0; else digit=$((digit + 1)); carry=0; fi
  fi
  next="$digit$next"
done
if [[ "$carry" == 1 ]]; then next="1$next"; fi
printf '%s.%s.%s\n' "$major" "$minor" "$next"
