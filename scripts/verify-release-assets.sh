#!/usr/bin/env bash
set -euo pipefail
version="${1:?version required}"
directory="${2:?asset directory required}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 1
cd "$directory" || exit 1
shopt -s nullglob dotglob
entries=(*)
archives=(junction-v"$version"-*.tar.gz junction-v"$version"-*.zip)
checksums=(junction-v"$version"-*.sha256)
if [[ ${#entries[@]} != 6 || ${#archives[@]} != 3 || ${#checksums[@]} != 3 ]]; then
  echo 'Expected three native archives and their checksums.' >&2
  exit 1
fi
linux=0
macos=0
windows=0
for archive in "${archives[@]}"; do
  case "$archive" in
    junction-v"$version"-*-unknown-linux-gnu.tar.gz) linux=$((linux + 1));;
    junction-v"$version"-*-apple-darwin.tar.gz) macos=$((macos + 1));;
    junction-v"$version"-*-pc-windows-msvc.zip) windows=$((windows + 1));;
    *) echo 'Unexpected native release archive.' >&2; exit 1;;
  esac
  [[ -f "$archive" && -s "$archive" && ! -L "$archive" && -f "$archive.sha256" && ! -L "$archive.sha256" ]] || exit 1
  # Accept only a digest for this exact basename; never checksum arbitrary paths.
  digest="$(awk -v name="$archive" '{sub(/\r$/, "")} NF == 2 && $2 == name {print $1}' "$archive.sha256")"
  [[ "$digest" =~ ^[a-f0-9]{64}$ ]] || exit 1
  [[ "$(wc -l < "$archive.sha256" | tr -d ' ')" == 1 ]] || exit 1
  if command -v sha256sum >/dev/null; then
    actual="$(sha256sum "$archive")"
  else
    actual="$(shasum -a 256 "$archive")"
  fi
  [[ "${actual%% *}" == "$digest" ]] || exit 1
done
[[ "$linux" == 1 && "$macos" == 1 && "$windows" == 1 ]]
