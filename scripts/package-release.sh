#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
version="${1:?version required}"
host="${2:?Rust host target required}"
platform="${3:?platform required}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
[[ "$host" =~ ^[a-zA-Z0-9_-]+$ ]]
[[ "$platform" == linux || "$platform" == macos || "$platform" == windows ]]
name="junction-v${version}-${host}"
package="dist/${name}"
suffix=""
if [[ "$platform" == windows ]]; then suffix=".exe"; fi
binary="${JUNCTION_BINARY:-target/release/junction${suffix}}"
if [[ "$("$binary" --version)" != "junction $version" ]]; then
  echo 'Binary version does not match the requested release version.' >&2
  exit 1
fi
# Require the integrated terminal explorer before creating any package files.
"$binary" tui --help >/dev/null
# Refuse stale package directories so files from earlier builds cannot enter a release.
mkdir -p dist
mkdir "$package"
cp "$binary" "$package/junction${suffix}"
cp LICENSE README.md CONTRIBUTING.md DISCLAIMER.md "$package/"
cp vendor/ratatui/LICENSE "$package/RATATUI-LICENSE.txt"
cp -R generated examples sources docs overrides "$package/"
"$binary" openapi --output "$package/generated/manifests/junction-openapi.json"
jq -e --arg version "$version" '.openapi == "3.1.1" and .info.version == $version' \
  "$package/generated/manifests/junction-openapi.json" >/dev/null
"$binary" --registry "$package/generated/registry/operations.json" api stats \
  > "$package/generated/manifests/operations-stats.json"
printf '%s\n' "$version" > "$package/VERSION"
printf '%s\n' "$host" > "$package/TARGET"
if [[ "$platform" == windows ]]; then
  # PowerShell runs in the workflow after this script has prepared the directory.
  printf '%s\n' "$package"
else
  tar -czf "dist/${name}.tar.gz" -C "$package" .
  (cd dist && if command -v sha256sum >/dev/null; then
    sha256sum "${name}.tar.gz" > "${name}.tar.gz.sha256"
  else
    shasum -a 256 "${name}.tar.gz" > "${name}.tar.gz.sha256"
  fi)
fi
