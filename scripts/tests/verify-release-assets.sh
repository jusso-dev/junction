#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
project="$PWD"
fixture_root="$(mktemp -d)"
staging="$fixture_root/assets"
mkdir "$staging"
trap 'rm -rf "$fixture_root"' EXIT
names=(junction-v0.1.1-x86_64-unknown-linux-gnu.tar.gz junction-v0.1.1-aarch64-apple-darwin.tar.gz junction-v0.1.1-x86_64-pc-windows-msvc.zip)
for name in "${names[@]}"; do
  printf 'fixture archive %s\n' "$name" > "$staging/$name"
  digest="$(shasum -a 256 "$staging/$name")"
  digest="${digest%% *}"
  if [[ "$name" == *.zip ]]; then
    printf '%s  %s\r\n' "$digest" "$name" > "$staging/$name.sha256"
  else
    printf '%s  %s\n' "$digest" "$name" > "$staging/$name.sha256"
  fi
done
bash "$project/scripts/verify-release-assets.sh" 0.1.1 "$staging"
expect_failure() {
  if bash "$project/scripts/verify-release-assets.sh" 0.1.1 "$staging" >/dev/null 2>&1; then
    echo 'Invalid release assets were accepted.' >&2
    exit 1
  fi
}
linux="${names[0]}"
cp "$staging/$linux" "$fixture_root/original"
printf 'modified\n' >> "$staging/$linux"
expect_failure
mv "$fixture_root/original" "$staging/$linux"
cp "$staging/$linux.sha256" "$fixture_root/checksum"
printf '%064d  ../private-file\n' 0 > "$staging/$linux.sha256"
expect_failure
mv "$fixture_root/checksum" "$staging/$linux.sha256"
mv "$staging/${names[2]}.sha256" "$staging/missing-checksum"
expect_failure
mv "$staging/missing-checksum" "$staging/${names[2]}.sha256"
cp "$staging/$linux" "$staging/junction-v0.1.1-aarch64-unknown-linux-gnu.tar.gz"
expect_failure
rm "$staging/junction-v0.1.1-aarch64-unknown-linux-gnu.tar.gz"
cp "$staging/$linux" "$staging/junction-v0.1.0-x86_64-unknown-linux-gnu.tar.gz"
expect_failure
rm "$staging/junction-v0.1.0-x86_64-unknown-linux-gnu.tar.gz"
printf 'extra\n' > "$staging/.extra"
expect_failure
rm "$staging/.extra"
mv "$staging/$linux" "$fixture_root/original"
ln -s "../original" "$staging/$linux"
expect_failure
rm "$staging/$linux"
mv "$fixture_root/original" "$staging/$linux"
bash "$project/scripts/verify-release-assets.sh" 0.1.1 "$staging"
printf 'Release asset verification tests passed.\n'
