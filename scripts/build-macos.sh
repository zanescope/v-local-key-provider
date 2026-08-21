#!/bin/sh

set -eu

arch="${1:-$(uname -m)}"
case "$arch" in
  x86_64|amd64) goarch=amd64 ;;
  arm64|aarch64) goarch=arm64 ;;
  *) echo "unsupported macOS architecture: $arch" >&2; exit 2 ;;
esac

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
output="$root/build/darwin-$goarch"
provider="$output/v-local-key-provider"
helper="$output/v-local-key-provider-helper"
identity="${V_LOCAL_KEY_PROVIDER_CODESIGN_IDENTITY:--}"

mkdir -p "$output"
(
  cd "$root"
  CGO_ENABLED=1 GOOS=darwin GOARCH="$goarch" go build -trimpath -o "$provider" .
)
cp "$provider" "$helper"
chmod 700 "$provider" "$helper"

if [ "$identity" != "-" ]; then
  codesign --force --options runtime --timestamp --sign "$identity" "$provider"
  codesign --force --options runtime --timestamp --entitlements "$root/scripts/macos-helper.entitlements" --sign "$identity" "$helper"
else
  # ad-hoc builds intentionally omit Hardened Runtime for the local compatibility
  # path; formal Developer ID builds retain it for notarization.
  codesign --force --sign "$identity" "$provider"
  codesign --force --entitlements "$root/scripts/macos-helper.entitlements" --sign "$identity" "$helper"
fi

codesign --verify --strict --verbose=2 "$provider"
codesign --verify --strict --verbose=2 "$helper"

printf '%s\n' "$provider" "$helper"
