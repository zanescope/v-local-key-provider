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
build_mode="${V_LOCAL_KEY_PROVIDER_BUILD_MODE:-development}"
ldflags=""
if [ "$identity" != "-" ]; then
  if [ "$build_mode" != "development" ]; then
    echo "a Developer ID signing identity always selects release mode; V_LOCAL_KEY_PROVIDER_BUILD_MODE must be omitted" >&2
    exit 2
  fi
  promotion="${V_LOCAL_KEY_PROVIDER_RELEASE_PROMOTION_PATH:-}"
  case "$promotion" in
    "$root"/compatibility-evidence/promotions/*) ;;
    *) echo "release requires a promotion manifest under compatibility-evidence/promotions" >&2; exit 2 ;;
  esac
  test -f "$promotion"
  promotion_sha="$(shasum -a 256 "$promotion" | awk '{print $1}')"
  ldflags="-X main.buildMode=release -X main.releasePromotionSHA256=$promotion_sha"
  (
    cd "$root"
    V_LOCAL_KEY_PROVIDER_REQUIRE_RELEASE_EVIDENCE=1 \
      V_LOCAL_KEY_PROVIDER_RELEASE_TARGET=darwin \
      V_LOCAL_KEY_PROVIDER_RELEASE_ARCH="$goarch" \
      V_LOCAL_KEY_PROVIDER_RELEASE_EVIDENCE_DIR="$root/compatibility-evidence" \
      V_LOCAL_KEY_PROVIDER_RELEASE_PROMOTION_PATH="$promotion" \
      go test -count=1 -run '^TestReleaseCompatibilityEvidenceGate$' .
  )
elif [ "$build_mode" = "candidate" ]; then
  ldflags="-X main.buildMode=candidate"
elif [ "$build_mode" != "development" ]; then
  echo "unsupported Provider build mode: $build_mode" >&2
  exit 2
fi

mkdir -p "$output"
(
  cd "$root"
  CGO_ENABLED=1 GOOS=darwin GOARCH="$goarch" go build -trimpath -ldflags "$ldflags" -o "$provider" ./cmd/v-local-key-provider
)
cp "$provider" "$helper"
chmod 700 "$provider" "$helper"

if [ "$identity" != "-" ]; then
  codesign --force --identifier com.zanescope.v-local-key-provider --options runtime --timestamp --sign "$identity" "$provider"
  codesign --force --identifier com.zanescope.v-local-key-provider.helper --options runtime --timestamp --entitlements "$root/scripts/macos-helper.entitlements" --sign "$identity" "$helper"
else
  # 临时签名构建会有意省略强化运行时，以保留本地兼容路径；正式的开发者标识构建
  # 会保留强化运行时，以便完成公证。
  codesign --force --identifier com.zanescope.v-local-key-provider --sign "$identity" "$provider"
  codesign --force --identifier com.zanescope.v-local-key-provider.helper --entitlements "$root/scripts/macos-helper.entitlements" --sign "$identity" "$helper"
fi

codesign --verify --strict --verbose=2 "$provider"
codesign --verify --strict --verbose=2 "$helper"

printf '%s\n' "$provider" "$helper"
