#!/usr/bin/env bash
# Build the FlowLens images and the offline POC package:
#
#   dist/flowlens-poc-<version>-<arch>.tar.gz
#     VERSION, SHA256SUMS, docker-compose.yaml, .env.example,
#     install.sh, flowlens-ctl.sh, conf/, docs/,
#     images/flowlens-images-<version>-<arch>.tar.gz  (docker save)
#
# Usage: scripts/package-poc.sh [--platform linux/amd64|linux/arm64]
#                               [--no-images] [--skip-build]
#   --platform    target platform (default: the Docker host's); a foreign
#                 platform needs buildx with QEMU emulation
#   --no-images   leave the images out (the target pulls/builds them)
#   --skip-build  package images already tagged flowlens-*:<version>
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PLATFORM=""
WITH_IMAGES=true
BUILD=true
while [ $# -gt 0 ]; do
  case "$1" in
    --platform) PLATFORM="${2:?--platform needs a value}"; shift ;;
    --no-images) WITH_IMAGES=false ;;
    --skip-build) BUILD=false ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

VERSION="$(sed -n 's/^[[:space:]]*Version[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' pkg/version/version.go)"
[ -n "$VERSION" ] || { echo "cannot read Version from pkg/version/version.go" >&2; exit 1; }
WEB_VERSION="$(sed -n 's/^[[:space:]]*"version":[[:space:]]*"\(.*\)".*/\1/p' web/package.json | head -n1)"
if [ "$WEB_VERSION" != "$VERSION" ]; then
  echo "version mismatch: pkg/version=$VERSION web/package.json=$WEB_VERSION" >&2
  exit 1
fi

if [ -z "$PLATFORM" ]; then
  PLATFORM="linux/$(docker version --format '{{.Server.Arch}}')"
fi
ARCH="${PLATFORM#linux/}"
PG_IMAGE="postgres:16-alpine"
IMAGES=("flowlens-platform:$VERSION" "flowlens-web:$VERSION" "flowlens-agent:$VERSION")

echo "==> FlowLens $VERSION for $PLATFORM"

if [ "$BUILD" = true ]; then
  build() { # build TAG CONTEXT DOCKERFILE
    echo "==> building $1"
    docker build --platform "$PLATFORM" --build-arg "VERSION=$VERSION" \
      -t "$1" -f "$3" "$2"
  }
  build "flowlens-platform:$VERSION" . platform/Dockerfile
  build "flowlens-agent:$VERSION" . agent/Dockerfile
  build "flowlens-web:$VERSION" web web/Dockerfile
fi
for img in "${IMAGES[@]}"; do
  docker image inspect "$img" >/dev/null || { echo "missing image $img" >&2; exit 1; }
done

NAME="flowlens-poc-$VERSION-$ARCH"
STAGE="dist/$NAME"
rm -rf "$STAGE"
mkdir -p "$STAGE/conf" "$STAGE/docs" "$STAGE/images"

cp deploy/poc/docker-compose.yaml deploy/poc/.env.example \
   deploy/poc/install.sh deploy/poc/flowlens-ctl.sh "$STAGE/"
cp deploy/poc/conf/agent-config.yaml deploy/poc/conf/demo-traffic.sh "$STAGE/conf/"
cp docs/POC_INSTALL.md "$STAGE/docs/"
cp docs/DATABASE_PERFORMANCE.md "$STAGE/docs/"
sed -i "s/^FLOWLENS_VERSION=.*/FLOWLENS_VERSION=$VERSION/" "$STAGE/.env.example"
echo "$VERSION" > "$STAGE/VERSION"
chmod 755 "$STAGE/install.sh" "$STAGE/flowlens-ctl.sh"

if [ "$WITH_IMAGES" = true ]; then
  if ! docker image inspect "$PG_IMAGE" >/dev/null 2>&1; then
    docker pull --platform "$PLATFORM" "$PG_IMAGE"
  fi
  echo "==> saving images"
  docker save "${IMAGES[@]}" "$PG_IMAGE" | gzip -6 > "$STAGE/images/flowlens-images-$VERSION-$ARCH.tar.gz"
else
  rmdir "$STAGE/images"
fi

(cd "$STAGE" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | sort | xargs sha256sum > SHA256SUMS)

tar -C dist -czf "dist/$NAME.tar.gz" "$NAME"
(cd dist && sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256")
rm -rf "$STAGE"

echo "==> dist/$NAME.tar.gz ($(du -h "dist/$NAME.tar.gz" | cut -f1))"
