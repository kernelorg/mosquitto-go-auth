#!/usr/bin/env bash
# Build the Mosquitto + go-auth image from Dockerfile.multiarch.
#
#   ./build-image.sh                      # linux/amd64, tag mosquitto-go-auth-radius:local
#   ./build-image.sh linux/arm64 mosquitto-go-auth-radius:arm64
#
# No QEMU/binfmt is needed for linux/arm64: the plugin is cross-compiled and
# the runtime stage only copies files. When the buildx CLI plugin is missing,
# the official docker:cli image (which bundles buildx) drives the build.
set -euo pipefail
cd "$(dirname "$0")"

PLATFORM=${1:-linux/amd64}
TAG=${2:-mosquitto-go-auth-radius:local}
DOCKERFILE=Dockerfile.multiarch

if docker buildx version >/dev/null 2>&1; then
	exec docker buildx build --platform "$PLATFORM" -f "$DOCKERFILE" -t "$TAG" --load .
fi

echo "docker buildx plugin not found, building through the docker:cli container" >&2
exec docker run --rm \
	-v /var/run/docker.sock:/var/run/docker.sock \
	-v "$PWD:/work" -w /work \
	docker:cli buildx build --platform "$PLATFORM" -f "$DOCKERFILE" -t "$TAG" --load .
