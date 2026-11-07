#!/usr/bin/env bash
# Build Inkay in the devkitPPC container (same setup as README.md, just wrapped).
# Usage:
#   ./build.sh             build everything (make), rebuilding the image if needed
#   ./build.sh clean       clean build artifacts, then exit
#   ./build.sh noimage     skip the image build/pull, just run make
#   ./build.sh -- ARGS...  pass ARGS straight to `make` inside the container
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

IMAGE=inkay
SKIP_IMAGE=0
MAKE_ARGS=(make)

if [ "${1:-}" = "clean" ]; then
    MAKE_ARGS=(make clean)
    shift
elif [ "${1:-}" = "noimage" ]; then
    SKIP_IMAGE=1
    shift
fi
if [ "${1:-}" = "--" ]; then
    shift
    MAKE_ARGS=(make "$@")
fi

if command -v docker >/dev/null 2>&1; then
    ENGINE=docker
elif command -v podman >/dev/null 2>&1; then
    ENGINE=podman
else
    echo "error: neither docker nor podman found on PATH" >&2
    exit 1
fi
echo "=== using $ENGINE ==="

if [ "$SKIP_IMAGE" -eq 0 ]; then
    echo "=== building image ==="
    "$ENGINE" build -t "$IMAGE" .
fi

echo "=== ${MAKE_ARGS[*]} ==="
"$ENGINE" run --rm -v "$(pwd):/app" "$IMAGE" "${MAKE_ARGS[@]}"

if [ "${MAKE_ARGS[1]:-}" = "clean" ]; then
    echo "=== cleaned ==="
    exit 0
fi

echo
echo "=== dist/ ==="
ls -la dist/ 2>/dev/null || echo "(no dist/ produced)"