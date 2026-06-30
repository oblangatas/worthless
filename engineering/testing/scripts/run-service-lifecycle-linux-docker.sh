#!/usr/bin/env bash
# Build and run service lifecycle live pack in Docker (systemd user session).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
IMAGE="${SERVICE_LIFECYCLE_DOCKER_IMAGE:-worthless-service-lifecycle-live:latest}"

echo "Building ${IMAGE}..."
docker build \
  -f "$REPO_ROOT/tests/install_fixtures/Dockerfile.service-lifecycle-live-linux" \
  -t "$IMAGE" \
  "$REPO_ROOT"

echo "Running service lifecycle Linux pack in Docker..."
CID="$(docker run -d --privileged \
  --cgroupns=host \
  -v "$REPO_ROOT:/repo" \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  "$IMAGE")"
trap 'docker rm -f "$CID" >/dev/null 2>&1 || true' EXIT

for _ in $(seq 1 30); do
  if docker exec "$CID" systemctl is-system-running --quiet 2>/dev/null; then
    break
  fi
  sleep 1
done

docker exec "$CID" /usr/local/bin/service-lifecycle-docker-entrypoint.sh
