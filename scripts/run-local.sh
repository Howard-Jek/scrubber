#!/usr/bin/env bash
# Run the scrubber service locally with Docker: starts MinIO, builds the image,
# and runs scrubberd wired so a browser can do the presigned uploads.
#
#   ./scripts/run-local.sh          # build + start
#   docker rm -f scrubberd scrubber-minio && docker network rm scrubnet   # stop
#
# Then open the UI at http://localhost:8080 and the MinIO console at
# http://localhost:9002 (minioadmin / minioadmin).
set -euo pipefail

IMAGE="${IMAGE:-scrubberd:0.8.0}"
NET=scrubnet
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Mirror the pod: same memory and CPU ceiling, same DECLARATIONS as
# deploy/openshift-manifests.yaml. Without --memory the container inherits the whole
# host and a local run cannot tell you anything about whether a bundle fits the pod --
# which is the thing worth checking.
#
# Note what is NOT set here. MAX_EXPAND_BYTES, MAX_OBJECT_BYTES, MAX_LEAF_BYTES, the
# SPILL_* pair and GOMEMLIMIT are all DERIVED by the service from MEM and
# SCRATCH_BYTES, exactly as they are in the pod. This script used to hardcode them,
# which made the one command people run to "check it like production" the one command
# that bypassed production's sizing -- and it drifted: it still said 1536Mi long after
# the manifest's SCRATCH_BYTES derived 1638Mi. Declare the inputs, let the service
# derive the outputs, and a local run can actually disagree with you.
#
# Any of them can still be exported to override, exactly as in the ConfigMap.
MEM="${MEM:-4g}"
CPUS="${CPUS:-1}"
# Matches the manifest's /work sizeLimit and limits.ephemeral-storage (14Gi), which
# derives a 4Gi expansion cap. Docker has no emptyDir sizeLimit to enforce, so this is
# a declaration only: a local run can overrun the volume where the pod would be
# evicted for ephemeral-storage.
SCRATCH_BYTES="${SCRATCH_BYTES:-14Gi}"                # == the manifest, verbatim

# POD_MEMORY_LIMIT is what the manifest projects with the Downward API. Docker's
# cgroup would also be readable, but passing it explicitly keeps the local run on the
# same code path as the pod.
mem_bytes() {
  case "$1" in
    *g|*G) echo $(( ${1%[gG]} * 1024 * 1024 * 1024 )) ;;
    *m|*M) echo $(( ${1%[mM]} * 1024 * 1024 )) ;;
    *)     echo "$1" ;;
  esac
}

docker network create "$NET" >/dev/null 2>&1 || true
docker rm -f scrubber-minio scrubberd >/dev/null 2>&1 || true

echo "Starting MinIO (CORS open so the browser can upload directly)..."
docker run -d --name scrubber-minio --network "$NET" -p 19000:9000 -p 9002:9002 \
  -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin \
  -e MINIO_API_CORS_ALLOW_ORIGIN='*' \
  minio/minio server /data --console-address ":9002" >/dev/null

echo "Building image ($IMAGE)..."
docker build -q -f "$ROOT/deploy/Containerfile" -t "$IMAGE" "$ROOT" >/dev/null

# Copy policies to a space-free temp dir (bind mounts dislike spaces in the path).
POL="$(mktemp -d)"
cp "$ROOT"/deploy/policies/*.json "$POL"/

# Docker resolves bind-mount sources on the *host*. Under Git Bash / MSYS on
# Windows, mktemp hands back an MSYS path like /tmp/tmp.XXXX, which Docker
# Desktop reads as a path inside its own Linux VM -- the mount silently comes up
# empty and the service exits with "no policies found". Translate it, and stop
# MSYS rewriting the container-side path in the -v argument.
MOUNT_SRC="$POL"
if command -v cygpath >/dev/null 2>&1; then
  MOUNT_SRC="$(cygpath -w "$POL")"
  export MSYS_NO_PATHCONV=1
fi

echo "Starting scrubberd (${MEM} / ${CPUS} CPU, same caps as the OCP manifest)..."
docker run -d --name scrubberd --network "$NET" -p 8080:8080 \
  --memory="$MEM" --cpus="$CPUS" \
  -v "$MOUNT_SRC":/etc/scrubber/policies:ro \
  -e MINIO_ENDPOINT=scrubber-minio:9000 \
  -e MINIO_PUBLIC_ENDPOINT=localhost:19000 -e MINIO_PUBLIC_TLS=false \
  -e MINIO_ACCESS_KEY=minioadmin -e MINIO_SECRET_KEY=minioadmin -e MINIO_USE_TLS=false \
  -e INPUT_BUCKET=scrub-input -e OUTPUT_BUCKET=scrub-output -e REPORTS_BUCKET=scrub-reports \
  -e DEFAULT_POLICY=default -e ENSURE_BUCKETS=true -e POLL_INTERVAL=2s \
  -e WORKERS=1 \
  -e SCRATCH_BYTES="$SCRATCH_BYTES" \
  -e POD_MEMORY_LIMIT="$(mem_bytes "$MEM")" \
  "$IMAGE" >/dev/null

echo
echo "  Scrubber UI:    http://localhost:8080"
echo "  MinIO console:  http://localhost:9002  (minioadmin / minioadmin)"
echo "  Watch memory:   docker stats scrubberd"
echo "  Stop:           docker rm -f scrubberd scrubber-minio && docker network rm $NET"
