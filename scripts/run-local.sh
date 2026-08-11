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

IMAGE="${IMAGE:-scrubberd:0.5.0}"
NET=scrubnet
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Mirror the pod: same memory and CPU ceiling, same caps as deploy/openshift-manifests.yaml.
# Without --memory the container inherits the whole host and a local run cannot tell you
# anything about whether a bundle fits the 2Gi pod -- which is the thing worth checking.
MEM="${MEM:-2g}"
CPUS="${CPUS:-1}"
MAX_OBJECT_BYTES="${MAX_OBJECT_BYTES:-671088640}"     # 640Mi
MAX_EXPAND_BYTES="${MAX_EXPAND_BYTES:-1610612736}"    # 1536Mi
SPILL_THRESHOLD="${SPILL_THRESHOLD:-4194304}"         # 4Mi
SPILL_RESIDENT_MAX="${SPILL_RESIDENT_MAX:-67108864}"  # 64Mi
GOMEMLIMIT="${GOMEMLIMIT:-1200MiB}"

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
  -e MAX_OBJECT_BYTES="$MAX_OBJECT_BYTES" -e MAX_EXPAND_BYTES="$MAX_EXPAND_BYTES" \
  -e SPILL_THRESHOLD="$SPILL_THRESHOLD" -e SPILL_RESIDENT_MAX="$SPILL_RESIDENT_MAX" \
  -e GOMEMLIMIT="$GOMEMLIMIT" \
  "$IMAGE" >/dev/null

echo
echo "  Scrubber UI:    http://localhost:8080"
echo "  MinIO console:  http://localhost:9002  (minioadmin / minioadmin)"
echo "  Watch memory:   docker stats scrubberd"
echo "  Stop:           docker rm -f scrubberd scrubber-minio && docker network rm $NET"
