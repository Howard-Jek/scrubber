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

IMAGE="${IMAGE:-scrubberd:0.1.0}"
NET=scrubnet
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

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

echo "Starting scrubberd..."
docker run -d --name scrubberd --network "$NET" -p 8080:8080 \
  -v "$POL":/etc/scrubber/policies:ro \
  -e MINIO_ENDPOINT=scrubber-minio:9000 \
  -e MINIO_PUBLIC_ENDPOINT=localhost:19000 -e MINIO_PUBLIC_TLS=false \
  -e MINIO_ACCESS_KEY=minioadmin -e MINIO_SECRET_KEY=minioadmin -e MINIO_USE_TLS=false \
  -e INPUT_BUCKET=scrub-input -e OUTPUT_BUCKET=scrub-output -e REPORTS_BUCKET=scrub-reports \
  -e DEFAULT_POLICY=default -e ENSURE_BUCKETS=true -e POLL_INTERVAL=2s \
  "$IMAGE" >/dev/null

echo
echo "  Scrubber UI:    http://localhost:8080"
echo "  MinIO console:  http://localhost:9002  (minioadmin / minioadmin)"
echo "  Stop:           docker rm -f scrubberd scrubber-minio && docker network rm $NET"
