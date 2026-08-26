#!/usr/bin/env bash
# End-to-end load benchmark for the scrubber service.
#
# Uploads N objects of size S all at once, waits for the service to drain them, and
# reports the numbers that distinguish "one at a time, in order" from "everything at
# once": total wall clock, time to the FIRST completion, per-object latency, and
# peak container memory.
#
#   ./scripts/bench-queue.sh                        # defaults: 25 objects of 8MiB
#   N=5 SIZE_MB=64 ./scripts/bench-queue.sh         # few large objects
#   IMAGE=scrubberd:baseline ./scripts/bench-queue.sh
#
# To compare against the pre-queue behaviour, build both images and run the same
# workload through each:
#
#   git stash && docker build -q -f deploy/Containerfile -t scrubberd:baseline . && git stash pop
#   docker build -q -f deploy/Containerfile -t scrubberd:queue .
#   IMAGE=scrubberd:baseline ./scripts/bench-queue.sh
#   IMAGE=scrubberd:queue    ./scripts/bench-queue.sh
#
# What to expect: serialising work does NOT create throughput on a single CPU --
# the same bytes still have to be scrubbed. Total wall clock should come out about
# level (a little better, from less GC pressure with half the live heap). The wins
# are time-to-first-completion, which should improve by roughly N times, and peak
# memory, which should roughly halve. If total wall clock is materially WORSE, that
# is a real regression and worth chasing rather than shipping.
set -euo pipefail

IMAGE="${IMAGE:-scrubberd:bench}"
N="${N:-25}"
SIZE_MB="${SIZE_MB:-8}"
NET=scrubbench
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Mirror the pod so the numbers mean something for the deployment. Memory tracks
# deploy/openshift-manifests.yaml (limits.memory: 4Gi); note it governs the SPILL_*
# knobs and MAX_LEAF_BYTES, NOT how large a bundle may expand -- that follows the
# scratch declaration, which this queue benchmark does not exercise.
CPUS="${CPUS:-1}"
MEMORY="${MEMORY:-4g}"

cleanup() {
  docker rm -f scrubbench-minio scrubbench-scrubberd >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  [[ -n "${WORK:-}" ]] && rm -rf "$WORK"
}
trap cleanup EXIT

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

echo "=== scrubber queue benchmark ==="
echo "image=$IMAGE objects=$N size=${SIZE_MB}MiB cpus=$CPUS memory=$MEMORY"
echo

cleanup
docker network create "$NET" >/dev/null

docker run -d --name scrubbench-minio --network "$NET" -p 19100:9000 \
  -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin \
  minio/minio server /data >/dev/null

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "Building $IMAGE..."
  docker build -q -f "$ROOT/deploy/Containerfile" -t "$IMAGE" "$ROOT" >/dev/null
fi

POL="$(mktemp -d)"
cp "$ROOT"/deploy/policies/*.json "$POL"/
MOUNT_SRC="$POL"
if command -v cygpath >/dev/null 2>&1; then
  MOUNT_SRC="$(cygpath -w "$POL")"
  export MSYS_NO_PATHCONV=1
fi

# GODEBUG=gctrace=1 puts GC cycles in the container log. Halving the live heap is
# one of the reasons serialising can come out ahead rather than merely level, so it
# is worth being able to see.
docker run -d --name scrubbench-scrubberd --network "$NET" -p 8180:8080 \
  --cpus "$CPUS" --memory "$MEMORY" \
  -v "$MOUNT_SRC":/etc/scrubber/policies:ro \
  -e MINIO_ENDPOINT=scrubbench-minio:9000 \
  -e MINIO_ACCESS_KEY=minioadmin -e MINIO_SECRET_KEY=minioadmin -e MINIO_USE_TLS=false \
  -e INPUT_BUCKET=scrub-input -e OUTPUT_BUCKET=scrub-output -e REPORTS_BUCKET=scrub-reports \
  -e DEFAULT_POLICY=default -e ENSURE_BUCKETS=true -e POLL_INTERVAL=2s \
  -e MAX_OBJECT_BYTES=$((SIZE_MB * 2 * 1024 * 1024)) \
  -e GODEBUG=gctrace=1 \
  "$IMAGE" >/dev/null

echo -n "Waiting for readiness"
for _ in $(seq 1 60); do
  if curl -fsS http://localhost:8180/readyz >/dev/null 2>&1; then break; fi
  echo -n "."; sleep 1
done
echo " ok"

# --- build the payload ---------------------------------------------------------
WORK="$(mktemp -d)"
echo "Generating $N objects of ${SIZE_MB}MiB..."
LINE='2024-01-01T12:00:00Z INFO  user bob@internal.acme.test at 10.1.2.3 contacted AcmeCorp about ticket'
BLOCK="$WORK/block.txt"
: >"$BLOCK"
for _ in $(seq 1 1000); do echo "$LINE" >>"$BLOCK"; done
BLOCK_BYTES=$(wc -c <"$BLOCK")
REPEATS=$(( SIZE_MB * 1024 * 1024 / BLOCK_BYTES + 1 ))
for i in $(seq 1 "$N"); do
  for _ in $(seq 1 "$REPEATS"); do cat "$BLOCK"; done >"$WORK/obj-$i.log"
done

# --- sample container memory in the background ---------------------------------
PEAK_FILE="$WORK/peak"
echo 0 >"$PEAK_FILE"
(
  while true; do
    used=$(docker stats --no-stream --format '{{.MemUsage}}' scrubbench-scrubberd 2>/dev/null | awk '{print $1}') || true
    case "$used" in
      *GiB) mb=$(awk -v v="${used%GiB}" 'BEGIN{printf "%d", v*1024}') ;;
      *MiB) mb=${used%MiB}; mb=${mb%.*} ;;
      *) mb=0 ;;
    esac
    cur=$(cat "$PEAK_FILE" 2>/dev/null || echo 0)
    [[ "${mb:-0}" -gt "$cur" ]] && echo "$mb" >"$PEAK_FILE"
    sleep 1
  done
) &
SAMPLER=$!

# --- upload everything at once -------------------------------------------------
echo "Uploading $N objects concurrently..."
START=$(date +%s.%N)
for i in $(seq 1 "$N"); do
  (
    url=$(curl -fsS -X POST http://localhost:8180/api/uploads \
      -H 'Content-Type: application/json' \
      -d "{\"name\":\"obj-$i.log\"}" | jq -r .url)
    # The presigned URL is signed for the in-cluster host; rewrite for the host side.
    url=${url/scrubbench-minio:9000/localhost:19100}
    curl -fsS -X PUT --upload-file "$WORK/obj-$i.log" "$url" >/dev/null
  ) &
done
wait
UPLOADED=$(date +%s.%N)
echo "All uploads accepted after $(awk -v a="$START" -v b="$UPLOADED" 'BEGIN{printf "%.1fs", b-a}')"

# --- watch the drain -----------------------------------------------------------
echo "Draining..."
FIRST_DONE=""
DONE=0
DEADLINE=$(( $(date +%s) + 1800 ))
while [[ "$DONE" -lt "$N" ]]; do
  if [[ $(date +%s) -gt $DEADLINE ]]; then
    echo "TIMED OUT with $DONE/$N complete" >&2
    break
  fi
  DONE=$(curl -fsS "http://localhost:8180/api/history?n=$N" 2>/dev/null | jq '.runs | length' 2>/dev/null || echo 0)
  if [[ -z "$FIRST_DONE" && "$DONE" -ge 1 ]]; then
    FIRST_DONE=$(date +%s.%N)
    depth=$(curl -fsS http://localhost:8180/api/queue 2>/dev/null | jq -r .depth 2>/dev/null || echo "?")
    echo "  first object complete (queue depth still $depth)"
  fi
  sleep 1
done
END=$(date +%s.%N)
kill "$SAMPLER" 2>/dev/null || true

# --- report --------------------------------------------------------------------
hist() { curl -fsS http://localhost:8180/metrics | grep -E "^$1" || true; }
quantile() { # metric_prefix -> rough p50/p95 from bucket counts
  curl -fsS http://localhost:8180/metrics \
    | awk -v m="$1" '$0 ~ "^"m"_bucket" {split($0,a,"le=\""); split(a[2],b,"\""); print b[1], $NF}'
}

echo
echo "=== results: $IMAGE ($N x ${SIZE_MB}MiB, cpus=$CPUS) ==="
awk -v a="$START" -v b="$END" 'BEGIN{printf "total wall clock        %.1fs\n", b-a}'
if [[ -n "$FIRST_DONE" ]]; then
  awk -v a="$START" -v b="$FIRST_DONE" 'BEGIN{printf "time to first complete  %.1fs\n", b-a}'
fi
echo "objects completed       $DONE / $N"
echo "peak container memory   $(cat "$PEAK_FILE") MiB"
echo
echo "-- queue depth / inflight --"
hist 'scrubber_queue_depth'
hist 'scrubber_inflight_objects'
echo
echo "-- per-object latency (arrival -> done), cumulative bucket counts --"
quantile scrubber_object_latency_seconds
echo
echo "-- queue wait (arrival -> start) --"
quantile scrubber_queue_wait_seconds
echo
echo "-- processing time only --"
hist 'scrubber_process_seconds_sum'
hist 'scrubber_process_seconds_count'
echo
echo "-- GC cycles observed --"
docker logs scrubbench-scrubberd 2>&1 | grep -c '^gc ' || true
echo
echo "(containers are torn down on exit; re-run with a different IMAGE to compare)"
