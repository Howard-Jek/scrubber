#!/usr/bin/env bash
# Confirm the worst-case memory shape end to end, against real MinIO and the real
# service, and report peak RSS against the pod's memory limit.
#
#   ./scripts/memory-matrix.sh
#   EXPAND_MIB=192 GOMEMLIMIT_MIB=1000 ./scripts/memory-matrix.sh
#
# Why this exists separately from `go test -run TestMemoryMatrix`: that test measures
# Go *heap* for many shapes cheaply, which is the right tool for ranking shapes and
# for catching regressions in CI. It cannot tell you RSS, and RSS is what the kubelet
# OOM-kills on. So the matrix picks the worst shape and this confirms that one shape
# against the number that actually matters.
#
# TestMemoryMatrix ranks "many tiny members in a .tar.gz" worst (~11.6x content),
# ahead of the few-large-members shape most people reach for when testing by hand.
# Per-member overhead, not per-byte, is what dominates.
set -uo pipefail

S="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-/tmp/scrubber-memory-matrix}"
LIMIT_MIB="${LIMIT_MIB:-2048}"      # the pod's memory limit this is judged against
TARGET_PCT="${TARGET_PCT:-60}"      # peak RSS should land under this share of it
EXPAND_MIB="${EXPAND_MIB:-160}"
GOMEMLIMIT_MIB="${GOMEMLIMIT_MIB:-900}"
OBJECT_MIB="${OBJECT_MIB:-64}"

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
command -v minio >/dev/null || MINIO=/root/go/bin/minio
MINIO="${MINIO:-$(command -v minio)}"
[ -x "$MINIO" ] || { echo "minio server binary not found (set MINIO=...)" >&2; exit 1; }

cleanup() {
  [ -n "${SP:-}" ] && kill -9 "$SP" 2>/dev/null
  [ -n "${MP:-}" ] && kill -9 "$MP" 2>/dev/null
  [ -n "${SAMP:-}" ] && kill -9 "$SAMP" 2>/dev/null
}
trap cleanup EXIT

rm -rf "$WORK"; mkdir -p "$WORK/data" "$WORK/policies"
cp "$S"/deploy/policies/*.json "$WORK/policies/"
go build -o "$WORK/scrubberd" "$S/cmd/scrubberd" || exit 1

# --- worst-shape fixture: many tiny members, dense matches, in a .tar.gz ----------
# Sized to draw the full expansion budget. A .tar.gz charges the budget twice (once
# for the decompressed tar, once for the member bodies), so content is half the cap,
# minus a margin so the guard does not trip and pass the object through unscrubbed.
python3 - "$WORK" "$EXPAND_MIB" <<'PY'
import io, os, sys, tarfile
work, expand_mib = sys.argv[1], int(sys.argv[2])
cap = expand_mib * 1024 * 1024

# Size the fixture against the budget the engine actually charges, not against
# content. A .tar.gz draws twice -- once for the whole decompressed tar, once for the
# member bodies copied out of it -- and for many *small* members the tar's own
# overhead is not a rounding error: every member costs a 512B header plus padding up
# to the next 512B block. Ignoring that overshoots the cap, the guard trips, and the
# object is emitted UNSCRUBBED, which looks like a memory pass but is a scrub failure.
PER = 4096                       # block-aligned, so no padding waste
PER_MEMBER_DRAW = (512 + PER) + PER   # tar header+body, then the body copied again
members = int(cap * 0.95 / PER_MEMBER_DRAW)   # 5% under the cap: probe the real worst case

line = b"2024-01-01T12:00:00Z INFO bob@acme.test 10.1.2.3 AcmeCorp\n"
body = (line * (PER // len(line) + 1))[:PER]
out = f"{work}/worst.tar.gz"
with tarfile.open(out, "w:gz", compresslevel=6) as tf:
    for i in range(members):
        info = tarfile.TarInfo(name="logs/svc-%05d/app.log" % i)
        info.size = len(body)
        tf.addfile(info, io.BytesIO(body))

draw = members * PER_MEMBER_DRAW
print(f"fixture: {os.path.getsize(out)/1e6:.2f}MB compressed, "
      f"{members} members x {PER}B = {members*PER/1024/1024:.0f}MiB content, "
      f"~{draw/1024/1024:.0f}MiB budget draw of {expand_mib}MiB "
      f"({100*draw/cap:.0f}% of cap)")
PY

# --- bring up MinIO + scrubberd --------------------------------------------------
MINIO_ROOT_USER=minioadmin MINIO_ROOT_PASSWORD=minioadmin \
  "$MINIO" server "$WORK/data" --address ":19000" >"$WORK/minio.log" 2>&1 &
MP=$!
for _ in $(seq 1 60); do curl -fsS http://127.0.0.1:19000/minio/health/live >/dev/null 2>&1 && break; sleep 1; done

MINIO_ENDPOINT=127.0.0.1:19000 MINIO_ACCESS_KEY=minioadmin MINIO_SECRET_KEY=minioadmin \
MINIO_USE_TLS=false INPUT_BUCKET=scrub-input OUTPUT_BUCKET=scrub-output \
REPORTS_BUCKET=scrub-reports ENSURE_BUCKETS=true DEFAULT_POLICY=default \
POLICIES_DIR="$WORK/policies" PORT=8080 LOG_LEVEL=info WORKERS=1 \
MAX_OBJECT_BYTES=$((OBJECT_MIB * 1024 * 1024)) \
MAX_EXPAND_BYTES=$((EXPAND_MIB * 1024 * 1024)) \
GOMEMLIMIT="${GOMEMLIMIT_MIB}MiB" \
  "$WORK/scrubberd" >"$WORK/scrubberd.log" 2>&1 &
for _ in $(seq 1 60); do curl -fsS http://127.0.0.1:8080/readyz >/dev/null 2>&1 && break; sleep 1; done
SP=$(pgrep -f "$WORK/scrubberd" | head -1)
[ -z "$SP" ] && { echo "scrubberd failed to start"; tail -5 "$WORK/scrubberd.log"; exit 1; }

echo
grep -o '"msg":"resource limits".*' "$WORK/scrubberd.log" | head -1
echo

( while [ -d "/proc/$SP" ]; do
    awk '/VmRSS/{print $2}' "/proc/$SP/status" 2>/dev/null
    sleep 0.2
  done ) >"$WORK/rss.txt" &
SAMP=$!

# --- run it ----------------------------------------------------------------------
r=$(curl -fsS -X POST localhost:8080/api/uploads -H 'Content-Type: application/json' \
      -d '{"name":"worst.tar.gz"}')
key=$(echo "$r" | jq -r .key); url=$(echo "$r" | jq -r .url)
curl -fsS -X PUT --upload-file "$WORK/worst.tar.gz" "$url" >/dev/null
echo "uploaded; draining..."

status=""
for _ in $(seq 1 900); do
  status=$(curl -fsS "localhost:8080/api/status?key=$key" | jq -r .status)
  case "$status" in scrubbed|error|skipped) break ;; esac
  sleep 1
done
final=$(curl -fsS "localhost:8080/api/status?key=$key")
kill -9 "$SAMP" 2>/dev/null; SAMP=""

hwm=$(awk '/VmHWM/{print $2}' "/proc/$SP/status" 2>/dev/null)
peak_mib=$(( ${hwm:-0} / 1024 ))
budget_mib=$(( LIMIT_MIB * TARGET_PCT / 100 ))

echo
echo "=== worst shape, end to end ==="
echo "$final" | jq -r '"  status:       \(.status)\n  matches:      \(.matches // 0)\n  passthrough:  \(.passthrough // 0)"'
echo "  peak RSS:     ${peak_mib} MiB"
echo "  pod limit:    ${LIMIT_MIB} MiB   (target ${TARGET_PCT}% = ${budget_mib} MiB)"
echo "  headroom:     $(( LIMIT_MIB - peak_mib )) MiB"
echo

pt=$(echo "$final" | jq -r '.passthrough // 0')
if [ "$status" != "scrubbed" ]; then
  echo "RESULT: FAIL - object did not scrub (status=$status)"; exit 1
elif [ "$pt" != "0" ]; then
  echo "RESULT: FAIL - $pt file(s) passed through UNSCRUBBED; the expansion guard tripped,"
  echo "        so this cap silently degrades the scrub rather than bounding memory."; exit 1
elif [ "$peak_mib" -gt "$budget_mib" ]; then
  echo "RESULT: FAIL - peak ${peak_mib} MiB exceeds the ${TARGET_PCT}% target of ${budget_mib} MiB."
  echo "        Lower MAX_EXPAND_BYTES (and GOMEMLIMIT with it)."; exit 1
else
  echo "RESULT: PASS - scrubbed cleanly at ${peak_mib} MiB, within the ${budget_mib} MiB target."
fi
