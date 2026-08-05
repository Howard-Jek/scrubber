#!/usr/bin/env bash
# Confirm the worst-case memory shapes end to end, against real MinIO and the real
# service, and report peak RSS against the pod's memory limit.
#
#   ./scripts/memory-matrix.sh
#   EXPAND_MIB=192 GOMEMLIMIT_MIB=1000 ./scripts/memory-matrix.sh
#   SHAPES=big ./scripts/memory-matrix.sh          # just the 500MiB bundle
#
# Why this exists separately from `go test -run TestMemoryMatrix`: that test measures
# Go *heap* for many shapes cheaply, which is the right tool for ranking shapes and
# for catching regressions in CI. It cannot tell you RSS, and RSS is what the kubelet
# OOM-kills on. So the matrix picks the worst shapes and this confirms them against
# the number that actually matters.
#
# Two shapes, because they fail differently:
#
#   tiny  many small members in a .tar.gz. TestMemoryMatrix ranks this worst per byte
#         of content -- per-member overhead, not per-byte, is what dominates. This is
#         the shape that used to hold the whole bundle in RAM at once.
#   big   ~500MiB of incompressible content, the real-world bundle. This is the shape
#         the disk spill exists for: it cannot fit in the pod at any cap setting
#         unless member bodies live on disk.
#
# The run also asserts that scrubberd leaves no temp files behind in TMPDIR -- a
# leaked spill file per object would fill the pod's emptyDir over a few days.
set -uo pipefail

S="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-/tmp/scrubber-memory-matrix}"
LIMIT_MIB="${LIMIT_MIB:-2048}"      # the pod's memory limit this is judged against
TARGET_PCT="${TARGET_PCT:-60}"      # peak RSS should land under this share of it
EXPAND_MIB="${EXPAND_MIB:-1536}"
GOMEMLIMIT_MIB="${GOMEMLIMIT_MIB:-1200}"
OBJECT_MIB="${OBJECT_MIB:-640}"
SPILL_THRESHOLD_MIB="${SPILL_THRESHOLD_MIB:-4}"
SPILL_RESIDENT_MIB="${SPILL_RESIDENT_MIB:-64}"
SHAPES="${SHAPES:-tiny big}"
BIG_MIB="${BIG_MIB:-500}"    # content size of the "big" incompressible shape

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

rm -rf "$WORK"; mkdir -p "$WORK/data" "$WORK/policies" "$WORK/scratch"
cp "$S"/deploy/policies/*.json "$WORK/policies/"
go build -o "$WORK/scrubberd" "$S/cmd/scrubberd" || exit 1

# --- fixtures --------------------------------------------------------------------
python3 - "$WORK" "$EXPAND_MIB" "$SHAPES" "$BIG_MIB" <<'PY'
import io, os, sys, tarfile
work, expand_mib, shapes, big_mib = sys.argv[1], int(sys.argv[2]), sys.argv[3].split(), int(sys.argv[4])
cap = expand_mib * 1024 * 1024
line = b"2024-01-01T12:00:00Z INFO bob@acme.test 10.1.2.3 AcmeCorp\n"

def report(path, members, content, draw, note):
    print(f"fixture {os.path.basename(path):18s} {os.path.getsize(path)/1e6:8.1f}MB on the wire, "
          f"{members} members, {content/1024/1024:.0f}MiB content, "
          f"~{draw/1024/1024:.0f}MiB budget draw of {expand_mib}MiB "
          f"({100*draw/cap:.0f}% of cap) -- {note}")

if "tiny" in shapes:
    # Size the fixture against the budget the engine actually charges, not against
    # content. A .tar.gz draws twice -- once for the whole decompressed tar, once for
    # the member bodies copied out of it -- and for many *small* members the tar's own
    # overhead is not a rounding error: every member costs a 512B header plus padding
    # up to the next 512B block. Ignoring that overshoots the cap, the guard trips, and
    # the object is emitted UNSCRUBBED, which looks like a memory pass but is a scrub
    # failure. MAX_MEMBERS is the other ceiling; stay clear of it for the same reason.
    PER = 4096                            # block-aligned, so no padding waste
    PER_MEMBER_DRAW = (512 + PER) + PER   # tar header+body, then the body copied again
    members = min(int(cap * 0.95 / PER_MEMBER_DRAW), 90000)
    body = (line * (PER // len(line) + 1))[:PER]
    out = f"{work}/tiny.tar.gz"
    with tarfile.open(out, "w:gz", compresslevel=6) as tf:
        for i in range(members):
            info = tarfile.TarInfo(name="logs/svc-%05d/app.log" % i)
            info.size = len(body)
            tf.addfile(info, io.BytesIO(body))
    report(out, members, members * PER, members * PER_MEMBER_DRAW,
           "per-member overhead dominates")

if "big" in shapes:
    # The real bundle: ~500MiB that does not compress, so uploaded size ~= expanded
    # size. Each member is mostly random bytes with a band of scrubbable lines at the
    # front, so the run proves the payload was actually read and rewritten rather than
    # streamed past. Written with compresslevel=1: gzip cannot shrink this and level 6
    # would only burn CPU proving it.
    PER = 10 * 1024 * 1024
    MEMBERS = max(1, big_mib * 1024 * 1024 // PER)
    MATCH_BAND = 64 * 1024
    band = (line * (MATCH_BAND // len(line) + 1))[:MATCH_BAND]
    out = f"{work}/big.tar.gz"
    with tarfile.open(out, "w:gz", compresslevel=1) as tf:
        for i in range(MEMBERS):
            body = band + os.urandom(PER - MATCH_BAND)
            info = tarfile.TarInfo(name="bundle/blob-%03d.bin" % i)
            info.size = len(body)
            tf.addfile(info, io.BytesIO(body))
    report(out, MEMBERS, MEMBERS * PER, MEMBERS * (512 + PER) + MEMBERS * PER,
           "incompressible, the shape the spill exists for")
PY

# --- bring up MinIO + scrubberd --------------------------------------------------
MINIO_ROOT_USER=minioadmin MINIO_ROOT_PASSWORD=minioadmin \
  "$MINIO" server "$WORK/data" --address ":19000" >"$WORK/minio.log" 2>&1 &
MP=$!
for _ in $(seq 1 60); do curl -fsS http://127.0.0.1:19000/minio/health/live >/dev/null 2>&1 && break; sleep 1; done

# TMPDIR mirrors the pod, where the Containerfile points it at the /work emptyDir.
# Pointing it at a directory of our own is what makes the leak check below meaningful.
TMPDIR="$WORK/scratch" \
MINIO_ENDPOINT=127.0.0.1:19000 MINIO_ACCESS_KEY=minioadmin MINIO_SECRET_KEY=minioadmin \
MINIO_USE_TLS=false INPUT_BUCKET=scrub-input OUTPUT_BUCKET=scrub-output \
REPORTS_BUCKET=scrub-reports ENSURE_BUCKETS=true DEFAULT_POLICY=default \
POLICIES_DIR="$WORK/policies" PORT=8080 LOG_LEVEL=info WORKERS=1 \
MAX_OBJECT_BYTES=$((OBJECT_MIB * 1024 * 1024)) \
MAX_EXPAND_BYTES=$((EXPAND_MIB * 1024 * 1024)) \
SPILL_THRESHOLD=$((SPILL_THRESHOLD_MIB * 1024 * 1024)) \
SPILL_RESIDENT_MAX=$((SPILL_RESIDENT_MIB * 1024 * 1024)) \
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

# --- run each shape --------------------------------------------------------------
fail=0
budget_mib=$(( LIMIT_MIB * TARGET_PCT / 100 ))
declare -a SUMMARY

for shape in $SHAPES; do
  f="$WORK/$shape.tar.gz"
  [ -f "$f" ] || continue
  r=$(curl -fsS -X POST localhost:8080/api/uploads -H 'Content-Type: application/json' \
        -d "{\"name\":\"$shape.tar.gz\"}")
  key=$(echo "$r" | jq -r .key); url=$(echo "$r" | jq -r .url)
  t0=$(date +%s)
  curl -fsS -X PUT --upload-file "$f" "$url" >/dev/null
  echo "uploaded $shape.tar.gz; draining..."

  status=""
  for _ in $(seq 1 1800); do
    status=$(curl -fsS "localhost:8080/api/status?key=$key" | jq -r .status)
    case "$status" in scrubbed|error|skipped) break ;; esac
    sleep 1
  done
  final=$(curl -fsS "localhost:8080/api/status?key=$key")
  secs=$(( $(date +%s) - t0 ))

  # Peak RSS is read fresh per shape from the running process, so a later shape
  # cannot hide behind an earlier one's high-water mark.
  hwm=$(awk '/VmHWM/{print $2}' "/proc/$SP/status" 2>/dev/null)
  peak_mib=$(( ${hwm:-0} / 1024 ))
  pt=$(echo "$final" | jq -r '.passthrough // 0')
  matches=$(echo "$final" | jq -r '.matches // 0')

  verdict=PASS
  if [ "$status" != "scrubbed" ]; then
    verdict="FAIL (status=$status)"; fail=1
  elif [ "$pt" != "0" ]; then
    verdict="FAIL ($pt passed through UNSCRUBBED)"; fail=1
  elif [ "$matches" = "0" ]; then
    verdict="FAIL (no matches: the payload was never scrubbed)"; fail=1
  elif [ "$peak_mib" -gt "$budget_mib" ]; then
    verdict="FAIL (peak ${peak_mib} MiB over the ${budget_mib} MiB target)"; fail=1
  fi
  SUMMARY+=("$(printf '  %-6s %-8s %8s matches  %5ss  peak %5s MiB (cumulative)  %s' \
      "$shape" "$status" "$matches" "$secs" "$peak_mib" "$verdict")")
done

kill -9 "$SAMP" 2>/dev/null; SAMP=""

# --- temp-file leak check --------------------------------------------------------
# Every spilled blob is a file under TMPDIR that only Blob.Close removes. If any
# survive an idle service, some path -- including the panic recovery in the worker --
# is dropping one per object, and the pod's emptyDir fills up in production.
#
# Wait for the directory to empty rather than sampling once. Reported status is not
# the end of the object: past staleAfter the API answers from the digest, which is
# written before the input is moved aside, and moving a half-gigabyte object is a
# server-side copy that takes seconds. Sampling straight after "scrubbed" therefore
# catches live files and calls them leaks. A leak is a file that never goes away.
for _ in $(seq 1 120); do
  [ -z "$(find "$WORK/scratch" -type f -print -quit)" ] && break
  sleep 1
done
leaked=$(find "$WORK/scratch" -type f | wc -l)
leak_list=$(find "$WORK/scratch" -type f | head -5)

hwm=$(awk '/VmHWM/{print $2}' "/proc/$SP/status" 2>/dev/null)
peak_mib=$(( ${hwm:-0} / 1024 ))

echo
echo "=== end to end, real MinIO, real service ==="
printf '%s\n' "${SUMMARY[@]}"
echo
echo "  pod limit:    ${LIMIT_MIB} MiB   (target ${TARGET_PCT}% = ${budget_mib} MiB)"
echo "  peak RSS:     ${peak_mib} MiB across the whole run"
echo "  headroom:     $(( LIMIT_MIB - peak_mib )) MiB"
echo "  temp files:   ${leaked} left in TMPDIR"
echo

if [ "$leaked" != "0" ]; then
  echo "RESULT: FAIL - ${leaked} spill file(s) leaked into TMPDIR:"
  echo "$leak_list" | sed 's/^/          /'
  fail=1
fi
if [ "$fail" != "0" ]; then
  echo "RESULT: FAIL - see the shape table above."
  exit 1
fi
echo "RESULT: PASS - every shape scrubbed cleanly at ${peak_mib} MiB peak, within the ${budget_mib} MiB target, no temp files leaked."
