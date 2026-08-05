#!/usr/bin/env bash
# Prove end to end, against real MinIO and the real service, that a UTF-16 log is
# scrubbed and comes back in the encoding it arrived in.
#
#   ./scripts/encoding-check.sh
#   SIZE_MB=3 ./scripts/encoding-check.sh
#
# This exists because the unit tests cannot see the whole path a real upload takes:
# presigned PUT into MinIO, the worker's bounded fetch, the spill staging, the scrub,
# the streamed PUT of the result, and the report the UI reads. The defect it guards
# against lived in the middle of that path and looked like success from both ends —
# a .txt file came back untouched and the run reported clean, because UTF-16 text
# carries a NUL in the high byte of every ASCII character and the binary check
# stopped at the first NUL it found.
#
# Shapes uploaded (same content in each, so the match counts must agree):
#   utf8      the file that always worked, as the control
#   utf16le   what PowerShell's `>` and Notepad's "Unicode" write
#   utf16be   the other byte order
#   utf16le-nobom   what most non-Windows tooling writes
#   binary    a PNG-like blob, which must STILL be skipped — and now be named
set -uo pipefail

S="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-/tmp/scrubber-encoding-check}"
SIZE_MB="${SIZE_MB:-3}"   # matches the reported file size

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
command -v minio >/dev/null || MINIO=/root/go/bin/minio
MINIO="${MINIO:-$(command -v minio)}"
[ -x "$MINIO" ] || { echo "minio server binary not found (set MINIO=...)" >&2; exit 1; }

cleanup() {
  [ -n "${SP:-}" ] && kill -9 "$SP" 2>/dev/null
  [ -n "${MP:-}" ] && kill -9 "$MP" 2>/dev/null
}
trap cleanup EXIT

rm -rf "$WORK"; mkdir -p "$WORK/data" "$WORK/policies"
cp "$S"/deploy/policies/*.json "$WORK/policies/"
go build -o "$WORK/scrubberd" "$S/cmd/scrubberd" || exit 1

python3 - "$WORK" "$SIZE_MB" <<'PY'
import os, sys
work, size_mb = sys.argv[1], int(sys.argv[2])
line = "2026-06-12T09:00:00Z INFO user bob@acme.test from 10.1.2.3 org=AcmeCorp\n"
# Size against the UTF-16 form, since that is the file whose byte count looked wrong.
lines = (size_mb * 1024 * 1024) // (2 * len(line))
text = line * lines
open(f"{work}/utf8.txt", "wb").write(text.encode("utf-8"))
open(f"{work}/utf16le.txt", "wb").write(b"\xff\xfe" + text.encode("utf-16-le"))
open(f"{work}/utf16be.txt", "wb").write(b"\xfe\xff" + text.encode("utf-16-be"))
open(f"{work}/utf16le-nobom.txt", "wb").write(text.encode("utf-16-le"))
open(f"{work}/binary.txt", "wb").write(b"\x89PNG\r\n\x1a\n" + os.urandom(64 * 1024))
print(f"fixtures: {lines} lines, {3*len(line)} matches expected per text shape, "
      f"utf-16 form is {os.path.getsize(work+'/utf16le.txt')/1e6:.1f}MB")
PY

MINIO_ROOT_USER=minioadmin MINIO_ROOT_PASSWORD=minioadmin \
  "$MINIO" server "$WORK/data" --address ":19000" >"$WORK/minio.log" 2>&1 &
MP=$!
for _ in $(seq 1 60); do curl -fsS http://127.0.0.1:19000/minio/health/live >/dev/null 2>&1 && break; sleep 1; done

MINIO_ENDPOINT=127.0.0.1:19000 MINIO_ACCESS_KEY=minioadmin MINIO_SECRET_KEY=minioadmin \
MINIO_USE_TLS=false INPUT_BUCKET=scrub-input OUTPUT_BUCKET=scrub-output \
REPORTS_BUCKET=scrub-reports ENSURE_BUCKETS=true DEFAULT_POLICY=default \
POLICIES_DIR="$WORK/policies" PORT=8080 LOG_LEVEL=info WORKERS=1 \
  "$WORK/scrubberd" >"$WORK/scrubberd.log" 2>&1 &
for _ in $(seq 1 60); do curl -fsS http://127.0.0.1:8080/readyz >/dev/null 2>&1 && break; sleep 1; done
SP=$(pgrep -f "$WORK/scrubberd" | head -1)
[ -z "$SP" ] && { echo "scrubberd failed to start"; tail -5 "$WORK/scrubberd.log"; exit 1; }

fail=0
declare -a SUMMARY
BASE_MATCHES=""

for shape in utf8 utf16le utf16be utf16le-nobom binary; do
  f="$WORK/$shape.txt"
  r=$(curl -fsS -X POST localhost:8080/api/uploads -H 'Content-Type: application/json' \
        -d "{\"name\":\"$shape.txt\"}")
  key=$(echo "$r" | jq -r .key); url=$(echo "$r" | jq -r .url)
  curl -fsS -X PUT --upload-file "$f" "$url" >/dev/null

  status=""
  for _ in $(seq 1 600); do
    status=$(curl -fsS "localhost:8080/api/status?key=$key" | jq -r .status)
    case "$status" in scrubbed|error|skipped) break ;; esac
    sleep 1
  done
  final=$(curl -fsS "localhost:8080/api/status?key=$key")
  matches=$(echo "$final" | jq -r '.matches // 0')
  skipped=$(echo "$final" | jq -r '.binary_skipped // 0')
  # Fetch the scrubbed output the same way the browser does, rather than reaching
  # into MinIO's on-disk layout: this exercises the presign + GET path too.
  dl=$(curl -fsS "localhost:8080/api/downloads?key=$key" | jq -r .url)
  curl -fsS "$dl" -o "$WORK/out-$shape.txt" || true

  verdict=$(python3 - "$WORK" "$shape" "$matches" "$skipped" "$status" <<'PY'
import sys
work, shape, matches, skipped, status = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
if status != "scrubbed":
    print(f"FAIL (status={status})"); sys.exit(0)
if shape == "binary":
    # Still skipped -- and now named, which is the half that was missing.
    print("PASS (skipped, named)" if skipped == 1 and matches == 0
          else f"FAIL (binary_skipped={skipped}, matches={matches})")
    sys.exit(0)
if matches == 0:
    print("FAIL (0 matches: the file was NOT scrubbed)"); sys.exit(0)
if skipped != 0:
    print(f"FAIL (counted as binary: {skipped})"); sys.exit(0)
print("PASS")
PY
)
  [[ "$verdict" == FAIL* ]] && fail=1
  # Every text shape must find the same number of matches: encoding must not change
  # what the matcher sees.
  if [ "$shape" != "binary" ]; then
    if [ -z "$BASE_MATCHES" ]; then BASE_MATCHES="$matches"
    elif [ "$matches" != "$BASE_MATCHES" ]; then
      verdict="FAIL (matches=$matches, utf8 found $BASE_MATCHES)"; fail=1
    fi
  fi
  SUMMARY+=("$(printf '  %-15s %-10s matches=%-8s binary_skipped=%-3s %s' \
      "$shape" "$status" "$matches" "$skipped" "$verdict")")
  eval "KEY_$(echo "$shape" | tr -- - _)=$key"
done

# The output must still be the encoding it arrived in: a scrubber that silently
# rewrites UTF-16 as UTF-8 breaks whatever reads the file next.
echo
echo "=== encodings, end to end ==="
printf '%s\n' "${SUMMARY[@]}"
echo
for shape in utf16le utf16be utf16le-nobom; do
  python3 - "$WORK/out-$shape.txt" "$shape" <<'PY' || fail=1
import os, sys
path, shape = sys.argv[1], sys.argv[2]
if not os.path.exists(path) or os.path.getsize(path) == 0:
    print(f"  {shape:15s} FAIL could not download the scrubbed output"); sys.exit(1)
data = open(path, "rb").read()
enc = "utf-16-le" if "le" in shape else "utf-16-be"
bom = data[:2] in (b"\xff\xfe", b"\xfe\xff")
want_bom = "nobom" not in shape
try:
    text = data.decode("utf-16" if bom else enc)
except Exception as e:
    print(f"  {shape:15s} FAIL output is not valid UTF-16: {e}"); sys.exit(1)
leaked = [s for s in ("bob@acme.test", "10.1.2.3", "AcmeCorp") if s in text]
if leaked:
    print(f"  {shape:15s} FAIL secrets survived: {leaked}"); sys.exit(1)
if bom != want_bom:
    print(f"  {shape:15s} FAIL byte-order mark {'lost' if want_bom else 'added'}"); sys.exit(1)
print(f"  {shape:15s} PASS still {enc}, BOM={'yes' if bom else 'no'}, secrets redacted")
PY
done

echo
if [ "$fail" != "0" ]; then
  echo "RESULT: FAIL - see the table above."; exit 1
fi
echo "RESULT: PASS - UTF-16 scrubs like UTF-8, round-trips its encoding, and binary is skipped by name."
