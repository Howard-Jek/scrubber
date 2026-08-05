#!/usr/bin/env bash
# Prove the failure handler end to end, against real MinIO and the real service.
#
#   ./scripts/coverage-check.sh
#
# The unit tests assert each hole is classified. This asserts the consequence: that a
# bundle the scrubber could not fully inspect is reported as such, is routed somewhere
# it cannot be mistaken for a finished artifact, and names every hole with a reason an
# operator can act on. That chain is what was missing when UTF-16 logs went out
# unscrubbed under a green check.
#
# Three uploads, three verdicts:
#
#   complete          every file inspected -> normal output, nothing to review
#   incomplete        a genuinely binary member skipped -> normal output, named
#   incomplete-risky  a skipped member that CONTAINS policy matches -> review/ prefix
set -uo pipefail

S="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-/tmp/scrubber-coverage-check}"

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

python3 - "$WORK" <<'PY'
import io, os, sys, tarfile
work = sys.argv[1]
line = "2026-06-12T09:00:00Z INFO user bob@acme.test from 10.1.2.3 org=AcmeCorp\n"
text = line * 200

def tgz(path, members):
    with tarfile.open(path, "w:gz") as tf:
        for name, body in members:
            info = tarfile.TarInfo(name=name)
            info.size = len(body)
            tf.addfile(info, io.BytesIO(body))

# 1. Everything inspectable, including a UTF-16 member: verdict must be complete.
tgz(f"{work}/complete.tar.gz", [
    ("logs/app.log", text.encode()),
    ("logs/windows.txt", b"\xff\xfe" + text.encode("utf-16-le")),
])

# 2. A real binary member. Skipped is correct and must NOT be treated as a failure,
#    or every bundle with an image ends up in the review queue and nobody reads it.
noise = bytes((i * 7 + i // 3) % 256 for i in range(8192))
tgz(f"{work}/incomplete.tar.gz", [
    ("logs/app.log", text.encode()),
    ("assets/logo.png", b"\x89PNG\r\n\x1a\n" + noise),
])

# 3. A member the scrubber cannot read that is full of live secrets. UTF-32 is the
#    honest case: a text encoding the tool does not round-trip, so it is skipped --
#    and the residual scan reads it anyway and escalates.
utf32 = b"\xff\xfe\x00\x00" + text.encode("utf-32-le")
tgz(f"{work}/risky.tar.gz", [
    ("logs/app.log", text.encode()),
    ("logs/lux.txt", utf32),
])
print("fixtures: complete / incomplete / risky")
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

check() { # shape want_verdict want_review
  local shape="$1" wantV="$2" wantReview="$3"
  local r key url final verdict outkey ni rh notes v="PASS"
  r=$(curl -fsS -X POST localhost:8080/api/uploads -H 'Content-Type: application/json' \
        -d "{\"name\":\"$shape.tar.gz\"}")
  key=$(echo "$r" | jq -r .key); url=$(echo "$r" | jq -r .url)
  curl -fsS -X PUT --upload-file "$WORK/$shape.tar.gz" "$url" >/dev/null
  for _ in $(seq 1 300); do
    [ "$(curl -fsS "localhost:8080/api/status?key=$key" | jq -r .status)" = "scrubbed" ] && break
    sleep 1
  done
  final=$(curl -fsS "localhost:8080/api/status?key=$key")
  verdict=$(echo "$final" | jq -r '.verdict // ""')
  outkey=$(echo "$final" | jq -r '.output_key // ""')
  ni=$(echo "$final" | jq -r '.not_inspected // 0')
  rh=$(echo "$final" | jq -r '.residual_hits // 0')
  notes=$(echo "$final" | jq -r '[.not_inspected_set[]?.code] | join(",")')

  [ "$verdict" != "$wantV" ] && { v="FAIL (verdict=$verdict, want $wantV)"; fail=1; }
  case "$wantReview" in
    yes) [[ "$outkey" != review/* ]] && { v="FAIL (not diverted: $outkey)"; fail=1; } ;;
    no)  [[ "$outkey" == review/* ]] && { v="FAIL (wrongly diverted: $outkey)"; fail=1; } ;;
  esac
  # Every hole must carry a reason code, never the unclassified tripwire.
  if [ "$ni" != "0" ] && { [ -z "$notes" ] || [[ "$notes" == *unclassified* ]]; }; then
    v="FAIL (holes without a usable reason: '$notes')"; fail=1
  fi
  SUMMARY+=("$(printf '  %-11s %-17s not_inspected=%-3s residual=%-4s reasons=%-22s out=%-28s %s' \
      "$shape" "$verdict" "$ni" "$rh" "${notes:--}" "$outkey" "$v")")
}

check complete   complete         no
check incomplete incomplete       no
check risky      incomplete-risky yes

echo
echo "=== coverage verdicts, end to end ==="
printf '%s\n' "${SUMMARY[@]}"
echo

# The metrics an operator alerts on must exist and carry the labels.
metrics=$(curl -fsS localhost:8080/metrics)
for want in 'scrubber_object_verdict_total{verdict="incomplete-risky"} 1' \
            'scrubber_files_not_inspected_total{reason="unsupported-format"}' \
            'scrubber_residual_hits_total'; do
  if ! grep -qF "$want" <<<"$metrics"; then
    echo "  MISSING METRIC: $want"; fail=1
  else
    echo "  metric present: $want"
  fi
done

# A reason code nobody has seen before is the signal a new failure mode exists, so
# the label set must be seeded rather than appearing only once something breaks.
seeded=$(grep -c 'scrubber_files_not_inspected_total{reason=' <<<"$metrics")
echo "  reason label set seeded with $seeded series"
[ "$seeded" -lt 5 ] && { echo "  FAIL: label set not seeded"; fail=1; }

echo
if [ "$fail" != "0" ]; then
  echo "RESULT: FAIL - see above."; exit 1
fi
echo "RESULT: PASS - verdicts correct, risky output diverted for review, every hole named with a reason."
