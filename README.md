# scrubber — recursive log sanitizer

`scrubber` takes a log bundle — an archive, a compressed file, a directory, or a
single file — recursively unpacks it, replaces sensitive terms in **every text
document inside (regardless of file extension)**, and repacks everything back into
its **original form** (same format, structure, filenames, and metadata). It's a
single self-contained binary that runs identically on Windows and Linux.

## Safety guarantees

These are the whole point of the tool — it is designed to *never* hand you a
corrupted or half-scrubbed bundle:

- **Fail-fast on bad config.** A malformed terms file, an uncompilable regex, or an
  unknown preset aborts the run with a clear message **before any input is touched**
  (exit code `2`). You can never get a partially-scrubbed bundle from a broken config.
- **Fail-safe passthrough, and it is never silent.** Any file that can't be opened —
  corrupted, truncated, encrypted, or in a format we can read but not rewrite — is
  emitted **byte-for-byte unchanged**. It is also *named* in the report, called out
  in the end-of-run banner, and surfaced in the UI as a warning rather than a
  success, because a bundle containing files the pipeline never inspected is not a
  clean result. `--fail-on-unscrubbed` turns it into a non-zero exit for pipelines.
- **Binaries are left alone.** Files are classified by *content*, not extension;
  binary files pass through untouched so byte-substitution can't break their format.
- **Bomb/quine resistant, without false positives.** Expansion is bounded by a
  cumulative budget enforced *while* decompressing, alongside caps on recursion
  depth and archive member count. In the service, payloads above a threshold are
  held on disk rather than in memory, so that budget bounds mostly scratch space
  and resident memory tracks the largest single member. There is deliberately **no
  expansion-ratio limit**: ratio cannot separate a bomb from an ordinary log (real
  logs compress 200:1 to 1000:1), so any threshold low enough to catch a bomb also
  rejects the tool's primary input — and a rejected file is emitted unscrubbed.
- **Atomic writes.** Output is written to a temp file and renamed into place, so a
  crash mid-write can't leave a corrupt file.
- **Full transparency.** Every replacement is recorded (rule, location, original →
  replacement) and a one-line summary banner prints at the end of every run.

## Build

Requires Go 1.22+.

```sh
# native build
go build -o scrubber .

# cross-compile (single static binary, no runtime needed on the target)
GOOS=linux   GOARCH=amd64 go build -o scrubber-linux-amd64 .
GOOS=windows GOARCH=amd64 go build -o scrubber-windows-amd64.exe .
```

## Quick start

```sh
scrubber --terms examples/terms.json \
         --in   bundle.tar.gz \
         --out  bundle.clean.tar.gz \
         --report report.json
```

Scrub a whole directory tree (mirrors the structure into `--out`):

```sh
scrubber --terms terms.json --in ./logs --out ./logs-clean --report report.json
```

Preview without writing anything:

```sh
scrubber --terms terms.json --in bundle.zip --dry-run --verbose
```

## Terms file

JSON describing what to scrub. Every section is optional, but at least one rule must
be present.

```json
{
  "default_replacement": "[REDACTED]",
  "literals": [
    { "value": "AcmeCorp", "replacement": "[COMPANY]", "case_insensitive": true },
    { "value": "hunter2", "whole_word": true }
  ],
  "regex": [
    { "pattern": "Bearer\\s+[A-Za-z0-9._-]+", "replacement": "[TOKEN]" },
    { "pattern": "user-\\d+", "replacement": "[USER]" }
  ],
  "presets": ["email", "ipv4", "ipv6", "credit_card", "ssn", "aws_key", "jwt"]
}
```

| Field | Meaning |
|---|---|
| `default_replacement` | Token used when a rule omits its own `replacement` (default `[REDACTED]`). |
| `literals[].value` | Exact substring to match. |
| `literals[].case_insensitive` | Match regardless of case. |
| `literals[].whole_word` | Require word boundaries around the match. |
| `regex[].pattern` | RE2 regular expression (Go syntax). Validated at load time. |
| `*.replacement` | Per-rule override of `default_replacement`. |
| `presets[]` | Names of built-in PII patterns to enable (see below). |

Rule precedence is: literals, then regex, then presets, in file order. When two
rules could match the same span, the earlier one wins.

### Built-in presets

| Name | Matches | Replacement |
|---|---|---|
| `email` | Email addresses | `[EMAIL]` |
| `ipv4` | IPv4 addresses | `[IPV4]` |
| `ipv6` | IPv6 addresses | `[IPV6]` |
| `credit_card` | 13–19 digit card numbers **validated with Luhn** | `[CARD]` |
| `ssn` | US SSNs (`###-##-####`) | `[SSN]` |
| `aws_key` | AWS access key IDs (`AKIA…`/`ASIA…`) | `[AWS_KEY]` |
| `jwt` | JSON Web Tokens | `[JWT]` |
| `phone_us` | US phone numbers | `[PHONE]` |
| `windows_account` | `DOMAIN\user` accounts (e.g. `ACME\jsmith`) | `[ACCOUNT]` |
| `upn` | User principal names / logins `user@domain` (e.g. `jsmith@acme.com`) | `[UPN]` |
| `fqdn` | Domain / host names (e.g. `db-prod-01.internal.acme.com`); skips filenames like `app.log`, `x.tar.gz` | `[FQDN]` |
| `hostname` | Short single-label hosts (e.g. `db-prod-01`); requires a digit/hyphen so plain words aren't matched | `[HOST]` |

> **Exact strings vs. patterns.** If you know the specific domains, hosts, or accounts,
> listing them under `literals` is the simplest and false-positive-free option. The
> `fqdn` and especially `hostname` presets match by *shape* and are the noisiest — for
> best accuracy, anchor to your own naming with a `regex` rule instead, e.g.
> `{ "pattern": "[a-z0-9-]+\\.(internal|corp|acme)\\.com", "replacement": "[HOST]" }`.
> Rule precedence is literals → regex → presets (earlier wins), so a literal that
> overlaps a preset takes over that match.

## CLI flags

| Flag | Default | Description |
|---|---|---|
| `--terms` | — | Path to the terms JSON (required). |
| `--in` | — | Input file or directory (required). |
| `--out` | — | Output path (required unless `--in-place` or `--dry-run`). |
| `--in-place` | `false` | Overwrite the input atomically instead of writing to `--out`. |
| `--dry-run` | `false` | Analyze and report without writing any output. |
| `--report` | — | Write the JSON run report to this path. |
| `--audit` | `full` | Report detail: `off` (summary only), `counts` (rule + location), `full` (includes original values). |
| `--redact-report` | `false` | Store salted hashes instead of cleartext original values in the report. |
| `--salt` | `scrubber` | Salt used by `--redact-report`. |
| `--max-depth` | `16` | Maximum container nesting depth. |
| `--max-expand-bytes` | `2147483648` | Cumulative decompressed bytes read per input. Enforced while reading, so it is a real bound — but payloads above the spill threshold are held on disk (`TMPDIR`), so it now bounds mostly scratch space rather than memory. |
| `--max-ratio` | — | **Deprecated and ignored** (warns if set). See the bomb-resistance note under [Safety guarantees](#safety-guarantees). |
| `--fail-on-unscrubbed` | `false` | Exit `3` if any file was emitted unscrubbed. |
| `--verbose` | `false` | Print the per-rule breakdown to stderr. |

## The report (transparency)

With `--report report.json`, every replacement is recorded with its location inside
the (possibly nested) bundle:

```json
{
  "source": "bundle.tar.gz",
  "output": "bundle.clean.tar.gz",
  "files": [
    {
      "path": "bundle.tar.gz!logs/app.log",
      "status": "scrubbed",
      "bytes_in": 564, "bytes_out": 465,
      "matches": [
        { "rule": "preset:email", "line": 3, "offset": 180,
          "original": "bob@acme.test", "replacement": "[EMAIL]" }
      ]
    }
  ],
  "summary": { "files_total": 4, "files_scrubbed": 2, "total_matches": 10, "matches_by_rule": { "preset:email": 1 } }
}
```

**Match lists are capped; counts never are.** Every retained match holds its rule,
original value and replacement, so the report grows with match *count* rather than
input size — a 1 MiB log that hits a term on every line builds a report far larger
than the file itself, and the expansion budget does not check it (that bounds bytes
read, not the report assembled from them). So the itemised list is capped per file and
across the whole report. When that bites, the entry carries `"matches_truncated": true`
alongside an exact `"match_count"`, and `summary.total_matches` plus the by-rule and
by-label breakdowns stay exact regardless. Truncation is always flagged: a short list
that looked complete would invite the conclusion that a bundle was barely touched when
it was in fact rewritten millions of times.

The service defaults to `AUDIT_LEVEL=counts`, which keeps the rule and location for
each retained match but not the matched text. The CLI still defaults to `--audit full`.

Per-file `status` is one of `scrubbed`, `unchanged`, `binary-skipped`,
`passthrough-error`, `unsupported-format`, or `guard-tripped`.

> ⚠️ **The default report contains the original cleartext values you just removed.**
> Treat it as sensitive. Use `--redact-report` to replace those values with salted
> hashes (keeping counts, locations, and rule attribution), or `--audit=counts`/`off`
> to omit them entirely.

## Supported formats

| Format | Read | Repack (scrub) | Notes |
|---|---|---|---|
| zip | ✅ | ✅ | Per-entry method/mode/time preserved |
| tar | ✅ | ✅ | Headers, modes, symlinks preserved |
| gzip | ✅ | ✅ | |
| zlib / raw deflate | ✅ | ✅ | |
| xz | ✅ | ✅ | |
| zstd | ✅ | ✅ | |
| bzip2 | ✅ | ❌ | Read-only in this build → passed through unchanged |
| 7z | ❌ | ❌ | Passed through unchanged, flagged in report |
| rar | ❌ | ❌ | Passed through unchanged, flagged in report |

Formats we can't fully round-trip are **passed through verbatim** and recorded as
`unsupported-format` — the bundle is never corrupted, but content inside those
containers is not scrubbed. (Nested formats are handled recursively, e.g.
`outer.tar.gz!inner.zip!app.log`.)

## Running as a service on OpenShift (`scrubberd`)

The same engine runs as a MinIO/S3 bucket-driven service (`cmd/scrubberd`) for
hosting on OCP. Drop a bundle in the **input** bucket → a scrubbed bundle appears in
the **output** bucket and a report in the **reports** bucket; the input is then moved
to a `processed/` prefix (or deleted).

**Two planes:**
- **Data plane (internal):** MinIO buckets only. No log bytes ever leave the cluster
  boundary through the service.
- **Control plane (Route-exposed, data-free):** `/healthz`, `/readyz`, `/metrics`
  (Prometheus), `/policies`, `/jobs`. Safe to expose externally even without app auth.

### Queueing and ordering

Objects are scrubbed **one at a time, in the order they arrived**. Uploads land in one
bucket regardless of who sent them, so five people uploading five bundles each get a
single queue served first-come-first-serve — no upload can be starved by arriving
alongside a larger batch, and none of them compete for the pod's single CPU.

- **Order is by upload *completion*, not upload start.** The queue sorts on the
  object's `LastModified` (the moment its PUT committed, from MinIO's own clock, so
  there is no client skew), tie-broken by key. A large upload that starts first and
  finishes last is served last — there is nothing to queue until the object exists.
- **The bucket is the durable queue.** The in-memory pending set is a derived view:
  after a restart the first listing rebuilds the same order, and nothing is lost.
- **Retries rejoin at the back.** An object whose move to `processed/` fails has the
  oldest `LastModified` in the bucket, so it is re-ordered on the time its backoff
  expires instead. Otherwise one object that can never be finalized would re-scrub
  itself at the head of the queue every minute, forever, ahead of real uploads.
- **`POLL_INTERVAL` governs discovery, not drain rate.** The consumer takes the next
  object the instant it finishes one. The interval only bounds how long a *new*
  upload waits to be noticed — and even that is short-circuited: the browser starts
  polling `/api/status` as soon as its upload lands, and that first poll nudges a
  listing. Note that listing covers the whole input bucket including `processed/`, so
  prune that prefix (a lifecycle rule, or `PROCESSED_ACTION=delete`) rather than
  shortening the interval.
- **The queue is per-pod**, which is the other reason `replicas: 1` is load-bearing.
  The Deployment uses `strategy: Recreate` on purpose: with `replicas: 1` the default
  RollingUpdate starts the new pod before stopping the old one, and two scrubberds
  polling the same bucket would double-process.
- **Upload a `<key>.terms.json` sidecar *before* its bundle.** The override is read
  when the bundle is processed, so a bundle that reaches the front first will miss a
  sidecar still in flight.

`/api/status` reports `queue_position` and `queue_depth` while an object waits, and
`/api/queue` shows the in-flight key plus the head of the pending list.

### Sizing and memory

Objects are scrubbed one at a time, and **archive members spill to disk**:
only the member being scrubbed right now is on the heap. That is what makes a
several-hundred-MiB bundle fit a 2 GiB pod, and it changes what each cap means.

- `MAX_OBJECT_BYTES + MAX_EXPAND_BYTES` bounds the bytes *read* — the compressed
  object plus everything decompressed out of it. Since payloads above
  `SPILL_THRESHOLD` live in `TMPDIR`, this is now mostly a **disk** bound. Size the
  `/work` volume from it; an ephemeral-storage eviction kills a pod as dead as an OOM.
- `SPILL_THRESHOLD` / `SPILL_RESIDENT_MAX` bound **resident memory**. The first sends
  any payload above it to disk on its own; the second is an aggregate budget, and it
  is the one that catches many-small-members bundles, where each member is
  individually under the threshold while together they would hold the whole archive.

The service logs `budget_bytes`, `est_peak_rss_bytes` and `scratch_bytes` at startup —
size `limits.memory` from the second and the `/work` `sizeLimit` from the third. Do not
size a pod from `budget_bytes`; that is the mistake this section exists to prevent.

**The multiplier depends on the shape of the object, not just its size.**
`go test ./internal/pipeline -run TestMemoryMatrix` measures peak heap across container
formats, member counts, match densities and compressibility. The worst case is not the
few-large-members bundle most people reach for when testing by hand — it is **many
small members**, where per-member overhead dominates:

| shape | peak heap / content | before the spill |
| --- | --- | --- |
| `.tar.gz`, 1000 small members, dense matches | **3.6×** | 11.6× |
| `.tar.gz`, 20000 tiny members, dense | 3.1× | — |
| bare `.tar`, 8 large members, dense | 2.8× | 4.7× |
| `.tar.gz`, 8 large members, dense | 2.6× | 8.3× |
| `.zip`, dense | 2.5× | 4.4× |
| `.tar.gz`, sparse matches, incompressible | 1.4× | 6.0× |

Note the ratio is now the wrong mental model: peak heap is bounded by the spill policy,
not by content, so it *falls* as bundles grow. The small fixtures above are the worst
case, not the large ones.

`scripts/memory-matrix.sh` confirms this end to end against real MinIO and real RSS —
which is what the kubelet OOM-kills on, and what the heap figures above cannot tell you.
At the shipped caps, both worst shapes in one run:

| shape | result | wall clock |
| --- | --- | --- |
| `.tar.gz`, 90000 members, 352 MiB content, 18.9M matches | scrubbed, 0 passthrough | 141s |
| `.tar.gz`, 50 members, **500 MiB incompressible content** | scrubbed, 0 passthrough | 146s |

Peak RSS across both, on one 1-CPU process: **445 MiB — 22% of the 2 GiB limit**, with
no temp files left behind. For contrast, before members spilled the same pod peaked at
1889 MiB (92%) on a 512Mi expansion budget, and a 500 MiB bundle did not fit at any cap
setting.

`GOMEMLIMIT` is a soft target the GC grows the heap *toward*, so it sets steady-state RSS
as much as it caps it, and it only holds while the *live* set fits beneath it. That was
the old failure: at `MAX_EXPAND_BYTES=512Mi` the live set exceeded 1600 MiB, the GC could
not keep up, and RSS overran. With the live set now bounded by the spill policy rather
than by the bundle, it holds with room to spare.

**Changing any cap means re-running `scripts/memory-matrix.sh`.** It fails if peak RSS
exceeds 60% of the limit, if an object comes back with a passthrough — a cap set too low
stops bounding memory and starts silently emitting unscrubbed files instead, which looks
like a pass if you only watch RSS — or if the service leaves a temp file behind, which
would fill the `/work` emptyDir over days and get the pod evicted for a reason that looks
nothing like its cause.

> **What still does not fit.** A single archive *member* larger than the memory budget:
> the leaf scrubber needs its payload contiguous in memory, so spilling does not help
> there and it stays bounded only by `MAX_EXPAND_BYTES`. Ordinary bundles of many
> members are fine at any total size the disk budget allows. Watch
> `scrubber_objects_total{status="too_large"}` to find out whether real uploads are
> being turned away.

`WORKERS` is retained for configuration compatibility but is **clamped to 1**; a higher
value is ignored with a warning. Concurrent scrubs on a single CPU do not add throughput,
and they multiply both budgets above.

> A `.tar.gz` draws on `MAX_EXPAND_BYTES` **twice** — once for the decompressed tar and
> once for the member bodies read out of it. Budget roughly half of `MAX_EXPAND_BYTES`
> as usable tar.gz content: ~768 MiB at the shipped cap.

`MAX_OBJECT_BYTES` is a separate ceiling on the *uploaded* (still compressed) object.
An upload above it is skipped rather than downloaded, and reported as `skipped` — so it
is usually the first limit a user hits, independent of `MAX_EXPAND_BYTES`.

**Policies ("both"):** named policy files (same schema as the terms file) are mounted
from a ConfigMap at `/etc/scrubber/policies/*.json` and hot-reloaded on change.
Resolution per object, highest precedence first:
1. per-object override `"<key>.terms.json"` sibling in the input bucket,
2. longest matching `PREFIX_POLICY_MAP` prefix → named policy,
3. `DEFAULT_POLICY`.

**Config (env / ConfigMap + Secret):** `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`/
`MINIO_SECRET_KEY`, `MINIO_USE_TLS`, `MINIO_CA_CERT`, `INPUT_BUCKET`, `OUTPUT_BUCKET`,
`REPORTS_BUCKET`, `INPUT_PREFIX`, `DEFAULT_POLICY`, `PREFIX_POLICY_MAP` (JSON),
`PROCESSED_ACTION` (`move`|`delete`), `POLL_INTERVAL` (default `15s`; discovery only),
`WORKERS` (clamped to 1), `QUEUE_MAX` (default `10000`), `FINALIZE_GRACE` (default `15s`),
`MAX_OBJECT_BYTES` (default 640Mi), `MAX_EXPAND_BYTES` (default 1536Mi),
`SPILL_THRESHOLD` (default 4Mi), `SPILL_RESIDENT_MAX` (default 64Mi),
`AUDIT_LEVEL` (`full`|`counts`|`off`, default `counts`),
`REDACT_REPORTS` (default `false`), `SCRUB_FILENAMES` (default `true`), `PORT` (default `8080`).

**Filenames & paths** are scrubbed by default (`SCRUB_FILENAMES=true`): archive member
names, directory segments, and the output object key are run through the same policy, so a
sensitive term in a *name* (`AcmeCorp-logs/jsmith-trace.log`) doesn't leak the way it would
if only contents were cleaned. Replacements can't introduce a path separator, so renaming is
traversal-safe. Set `SCRUB_FILENAMES=false` to keep exact names (CLI: `--scrub-names=false`).

**Large objects & memory.** The uploaded object is staged on scratch storage, not the
heap, and the read is still capped at `MAX_OBJECT_BYTES` (default 640Mi) via a bounded
fetch: an object larger than the cap is **skipped and moved aside**, never downloaded
whole. Inside the walk, payloads above `SPILL_THRESHOLD` also live on disk, so what has
to fit in memory is the largest single archive *member* being scrubbed — not the bundle.
Size `limits.memory` from `est_peak_rss_bytes` in the startup log, and the `/work`
volume from `scratch_bytes`; see [Sizing and memory](#sizing-and-memory) for the measurements behind both.

**Run it locally (Docker)** — one command brings up MinIO + the service, wired for
browser uploads. It runs the container under the pod's own ceiling (`--memory=2g
--cpus=1`) and the manifest's caps, so a local pass means something about production:
```sh
./scripts/run-local.sh
#  Scrubber UI:   http://localhost:8080
#  MinIO console: http://localhost:9002  (minioadmin / minioadmin)
#  Memory:        docker stats scrubberd
# stop:  docker rm -f scrubberd scrubber-minio && docker network rm scrubnet
```
[`docs/HANDOVER.md`](docs/HANDOVER.md) walks through what to check on that local
deployment, and how to export the image into an air-gapped environment.

**Deploy on OpenShift:**
```sh
# 1. build + push the image (air-gap: override BASE_*_IMAGE / GOPROXY to Artifactory mirrors)
podman build -f deploy/Containerfile -t <artifactory>/docker-local/scrubberd:0.3.0 .
podman push <artifactory>/docker-local/scrubberd:0.3.0
#    (air-gapped: transfer dist/scrubberd-0.3.0.tar and `podman load -i` on the target)

# 2. prereqs: MinIO creds Secret + named-policy ConfigMap
oc create secret generic scrubber-secret \
  --from-literal=MINIO_ACCESS_KEY=... --from-literal=MINIO_SECRET_KEY=...
oc create configmap scrubber-policies --from-file=deploy/policies/

# 3. edit <PLACEHOLDERS> in deploy/openshift-manifests.yaml (image ref, MINIO_ENDPOINT,
#    MINIO_PUBLIC_ENDPOINT, buckets), then apply
oc apply -f deploy/openshift-manifests.yaml
```
Buckets `scrub-input` / `scrub-output` / `scrub-reports` must exist in MinIO, MinIO must be
browser-reachable (its own Route) with CORS allowing the scrubber origin, and the Route
should stay on a trusted network (see the auth caveat below).

The image runs as an arbitrary non-root UID (group 0), `readOnlyRootFilesystem` with
an emptyDir `/work` for temp (`TMPDIR`, and therefore where spilled payloads land — it
carries a `sizeLimit`, which is load-bearing: an unbounded emptyDir can eat the node's
ephemeral storage and get the pod evicted), drops all capabilities, and ships with `replicas: 1`
and `strategy: Recreate` (single-writer, single queue; horizontal scale-out needs a
distributed object claim and is a documented follow-up).

### Metrics

`/metrics` exposes, alongside the per-object counters (`scrubber_objects_total{status}`,
`scrubber_matches_total`, `scrubber_passthrough_total`, `scrubber_errors_total`,
`scrubber_bytes_in_total`, `scrubber_bytes_out_total`, `scrubber_process_seconds`):

| Metric | Meaning |
| --- | --- |
| `scrubber_queue_depth` | objects waiting, plus the one in flight |
| `scrubber_inflight_objects` | objects being scrubbed right now (0 or 1) |
| `scrubber_queue_wait_seconds` | arrival → start of scrubbing |
| `scrubber_object_latency_seconds` | arrival → finished; what a user actually waits |

`scrubber_process_seconds` starts counting only once an object reaches the front of
the queue, so it cannot show what someone behind a backlog experiences —
`scrubber_object_latency_seconds` is the number to watch for that.

### Benchmarking

```sh
go test ./internal/queue ./internal/scrub ./internal/pipeline -bench=. -benchmem
go test ./internal/worker -bench=DrainSerialVsFanOut -cpu=1   # -cpu=1 models the pod
./scripts/bench-queue.sh                                      # end-to-end, needs Docker
```

`scripts/bench-queue.sh` uploads N objects at once, drains them, and reports total
wall clock, time to the first completion, per-object latency and peak container
memory. Point it at two images to compare a change honestly:

```sh
git stash && docker build -q -f deploy/Containerfile -t scrubberd:baseline . && git stash pop
docker build -q -f deploy/Containerfile -t scrubberd:queue .
IMAGE=scrubberd:baseline ./scripts/bench-queue.sh
IMAGE=scrubberd:queue    ./scripts/bench-queue.sh
```

Serialising does **not** buy raw throughput — on one CPU the same bytes have to be
scrubbed either way, and `BenchmarkDrainSerialVsFanOut` measures the old fan-out as
roughly 8% faster on total drain time. What it buys is a halved memory budget
(one object resident instead of two) and arrival-ordered completion, so the first upload
finishes early instead of every upload finishing late together. `-cpu=1` matters:
unpinned on a multi-core box the fan-out looks twice as fast, which is true of
hardware the pod does not have, so the benchmark skips rather than print it.

### Web front page

`scrubberd` serves a small self-contained upload page at `/` plus a thin browser API.
Crucially, **no bundle bytes pass through the service**: the browser uploads straight
to MinIO and downloads straight from it, using short-lived presigned URLs that the
service mints.

Flow: browser `POST /api/uploads {name}` → gets a presigned PUT + object key → PUTs the
file directly to the input bucket → polls `GET /api/status?key=…` until `scrubbed` → gets
the label-only match breakdown for the "active policy" panel → `GET /api/downloads?key=…`
for a presigned GET of the scrubbed output.

**Status is answered from storage, not just memory.** Recent job outcomes are cached in
a per-process ring, but that cache is lost on restart and can evict entries under load.
When it has no terminal answer for a key, `/api/status` reads the stored run report
instead, so a client is never told "processing" forever for an object that finished.
Reports are keyed by the **input** key (`<key>.report.json` in the reports bucket) —
the only key a client knows — and record where the output landed, so downloads keep
working even when filename scrubbing renamed the output.

While a job is in flight the status response carries real progress (`files_done`,
`current_file`, `phase`) rather than a client-side animation.

**While an object is waiting**, `/api/status` returns `phase: "queued"` with
`queue_position` and `queue_depth`, and the UI shows "Queued — 3 of 7". That answer
comes from the in-memory queue and touches no storage: a queued key has no report
yet, so falling through to the reports bucket would cost two failed object reads per
client poll — with a full queue and second-scale polling, dozens of pointless MinIO
round-trips per second for the whole drain. The progress bar deliberately does *not*
advance while queued; a bar creeping toward full while an object sits twentieth in
line reads as "almost done" when nothing has happened.

- `GET /api/history?n=N` — the last N completed runs, rebuilt from the reports bucket
  and shown in the **Recent scrubs** panel. Survives a page refresh and a pod restart.
  N is settable in the UI and capped by `HISTORY_MAX`.
- `GET /api/report?key=…` — the full stored report for one run.
- `GET /api/queue` — the object being scrubbed plus the head of the pending list, in
  order. Keys only.

A run that contains files the pipeline could not inspect is shown as an amber
**"N files NOT scrubbed"** state naming each file and why — never a green check.

The tool is operated by people **inside** your trust boundary who are preparing logs to
send out, so the UI deliberately shows the full policy — the literal terms, patterns, and
presets — so operators can verify exactly what will be scrubbed. The thing that must never
leave your environment is the **scrubbed log content**, and that is enforced by the
scrubbing itself. Reports (in an internal bucket) show the actual original values by
default so the scrub can be audited; set `REDACT_REPORTS=true` to store salted hashes
instead if that bucket is less trusted than the operators.

The **Active policy** panel has an **Edit terms.json** control: operators can edit the
policy inline or **Upload** a `terms.json`, then **Apply**. Apply validates and compiles
it server-side (identical fail-fast rules to the CLI — a bad preset or regex returns a
precise error and the current policy is left untouched) and activates it immediately for
subsequent scrubs; the panel re-renders from the result. This edit is **live but
in-memory** — a policy reload or pod restart reverts it, so durable changes should go
through the policy source (see "Updating the default policy" below). Disable UI editing
with `ALLOW_POLICY_EDIT=false`.

Extra env for the UI:
- `MINIO_PUBLIC_ENDPOINT` / `MINIO_PUBLIC_TLS` — the browser-reachable MinIO host, used to
  rewrite presigned URLs when the in-cluster endpoint differs from the external one.
- `UPLOAD_EXPIRY` — presigned URL lifetime (default `15m`).
- `ALLOW_POLICY_EDIT` — allow `PUT /api/policy` from the UI (default `true`).

The page uses the same clean design language as the project's mockups (claude-style
neutral tokens, light/dark, Tabler outline icons). The icon font is loaded from a CDN;
on an **air-gapped** cluster the layout still works but icons render blank — vendor the
Tabler `woff2` + CSS into the image (or an internal mirror) to make it fully offline.

Two deployment requirements for the browser path:
- MinIO must be reachable by the browser (its own Route/ingress) and have **CORS** allowing
  the scrubber page origin (presigned PUT/GET are cross-origin to MinIO).
- Under **network-only** auth the browser API is unauthenticated — anyone who can reach the
  Route can mint upload/download URLs and see the policy (including literal terms). Since the
  operators are insiders, keep the Route on a trusted/internal network. For genuine external
  exposure, put auth in front (e.g. OpenShift OAuth proxy) — the endpoints are structured so
  this can be added without app changes.

## Updating the default policy and presets

There are three ways to change what gets scrubbed, from most transient to most permanent:

1. **Live, from the UI** (fastest) — Active policy panel → Edit terms.json → Apply, or
   Upload a `terms.json`. Takes effect immediately; reverts on reload/restart. Also
   available as `PUT /api/policy` with a terms.json body.

2. **Durable, via the policy source** — the named policies are files:
   - Repo/CLI default: [examples/terms.json](examples/terms.json).
   - Service defaults: [deploy/policies/](deploy/policies/) (`default.json`, `strict.json`).
   - In-cluster the service reads them from the `scrubber-policies` ConfigMap; update it and
     the pod hot-reloads (fsnotify):
     ```sh
     oc create configmap scrubber-policies --from-file=deploy/policies/ \
       --dry-run=client -o yaml | oc apply -f -
     ```
   Add a new named policy by adding `deploy/policies/<name>.json`, then reference it from
   `DEFAULT_POLICY` or `PREFIX_POLICY_MAP`.

3. **Adding a new preset** (a code change — presets are compiled in) — edit
   [internal/config/presets.go](internal/config/presets.go): add an entry to the `presets`
   map with a `pattern`, a `replacement` label, and an optional `valid` validator to cut
   false positives (RE2 has no lookahead, so validators are how `fqdn`/`hostname` filter
   filenames and plain words). Example:
   ```go
   "mac_address": {
       pattern:     `\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b`,
       replacement: "[MAC]",
   },
   ```
   Then rebuild the image (`podman build -f deploy/Containerfile ...`) and redeploy. Add a
   test in [internal/config/presets_test.go](internal/config/presets_test.go) alongside it.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. |
| `1` | Fatal I/O error (e.g. input unreadable). Output may not have been written. |
| `2` | Invalid usage or invalid terms file. **No input was touched.** |
| `3` | Completed, but some files were emitted unscrubbed (only with `--fail-on-unscrubbed`). |

## Notes & limitations (v1)

- Text is handled as UTF-8 (with or without BOM) and ASCII/Latin-1. UTF-16/UTF-32
  files contain NUL bytes and are therefore treated as binary and passed through.
- Expansion is bounded by the cumulative `--max-expand-bytes` budget for a whole
  input (nested streams and archive members draw from the same budget). Payloads
  above the spill threshold are held on disk under `TMPDIR`, so that budget bounds
  mostly scratch space; resident memory tracks the largest single member instead.
- A single archive *member* larger than the memory budget is still only bounded by
  `--max-expand-bytes`: the leaf scrubber needs its payload contiguous in memory, so
  one enormous member inside an otherwise ordinary bundle is the shape the spill does
  not help with.
- The queue lives in the pod, so `replicas: 1` is a correctness requirement, not a
  capacity choice — two pods polling one bucket would double-process. Scaling out
  needs a distributed object claim.
- The service scrubs one object at a time in arrival order. That is strict FCFS with
  no per-tenant fairness: a single user who uploads a large batch does hold up the
  users behind them until it drains. Round-robin between uploaders would need a
  tenant identity, which the service does not have (there is no app auth).
- Shelling out to a system `7z`/`xz`, and length-preserving / hashing replacement
  modes, are intentionally out of scope for v1.

## License

MIT — see [LICENSE](LICENSE). Third-party dependencies and their licenses are
listed in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md), regenerated with
`scripts/gen-notices.sh`. All current dependencies are permissively licensed
(MIT, BSD-2/3-Clause, Apache-2.0).

The web UI has no external assets — icons are an inline SVG sprite and there are
no CDN, font, or script fetches — so it renders in an air-gapped cluster.
