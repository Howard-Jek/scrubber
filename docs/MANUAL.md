# scrubber — reference manual

The in-depth companion to the [README](../README.md). The README covers installing,
running, writing a policy and reading the result codes; this document covers everything
else: the full flag and environment reference, the coverage contract and the reasoning
behind it, sizing and memory, the service, metrics, the web UI, and benchmarking.

- [Safety guarantees](#safety-guarantees)
- [CLI reference](#cli-reference)
- [The report](#the-report)
- [Coverage: what was *not* inspected](#coverage-what-was-not-inspected)
- [Running as a service (`scrubberd`)](#running-as-a-service-scrubberd)
  - [Queueing and ordering](#queueing-and-ordering)
  - [Sizing and memory](#sizing-and-memory)
  - [Policies](#policies)
  - [Configuration reference](#configuration-reference)
  - [Deploying on OpenShift](#deploying-on-openshift)
  - [Metrics](#metrics)
  - [Web front page](#web-front-page)
- [Updating the default policy and presets](#updating-the-default-policy-and-presets)
- [Benchmarking](#benchmarking)
- [Notes and limitations](#notes-and-limitations)

---

## Safety guarantees

These are the whole point of the tool — it is designed to *never* hand you a corrupted
or half-scrubbed bundle.

- **Fail-fast on bad config.** A malformed terms file, an uncompilable regex, or an
  unknown preset aborts the run with a clear message **before any input is touched**
  (exit code `2`). You can never get a partially-scrubbed bundle from a broken config.
- **Fail-safe passthrough, and it is never silent.** Any file that can't be opened —
  corrupted, truncated, encrypted, or in a format we can read but not rewrite — is
  emitted **byte-for-byte unchanged**. It is also *named* in the report, called out in
  the end-of-run banner, and surfaced in the UI as a warning rather than a success,
  because a bundle containing files the pipeline never inspected is not a clean result.
  `--fail-on-unscrubbed` turns it into a non-zero exit for pipelines.
- **Binaries are left alone.** Files are classified by *content*, not extension; binary
  files pass through untouched so byte-substitution can't break their format.
- **Bomb/quine resistant, without false positives.** Expansion is bounded by a
  cumulative budget enforced *while* decompressing, alongside caps on recursion depth
  and archive member count. In the service, payloads above a threshold are held on disk
  rather than in memory, so that budget bounds mostly scratch space and resident memory
  tracks the largest single member. There is deliberately **no expansion-ratio limit**:
  ratio cannot separate a bomb from an ordinary log (real logs compress 200:1 to
  1000:1), so any threshold low enough to catch a bomb also rejects the tool's primary
  input — and a rejected file is emitted unscrubbed.
- **Atomic writes.** Output is written to a temp file and renamed into place, so a crash
  mid-write can't leave a corrupt file.
- **Full transparency.** Every replacement is recorded (rule, location, original →
  replacement) and a one-line summary banner prints at the end of every run.

---

## CLI reference

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
| `--scrub-names` | `true` | Scrub archive member names, directory segments and the output key. |
| `--max-depth` | `16` | Maximum container nesting depth. |
| `--max-expand-bytes` | `2147483648` | Cumulative decompressed bytes read per input. Enforced while reading, so it is a real bound — but payloads above the spill threshold are held on disk (`TMPDIR`), so it now bounds mostly scratch space rather than memory. |
| `--max-ratio` | — | **Deprecated and ignored** (warns if set). See [Safety guarantees](#safety-guarantees). |
| `--fail-on-unscrubbed` | `false` | Exit `3` if **any** file was emitted without being inspected — binary, guard-tripped, unreadable or an unsupported container. |
| `--fail-on-risky` | `false` | Exit `3` only when content that was *not* inspected is found to contain policy matches. The narrower gate for pipelines that legitimately carry images. |
| `--verify-output` | `false` | Re-scan every scrubbed file to confirm the policy no longer matches it. Roughly doubles matcher work; see [Coverage](#coverage-what-was-not-inspected). |
| `--verbose` | `false` | Print the per-rule breakdown to stderr. |

---

## The report

With `--report report.json`, every replacement is recorded with its location inside the
(possibly nested) bundle:

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
  "summary": { "files_total": 4, "files_scrubbed": 2, "total_matches": 10,
               "matches_by_rule": { "preset:email": 1 } }
}
```

**Match lists are capped; counts never are.** Every retained match holds its rule,
original value and replacement, so the report grows with match *count* rather than input
size — a 1 MiB log that hits a term on every line builds a report far larger than the
file itself, and the expansion budget does not check it (that bounds bytes read, not the
report assembled from them). So the itemised list is capped per file and across the whole
report. When that bites, the entry carries `"matches_truncated": true` alongside an exact
`"match_count"`, and `summary.total_matches` plus the by-rule and by-label breakdowns stay
exact regardless. Truncation is always flagged: a short list that looked complete would
invite the conclusion that a bundle was barely touched when it was in fact rewritten
millions of times.

The service defaults to `AUDIT_LEVEL=counts`, which keeps the rule and location for each
retained match but not the matched text. The CLI still defaults to `--audit full`.

> ⚠️ **The default report contains the original cleartext values you just removed.**
> Treat it as sensitive. Use `--redact-report` to replace those values with salted
> hashes (keeping counts, locations, and rule attribution), or `--audit=counts`/`off` to
> omit them entirely.

---

## Coverage: what was *not* inspected

A scrubber that quietly skips a file is worse than one that fails, because the output
still looks finished. Three bugs shipped in that shape — UTF-16 text read as binary,
plain text mistaken for a zlib stream, text beginning `BZh` sent to the decompressor —
and each was invisible afterwards for the same reason: "not scrubbed" was decided in four
places that disagreed with each other. So it is decided in one place now. (The full
account of each is in [CHANGELOG.md](CHANGELOG.md).)

**Every file gets a disposition.** `Inspected` means the content reached the matcher and
the output is clean. `NotInspected` means it did not, or it did and the policy still
matches the result. There is no third answer and no default; adding a status without
classifying it is a compile error (`report.Status.Disposition`).

**Every hole gets a reason code.** The full table of statuses, reason codes and verdicts
is on the [front page](../README.md#reading-the-result) — it is the part most people need
most often. What follows is why the machinery around them exists.

**Whatever is skipped gets looked inside anyway.** Every guard trusts a classification,
and a wrong classification is invisible to everything derived from it. So
`internal/residual` does not classify: it pulls printable runs straight out of the raw
bytes at every code-unit width Latin text uses — one byte, UTF-16's two, UTF-32's four,
either byte order — and runs the policy over them. A UTF-16 log misfiled as binary still
contains a recognisable address, and this finds it without knowing what UTF-16 is.
Bounded by `RESIDUAL_BUDGET` (default 64Mi per object); set it negative to disable, which
removes the only check that does not depend on the pipeline being right.

**A policy that cannot converge is rejected when it loads.** If a rule replaces `secret`
with `secret-[REDACTED]`, the "redacted" output still contains the term and every file it
touches comes out half-scrubbed while reporting success. That is a property of the
*policy*, not of any file, so `scrub.NewMatcher` refuses it before any data is touched
(CLI: exit 2). The check runs the real matcher, so rules with candidate validators are
judged exactly as they will be in production.

`VERIFY_OUTPUT` (CLI `--verify-output`) additionally re-scans every scrubbed file to
confirm the policy no longer matches it. It is **off by default**, and the reason is
measured rather than assumed: it roughly doubles the matcher's work and cost ~70% of the
drain rate on the 500 MiB shape in `scripts/memory-matrix.sh` — 139s against 237s. With
the load-time check in place, what it still guards against is a bug inside the matcher
itself, which is worth having available and not worth paying for on every object of every
run.

At the edges: the UI requires an explicit acknowledgement before it will download an
`incomplete-risky` result, `--fail-on-unscrubbed` exits 3 on any hole (it used to ignore
binary skips, so it was silent on exactly the case it exists for), and `--fail-on-risky`
is the narrower gate for pipelines that legitimately carry images.

> **One honest limit.** When the expansion budget refuses to decompress a container, the
> residual scan sees only compressed bytes and finds nothing — so a too-large bundle
> reports `incomplete`, not `incomplete-risky`, however much it contains. Refusing to
> expand is precisely what stops anything looking inside. The hole is still named with
> reason `expansion-budget`.

**Adding a format or an encoding means adding rows to
`internal/pipeline/corpus_test.go`** — one per shape, declaring its status, disposition
and reason. A row that cannot be written, because the outcome has no reason code, is the
design telling you the case is unclassified. The three bugs above are rows in it, and
reverting any of their fixes fails the table.

---

## Running as a service (`scrubberd`)

The same engine runs as a MinIO/S3 bucket-driven service (`cmd/scrubberd`) for hosting on
OCP. Drop a bundle in the **input** bucket → a scrubbed bundle appears in the **output**
bucket and a report in the **reports** bucket; the input is then moved to a `processed/`
prefix (or deleted).

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

- **Order is by upload *completion*, not upload start.** The queue sorts on the object's
  `LastModified` (the moment its PUT committed, from MinIO's own clock, so there is no
  client skew), tie-broken by key. A large upload that starts first and finishes last is
  served last — there is nothing to queue until the object exists.
- **The bucket is the durable queue.** The in-memory pending set is a derived view: after
  a restart the first listing rebuilds the same order, and nothing is lost.
- **Retries rejoin at the back.** An object whose move to `processed/` fails has the
  oldest `LastModified` in the bucket, so it is re-ordered on the time its backoff expires
  instead. Otherwise one object that can never be finalized would re-scrub itself at the
  head of the queue every minute, forever, ahead of real uploads.
- **`POLL_INTERVAL` governs discovery, not drain rate.** The consumer takes the next
  object the instant it finishes one. The interval only bounds how long a *new* upload
  waits to be noticed — and even that is short-circuited: the browser starts polling
  `/api/status` as soon as its upload lands, and that first poll nudges a listing. Note
  that listing covers the whole input bucket including `processed/`, so prune that prefix
  (a lifecycle rule, or `PROCESSED_ACTION=delete`) rather than shortening the interval.
- **The queue is per-pod**, which is the other reason `replicas: 1` is load-bearing. The
  Deployment uses `strategy: Recreate` on purpose: with `replicas: 1` the default
  RollingUpdate starts the new pod before stopping the old one, and two scrubberds polling
  the same bucket would double-process.
- **Upload a `<key>.terms.json` sidecar *before* its bundle.** The override is read when
  the bundle is processed, so a bundle that reaches the front first will miss a sidecar
  still in flight.

`/api/status` reports `queue_position` and `queue_depth` while an object waits, and
`/api/queue` shows the in-flight key plus the head of the pending list.

### Sizing and memory

Objects are scrubbed one at a time, and **archive members spill to disk**: only the member
being scrubbed right now is on the heap. That is what makes a several-hundred-MiB bundle
fit a 2 GiB pod, and it changes what each cap means.

- `MAX_OBJECT_BYTES + MAX_EXPAND_BYTES` bounds the bytes *read* — the compressed object
  plus everything decompressed out of it. Since payloads above `SPILL_THRESHOLD` live in
  `TMPDIR`, this is now mostly a **disk** bound. Size the `/work` volume from it; an
  ephemeral-storage eviction kills a pod as dead as an OOM.
- `SPILL_THRESHOLD` / `SPILL_RESIDENT_MAX` bound **resident memory**. The first sends any
  payload above it to disk on its own; the second is an aggregate budget, and it is the
  one that catches many-small-members bundles, where each member is individually under the
  threshold while together they would hold the whole archive.

The service logs `budget_bytes`, `est_peak_rss_bytes` and `scratch_bytes` at startup —
size `limits.memory` from the second and the `/work` `sizeLimit` from the third. Do not
size a pod from `budget_bytes`; that is the mistake this section exists to prevent.

**The multiplier depends on the shape of the object, not just its size.**
`go test ./internal/pipeline -run TestMemoryMatrix` measures peak heap across container
formats, member counts, match densities and compressibility. The worst case is not the
few-large-members bundle most people reach for when testing by hand — it is **many small
members**, where per-member overhead dominates:

| Shape | Peak heap / content | Before the spill |
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

| Shape | Result | Wall clock |
| --- | --- | --- |
| `.tar.gz`, 90000 members, 352 MiB content, 18.9M matches | scrubbed, 0 passthrough | 141s |
| `.tar.gz`, 50 members, **500 MiB incompressible content** | scrubbed, 0 passthrough | 146s |

Peak RSS across both, on one 1-CPU process: **445 MiB — 22% of the 2 GiB limit**, with no
temp files left behind. For contrast, before members spilled the same pod peaked at
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
> there and it stays bounded only by `MAX_EXPAND_BYTES`. Ordinary bundles of many members
> are fine at any total size the disk budget allows. Watch
> `scrubber_objects_total{status="too_large"}` to find out whether real uploads are being
> turned away.

`WORKERS` is retained for configuration compatibility but is **clamped to 1**; a higher
value is ignored with a warning. Concurrent scrubs on a single CPU do not add throughput,
and they multiply both budgets above.

> A `.tar.gz` draws on `MAX_EXPAND_BYTES` **twice** — once for the decompressed tar and
> once for the member bodies read out of it. Budget roughly half of `MAX_EXPAND_BYTES` as
> usable tar.gz content: ~768 MiB at the shipped cap.

`MAX_OBJECT_BYTES` is a separate ceiling on the *uploaded* (still compressed) object. An
upload above it is skipped rather than downloaded, and reported as `skipped` — so it is
usually the first limit a user hits, independent of `MAX_EXPAND_BYTES`.

**Large objects.** The uploaded object is staged on scratch storage, not the heap, and the
read is capped at `MAX_OBJECT_BYTES` via a bounded fetch: an object larger than the cap is
**skipped and moved aside**, never downloaded whole.

**Filenames and paths** are scrubbed by default (`SCRUB_FILENAMES=true`): archive member
names, directory segments, and the output object key are run through the same policy, so a
sensitive term in a *name* (`AcmeCorp-logs/jsmith-trace.log`) doesn't leak the way it would
if only contents were cleaned. Replacements can't introduce a path separator, so renaming
is traversal-safe. Set `SCRUB_FILENAMES=false` to keep exact names (CLI: `--scrub-names=false`).

### Policies

Named policy files (same schema as the terms file) are mounted from a ConfigMap at
`/etc/scrubber/policies/*.json` and hot-reloaded on change. Resolution per object, highest
precedence first:

1. per-object override `"<key>.terms.json"` sibling in the input bucket,
2. longest matching `PREFIX_POLICY_MAP` prefix → named policy,
3. `DEFAULT_POLICY`.

### Configuration reference

Supplied as environment variables, in practice via a ConfigMap plus a Secret.

| Variable | Default | Meaning |
| --- | --- | --- |
| `MINIO_ENDPOINT` | — | In-cluster MinIO host:port (required). |
| `MINIO_ACCESS_KEY` / `MINIO_SECRET_KEY` | — | Credentials (Secret). |
| `MINIO_USE_TLS` | `false` | TLS to MinIO. |
| `MINIO_CA_CERT` | — | Path to a private CA bundle. |
| `INPUT_BUCKET` / `OUTPUT_BUCKET` / `REPORTS_BUCKET` | — | Bucket names. |
| `INPUT_PREFIX` | — | Restrict listing to a prefix. |
| `DEFAULT_POLICY` | — | Named policy used when nothing more specific matches. |
| `PREFIX_POLICY_MAP` | — | JSON object mapping key prefix → policy name. |
| `PROCESSED_ACTION` | `move` | `move` (to `processed/`) or `delete`. |
| `POLL_INTERVAL` | `15s` | Discovery interval. Does **not** govern drain rate. |
| `WORKERS` | `1` | Clamped to 1; higher values warn and are ignored. |
| `QUEUE_MAX` | `10000` | Cap on the in-memory pending set; the service warns when it truncates. |
| `FINALIZE_GRACE` | `15s` | On shutdown, how long a finished object may keep writing its output. Keep inside `terminationGracePeriodSeconds`. |
| `MAX_OBJECT_BYTES` | 640Mi | Ceiling on the uploaded (compressed) object. |
| `MAX_EXPAND_BYTES` | 1536Mi | Cumulative decompressed bytes. Now mostly a **disk** bound. |
| `SPILL_THRESHOLD` | 4Mi | Payloads above this go to `/work` individually. |
| `SPILL_RESIDENT_MAX` | 64Mi | Aggregate in-memory budget. **This is what bounds RSS.** |
| `RESIDUAL_BUDGET` | 64Mi | Per-object budget for the residual scan; negative disables it. |
| `VERIFY_OUTPUT` | `false` | Re-scan scrubbed output (~70% slower). |
| `REVIEW_PREFIX` | `review/` | Where risky results are diverted; empty disables diverting. |
| `AUDIT_LEVEL` | `counts` | `full` \| `counts` \| `off`. |
| `REDACT_REPORTS` | `false` | Store salted hashes instead of cleartext originals. |
| `SCRUB_FILENAMES` | `true` | Also scrub member names, paths and the output key. |
| `MAX_DEPTH` | `16` | Container nesting depth. |
| `MAX_MEMBERS` | `100000` | Archive member cap. |
| `HISTORY_MAX` | `100` | Past runs `/api/history` may return. |
| `GOMEMLIMIT` | `1200MiB` | Soft GC target. Keep below `limits.memory`. |
| `LOG_LEVEL` | `info` | `debug` logs a line per file inside every bundle. |
| `PORT` | `8080` | Listen port. |
| `MINIO_PUBLIC_ENDPOINT` / `MINIO_PUBLIC_TLS` | — | Browser-reachable MinIO host, for rewriting presigned URLs. |
| `UPLOAD_EXPIRY` | `15m` | Presigned URL lifetime. |
| `ALLOW_POLICY_EDIT` | `true` | Allow `PUT /api/policy` from the UI. |

### Deploying on OpenShift

```sh
# 1. build + push the image (air-gap: override BASE_*_IMAGE / GOPROXY to Artifactory mirrors)
podman build -f deploy/Containerfile -t <artifactory>/docker-local/scrubberd:0.5.0 .
podman push <artifactory>/docker-local/scrubberd:0.5.0
#    (air-gapped: transfer dist/scrubberd-0.5.0.tar and `podman load -i` on the target)

# 2. prereqs: MinIO creds Secret + named-policy ConfigMap
oc create secret generic scrubber-secret \
  --from-literal=MINIO_ACCESS_KEY=... --from-literal=MINIO_SECRET_KEY=...
oc create configmap scrubber-policies --from-file=deploy/policies/

# 3. edit <PLACEHOLDERS> in deploy/openshift-manifests.yaml (image ref, MINIO_ENDPOINT,
#    MINIO_PUBLIC_ENDPOINT, buckets), then apply
oc apply -f deploy/openshift-manifests.yaml
```

Buckets `scrub-input` / `scrub-output` / `scrub-reports` must exist in MinIO, MinIO must
be browser-reachable (its own Route) with CORS allowing the scrubber origin, and the Route
should stay on a trusted network (see the auth caveat under
[Web front page](#web-front-page)).

Build for the cluster's architecture. The image is single-arch: add
`--platform linux/amd64` if you are building on an Apple-silicon Mac for an x86 cluster,
or a `docker save` of an arm64 image will load fine and then fail to start there.

The image satisfies the `restricted-v2` SCC: it runs as an arbitrary non-root UID in group
0 (`/work` and `/etc/scrubber` are `chgrp 0` and group-writable, and `USER` is numeric,
which admission requires under `runAsNonRoot`), with `readOnlyRootFilesystem`, all
capabilities dropped, and `seccompProfile: RuntimeDefault`. `/work` is an emptyDir serving
as `TMPDIR` — and therefore where spilled payloads land. Its `sizeLimit` is load-bearing:
an unbounded emptyDir can eat the node's ephemeral storage and get the pod evicted. Ships
with `replicas: 1` and `strategy: Recreate` (single writer, single queue; horizontal
scale-out needs a distributed object claim and is a documented follow-up).

### Metrics

`/metrics` exposes, alongside the per-object counters (`scrubber_objects_total{status}`,
`scrubber_matches_total`, `scrubber_passthrough_total`, `scrubber_errors_total`,
`scrubber_bytes_in_total`, `scrubber_bytes_out_total`, `scrubber_process_seconds`):

| Metric | Meaning |
| --- | --- |
| `scrubber_queue_depth` | Objects waiting, plus the one in flight |
| `scrubber_inflight_objects` | Objects being scrubbed right now (0 or 1) |
| `scrubber_object_verdict_total{verdict}` | Objects by coverage verdict — **the series to alert on** |
| `scrubber_files_not_inspected_total{reason}` | Files emitted uninspected, by reason code. A code appearing that you have not seen before is a new failure mode |
| `scrubber_residual_hits_total` | Policy matches found inside content that was NOT inspected |
| `scrubber_queue_wait_seconds` | Arrival → start of scrubbing |
| `scrubber_object_latency_seconds` | Arrival → finished; what a user actually waits |

`scrubber_process_seconds` starts counting only once an object reaches the front of the
queue, so it cannot show what someone behind a backlog experiences —
`scrubber_object_latency_seconds` is the number to watch for that.

The label sets are seeded at startup, so a fresh pod shows zeros rather than missing series
— "no incomplete runs" and "this metric does not exist yet" look identical otherwise.

The three alerts worth having:

```
scrubber_object_verdict_total{verdict="incomplete-risky"}  > 0   → something skipped that contains matches
scrubber_files_not_inspected_total{reason="..."}                 → a reason you have not seen before
scrubber_objects_total{status="too_large"}                       → real uploads being turned away
```

### Web front page

`scrubberd` serves a small self-contained upload page at `/` plus a thin browser API.
Crucially, **no bundle bytes pass through the service**: the browser uploads straight to
MinIO and downloads straight from it, using short-lived presigned URLs that the service
mints.

Flow: browser `POST /api/uploads {name}` → gets a presigned PUT + object key → PUTs the
file directly to the input bucket → polls `GET /api/status?key=…` until `scrubbed` → gets
the label-only match breakdown for the "active policy" panel → `GET /api/downloads?key=…`
for a presigned GET of the scrubbed output.

**Status is answered from storage, not just memory.** Recent job outcomes are cached in a
per-process ring, but that cache is lost on restart and can evict entries under load. When
it has no terminal answer for a key, `/api/status` reads the stored run report instead, so
a client is never told "processing" forever for an object that finished. Reports are keyed
by the **input** key (`<key>.report.json` in the reports bucket) — the only key a client
knows — and record where the output landed, so downloads keep working even when filename
scrubbing renamed the output.

While a job is in flight the status response carries real progress (`files_done`,
`current_file`, `phase`) rather than a client-side animation.

**While an object is waiting**, `/api/status` returns `phase: "queued"` with
`queue_position` and `queue_depth`, and the UI shows "Queued — 3 of 7". That answer comes
from the in-memory queue and touches no storage: a queued key has no report yet, so falling
through to the reports bucket would cost two failed object reads per client poll — with a
full queue and second-scale polling, dozens of pointless MinIO round-trips per second for
the whole drain. The progress bar deliberately does *not* advance while queued; a bar
creeping toward full while an object sits twentieth in line reads as "almost done" when
nothing has happened.

Other endpoints:

- `GET /api/history?n=N` — the last N completed runs, rebuilt from the reports bucket and
  shown in the **Recent scrubs** panel. Survives a page refresh and a pod restart. N is
  settable in the UI and capped by `HISTORY_MAX`.
- `GET /api/report?key=…` — the full stored report for one run.
- `GET /api/queue` — the object being scrubbed plus the head of the pending list, in
  order. Keys only.

A run that contains files the pipeline could not inspect is shown as an amber **"N files
NOT scrubbed"** state naming each file and why — never a green check.

The tool is operated by people **inside** your trust boundary who are preparing logs to
send out, so the UI deliberately shows the full policy — the literal terms, patterns and
presets — so operators can verify exactly what will be scrubbed. The thing that must never
leave your environment is the **scrubbed log content**, and that is enforced by the
scrubbing itself. Reports (in an internal bucket) show the actual original values by
default so the scrub can be audited; set `REDACT_REPORTS=true` to store salted hashes
instead if that bucket is less trusted than the operators.

The **Active policy** panel has an **Edit terms.json** control: operators can edit the
policy inline or **Upload** a `terms.json`, then **Apply**. Apply validates and compiles it
server-side (identical fail-fast rules to the CLI — a bad preset or regex returns a precise
error and the current policy is left untouched) and activates it immediately for subsequent
scrubs. This edit is **live but in-memory** — a policy reload or pod restart reverts it, so
durable changes should go through the policy source (see
[Updating the default policy](#updating-the-default-policy-and-presets)). Disable UI editing
with `ALLOW_POLICY_EDIT=false`.

The page has **no external assets** — icons are an inline SVG sprite, and there are no CDN,
font or script fetches — so it renders correctly on an air-gapped cluster.

Two deployment requirements for the browser path:

- MinIO must be reachable by the browser (its own Route/ingress) and have **CORS** allowing
  the scrubber page origin (presigned PUT/GET are cross-origin to MinIO).
- Under **network-only** auth the browser API is unauthenticated — anyone who can reach the
  Route can mint upload/download URLs and see the policy (including literal terms). Since
  the operators are insiders, keep the Route on a trusted/internal network. For genuine
  external exposure, put auth in front (e.g. OpenShift OAuth proxy) — the endpoints are
  structured so this can be added without app changes.

---

## Updating the default policy and presets

Three ways to change what gets scrubbed, from most transient to most permanent:

1. **Live, from the UI** (fastest) — Active policy panel → Edit terms.json → Apply, or
   Upload a `terms.json`. Takes effect immediately; reverts on reload/restart. Also
   available as `PUT /api/policy` with a terms.json body.

2. **Durable, via the policy source** — the named policies are files:
   - Repo/CLI default: [examples/terms.json](../examples/terms.json).
   - Service defaults: [deploy/policies/](../deploy/policies/) (`default.json`, `strict.json`).
   - In-cluster the service reads them from the `scrubber-policies` ConfigMap; update it
     and the pod hot-reloads (fsnotify):
     ```sh
     oc create configmap scrubber-policies --from-file=deploy/policies/ \
       --dry-run=client -o yaml | oc apply -f -
     ```

   Add a new named policy by adding `deploy/policies/<name>.json`, then reference it from
   `DEFAULT_POLICY` or `PREFIX_POLICY_MAP`.

3. **Adding a new preset** (a code change — presets are compiled in) — edit
   [internal/config/presets.go](../internal/config/presets.go): add an entry to the
   `presets` map with a `pattern`, a `replacement` label, and an optional `valid` validator
   to cut false positives (RE2 has no lookahead, so validators are how `fqdn`/`hostname`
   filter filenames and plain words):
   ```go
   "mac_address": {
       pattern:     `\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b`,
       replacement: "[MAC]",
   },
   ```
   Then rebuild the image and redeploy. Add a test in
   [internal/config/presets_test.go](../internal/config/presets_test.go) alongside it.

---

## Benchmarking

```sh
go test ./internal/queue ./internal/scrub ./internal/pipeline -bench=. -benchmem
go test ./internal/worker -bench=DrainSerialVsFanOut -cpu=1   # -cpu=1 models the pod
./scripts/bench-queue.sh                                      # end-to-end, needs Docker
```

`scripts/bench-queue.sh` uploads N objects at once, drains them, and reports total wall
clock, time to the first completion, per-object latency and peak container memory. Point it
at two images to compare a change honestly:

```sh
git stash && docker build -q -f deploy/Containerfile -t scrubberd:baseline . && git stash pop
docker build -q -f deploy/Containerfile -t scrubberd:queue .
IMAGE=scrubberd:baseline ./scripts/bench-queue.sh
IMAGE=scrubberd:queue    ./scripts/bench-queue.sh
```

Serialising does **not** buy raw throughput — on one CPU the same bytes have to be scrubbed
either way, and `BenchmarkDrainSerialVsFanOut` measures the old fan-out as roughly 8% faster
on total drain time. What it buys is a halved memory budget (one object resident instead of
two) and arrival-ordered completion, so the first upload finishes early instead of every
upload finishing late together. `-cpu=1` matters: unpinned on a multi-core box the fan-out
looks twice as fast, which is true of hardware the pod does not have, so the benchmark skips
rather than print it.

Other useful scripts:

```sh
./scripts/memory-matrix.sh      # both worst-case shapes end to end, ~6 min
./scripts/coverage-check.sh     # proves the coverage verdicts end to end
./scripts/encoding-check.sh     # proves UTF-16/UTF-32 handling end to end
```

---

## Notes and limitations

- Text is handled as UTF-8 (with or without BOM), ASCII/Latin-1, and **UTF-16 and UTF-32**
  in either byte order, with or without a BOM. Each is scrubbed and written back in the
  encoding it arrived in, so whatever reads it next is unaffected. Single-byte encodings
  beyond Latin-1 (cp1252, and ASCII-compatible multi-byte ones such as Shift-JIS) pass
  through the matcher as bytes, so terms in the ASCII range — which is what addresses,
  hostnames and keys are — still match.
- **Base64-encoded content is not decoded.** Secrets inside it are not matched, and because
  base64 output is plain ASCII the file is not flagged as binary either — the run reports a
  clean pass. Tracked in [#15](https://github.com/Howard-Jek/scrubber/issues/15).
- Text that is **malformed** in the encoding it claims (an unpaired UTF-16 surrogate, a
  UTF-32 code point past U+10FFFF, a length that is not a whole number of code units) is
  refused rather than repaired: it is passed through untouched and reported with reason
  `encoding-unsupported`. The residual scan reads it at one-, two- and four-byte stride
  anyway, so such a file full of live data escalates the run to `incomplete-risky` rather
  than passing quietly.
- Expansion is bounded by the cumulative `--max-expand-bytes` budget for a whole input
  (nested streams and archive members draw from the same budget). Payloads above the spill
  threshold are held on disk under `TMPDIR`, so that budget bounds mostly scratch space;
  resident memory tracks the largest single member instead.
- A single archive *member* larger than the memory budget is still only bounded by
  `--max-expand-bytes`: the leaf scrubber needs its payload contiguous in memory, so one
  enormous member inside an otherwise ordinary bundle is the shape the spill does not help
  with.
- The queue lives in the pod, so `replicas: 1` is a correctness requirement, not a capacity
  choice — two pods polling one bucket would double-process. Scaling out needs a distributed
  object claim.
- The service scrubs one object at a time in arrival order. That is strict FCFS with no
  per-tenant fairness: a single user who uploads a large batch does hold up the users behind
  them until it drains. Round-robin between uploaders would need a tenant identity, which the
  service does not have (there is no app auth).
- The residual scan is a signal, not a proof. It can produce false positives on genuine
  binary (an image whose bytes happen to spell an IP address) and it cannot see inside content
  a guard refused to decompress. It is deliberately tuned to say "look at this" rather than to
  be authoritative, because the alternative — a check precise enough to trust blindly — is the
  thing that keeps turning out to be wrong.
- Shelling out to a system `7z`/`xz`, and length-preserving / hashing replacement modes, are
  intentionally out of scope for v1.
