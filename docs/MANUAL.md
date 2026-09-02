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
  - [Sizing the pod](#sizing-the-pod)
  - [Sizing and memory](#sizing-and-memory)
  - [Policies](#policies)
  - [Configuration reference](#configuration-reference)
  - [Deploying on OpenShift](#deploying-on-openshift)
  - [Metrics](#metrics)
  - [Web front page](#web-front-page)
- [Updating the default policy and presets](#updating-the-default-policy-and-presets)
- [Benchmarking](#benchmarking)
- [Nothing bounds the scrub itself](#nothing-bounds-the-scrub-itself)
- [Troubleshooting by symptom](#troubleshooting-by-symptom)
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
  tracks the largest single member — which is itself capped by `MAX_LEAF_BYTES`, because
  that one member has to be contiguous in memory. There is deliberately **no
  expansion-ratio limit**: ratio cannot separate a bomb from an ordinary log (real logs
  compress 200:1 to 1000:1), so any threshold low enough to catch a bomb also rejects the
  tool's primary input — and a rejected file is emitted unscrubbed.
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
| `--max-expand-bytes` | `2147483648` | Expanded content accepted per input, enforced while reading (bounds `TMPDIR`, not memory). Payloads above the spill threshold are held on disk, so this is a scratch-space bound. "Content" is literal: a nested container is charged once, not once for itself and again for its members. |
| `--max-leaf-bytes` | `0` (off) | Largest single file to scrub. The matcher needs the payload contiguous in memory, so one file costs 3–4× its size in heap whatever the spill settings are; a file above the cap is passed through and flagged `guard-tripped` / `leaf-cap`, and **the rest of the archive is still scrubbed**. Off by default because a workstation has the memory for one large log and no kubelet to answer to; the service derives a value (see [Sizing the pod](#sizing-the-pod)). |
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

> **The narrow hole, for contrast.** A file above `MAX_LEAF_BYTES` (the per-file cap; see
> [Sizing the pod](#sizing-the-pod)) is skipped with reason `leaf-cap`, and *only that
> file* — every other member of the archive is still scrubbed,
> where an `expansion-budget` trip inside a container discards everything in it. The
> residual scan can also read a leaf-capped file, because it is plain text rather than a
> container nobody was allowed to open, so one full of live data escalates the run to
> `incomplete-risky` instead of passing quietly as `incomplete`.

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

### Sizing the pod

**Two ceilings, two different resources, and they are not interchangeable.**

| What you are bounding | What bounds it | The cap |
| --- | --- | --- |
| How large a bundle may **expand** | ephemeral storage — the `/work` volume | `MAX_EXPAND_BYTES` |
| How large one **file** may be scrubbed | `limits.memory` | `MAX_LEAF_BYTES` |

Every expanded byte lands on `/work`, so an expansion cap sized from `limits.memory` gets
the pod **evicted for ephemeral-storage**. One file has to be contiguous in memory for the
matcher and that copy never touches disk, so a per-file cap sized from the volume
**OOM-kills** it. Stated plainly, because the mistake reads perfectly plausible both ways:
`limits.memory` does **not** affect how large a bundle can expand.

**The rule: size `/work` at 3.5× the expanded content you want to accept.**

| `/work` `sizeLimit` (= both `ephemeral-storage` values = `SCRATCH_BYTES`) | Expanded content accepted |
| --- | --- |
| 4 GiB | 1.14 GiB |
| 10 GiB | 2.86 GiB |
| **14 GiB (shipped)** | **4.00 GiB** |
| 20 GiB | 5.71 GiB |
| 21 GiB | 6.00 GiB |

Every figure here is binary (GiB), not decimal. A "6 GB" requirement is 5.59 GiB if
someone means decimal and 6.00 GiB if they mean binary; size for the larger one.

The 3.5 is not padding. A `.tar.gz` whose content expands to N holds three copies on the
volume at the same instant — the decompressed tar, the member bodies read out of it, and
the repacked result — on top of the compressed object staged for the download, which is at
most 0.42N. That is C + 3N ≈ 3.42N; 3.5 is it rounded up.

**Nothing here is compiled in any more.** Both caps are derived at startup from what the
Deployment declares about itself, so raising the declaration raises the ceiling on the next
rollout with no code change and no knob to remember. The shipped manifest declares
`SCRATCH_BYTES: "14Gi"`, a `/work` `sizeLimit` of 14Gi, `limits.memory: 4Gi`, and
`ephemeral-storage: 14Gi` in both `limits` and `requests` — and derives:

| Cap | Shipped value | Derived as |
| --- | --- | --- |
| `MAX_EXPAND_BYTES` | `4294967296` — **4.00 GiB exactly** | `SCRATCH_BYTES / 3.5` |
| `MAX_OBJECT_BYTES` | `1789569706` — 1707 MiB | 41.7% of `MAX_EXPAND_BYTES` |
| `MAX_LEAF_BYTES` | `201326592` — 192 MiB | 96Mi × (`limits.memory` / 2Gi) |
| `SPILL_THRESHOLD` | `8388608` — 8 MiB | 4Mi × (`limits.memory` / 2Gi) |
| `SPILL_RESIDENT_MAX` | `134217728` — 128 MiB | 64Mi × (`limits.memory` / 2Gi) |
| `GOMEMLIMIT` | `2516582400` — 2400 MiB | 58.6% of `limits.memory` |

The **four** scratch declarations must move together — the `/work` `sizeLimit` is what the
kubelet enforces, `limits.ephemeral-storage` is what it evicts against,
`requests.ephemeral-storage` is what the scheduler reserves on the node, and
`SCRATCH_BYTES` is what the process is told. Forgetting `requests` is the one that bites
late rather than at rollout: the pod lands on a node with the old headroom and evicts
under load. All four accept Kubernetes quantities, so write `14Gi` in all four and they
diff by eye. `cmd/scrubberd/main_test.go` parses the shipped manifest through the same
parser the service uses and asserts it derives 4 GiB, so the manifest and the code can no
longer drift apart.

At that configuration the pod estimates a peak RSS of ~2083 MiB against a 60% gate of
2458 MiB, and needs 14.00 GiB of scratch against 14 GiB declared — so it starts with
neither of its two sizing warnings. Both are close, and that is deliberate: the
declarations are meant to be spent, not admired.

### Sizing and memory

Objects are scrubbed one at a time, and **archive members spill to disk**: only the member
being scrubbed right now is on the heap. That is what lets a bundle far larger than the pod
fit through it, and it changes what each cap means.

- `MAX_OBJECT_BYTES + MAX_EXPAND_BYTES` bounds the bytes *read* — the compressed object
  plus everything decompressed out of it. Since payloads above `SPILL_THRESHOLD` live in
  `TMPDIR`, this is a **disk** bound. It is derived *from* the `/work` volume rather than
  something to size the volume from; an ephemeral-storage eviction kills a pod as dead as
  an OOM.
- `SPILL_THRESHOLD` / `SPILL_RESIDENT_MAX` bound **resident memory**. The first sends any
  payload above it to disk on its own; the second is an aggregate budget, and it is the
  one that catches many-small-members bundles, where each member is individually under the
  threshold while together they would hold the whole archive.
- `MAX_LEAF_BYTES` bounds the one payload the two above cannot: the single file the matcher
  is working on, which is read back off disk in full and outside the spill accounting. It
  is the other half of the resident-memory bound, and the only cap that follows
  `limits.memory`.

The service logs one `resource limits` line at startup with all of it. Read
`budget_bytes`, `est_peak_rss_bytes` and `scratch_bytes` as **checks on what you
declared**, not as instructions for writing it — the `/work` `sizeLimit` is an input
now, and `scratch_bytes` is that declaration divided by 3.5 and multiplied back, so
sizing the volume from it would be circular. The one still worth sizing against is
`est_peak_rss_bytes`: compare it to `limits.memory`, and if it is close, lower
`MAX_LEAF_BYTES` or raise the memory. Do not size a pod from `budget_bytes`; that is
the mistake this section exists to prevent. Alongside them,
`max_leaf_bytes` is the largest file this pod can actually scrub as opposed to the largest
bundle it can open, and `scratch_declared_bytes` / `scratch_source` say what the expansion
cap was derived from and where that number came from. Two warnings can follow the line —
one when the scratch a single object needs exceeds the declaration, one when
`MAX_EXPAND_BYTES` sits well below what the declaration would allow — and both name
`scratch_source`, because it is usually the answer.

### The caps size themselves against the pod

Every number in this section was measured on a 2 GiB / 1 CPU pod, and for a while it was
also compiled in as a default — which quietly made 2 GiB the only size the service was
tuned for. On a larger pod it left most of the memory idle and scrubbed no faster, and
the only recourse was to raise the spill knobs by hand. That is a trap: raise them far
enough to matter and members stop spilling, the live set climbs past `GOMEMLIMIT`, and
the GC burns the single CPU it has. Giving the pod more memory made it slower.

So the measured values are stored as a *ratio* to the pod they were measured on, and the
real ceilings are read at startup from what the pod declares about itself:

| Pod memory | `mem_scale` | `SPILL_THRESHOLD` | `SPILL_RESIDENT_MAX` | `MAX_LEAF_BYTES` | `GOMEMLIMIT` |
| --- | --- | --- | --- | --- | --- |
| 2 GiB | 1× | 4 MiB | 64 MiB | 96 MiB | 1200 MiB |
| **4 GiB (shipped)** | 2× | 8 MiB | 128 MiB | 192 MiB | 2400 MiB |
| 8 GiB | 4× | 16 MiB | 256 MiB | 384 MiB | 4800 MiB |

**At 2 GiB the `SPILL_*` and `GOMEMLIMIT` columns are byte-identical to what shipped
before v0.8.0**, so the heap and RSS measurements taken there stay valid at that size.
`MAX_LEAF_BYTES` is the exception and cannot be: it did not exist before v0.8.0, and its
96 MiB baseline was solved for rather than measured — it is the largest leaf that keeps
`est_peak_rss_bytes` under the same 60% gate the memory matrix fails on. Change `limits.memory` and they
follow. `est_peak_rss_bytes` is deliberately *not* a column: it also depends on
`MAX_MEMBERS` and, since v0.8.0, on the leaf cap rather than on the spill threshold — the
old estimate assumed the spill threshold bounded the largest payload the matcher holds,
which it never did, so it was short by the difference between 4 MiB and the biggest file in
the bundle. That gap is what OOM-kills a pod. Read the number the pod prints; at the
shipped 4 GiB / 14 GiB configuration it is 2083 MiB against a gate of 2458 MiB.

**Where each ceiling comes from**, highest precedence first:

| Cap follows | Precedence |
| --- | --- |
| memory | `POD_MEMORY_LIMIT` → cgroup v2 `memory.max` → cgroup v1 `memory.limit_in_bytes` → *not detected* |
| scratch | `SCRATCH_BYTES` → `POD_EPHEMERAL_LIMIT` → *not declared* |

`POD_MEMORY_LIMIT` and `POD_EPHEMERAL_LIMIT` are the Downward API: the Deployment projects
its own `resources` block back into the pod, which is the only way the numbers an operator
wrote in `deployment.yaml` arrive as the numbers they wrote rather than as whatever the
kernel happens to expose.

```yaml
- name: POD_MEMORY_LIMIT
  valueFrom: { resourceFieldRef: { containerName: scrubberd,
              resource: limits.memory, divisor: "1" } }
- name: POD_EPHEMERAL_LIMIT
  valueFrom: { resourceFieldRef: { containerName: scrubberd,
              resource: limits.ephemeral-storage, divisor: "1" } }
```

`containerName: scrubberd` is required, and `divisor: "1"` means bytes.

> ⚠️ **The ephemeral reference has a trap.** If a container declares no
> `limits.ephemeral-storage`, Kubernetes does not fail the reference — it resolves it to
> the **node's** allocatable storage, a number many times the pod's share, and a budget
> derived from that is one that gets the pod evicted. The shipped manifest declares the
> limit explicitly, and `SCRATCH_BYTES` overrides it in any case.

**Scratch used to be the carve-out here; it is not any more.** What has not changed is the
reason there is no *measured* fallback: an emptyDir's `sizeLimit` is enforced by the
kubelet, not by the filesystem, so `statfs` inside the container reports the whole node's
disk — a number that looks authoritative and is wrong in the direction that gets the pod
evicted. What changed is that the ceiling no longer has to be guessed, because the
deployment declares it. When neither `SCRATCH_BYTES` nor `POD_EPHEMERAL_LIMIT` is present,
the ceiling falls back to 4 GiB — the `sizeLimit` the manifest has always carried — and is
derived from exactly as if it had been declared, so there is one derivation path rather
than a derived one and a compiled-in one. The flat 1536Mi default is gone.

**`scratch_source` is the line to read first** when `max_expand_bytes` is not what you
expected. `default (undeclared)` means the manifest never told the pod how much `/work` it
has, so it is sizing itself from 4 GiB regardless of what the volume actually grants.

What the derivation still does not do is override an explicit environment variable: setting
one wins, and still freezes that value at whatever the pod was when you typed it. Startup
warns in both directions — when the scratch one object needs exceeds the declaration
(eviction), and when `MAX_EXPAND_BYTES` sits well *below* what the declaration allows,
which is the quiet one: the pod refuses bundles it now has the disk for, and refusing means
emitting them unscrubbed.

An undetectable memory limit (`pod_memory_bytes: 0` in the startup log) falls back to the
measured 2 GiB ratios rather than extrapolating from a number nobody has.

> **Check `pod_cpus` in the startup log.** Go derives `GOMAXPROCS` from the cgroup CPU
> limit, but only under cgroup v2. On a cgroup v1 node it reports the *node's* core
> count, so the runtime schedules many more threads than the pod has CPU for and pays
> GC coordination overhead for them. If `pod_cpus` is much larger than your
> `limits.cpu`, set `GOMAXPROCS` explicitly to match.

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

Those are **heap** multipliers, and they are the ones that stop mattering as bundles grow.
Two others do not, and both are flat: one byte of content draws roughly one byte of
expansion budget whatever the format ([below](#the-budget-draws-once-per-byte-of-content)),
and one byte of content occupies up to 3.5 bytes of `/work` — which is why the volume, and
not the heap, is what a large bundle is sized against.

`scripts/memory-matrix.sh` confirms this end to end against real MinIO and real RSS —
which is what the kubelet OOM-kills on, and what the heap figures above cannot tell you.
Measured on a **2 GiB pod with the caps pinned by hand at expand 1536Mi / object
640Mi** — the values `memory-matrix.sh` used to export, which were never what the
shipped manifest produced: `SCRATCH_BYTES=4Gi` under the old ÷2.5 derived 1638Mi and
682.7Mi. Both worst shapes in one run:

| Shape | Result | Wall clock |
| --- | --- | --- |
| `.tar.gz`, 90000 members, 352 MiB content, 18.9M matches | scrubbed, 0 passthrough | 141s |
| `.tar.gz`, 50 members, **500 MiB incompressible content** | scrubbed, 0 passthrough | 146s |

Peak RSS across both, on one 1-CPU process: **445 MiB — 22% of that 2 GiB limit**, with no
temp files left behind. For contrast, before members spilled the same pod peaked at
1889 MiB (92%) on a 512Mi expansion budget, and a 500 MiB bundle did not fit at any cap
setting. Neither shape has a large single member, so neither exercised the leaf path —
which is why `MAX_LEAF_BYTES` had to be derived from the arithmetic rather than read off
this measurement.

`GOMEMLIMIT` is a soft target the GC grows the heap *toward*, so it sets steady-state RSS
as much as it caps it, and it only holds while the *live* set fits beneath it. That was
the old failure: at `MAX_EXPAND_BYTES=512Mi` the live set exceeded 1600 MiB, the GC could
not keep up, and RSS overran. With the live set now bounded by the spill policy rather
than by the bundle, it holds with room to spare — with one exception the spill policy does
not cover, the leaf the matcher is working on, which is bounded by `MAX_LEAF_BYTES`
instead. Setting `MAX_LEAF_BYTES=0` in the service removes that bound and leaves the whole
expansion budget as the only limit on a single file, which no pod can hold contiguously;
startup names the leaf term in its peak-RSS warning for exactly that reason.

**Changing any cap means re-running `scripts/memory-matrix.sh`.** It defaults to the
shipped pod (`LIMIT_MIB=4096`, `SCRATCH_MIB=14336`) and lets the service derive everything
else, so the run exercises production's arithmetic rather than bypassing it —
`EXPAND_MIB`, `OBJECT_MIB`, `LEAF_MIB`, `GOMEMLIMIT_MIB` and both `SPILL_*_MIB` are empty
unless you set them, and are only passed when you do. (`SCRATCH_MIB=4096 LIMIT_MIB=2048`
reproduces the old 2 GiB pod.) It used to pin all of those and never set `SCRATCH_BYTES` at
all, which meant the gate would have passed cleanly with the derivation deleted outright.

It fails on **five** conditions, and only the first is the one people expect:

1. the object did not come back `scrubbed`;
2. it came back with a **passthrough** — a cap set too low stops bounding memory and starts
   silently emitting unscrubbed files instead, which looks like a pass if you only watch
   RSS;
3. it reported **zero matches** — the payload went through the pipeline without ever
   reaching the matcher, which also looks like a pass;
4. peak RSS exceeded `TARGET_PCT` (default 60) of `LIMIT_MIB` — the same 60% gate the
   service warns at, so the two agree on what "too close" means;
5. the service left a **temp file** behind in `TMPDIR`, which would fill the `/work`
   emptyDir over days and get the pod evicted for a reason that looks nothing like its
   cause.

### Where it actually fails

Measured end to end against real MinIO, one 1-CPU process, with zips of log-shaped
text. "Expanded" is the sum of member bodies; the compressed object is much smaller.

**Read the "caps in force" column literally.** These runs were made at caps pinned by hand,
and none of them is what a manifest derives today: `SCRATCH_BYTES=4Gi` under the old
÷2.5 derived 1638Mi and 682.7Mi rather than the 1536Mi/640Mi quoted here and elsewhere in
the older docs, and under today's ÷3.5 it derives 1170Mi. The runs are still the honest
record of what the engine did with the caps named; they are not a description of the
shipped configuration.

The column that separates the failing row from the succeeding one is **scratch**, not
memory. It is given its own column here for that reason.

| Memory | Scratch | Caps in force | Bundle | Result |
| --- | --- | --- | --- | --- |
| 2 GiB | 4Gi | expand 1536Mi, object 640Mi | 1.37 GiB expanded, 280 members | **scrubbed**, `complete`, 32.3M matches, 7m17s, peak RSS 130 MiB |
| 2 GiB | 4Gi | same | 1.66 GiB expanded, 340 members | **not scrubbed** — `guard-tripped` / `expansion-budget` after 5.3s, emitted byte-for-byte, verdict `incomplete` |
| 8 GiB | **12Gi** | expand 4.8Gi, object 2Gi | 1.66 GiB expanded, 340 members | **scrubbed**, `complete`, 39.2M matches, 8m38s, peak RSS ~890 MiB |

The bundles were zips, which never drew on the budget twice, so the double-draw fix does
not move these figures. The third row's arithmetic has moved, though: 12 GiB of scratch
derived 4.8 GiB under the old ÷2.5 and derives 3.43 GiB under ÷3.5, and 4.8 GiB of expanded
content now wants 16.8 GiB declared. That is not the factor being stingy — it is the factor
finally covering the disk a `.tar.gz` actually touches.

Three things worth taking from this:

- **The ceiling is the configured cap, not a cliff.** Nothing OOMs at the boundary.
  Over-budget input trips a guard in seconds, is passed through verbatim and is named
  with reason `expansion-budget`. Peak RSS at 2 GiB was 130 MiB — 6% of the pod — because
  what bounds memory is the spill policy, not the bundle.
- **It was the scratch declaration that admitted the bundle, not the memory.** The
  identical object came back unscrubbed at `SCRATCH_BYTES=4Gi` and scrubbed completely at
  `SCRATCH_BYTES=12Gi`. `limits.memory` moved from 2 GiB to 8 GiB in the same runs and is
  a passenger here: it raised the SPILL_* knobs and (today) `MAX_LEAF_BYTES`, none of
  which decide how large a bundle may expand. **Raising `limits.memory` on its own would
  not have changed the second row's outcome.** Throughput per member was unchanged (0.64
  vs 0.68 files/s) — neither resource buys speed, which is CPU-bound on a one-core pod.
- **The practical ceiling of the shipped pod** is not on this table, because it is derived
  rather than measured: 14 GiB of declared scratch gives **1707 MiB compressed / 4.00 GiB
  expanded**, with the largest single *file* capped at 192 MiB by the 4 GiB of memory.
  Raise `limits.ephemeral-storage`, `requests.ephemeral-storage`, the `/work` `sizeLimit`
  and `SCRATCH_BYTES` together
  and both of those move; raise `limits.memory` and only the per-file cap does.

> ⚠️ **An over-budget bundle is flagged but not diverted.** The residual scan cannot see
> inside a container the budget refused to decompress, so the run reports `incomplete`
> rather than `incomplete-risky` and the output lands in the **normal** output bucket,
> not under `review/`. It is named in the report with reason `expansion-budget`, but
> nothing physically separates it from finished work. If your bundles approach the cap,
> alert on `scrubber_files_not_inspected_total{reason="expansion-budget"}` rather than
> relying on the review queue.

> **What still does not fit — and what now happens instead.** A single archive *member*
> above `MAX_LEAF_BYTES` (192 MiB on the shipped 4 GiB pod). The matcher needs its payload
> contiguous as a string, and spilling does not help: `spill.Blob.Bytes` reads a spilled
> leaf back in full, *outside* the resident reservation `SPILL_RESIDENT_MAX` enforces, and
> `textenc.Decode`, `Matcher.Scrub` and `textenc.Encode` then each hold their own copy — so
> one text file costs 3–4× its size in heap however low the spill knobs are set.
>
> That was survivable only while the expansion budget was small enough to bound it by
> accident. Once the budget follows the volume it no longer does, and the failure it
> produces is an OOM *mid-object*: the pod dies, restarts, picks the same object up and
> dies again. So the file is passed through and flagged `guard-tripped` / `leaf-cap`
> instead, **and the rest of the archive is still scrubbed** — unlike an expansion-budget
> trip inside a container, which discards every member of that container. Ordinary bundles
> of many members are fine at any total size the disk budget allows.
>
> Watch `scrubber_files_not_inspected_total{reason="leaf-cap"}` for individual files being
> turned away, and `scrubber_objects_total{status="too_large"}` for whole uploads.

`WORKERS` is retained for configuration compatibility but is **clamped to 1**; a higher
value is ignored with a warning. Concurrent scrubs on a single CPU do not add throughput,
and they multiply both budgets above.

#### The budget draws once per byte of content

A `.tar.gz` used to draw on `MAX_EXPAND_BYTES` **twice** — once for the decompressed tar
and once for the member bodies read out of it — so a 4 GiB setting admitted only about
2 GiB of content and the cap did not mean what its name said. `internal/pipeline`'s
`descend` now *lends* a container's charge back before walking into it and settles up
afterwards, so the content is charged once:

| Container | Minimum budget per byte of content | Before |
| --- | --- | --- |
| `.tar.gz` | **1.03×** | 2.03× |
| plain `.tar` | 1.00× | 1.00× (never double-drew) |
| plain `.zip` | 1.00× | 1.00× (never double-drew) |

Measured in `internal/pipeline/budget_test.go` with a 57,000-byte body inside a
58,880-byte tar: the smallest budget that admits it fell from 115,880 to 58,880 bytes. The
residual 3% is the tar's own block padding, not a second copy of anything.

The lend has to happen *before* the walk rather than as a refund after it, because the
remaining budget is what gets passed down as the read ceiling — `ReadTar`, `ReadZip` and
`DecompressBlob` all take it. And the settle re-charges the difference when the contents
turn out to cost *less* than the container did, so an archive of large, nearly empty inner
containers still trips the guard rather than being handed free budget;
`TestRefundCannotBeUsedToBeatTheGuard` pins that.

#### The compressed-object ceiling

`MAX_OBJECT_BYTES` is a separate ceiling on the *uploaded* (still compressed) object, held
at 41.7% of `MAX_EXPAND_BYTES` so it stays the limit a user hits first — it is the one with
a clear error message, and it is the **only** cap that turns an upload away. The other
two do not reject; they emit and flag, and they differ in how much:

| Cap | What happens | Blast radius |
| --- | --- | --- |
| `MAX_OBJECT_BYTES` | upload **rejected**, `scrubber_objects_total{status="too_large"}` | nothing is produced |
| `MAX_EXPAND_BYTES` | emitted unscrubbed, `guard-tripped` / `expansion-budget` | the **whole container** — every member of it is uninspected |
| `MAX_LEAF_BYTES` | emitted unscrubbed, `guard-tripped` / `leaf-cap` | **that one file**; the rest of the archive is scrubbed normally |

Do not blur the three.

**Large objects.** The uploaded object is staged on scratch storage, not the heap, and the
read is capped at `MAX_OBJECT_BYTES` via a bounded fetch. Be precise about what that costs:
`store.Client.GetLimitedTo` streams the object to `/work` and stops at `max+1` bytes, then
returns `ErrTooLarge`. An oversized object is **not kept** — it is reported as `skipped` and
moved aside, and never buffered whole in memory — but it *is* transferred up to the cap.
It is not free, it is just not retained.

#### Filenames and paths

Names are scrubbed by default (`SCRUB_FILENAMES=true`): archive member names, directory
segments, and the output object key are run through the same policy, so a sensitive term in
a *name* (`AcmeCorp-logs/jsmith-trace.log`) doesn't leak the way it would if only contents
were cleaned. Replacements can't introduce a path separator, so renaming
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
| `POD_MEMORY_LIMIT` | — | Downward API `limits.memory` in bytes (`divisor: "1"`). Preferred over the cgroup because it is the number the operator wrote. Governs the memory-scaled caps only. |
| `POD_EPHEMERAL_LIMIT` | — | Downward API `limits.ephemeral-storage` in bytes. Used for the scratch ceiling when `SCRATCH_BYTES` is unset. **Only meaningful if the container declares `limits.ephemeral-storage`** — undeclared, Kubernetes resolves it to the node's allocatable storage. |
| `SCRATCH_BYTES` | `POD_EPHEMERAL_LIMIT`, else 4Gi | Ephemeral-storage ceiling one object may fill, and the input every other size cap is derived from. **Keep it equal to the `/work` emptyDir `sizeLimit` and to BOTH `ephemeral-storage` values.** Accepts Kubernetes quantities as well as plain byte counts; an unreadable value is warned about at startup and ignored. Shipped: `14Gi`. Undeclared, `scratch_source` reads `default (undeclared)`. |
| `MAX_EXPAND_BYTES` | *derived* | Expanded **content** one object may hold, enforced while reading. Derived as `SCRATCH_BYTES / 3.5`; 4.00 GiB as shipped. A **disk** bound: the disk actually touched is that multiple again. Set it only to go *below* the derivation — above it is how a pod gets evicted, and startup warns either way. Clamped to 1 PiB with a warning — the guards evaluate `budget+1`, which wraps negative near `MaxInt64`, and a wrapped budget makes every payload read as *empty*: the object ships unscrubbed while the report calls it complete. |
| `MAX_LEAF_BYTES` | *derived* | Largest single file the matcher will scrub, derived as 96Mi × (`limits.memory` / 2Gi); 192Mi as shipped. The one cap that follows **memory**, because the payload must be contiguous and each of `Bytes`/`Decode`/`Scrub`/`Encode` holds a copy outside the spill accounting. A larger file is passed through and flagged `leaf-cap`; the rest of the archive is still scrubbed. `0` disables it, which leaves the whole expansion budget as the only bound. |
| `MAX_OBJECT_BYTES` | *derived* | Ceiling on the uploaded (compressed) object — the only cap that turns an upload away. Derived as 41.7% of `MAX_EXPAND_BYTES`; 1707Mi as shipped. |
| `SPILL_THRESHOLD` | *derived* | Payloads above this go to `/work` individually. Scaled from the pod's memory (4Mi at 2Gi, 8Mi as shipped), floored at 512Ki. |
| `SPILL_RESIDENT_MAX` | *derived* | Aggregate in-memory budget. **This is what bounds RSS**, together with `MAX_LEAF_BYTES` — on its own it does not, because the leaf being scrubbed is read back off disk outside this accounting. Scaled from the pod's memory (64Mi at 2Gi, 128Mi as shipped). |
| `STALL_WARN_AFTER` | `5m` | How long the in-flight object may sit in one phase before the worker logs that it may be stalled. **A log threshold, never a kill** — see [Nothing bounds the scrub itself](#nothing-bounds-the-scrub-itself). Zero disables. |
| `TRANSFER_STALL_TIMEOUT` | `60s` | Abandon an object-storage transfer that has moved **no bytes** for this long. Not a deadline on the transfer. Also bounds metadata calls (10× for listings). Negative disables, restoring an unbounded wait. |
| `ALLOW_CANCEL` | `true` | Enable `POST /api/cancel`. A cancel must still present the token this server minted for that key at upload time. |
| `ALLOW_CANCEL_ANY` | `false` | Drop the token requirement, so any caller can withdraw any key. **Do not enable without real authentication in front of the Route** — `/api/queue` and `/api/history` both publish live input keys, so this turns a two-line loop into a durable evacuation of every user's work. It exists because clearing *somebody else's* stuck object is the operator's real need. |
| `CANCELLED_PREFIX` | `cancelled/` | Where a withdrawn input is moved under `PROCESSED_ACTION=move`. Never empty — every string has `""` as a prefix, so an empty value would make the whole bucket ineligible. |
| `CANCEL_BUDGET` | `60s` | Storage time one cancel may take. Larger than `API_STORAGE_BUDGET` because the withdrawal is a server-side copy of a possibly large object, and the caller wants a truthful answer more than a fast one. |
| `LIST_TIMEOUT` | `90s` | Bound on one bucket listing. Separate from the stall timeout because a listing's honest duration scales with the bucket (it paginates, and the input bucket includes `processed/`) rather than with the network. Negative disables. |
| `API_STORAGE_BUDGET` | `5s` | Total object-storage time **one HTTP request** may spend, shared across every call it makes. The per-call bound above is the safety net; this is what a browser polling every second experiences. On expiry `/api/status` answers `backend: "unreachable"`, `/api/history` returns `partial: true`, `/api/report` returns 504. Negative disables. |
| `RESIDUAL_BUDGET` | 64Mi | Per-object budget for the residual scan; negative disables it. |
| `VERIFY_OUTPUT` | `false` | Re-scan scrubbed output (~70% slower). |
| `REVIEW_PREFIX` | `review/` | Where risky results are diverted; empty disables diverting. |
| `AUDIT_LEVEL` | `counts` | `full` \| `counts` \| `off`. |
| `REDACT_REPORTS` | `false` | Store salted hashes instead of cleartext originals. |
| `SCRUB_FILENAMES` | `true` | Also scrub member names, paths and the output key. |
| `MAX_DEPTH` | `16` | Container nesting depth. |
| `MAX_MEMBERS` | `100000` | Archive member cap. |
| `HISTORY_MAX` | `100` | Past runs `/api/history` may return. |
| `GOMEMLIMIT` | *derived* | Soft GC target, 58.6% of the detected pod memory (1200MiB at 2Gi, 2400MiB as shipped). Keep below `limits.memory`. Only derived when it is not already set — Go applies it from the environment at init. |
| `LOG_LEVEL` | `info` | `debug` logs a line per file inside every bundle. |
| `PORT` | `8080` | Listen port. |
| `MINIO_PUBLIC_ENDPOINT` / `MINIO_PUBLIC_TLS` | — | Browser-reachable MinIO host, for rewriting presigned URLs. |
| `UPLOAD_EXPIRY` | `15m` | Presigned URL lifetime. |
| `ALLOW_POLICY_EDIT` | `true` | Allow `PUT /api/policy` from the UI. |

### Deploying on OpenShift

```sh
# 1. build + push the image (air-gap: override BASE_*_IMAGE / GOPROXY to Artifactory mirrors)
podman build -f deploy/Containerfile -t <artifactory>/docker-local/scrubberd:0.8.1 .
podman push <artifactory>/docker-local/scrubberd:0.8.1
#    (air-gapped: transfer dist/scrubberd-0.8.0.tar and `podman load -i` on the target)

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
capabilities dropped, and `seccompProfile: RuntimeDefault`. Ships with `replicas: 1` and
`strategy: Recreate` (single writer, single queue; horizontal scale-out needs a distributed
object claim and is a documented follow-up).

**The `/work` volume.** It is an emptyDir serving as `TMPDIR`, and therefore where every
spilled payload, every expanded container and every repacked result lands. Its `sizeLimit`
is load-bearing twice over. It bounds the volume — an unbounded emptyDir can eat the node's
ephemeral storage and get the pod evicted — and it is also the **input to the sizing**: the
same 14Gi appears as the `sizeLimit`, as `limits.ephemeral-storage`, as
`requests.ephemeral-storage`, and as `SCRATCH_BYTES` in the ConfigMap, and `MAX_EXPAND_BYTES` is that number divided by 3.5.
The four are one volume described to four different readers — the kubelet enforces the
`sizeLimit`, evicts against `limits.ephemeral-storage`, the scheduler reserves
`requests.ephemeral-storage`, and the process is told `SCRATCH_BYTES` — so change them
together. Lower all four and a too-large bundle comes back flagged and
unscrubbed — visible, recoverable, and named in the report. Leave the volume undersized
instead and the kubelet evicts the pod mid-object, with no report at all.

### Metrics

The running build is reported three ways, so "which version is deployed?" can be
answered from wherever the question came up: `GET /api/version` returns
`{"version":"0.8.0"}`, the `scrubber_build_info` metric carries it as a label, and
the UI shows it as a chip in the header. All three read the same string, stamped at
build time with `-ldflags "-X main.version=..."` from the `VERSION` build-arg in
`deploy/Containerfile`. **Keep that arg equal to the image tag** — a version that
disagrees with the tag answers the question wrongly, which is worse than the
`dev` an unstamped build honestly reports.

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
| `scrubber_discovery_failures_total` | Failed listings of the input bucket. **Alert on this** — rising steadily while every per-object counter stays flat means no work is being discovered at all, and the service looks idle rather than broken |
| `scrubber_queue_wait_seconds` | Arrival → start of scrubbing |
| `scrubber_object_latency_seconds` | Arrival → finished; what a user actually waits |
| `scrubber_build_info{version}` | Always 1; the running build is in the label. Join it onto any other series to answer "did this change when 0.8.0 rolled out?", and query it to answer "which version is in this namespace?" without an `oc exec` |
| `scrubber_inflight_phase_seconds` | Seconds the in-flight object has spent in its current phase, 0 when idle. **The series that separates a slow object from a wedged one** — neither probe can, since `/healthz` answers 200 whatever the worker is doing and `/readyz` only says the backend is reachable |

`scrubber_process_seconds` starts counting only once an object reaches the front of the
queue, so it cannot show what someone behind a backlog experiences —
`scrubber_object_latency_seconds` is the number to watch for that.

The label sets are seeded at startup, so a fresh pod shows zeros rather than missing series
— "no incomplete runs" and "this metric does not exist yet" look identical otherwise.

The alerts worth having:

```
scrubber_object_verdict_total{verdict="incomplete-risky"}       > 0   → something skipped that contains matches
scrubber_files_not_inspected_total{reason="..."}                      → a reason you have not seen before
scrubber_files_not_inspected_total{reason="expansion-budget"}   > 0   → bundles too large to expand on this volume
scrubber_files_not_inspected_total{reason="leaf-cap"}           > 0   → single files too large to scrub in this pod's memory
scrubber_objects_total{status="too_large"}                            → real uploads being turned away
```

The two named reason codes point at different knobs, and reaching for the wrong one moves
nothing: `expansion-budget` says raise all four scratch declarations together; `leaf-cap` says raise `limits.memory`. Neither is an error
counter — both name files that were emitted **unscrubbed**.

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
`current_file`, `phase`, `phase_seconds`) rather than a client-side animation.

**The phases, and why `unpacking` is named separately:**

| Phase | What is happening | `files_done` |
| --- | --- | --- |
| `queued` | Waiting its turn. The bar deliberately does not move. | 0 |
| `reading` | Streaming the object out of MinIO onto scratch. | 0 |
| `unpacking` | Expanding the container. | 0 |
| `scrubbing` | Members going through the matcher. | counts up |
| `writing` | Output, report and digest being stored. | final |

`unpacking` exists because it is the one stage that can report no per-file progress at
all: a container is expanded in full before its first member reaches the matcher, so
`files_done` is pinned at 0 for however long that takes. On a 1.4 GiB zip it is about six
seconds; on a backend read that never returns it is unbounded.

The page used to paper over that gap by advancing the bar 2% per poll to 95%, which it
reached 42 seconds after upload and then held indefinitely. A bundle that finished in
four minutes and one wedged forever looked identical, and the number on screen was a
timer rather than a measurement. It now holds the bar and shows `phase_seconds`, which is
real — and `scrubber_inflight_phase_seconds` exposes the same signal to alerting.

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
- `POST /api/cancel` — withdraw a package, queued or mid-scrub. See below.

### Withdrawing a package

The queue is strict FCFS with a single consumer, so one object that cannot make
progress holds up everyone behind it. `POST /api/cancel` is the escape hatch, and
the **Withdraw** button on each upload card is its front end.

```
POST /api/cancel   Content-Type: application/json
{"key": "<input key>", "token": "<cancel_token from /api/uploads>"}
```

| Outcome | HTTP | Meaning |
| --- | --- | --- |
| `withdrawn` | 200 | It was not running. The input is disposed of; it will never be scrubbed. |
| `aborting` | 202 | It was mid-scrub and has been told to stop. The walk halts between archive members — seconds, not instant. |
| `too-late` | 409 | The scrubbed output was already written. **Nothing was withdrawn.** |
| `not-found` | 404 | No such object in the input bucket. |

**What "withdraw" does to the data.** Under `PROCESSED_ACTION=move` (the default)
the input is moved to `CANCELLED_PREFIX`, not deleted — the bundle is the user's
own copy of logs they were preparing to send out, and the usual reason to withdraw
is that it is stuck, not that it is unwanted. Under `PROCESSED_ACTION=delete` it is
deleted, because a deployment that asked for inputs to be destroyed did not ask for
an exception. A withdrawn object produces **no output, no report and no digest**.

**Why it must reach the object and not just the queue.** The in-memory queue is a
derived view: `Sync()` rebuilds it wholesale from a bucket listing on every poll, so
removing a key from memory withdraws nothing — the next listing puts it straight
back. The durable disposition is the cancel; the in-memory mark only covers the
seconds before it lands.

**Two security properties worth understanding before you enable this**, because the
browser API has no authentication of its own:

- A cancel must present the token `/api/uploads` issued for that exact key. It is
  not authentication — it proves nothing about who is asking — but it scopes the
  endpoint to keys the caller was actually handed, rather than to every key
  `/api/queue` and `/api/history` print. Without it, cancel is a two-line loop that
  durably evacuates the queue for every user.
- `ALLOW_CANCEL_ANY=true` removes that scoping. It is the operator path for
  clearing someone else's stuck object, and it should only be on behind real
  authentication.

An aborted walk never repacks. Members scrubbed before the abort and members not
yet reached would otherwise rebuild into a well-formed archive of mixed scrubbed
and raw content — so every container returns its **original input** once the abort
trips, `changed` collapses to false at every level, and there is nothing to ship.

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
./scripts/run-local.sh          # the service in Docker, sized like the pod
```

`run-local.sh` declares what the manifest declares — `MEM=4g`, `SCRATCH_BYTES=14Gi`, and
`POD_MEMORY_LIMIT` passed the way the Downward API passes it — and lets the service derive
the caps from them, so a local run exercises production's sizing instead of a set of
hardcoded numbers that quietly drift away from it. One caveat: Docker has no emptyDir
`sizeLimit` to enforce, so `SCRATCH_BYTES` there is a declaration only. A local run can
overrun the volume where the pod would be evicted.

---

## Nothing bounds the scrub itself

Worth stating plainly, because the timeouts have names that sound like they cover
it and they do not:

| Setting | What it bounds | Kills a slow scrub? |
| --- | --- | --- |
| `TRANSFER_STALL_TIMEOUT` | one object-storage transfer that has moved **no bytes** | no |
| `LIST_TIMEOUT` | one bucket listing | no |
| `API_STORAGE_BUDGET` | the storage time one HTTP request may spend | no |
| `STALL_WARN_AFTER` | nothing — it **only logs** | no |

All four bound **I/O**. None bounds **compute**. The walk takes no context, so a
bundle that is expanding and scrubbing runs to completion however long that takes;
`Engine.Abort` is the only thing that stops it, and the only thing wired to Abort is
an operator pressing **Withdraw**. That is deliberate — killing a scrub mid-flight
destroys work, and how long is too long depends on the bundle, which the process
does not know.

The consequence to plan for: **one slow object holds the queue.** The consumer is
single and strictly FCFS, so everything behind it waits. Withdraw is the escape
hatch, and `scrubber_inflight_phase_seconds` is the series to alert on.

Note also that a transfer trickling bytes slowly never trips the stall guard — the
guard fires on *no* movement, not on *slow* movement, because a large object over a
congested link legitimately takes minutes.

## Troubleshooting by symptom

Sizing problems are easier to reason about forwards than backwards, and an operator
usually arrives backwards — with a pod that died, not with a cap they chose. Start here.

**The pod restarted, and `oc describe pod` says `Evicted` with
`ephemeral-storage` (or the events show `Usage of EmptyDir volume "work" exceeds the
limit`).** The volume ran out mid-object. `/work` is smaller than the peak the expansion
cap implies, so the guard never got a chance to fire — the kubelet acted first. This is
the worst failure mode the service has, because nothing is written: no report, no reason
code, no metric. Worse, the object goes back to the input bucket unprocessed, so the
restarted pod picks up the same bundle and does it again — the same repeating loop the
leaf cap exists to prevent on the memory side.

Read the startup line: if `scratch_bytes` is larger than the volume actually granted, the
pod is planning for storage it does not have. Either raise all four declarations (see
[Sizing the pod](#sizing-the-pod)) or lower `MAX_EXPAND_BYTES` — the second is
immediate and safe, since an oversized bundle then comes back flagged rather than killing
the pod. Two ways to get here:

- `MAX_EXPAND_BYTES` pinned by hand above `SCRATCH_BYTES / 3.5`. Startup warns about
  this explicitly. Unset it and let it derive.
- The four declarations disagree — most often `requests.ephemeral-storage` left behind
  when the other three were raised, which schedules the pod onto a node with the old
  headroom.

**The pod was OOM-killed (`Reason: OOMKilled`, exit 137) partway through a bundle.**
A single file was too large to hold contiguously. Check
`scrubber_files_not_inspected_total{reason="leaf-cap"}`: if it is zero, the leaf cap is
disabled or set too high and this is the failure it exists to convert into a flagged
passthrough. `MAX_LEAF_BYTES=0` disables it entirely and makes `est_peak_rss_bytes` fall
back to the whole expansion budget, which no pod can hold — startup warns when the
estimate crosses 60% of `limits.memory`. Raise `limits.memory` or lower the cap.

**A bundle came back `incomplete` and nothing crashed.** This is the system working.
Read the reason code on the report, and note that the three size caps have different
blast radii — see [the blast-radius table](#the-compressed-object-ceiling). Nothing errored, so error counters
will not show it; alert on `scrubber_files_not_inspected_total` by reason.

**A bundle has been "Scrubbing… N files" for hours and the bar will not move.**
First, read the bar as decoration: it is a log curve over `files_done`, capped well
short of full, because the total file count is unknown until the walk ends and there
is no honest fraction to draw. Before v0.8.0 it reached its 95% ceiling at 78 files,
so any real bundle sat at "92%" for the whole run and looked wedged.

The real signals are on the same card: elapsed time, the file count, and the file
being scrubbed right now. If the count is advancing, it is slow, not stuck — and the
card says so. If it has not advanced, the card says **"no new file in …"**, which is
the reading that distinguishes the two.

A count that is genuinely stuck means one member is taking that long. Check
`scrubber_files_not_inspected_total{reason="leaf-cap"}`: before v0.8.0 nothing
bounded a single file, so one very large log could hold the queue indefinitely while
the matcher worked through it and the GC thrashed on three or four copies of it.
`MAX_LEAF_BYTES` is what turns that into a flagged passthrough. And note that no
timeout will end it — see [Nothing bounds the scrub itself](#nothing-bounds-the-scrub-itself).

**The caps are not what the manifest says.** Read `scratch_source` in the startup
`resource limits` line. `default (undeclared)` means neither `SCRATCH_BYTES` nor
`POD_EPHEMERAL_LIMIT` reached the process and it is sizing from the built-in 4Gi — check
the ConfigMap key spelling and the Downward API block. A `SCRATCH_BYTES` that was set but
unreadable is warned about by name at startup and then ignored; the value must be a plain
byte count or a Kubernetes quantity (`14Gi`, `512Mi`, `2G`).

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
  (nested streams and archive members draw from the same budget, and a nested container is
  charged once rather than once for itself and again for its members). Payloads above the
  spill threshold are held on disk under `TMPDIR`, so that budget bounds mostly scratch
  space; resident memory tracks the largest single member instead.
- A single file larger than `--max-leaf-bytes` is passed through and flagged
  `guard-tripped` / `leaf-cap`: the leaf scrubber needs its payload contiguous in memory,
  so one enormous member inside an otherwise ordinary bundle is the shape the spill does
  not help with. The rest of the archive is still scrubbed. The CLI leaves this off by
  default (`0`); the service derives it from `limits.memory`, because a pod that OOMs
  mid-object restarts, picks the same object up, and OOMs again.
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
