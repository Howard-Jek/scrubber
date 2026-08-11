# Fix records

What broke, why it broke, and what changed — newest first. Kept in this shape rather
than as a terse changelog because most entries here are the *same class* of bug (content
leaving the pipeline uninspected while the run reported clean), and the reasoning is the
part worth carrying forward.

For what to verify on your own cluster after taking a new image, see
[HANDOVER.md](HANDOVER.md).

---

## Unreleased

### The progress bar was a timer, and it hid a real stall

**The bug.** A user reported a 300 MB zip "stuck at unpacking 95% for over 1200
seconds". Both halves of what they were shown were invented.

There was no `unpacking` phase. The worker set `Phase = "scrubbing"` *before* the
engine started, so throughout the expansion it reported the one thing that was
certainly not happening. The word "Unpacking" came from the browser, inferred from
`files_done === 0`.

And the bar was a timer. Three branches handled progress; two had been fixed to
stop animating, and the third had not:

```js
} else {                          // files_done === 0
  creep=Math.min(95,creep+2);     // +2% every 1.2s poll, no server input
  st.textContent=isArch?'Unpacking…':'Scrubbing…';
}
```

Starting from 60 after upload, that reaches 95% in 42 seconds and holds there
forever. A bundle that finishes in four minutes and one wedged on a backend read
that never returns produce identical screens.

**Why the gap existed at all.** A container is expanded in full before its first
member reaches the matcher — `handleZip` calls `archive.ReadZip`, which
materialises every member — so nothing can increment `FilesDone` until that
completes. It is a genuine blind window, not an oversight in the reporting.

**Fixed.** `unpacking` is a real phase, set before the engine runs and flipped to
`scrubbing` by the first recorded leaf. `/api/status` carries `phase_seconds`
alongside it, and the page holds the bar and shows elapsed time in the phase
instead of creeping. Measured on a 1.37 GiB, 280-member zip at the shipped caps:
the whole silent window — MinIO read plus full expansion — is **6.55 seconds**,
1.5% of a 7m17s run. So the reported 1200 seconds was never unpacking.

**Also new: `scrubber_inflight_phase_seconds`.** Nothing outside the process could
distinguish slow from wedged. `/healthz` is a pure liveness signal that answers 200
whatever the worker is doing, and making it fail on a long scrub would kill
legitimate work. `/readyz` only reports that MinIO is reachable — and a stalled
read leaves it green. The new gauge is a `GaugeFunc` read at scrape time, not a
value the worker pushes, precisely because a stalled worker updates nothing: a
pushed gauge would freeze at its last value and look healthy. `STALL_WARN_AFTER`
(default 5m) logs the same condition for anyone reading pod logs rather than a
dashboard. Neither ever kills the pod; what counts as too long depends on the
bundles, which this process does not know.

### Caps now size themselves against the pod

**The problem.** Every cap was measured on a 2 GiB pod and compiled in as a
default, which made 2 GiB the only size the service was tuned for. On a 4 or 8 GiB
pod it left most of the memory idle and scrubbed no faster.

Worse, the obvious workaround was a trap. Raising `SPILL_RESIDENT_MAX` and
`SPILL_THRESHOLD` by hand to "use the new memory" stops members spilling, the live
set climbs past `GOMEMLIMIT`, and the GC burns the single CPU the pod has — the
exact pre-0.3.0 failure. Giving the pod more memory could make it slower.

**Fixed.** The measured values are now a ratio to the pod they were measured on,
and the ceiling is read from the cgroup (v2 `memory.max`, then v1
`memory.limit_in_bytes`) at startup:

| Pod memory | scale | `SPILL_THRESHOLD` | `SPILL_RESIDENT_MAX` | `GOMEMLIMIT` | `est_peak_rss` |
| --- | --- | --- | --- | --- | --- |
| 2 GiB | 1× | 4 MiB | 64 MiB | 1200 MiB | 513 MiB (25%) |
| 4 GiB | 2× | 8 MiB | 128 MiB | 2400 MiB | 703 MiB (17%) |
| 8 GiB | 4× | 16 MiB | 256 MiB | 4800 MiB | 1083 MiB (13%) |

At 2 GiB every derived value is byte-identical to what shipped, so every published
measurement stays valid. An explicit environment variable still overrides — and
still freezes that value at whatever the pod was when it was typed, which is why
the manifest now leaves them commented out rather than set.

Scratch is deliberately *not* auto-detected: an emptyDir's `sizeLimit` is enforced
by the kubelet, not the filesystem, so `statfs` inside the container reports the
node's whole disk and would license a budget that gets the pod evicted. Declare it
with the new `SCRATCH_BYTES`, which must equal the `/work` `sizeLimit`;
`MAX_EXPAND_BYTES` and `MAX_OBJECT_BYTES` derive from it.

**Measured.** The same 1.66 GiB-expanded zip, twice:

| Pod | Caps | Result |
| --- | --- | --- |
| 2 GiB | expand 1536Mi | refused — `expansion-budget` after 5.3s, passed through unscrubbed |
| 8 GiB + `SCRATCH_BYTES=12Gi` | expand 4.8Gi | **scrubbed**, `complete`, 39.2M matches, 8m38s, peak RSS ~890 MiB |

Only `limits.memory` and `SCRATCH_BYTES` changed between those two runs. Per-member
throughput was unchanged (0.64 vs 0.68 files/s): more memory buys capacity, not
speed, which is CPU-bound on a one-core pod.

**Known caveat.** Go derives `GOMAXPROCS` from the cgroup CPU limit only under
cgroup v2. On a cgroup v1 node the startup log's `pod_cpus` shows the node's core
count, not `limits.cpu`, and `GOMAXPROCS` should be set explicitly.

### `run-local.sh` was not executable on a fresh clone

**The bug.** `scripts/run-local.sh` and `scripts/gen-notices.sh` were committed as mode
`100644` while every sibling script in `scripts/` was `100755`. On Linux and macOS the
documented bring-up command died before Docker was ever invoked:

```
$ ./scripts/run-local.sh
Permission denied   (exit 126)
```

**Why it survived review.** NTFS does not carry the exec bit and Git Bash runs the file
regardless, so the omission is invisible on Windows — the repo worked perfectly for the
author and failed immediately for anyone who cloned it onto a Linux box or a Codespace.

**Fixed** in `64496ac` (`git update-index --chmod=+x`). Workaround on any older
checkout: `bash scripts/run-local.sh`.

### Known gap opened: base64

Base64-encoded content is not decoded, so secrets inside it pass through **and the run
still reports clean** — unlike every other hole, this one is not announced, because
base64 output is plain ASCII and is correctly classified as text that simply does not
match. Tracked in [#15](https://github.com/Howard-Jek/scrubber/issues/15); deferred, not
fixed.

### UTF-32 is scrubbed, not skipped

**What changed.** UTF-32 in either byte order, with or without a BOM, is now decoded,
scrubbed and written back in the same encoding — the same contract UTF-16 already had.
It used to be classified binary on the strength of its NULs (a UTF-32 `A` is
`41 00 00 00`), so an ordinary text log was emitted unscrubbed. The safety net did catch
it — those runs came back `incomplete-risky` and were diverted to `review/` — but
"flagged and quarantined" is not the same as "scrubbed", and UTF-32 is common enough
(`iconv -t UTF-32`, some Unix log tooling) to belong in the covered tier.

**Why it was not just a table entry.** UTF-32LE opens `FF FE 00 00`, which *is* a
UTF-16LE BOM, so the longer signature has to be tested first or the file decodes as
UTF-16 with a NUL between every character. The BOM-less case needs its own heuristic for
the same reason: ASCII in UTF-32LE puts a NUL in every odd byte, which is exactly what
the UTF-16LE sniffer looks for.

**The safety contract is unchanged and still enforced.** `Encode(Decode(x)) == x` byte
for byte, so a rewritten file differs from its input only where a match was replaced.
Malformed UTF-32 — a code point past U+10FFFF, a surrogate (which UTF-32 never encodes),
a length that is not a multiple of four — is refused rather than repaired, because
`WriteRune` would substitute U+FFFD and silently rewrite bytes no match touched. Those
files keep the old behaviour: passed through, named `encoding-unsupported`, and read by
the residual scan anyway.

**Verified:** `go test ./... -race` green; the conformance corpus gained four UTF-32 rows
(both byte orders × BOM) plus a malformed-UTF-32 row; `FuzzRoundTrip` ran 6.4M executions
against the byte-identical contract with no counterexample; and end to end against the
real service all ten well-formed Unicode shapes come back `complete` with 600 matches
each, BOM preserved, output still decoding in its original encoding.

---

## Image 0.5.0 — a coverage contract, so skipped files stop being a discovery

Three bugs in a row had the same shape — a file left the pipeline uninspected and the run
reported clean — so this change goes after the shape rather than another instance.

**The root cause was structural.** "Not scrubbed" was decided in four places that
disagreed: the summary buckets, the rollback switch, `HasUnscrubbed`, and the worker's
per-file log. A binary skip was a problem to the log and not a problem to
`--fail-on-unscrubbed`. Nothing forced a new failure mode to declare whether content had
been inspected, so its visibility depended on which bucket its author picked.

**Four things now hold:**

1. **One definition.** Every file gets a disposition — inspected, or not — from a single
   exhaustive function. Adding a status without classifying it is a compile error. Every
   hole carries a machine-readable reason code (`binary`, `unsupported-format`,
   `expansion-budget`, …), and `unclassified` is a tripwire the conformance corpus
   asserts never appears.
2. **Whatever is skipped gets looked inside anyway.** A new package pulls printable runs
   straight out of the raw bytes at every code-unit width Latin text uses — one byte,
   UTF-16's two, UTF-32's four, either byte order — and runs the policy over them. It
   never asks what the format is, which is exactly why it survives the classification
   being wrong. This is the check that would have caught `lux.txt` on day one.
3. **One verdict, and it routes the output.** `complete` / `incomplete` /
   `incomplete-risky`. A bundle whose skipped parts contain policy matches is written
   under `review/` instead of the normal output key, and the UI makes you tick a box
   before it will download one. Harmless skips deliberately do *not* divert — if every
   bundle with an image landed in the review queue nobody would read it.
4. **A conformance corpus.** 28 rows: every format × encoding × failure mode, each
   declaring its expected status, disposition and reason. Adding a format means adding
   rows. Verified to catch all three shipped bugs by reverting each fix and watching the
   table fail.

**One thing measured, then reconsidered.** A check that re-scanned every scrubbed file to
confirm the policy no longer matched it cost **~70% of the drain rate** on the 500 MiB
shape — 139s to 237s. The failure it catches (a policy whose replacement matches its own
rule) is a property of the *policy*, so it is now rejected when the policy loads instead,
for free and before any data is touched. The re-scan survives as `VERIFY_OUTPUT=true`, off
by default. At the defaults this whole change costs nothing measurable: 134s/127s against
a 136s/130s baseline, same 435 MiB peak.

**New config:** `REVIEW_PREFIX` (default `review/`, empty disables diverting),
`RESIDUAL_BUDGET` (default 64Mi, negative disables the scan), `VERIFY_OUTPUT` (default
false).

**New metrics — these are the ones to alert on:**

```
scrubber_object_verdict_total{verdict="incomplete-risky"}   > 0  → something skipped that contains matches
scrubber_files_not_inspected_total{reason="..."}                 → a reason you have not seen before is a new failure mode
scrubber_residual_hits_total
```

The label sets are seeded at startup, so a fresh pod shows zeros rather than missing
series — "no incomplete runs" and "this metric does not exist yet" look identical
otherwise.

---

## Image 0.4.0 — UTF-16 text was being skipped entirely

**The bug.** Two `.txt` files, same content, same policy: the UTF-8 one scrubbed, the
UTF-16 one came back untouched. The binary check called anything binary the moment it saw
a NUL byte, and UTF-16 is more than half NUL bytes — ASCII `A` is `41 00` — so every
UTF-16 file tripped it on byte two. That is also why the size looked wrong: UTF-16 spends
two bytes per character, so a 1.5M character log is 3 MB on disk. On Windows this is the
*default*: PowerShell's `>` and `Out-File`, and Notepad's "Save as Unicode", all write
UTF-16LE.

**And nothing told you.** A binary skip was counted separately from a passthrough, so
`--fail-on-unscrubbed` stayed quiet, the API had no field for it, and the UI drew a green
check over a bundle containing a log that was never inspected.

**Fixed.** UTF-16 in either byte order, with or without a BOM, is now decoded, scrubbed
and written back *in the same encoding* — the output stays usable by whatever reads it.
Malformed UTF-16 is refused rather than repaired, so a file we rewrite differs from its
input only where a match was replaced. Every skipped file is now named in the report, the
API, the run banner, the worker log and the UI.

Two smaller paths to the same symptom went with it: a text file starting `x `, `H,` or
`h$` was mistaken for a zlib stream (13 two-byte prefixes collide) and emitted unscrubbed
— it is now retried as text when inflation fails; and bzip2 detection now requires the
digit the format mandates after `BZh`, so a line starting "BZhang" is not sent to the
decompressor.

---

## Image 0.3.0 — queue + disk spill

Four parts, all on one branch.

1. **A FCFS queue.** Objects were all scrubbed at once, which turned five concurrent
   uploads into five slow uploads. The worker is now a producer (lists the bucket) and a
   single consumer (drains it), ordered by `(LastModified, Key)`. `WORKERS` is clamped to
   1 — a higher value is ignored with a warning. `/api/status` returns `queue_position`
   and `queue_depth`; `/api/queue` shows the in-flight key and the head of the pending
   list.
2. **Bounded report memory.** The run report retained every match. On a bundle with 3.8M
   of them that was ~440 MiB of the pod, on its own. Counts stay exact; only the itemised
   lists truncate, and truncation is flagged in the report.
3. **Caps set from measurement, not arithmetic.** `TestMemoryMatrix` ranks shapes by peak
   heap; `scripts/memory-matrix.sh` confirms the worst ones end to end against real MinIO
   and real RSS.
4. **Archive members spill to disk** (`internal/spill`). Only the member being scrubbed is
   on the heap. This is what makes ~500 MiB bundles processable at all — before it, the
   pipeline held the input, the decompressed container, every member body, every scrubbed
   body and the repacked archive at once, and no cap setting made that fit 2 GiB.

Shipped settings (`deploy/openshift-manifests.yaml`), all changed together:

| Setting | Was | Now |
| --- | --- | --- |
| `MAX_OBJECT_BYTES` | 64Mi | **640Mi** |
| `MAX_EXPAND_BYTES` | 160Mi | **1536Mi** (now bounds mostly *disk*) |
| `SPILL_THRESHOLD` | — | **4Mi** |
| `SPILL_RESIDENT_MAX` | — | **64Mi** (this is what bounds memory now) |
| `GOMEMLIMIT` | 900MiB | **1200MiB** |
| `/work` emptyDir | no limit | **`sizeLimit: 4Gi`** |
| `WORKERS` | 4 | **1** (clamped) |

Measured after the change, against real MinIO and the real service:

- `go build ./... && go vet ./... && go test ./... -race` — green.
- `scripts/memory-matrix.sh` at the shipped caps, two shapes in one process:

  | Shape | Result | Wall clock |
  | --- | --- | --- |
  | `.tar.gz`, 90000 members, 352 MiB content, 18.9M matches | scrubbed, 0 passthrough | 141s |
  | `.tar.gz`, 50 members, **500 MiB incompressible content** | scrubbed, 0 passthrough | 146s |

  **Peak RSS 445 MiB — 22% of the 2 GiB limit.** No temp files left behind.
- Serialisation proven from the logs: `[start,end]` intervals over 25 objects, **zero
  overlaps**, FCFS order exact in both a sequential upload and a 5-user interleaved one.
- Peak heap per shape fell from a worst case of 11.6× content to **3.6×**.

---

## Known and accepted

Recorded rather than fixed, so nothing here is a surprise later:

- **Base64 is not decoded**, and unlike every other gap it is not announced —
  [#15](https://github.com/Howard-Jek/scrubber/issues/15).
- **Strict FCFS has no per-tenant fairness.** One user uploading a large batch does hold
  up the users behind them. Round-robin needs a tenant identity and there is no app auth.
- **The queue is per-pod, so `replicas: 1` is a correctness requirement**, not a capacity
  choice — two pods polling one bucket would double-process. The Deployment uses
  `strategy: Recreate` for the same reason: the default RollingUpdate briefly runs two
  pods even at `replicas: 1`.
- **A single archive *member* larger than the memory budget is still bounded only by
  `MAX_EXPAND_BYTES`.** The leaf scrubber needs its payload contiguous in memory, so
  spilling does not help for one enormous member inside an otherwise ordinary bundle.
- **`/work` must have a `sizeLimit`.** It is load-bearing now that members spill there; an
  unbounded emptyDir can eat node ephemeral storage and get the pod evicted.
- **The image is single-arch (`linux/amd64`).** Building on Apple silicon for an x86
  cluster needs `--platform linux/amd64`, or the loaded image fails to start.
