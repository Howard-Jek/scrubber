# Fix records

What broke, why it broke, and what changed — newest first. Kept in this shape rather
than as a terse changelog because most entries here are the *same class* of bug (content
leaving the pipeline uninspected while the run reported clean), and the reasoning is the
part worth carrying forward.

For what to verify on your own cluster after taking a new image, see
[HANDOVER.md](HANDOVER.md).

---

## 0.8.3 — size the timeout from the CPU the pod is promised, not the one it may borrow

Prompted by a real deployment: `requests.cpu: 100m`, `limits.cpu: 4`,
`requests.memory: 256Mi`, `limits.memory: 8Gi`, and a reasonable expectation that the
service would read all four and work around them. It read two.

**CPU was detected and then ignored.** `podres.CPUs` was GOMAXPROCS, reported on the
startup line and used by nothing. Worse, GOMAXPROCS follows `limits.cpu` — the burst
ceiling — while what a scrub actually gets on a busy node is `requests.cpu`. For the
deployment above that is the difference between four cores and a tenth of one, a 40x
spread in how long a bundle takes, and the slow end is the end that trips the timeout
0.8.2 just introduced. `SCRUB_TIMEOUT`'s sizing check used a flat 1.75 MB/s and would
have stayed silent while every large bundle on that pod failed.

`requests.cpu` and `limits.cpu` now arrive through the Downward API and the check is
computed from the guarantee. On the deployment above:

```
cpu_request_milli=100  cpu_limit_milli=4000  expected_full_bundle_drain=1h53m46s
WARN  SCRUB_TIMEOUT is too short for the largest bundle this pod will accept at the
      CPU it is guaranteed ... needed_at_guaranteed_cpu=1h53m46s scrub_timeout=1h0m0s
```

Raising `requests.cpu` to `1` takes the same bundle to **11m22s** and silences it.
Raising it beyond `1` does nothing for a single object: the walk is single-threaded and
`WORKERS` is clamped to 1, so **`limits.cpu` above one core cannot make a bundle
finish sooner** — it only makes the pod steadier when the node is busy. That is now
stated on the startup line, in the manual and in the manifest, because "give it more
CPU" is the first thing anyone tries and most of it goes nowhere.

> **Units.** The Downward API renders cpu in the divisor's units, and the default
> divisor is whole cores **rounded up** — a container requesting `100m` is handed
> `"1"`. The manifest sets `divisor: "1m"`, which yields a bare `"100"`. The variables
> are therefore named `POD_CPU_REQUEST_MILLI` / `POD_CPU_LIMIT_MILLI`: a variable
> called `POD_CPU_REQUEST` holding `"100"` reads as a hundred cores, and parsing it
> that way is a 1000x error in the flattering direction. This was written the wrong
> way round first and caught by reading the derived numbers back.

**The memory side, measured rather than assumed.** `scripts/memory-matrix.sh` had
never actually been run — it needs Linux, a real MinIO and real disk. Run now against
`limits.memory: 8Gi` / 14Gi ephemeral, both worst-case shapes end to end:

| shape | | matches | time | peak RSS |
|---|---|---|---|---|
| tiny (90,000 members, 352 MiB) | scrubbed | 18,900,000 | 153s | 981 MiB |
| big (50 × 10 MiB incompressible) | scrubbed | 169,481 | 173s | 1060 MiB |

**1060 MiB peak against a 4915 MiB target, 7132 MiB headroom, zero temp files leaked.**
The `est_peak_rss_bytes` the service prints for that pod is 3.75 GiB — it errs high on
purpose, and it errs high by about 3.5x, which is worth knowing before sizing
`requests.memory` from it.

**`-race` run, finally.** Also never run: the dev box has no cgo toolchain. Clean
across every package on Linux, including the timer goroutine 0.8.2 added.

**Shell scripts were unrunnable from a Windows checkout.** No `.gitattributes`, so
every `.sh` got CRLF and `#!/usr/bin/env bash` failed with *"bash: No such file or
directory"* — which reads as a missing interpreter, not a line ending. That is why the
memory matrix had never run here. Added, covering `*.sh`, `Containerfile` and the
YAML.

---

## 0.8.2 — a scrub nothing could stop, and a progress bar that could never finish

Both found from one report: an object sitting at three hours, and a bar that had been
stuck at 92% for most of it. They looked like one bug. They were two, and neither was
the stall the timeout work in 0.8.1 was aimed at.

**Nothing bounded the scrub.** `STALL_WARN_AFTER` writes a log line and returns to its
ticker — it never touched the abort flag. `TRANSFER_STALL_TIMEOUT` and `LIST_TIMEOUT`
bound object-storage calls, not the work between them. The only thing that could stop
a walk was the manual cancel API. So an object ran until it finished, and with a
single-threaded matcher on a CPU-limited pod, a full-sized bundle legitimately takes
hours — measured at **8.4 MB/s** of expanded content on one unthrottled core and
**3.5 MB/s** throttled, against a 4 GiB expansion ceiling.

`SCRUB_TIMEOUT` (default **1h**) is now the one bound on the walk. It reuses the
existing abort seam, so it is enforced between archive members — the only place a walk
can stop without leaving a container half-rewritten — and a scrub overruns by at most
one member. It is deliberately *not* enforced during the final write: by then the work
is done and discarding it would cost more than the overrun. `0` restores the old
unbounded behaviour.

A timed-out object **fails**, and the input is moved aside rather than retried. That
looks harsh and is not: a bundle that needs longer than the budget needs longer on
every attempt, so retrying fails it again forever with the whole queue behind it.

**Every failure now says where it happened.** A timeout has no underlying error to
read, so anything the message does not say, nobody learns. It now reports the phase at
the instant the deadline passed (captured on the timer's goroutine from the job log,
not from the walk's own locals — the walk is still running), how many files of how many
were finished, the last one completed, how long it had gone without finishing one, that
nothing was published, where the input went, and which knob to turn. Ordinary failures
carry the same position, so `put output: connection reset` no longer leaves open
whether the bundle was half-scrubbed. Paths in that text go through the same redaction
as `current_file`, because failure text is served from the unauthenticated
`/api/status`.

**The progress bar could not reach the end, and nesting is why.** `files_total` counted
every archive *member*; `files_done` counts every report *entry*. A member that turns
out to be a container files no entry of its own — only its children do — so each nested
archive left the denominator permanently one above anything the numerator could reach.
Directory and symlink entries did the same to a flat archive. The bar is drawn as
`60 + (done/total) * 35`, so the shape in the report — 53-odd files across five nested
zips — lands on exactly **92%** and stays there however long the scrub runs:

| bundle | entries filed | old total | old ceiling |
|---|---|---|---|
| flat zip | 53 | 53 | 95% |
| one nested zip | 53 | 54 | 94% |
| five nested zips | 50 | 55 | **92%** |
| eight nested zips | 48 | 56 | 90% |

The count now announces only members that will actually file an entry, and a container
that is itself a member replaces itself in the total instead of adding to it. So the
92% was never a stall, and no timeout could have fixed it — which is why it survived
0.8.1.

**Half the Withdraw button was behind the policy panel.** Reported from use, and the
cause is one line of CSS the whole page had been getting away with. The card header is
a flex row, and a flex item does not shrink below its own content unless told to — so a
long object key, or a long status, pushed the row wider than the card. The card does not
clip, so the overflow rendered on top of the *Active policy* panel beside it: 39px past
the card edge, 23px of the button genuinely hidden, and at the exact moment someone
wanted to withdraw a bundle that looked stuck.

An audit for it (walk the DOM, flag anything rendering past a parent that does not clip)
found five more, all the same shape:

| where | over | when |
|---|---|---|
| Withdraw button | 39px desktop, 180px at 375px wide | long name or long status |
| status line | 92px | at 375px wide |
| header chips + theme button | 58px, **and the page scrolled sideways** | any phone |
| drop zone | 40px | at 320px wide |
| coverage paths, residual samples | — | any path without hyphens to break at |
| the timeout message itself | would have been ~600px | every timeout, once 0.8.2 shipped |

Three utilities (`.row`, `.ell`, `.brk`) now carry `min-width:0` where flex items must
shrink, an ellipsis where the shape of a name is what you read, and `overflow-wrap` where
you need the whole string. The status and Withdraw travel as one group that wraps to its
own line rather than squeezing each other out, and the filename keeps a 10ch floor —
a name shrunk to nothing identifies nothing.

Two consequences worth calling out. A failure no longer goes on the status line: it gets
a block that wraps, because the timeout added above explains itself in a paragraph and
that paragraph on a nowrap flex line is what would have pushed the row off the card
again. And the stall hint moved off the status line too — appended there it was the first
thing an ellipsis ate on a narrow card, and *"no new file in 12m"* is the one reading
that separates slow from stuck.

Verified at 320, 360, 375, 390, 480, 600, 768, 900, 1024, 1280 and 1440px, in both
themes, with every surface open at once — two cards (one mid-scrub with a long name, a
long status and a stall warning, one finished with its stats panel expanded), the policy
editor, and ten history rows: **zero elements rendering outside their parent, zero
horizontal page scroll.**

**Nesting itself is not slow.** Worth stating, because it was the obvious suspect. The
same 480 MiB of content took 59.5s flat, 56.1s as a zip in a zip, and 59.8s at three
levels — within noise, and unchanged when every payload is forced onto disk. The cost
is throughput, not depth. If a bundle must go faster, that is CPU: `limits.cpu: "1"`
on a single-threaded matcher means one object never exceeds one core, and
`requests.cpu: 500m` makes it the first thing throttled under pressure.

---

## 0.8.1 — a stall warning that fired on healthy runs, and no way to see what was happening

Found by running a real 4 GB bundle end to end rather than by reading code.

**The false stall.** A 19-minute, 60-file scrub logged *"it may be stalled"* three
times while `files_done` climbed 25 → 40 → 55. `PhaseSince` is stamped once when
scrubbing begins and never updated, so the check measured time-in-**phase**, not
time-since-**progress** — meaning every scrub longer than `STALL_WARN_AFTER` fired it.
A warning that goes off on correct behaviour is worse than no warning: it trains the
reader to ignore the real one. `ProgressSince` now stamps on each finished file and
each phase change, `ProgressSeconds` is what the check reads, and `progress_seconds`
is exposed on the status API. Re-running the identical bundle with a *stricter* 2m
threshold produced **zero** warnings.

**No visibility into which member was being worked on.** The server had always
reported `current_file`; the page put it in a `title` attribute, so the one detail
that says where a long run is sitting was invisible unless you hovered. It is now a
line on the card, and the count reads **"file 7 of 10"** against a real member total
(`Report.NoteMembers`, announced as each container opens) with a bar drawn in
proportion instead of a log curve that pinned near full at 78 files.

**A count that disagreed with itself.** A scrubbed *filename* files its own report
entry — correct for the audit record, wrong for a tally someone is watching. A
10-member archive with two renamed members reported "file 10 of 10" live and "12
files" in its history. The file tally now skips those entries in both directions
(record and rollback); their matches still count and the rename is still recorded.

**A disclosure the transparency work would have made worse.** Member paths are
recorded unscrubbed, which is right for a report in an internal bucket. `/api/status`
is neither internal nor authenticated, and `SCRUB_FILENAMES` exists precisely because
a path carries the same class of data as a body — verified: a member named
`logs/AcmeCorp-prod/alice@acme.test-session.log` is renamed in the emitted bundle and
was still reported verbatim. Displaying that live would have had the tool broadcast
exactly what it was asked to remove. The same matcher now rewrites paths on the way
to the API, so what the UI shows is what the recipient of the bundle would see. This
also covers `passthrough_paths`, `binary_skip_paths` and `not_inspected_set`.

**Durations** are `h/m/s` throughout; a finished run reported `12043.6s` before.

**A version indicator**, since nothing reported which build was running: stamped from
the `VERSION` build-arg and surfaced at `GET /api/version`, in `scrubber_build_info`,
in the first startup log line, and as a chip in the UI header.

Measured on the 4 GB tar (60 members × 66.6 MB, 1 CPU, 4 GiB): upload 125 MB/s, scrub
**3.5 MB/s** and CPU-bound, memory flat at 322–896 MiB, `/work` peaking at 7.6 GB,
88,133,040 matches, verdict `complete`.

---

## Image 0.8.0 — the expansion cap follows the volume, and a bundle costs its content once

0.6.0 sized the memory knobs from the pod and left the one cap operators actually
want to change — how large a bundle may expand — compiled in at 1536Mi with an
environment variable bolted on. Raising it turned out to be unsafe for two reasons
that had nothing to do with the number: a `.tar.gz` drew on the budget twice, so
half of it was never usable, and nothing at all bounded what a single large file
costs in memory. All three move together here, because raising the budget without
the other two converts a clean guard trip into an OOM crash-loop.

### The expansion cap is derived from the declared volume, not compiled in

**What changed.** `maxExpandDefault` — a flat 1536Mi unless `SCRATCH_BYTES` said
otherwise — is gone. The caps are derived at startup from what the deployment
declares:

```
MAX_EXPAND_BYTES = SCRATCH_BYTES / 3.5
MAX_OBJECT_BYTES = 41.7% of MAX_EXPAND_BYTES
MAX_LEAF_BYTES   = 96Mi x (limits.memory / 2Gi)
```

Raise the declaration in `deployment.yaml` and the cap follows on the next rollout.
An undeclared scratch ceiling no longer falls back to a constant *cap*; it falls
back to a constant *scratch* of 4Gi and derives from that, so there is exactly one
derivation path and a manifest that declares nothing still produces caps that hang
together.

**Two ceilings, two resources, and they are not interchangeable.**

- How large a bundle may **expand** is bounded by ephemeral storage (`/work`).
- How large one **file** may be scrubbed is bounded by `limits.memory`.

`limits.memory` does not affect how large a bundle can expand. An expansion cap
sized from `limits.memory` gets the pod evicted for ephemeral-storage; a per-file
cap sized from the volume OOM-kills it. This is the sentence to keep: memory buys
files, the volume buys bundles.

**What the shipped manifest declares.** These are the inputs; every cap below is
arithmetic on them.

```
SCRATCH_BYTES:                       "14Gi"          # quantities are accepted now
/work emptyDir sizeLimit:            14Gi
resources.limits.ephemeral-storage:  14Gi            # requests too
resources.limits.memory:             4Gi             # was 2Gi; requests 512Mi
```

`limits.cpu` stays at `1` with `requests.cpu` 500m, and the image is
`scrubberd:0.8.0`. 14Gi is not a typo: a `.tar.gz` expanding to 4 GiB holds the
decompressed tar, the member bodies and the repacked result on `/work` at once.

**What that derives**, exactly — these are asserted against the manifest file itself
by `TestShippedManifestDerivesItsDocumentedCaps`, not typed here by hand:

| Derived | Value |
| --- | --- |
| `MAX_EXPAND_BYTES` | **4294967296** — 4.00 GiB exactly |
| `MAX_OBJECT_BYTES` | 1789569706 — 1707 MiB |
| `MAX_LEAF_BYTES` | 201326592 — 192 MiB |
| `SPILL_THRESHOLD` | 8388608 — 8 MiB |
| `SPILL_RESIDENT_MAX` | 134217728 — 128 MiB |
| `GOMEMLIMIT` | 2516582400 — 2400 MiB |

Estimated peak RSS is ~2083 MiB against the 60% gate of 2458 MiB, and peak scratch
works out at 14.00 Gi against the 14 Gi declared. Both are inside their gates, so a
pod on this manifest starts with no sizing warning — which is the point of printing
them.

**Rule of thumb for sizing your own: `/work` is 3.5x the content you need expanded.**

| `/work` (= `SCRATCH_BYTES` = both `ephemeral-storage` values) | Content it admits |
| --- | --- |
| 4Gi | 1.14 GiB |
| 10Gi | 2.86 GiB |
| 14Gi | **4.00 GiB** (shipped) |
| 20Gi | 5.71 GiB |

**The pod reads its own resources block.** The Deployment projects it with the
Downward API: `POD_MEMORY_LIMIT` from `resourceFieldRef: limits.memory` and
`POD_EPHEMERAL_LIMIT` from `limits.ephemeral-storage`, both with `divisor: "1"`
(bytes) and `containerName: scrubberd`, which is required. Precedence is explicit in
both directions:

```
memory:   POD_MEMORY_LIMIT -> cgroup v2 memory.max -> cgroup v1 -> not detected
scratch:  SCRATCH_BYTES    -> POD_EPHEMERAL_LIMIT  -> not declared (4Gi default)
```

**A trap worth knowing before you copy that env block.** If a container declares no
`limits.ephemeral-storage`, Kubernetes does not fail the reference — it resolves it
to the **node's** allocatable storage, a number far larger than the pod's share,
which would derive an expansion cap that gets the pod evicted mid-object. The
shipped manifest declares the limit explicitly, and `SCRATCH_BYTES` overrides the
projected value anyway. Do not wire one without the other.

Scratch still has no measured fallback, for the reason 0.6.0 gave and which has not
changed: an emptyDir's `sizeLimit` is enforced by the kubelet, not the filesystem,
so `statfs` inside the container reports the node's whole disk.

**This is a breaking deployment change.** A 0.7.0 manifest applied to 0.8.0 keeps
working — nothing crashes, nothing is refused at startup — but it declares
`SCRATCH_BYTES=4Gi` and no Downward API, so it sizes from 4Gi and derives an
expansion cap of **1.14 GiB**. That number is lower than the 1638Mi the same
manifest got from 0.7.0, while the `.tar.gz` content it actually admits is higher,
so a straight before/after comparison of the cap tells you nothing useful. To get
the new caps, four things change together:

1. `SCRATCH_BYTES` in the ConfigMap,
2. the `/work` emptyDir `sizeLimit`,
3. `resources.limits.ephemeral-storage` (and `requests`),
4. the `POD_MEMORY_LIMIT` / `POD_EPHEMERAL_LIMIT` env block on the container.

The first four are the same volume and must carry the same number — the `sizeLimit` is
what the kubelet enforces, `limits.ephemeral-storage` is what it evicts against,
`requests.ephemeral-storage` is what the scheduler reserves on the node, and
`SCRATCH_BYTES` is what the process is told.
`TestManifestDeclaresScratchConsistently` fails if they drift.

**Read `scratch_source` first when the caps are not what you expected.** The startup
"resource limits" line gained `max_leaf_bytes`, `scratch_declared_bytes` and
`scratch_source`. A `scratch_source` of `default (undeclared)` means the manifest
never told the pod how much `/work` it has, which is the usual reason a cap comes
out a third of what someone expected. A new warning fires when `MAX_EXPAND_BYTES` is
pinned well *below* what the declared scratch would allow — bundles refused on a
volume with room for them — and the existing scratch warning now names
`scratch_source` and `max_expand_bytes`, so the line says which input to go and
change.

### A `.tar.gz` drew on the expansion budget twice

**The bug.** Expanding a `.tar.gz` charged the budget for the decompressed tar, then
charged it again for the member bodies read out of that tar. The same bytes were
counted twice, so a 4 GiB setting admitted only about 2 GiB of content and the guard
tripped on bundles that fit the volume with room to spare. And an expansion trip
does not turn an upload away: the bundle is emitted **unscrubbed** and flagged, so
the cost of the double-draw was content leaving the pipeline uninspected, not a
rejection anyone had to argue with. (Only `MAX_OBJECT_BYTES` refuses an object
outright.)

**Fixed** in `internal/pipeline/pipeline.go`, which gained `descend()`: it lends the
container's own charge back to the budget before walking into it, and settles up
afterwards. **The lend has to happen before the walk, not as a refund after it** —
what remains of the budget is passed down as the *read ceiling* (`ReadTar`,
`ReadZip` and `DecompressBlob` all take `e.budget`), so a credit paid at the end
arrives after the reads it was meant to license have already been capped.

**Measured** in `internal/pipeline/budget_test.go` — the smallest budget that admits
a 57,000-byte body in a 58,880-byte tar:

| Shape | Before | After |
| --- | --- | --- |
| `.tar.gz` | 115,880 — **2.03x** content | 58,880 — **1.03x** content |
| `.tar`, `.zip` | 57,000 — 1.00x | 57,000 — unchanged |

The residual 3% is the tar's own size: block padding, not a second copy of anything.
Plain containers never had a double-draw and are byte-for-byte unaffected.

**The refund cannot be used to beat the guard.** Settling re-charges the difference
when a container's contents cost *less* than the container did, so an archive of
large, near-empty inner containers still trips the guard instead of expanding
forever on credit it never spent. Pinned by `TestRefundCannotBeUsedToBeatTheGuard`.

### One large text file could still take the pod down: `MAX_LEAF_BYTES`

**Why this had to arrive in the same release as the derived cap.** The matcher needs
its payload contiguous as a string. `spill.Blob.Bytes()` does an `os.ReadFile` on a
spilled leaf — reading the whole thing back in, *outside* the resident reservation
`SPILL_RESIDENT_MAX` enforces — and then `textenc.Decode`, `Matcher.Scrub` and
`textenc.Encode` each hold their own copy. One text file therefore costs 3-4x its
size in heap no matter how low the `SPILL_*` pair is set. Spilling decides *where* a
member lives; it never bounded how large the one being scrubbed may be.

That was survivable only by accident: the old expansion budget was small enough to
bound the largest possible member for us. Once the budget follows the volume it no
longer does, and the failure is the worst shape available — an OOM in the middle of
an object, so the pod dies, restarts, takes the same object off the queue and dies
again.

**What the cap does.** A file above `MAX_LEAF_BYTES` is passed through unchanged and
recorded as `guard-tripped` with the reason code `leaf-cap`. **The rest of the
archive is still scrubbed** — unlike an expansion-budget trip inside a container,
which discards every member of that container. `0` disables the check, and the CLI
defaults it to `0` and gained `--max-leaf-bytes`: a workstation has the memory for
one large log and no kubelet to answer to.

**The startup estimate had been wrong in the same direction.** `est_peak_rss_bytes`
computed its leaf term as `leafCopies * SPILL_THRESHOLD`, which quietly assumed the
spill threshold bounds the largest payload the matcher holds. It does not, so the
estimate was short by the difference between 4Mi and the biggest file in the bundle,
and that gap is exactly what OOM-kills a pod whose own startup log called it
comfortable. The term is now `leafCopies * MAX_LEAF_BYTES`.

### `scratchFactor` went 2.5 → 3.5, and it had to move with the refund

The divisor that turns declared scratch into the expansion budget was 2.5 and is now
3.5. **That is not a separate tuning change; it is the other half of the double-draw
fix.**

For a `.tar.gz` whose content expands to N, three copies are live on `/work` at
once: the decompressed tar, the member bodies read out of it, and the repacked
result, on top of the compressed object C staged for the download. Peak disk is C +
3N, and C is at most `shippedObjectShare` of N, so 3.42 covers it; 3.5 is that
rounded up.

2.5 was only ever safe *because* the budget double-counted: 2.5 x 2N already
exceeded C + 3N. Now that `descend` counts N once, the factor has to carry the whole
multiple itself. Leaving it at 2.5 alongside the refund would license 2.5N of disk
for a shape that needs 3.42N, and the pod would be evicted for ephemeral-storage
mid-object — which produces no report at all, unlike a cap that refuses cleanly and
says so. `TestScratchFactorCoversPeakDisk` asserts the round trip, and the startup
check makes the same statement about the shipped manifest: 14.00 Gi of peak scratch
against 14 Gi declared.

### At the top of the int64 range, a full stream was reported as empty

**The bug**, and it is this document's recurring shape in its purest form. The read
guards evaluate `budget+1` to tell "exactly at the limit" from "over it". With the
budget near `MaxInt64` that addition wraps negative; `io.CopyN` copies nothing for a
negative count; and the guard therefore reports a **full stream as empty**. The
payload is dropped, the object ships unscrubbed, and the report certifies it
`complete`.

**Reproduced end to end** at `MaxTotalBytes=MaxInt64` with `SPILL_THRESHOLD=0`:
1,500 secrets in, **0 matches**, verdict `complete`, output byte-identical to input.
Nothing in the run indicated a fault, because from the guard's point of view there
wasn't one.

**Fixed in three places**: `archive.plusOne()`, the saturating room calculation in
`spill.FromReader`, and a `maxExpandCeiling` of `1<<50` in `cmd/scrubberd` that
clamps an absurd expansion cap and warns rather than accepting it. The clamp earns
its place now in a way it would not have before: the caps are computed from
operator-supplied numbers, so a fat-fingered `SCRATCH_BYTES` reaches this arithmetic
directly.

### The scripts now exercise the derivation instead of bypassing it

`scripts/run-local.sh` hardcoded `MAX_EXPAND_BYTES`, `MAX_OBJECT_BYTES`, the
`SPILL_*` pair and `GOMEMLIMIT`, which made the one command people run to "check it
like production" the one command that bypassed production's sizing — and it had
drifted: it still said 1536Mi long after the manifest's `SCRATCH_BYTES` derived
1638Mi. It now declares inputs only — `MEM=4g`, `SCRATCH_BYTES=14Gi`, and
`POD_MEMORY_LIMIT` passed explicitly so the local run takes the same code path as
the pod — and lets the service derive the outputs. Any of them can still be exported
to override, exactly as in the ConfigMap.

`scripts/memory-matrix.sh` had the same problem somewhere it mattered more: the gate
that is supposed to validate the shipped sizing was passing every cap in explicitly,
so it validated numbers a human had typed rather than the numbers the service
computes. `LIMIT_MIB` is now 4096 with a new `SCRATCH_MIB=14336`, and `EXPAND_MIB`,
`OBJECT_MIB`, `LEAF_MIB`, `GOMEMLIMIT_MIB` and both `SPILL_*_MIB` default to
**empty** and are passed only when explicitly set. `SCRATCH_MIB=4096 LIMIT_MIB=2048`
reproduces the old 2 GiB pod.

### New tests, and a manifest that can no longer drift from the code

`cmd/scrubberd` had no tests at all. It now has `TestDeriveCaps*` over the
derivation itself — that it follows declared scratch, that it is linear in it, that
scratch is not memory, that the object cap stays under the expansion cap, that it
does not overflow — plus three that parse `deploy/openshift-manifests.yaml` and
assert what the shipped file actually produces:
`TestShippedManifestDerivesItsDocumentedCaps` (4 GiB, exactly),
`TestManifestDeclaresScratchConsistently` and `TestManifestWiresTheDownwardAPI`.
Every cap this record has ever published was, until now, a claim about a file
nothing checked.

`internal/pipeline/budget_test.go` covers the double-draw, the refund's safety cap
and the leaf cap. `internal/podres/podres_test.go` covers the Downward API
precedence chains above and the unusable declared values that have to be ignored
rather than believed.

### What 0.7.0 was actually running, which was not what the docs said

Worth knowing before anyone compares before-and-after numbers. The docs — this
record included — described the shipped caps as **1536Mi / 640Mi**. They were not.
Those were the compiled-in defaults, and they applied only when `SCRATCH_BYTES` was
undeclared; the shipped manifest declared it at 4Gi, from which the 0.6.0 derivation
produced **1,717,986,918 (1638Mi)** and **715,827,882 (682.7Mi)**. Every published
measurement labelled "at the shipped caps" was taken at a configuration the shipped
manifest did not produce.

Nothing below is being rewritten — the entries record what was measured and believed
at the time. But two of them state a cap as a *current* fact, and both are
superseded here:

- **0.6.0, "Caps now size themselves against the pod".** Its closing paragraph —
  declare `SCRATCH_BYTES` equal to the `/work` `sizeLimit`, and `MAX_EXPAND_BYTES`
  and `MAX_OBJECT_BYTES` derive from it — still holds in shape, but the divisor is
  now 3.5, `MAX_LEAF_BYTES` derives alongside them from `limits.memory`, an
  undeclared ceiling falls back to 4Gi of scratch rather than a flat cap, and
  `SCRATCH_BYTES` is no longer the only way to declare it: `POD_EPHEMERAL_LIMIT` is
  read when it is absent. That section's `est_peak_rss` column also predates the
  leaf term — at 4 GiB the estimate is now ~2083 MiB rather than 703 MiB, because it
  stopped assuming the spill threshold bounds the largest payload the matcher holds.
- **0.3.0, the shipped-settings table.** `MAX_OBJECT_BYTES 640Mi`, `MAX_EXPAND_BYTES
  1536Mi` and `/work sizeLimit: 4Gi` were that release's shipped numbers. None of
  the three is a setting any more: two are derived, and the third is 14Gi.

---

## Image 0.7.0 — an escape hatch from the queue, and a failure that used to be invisible

### A failing discovery loop had no metric

A listing failure logged one ERROR line and returned. Nothing else moved: not
`scrubber_errors_total` (which is per-object, and on this path no object was ever
seen), not the queue gauges, nothing. So a service with a misconfigured bucket name
sat accepting uploads it would never scrub, with every per-object metric flat and
the whole thing looking idle rather than broken — and no series existed to alert on.

Found the honest way: a leftover test container had been logging
`list input bucket: Bucket name cannot be shorter than 3 characters` every 15
seconds for a day, and nothing anywhere would have escalated it.

`scrubber_discovery_failures_total` now counts them. **Alert on it** — a steadily
rising value with flat object counters means no work is being discovered at all.

The log is also no longer a flood. At the default 15s interval an unrecoverable
listing failure produced 5,760 identical lines a day, which is how a real fault
comes to look like background noise. The first failure is logged in full; repeats
are throttled to one every two minutes and carry the consecutive-failure count and
how long it has been failing. Recovery is logged too, so the log records the fix
rather than just going quiet.

On a cluster the readiness probe does catch this specific case — `Healthy()` checks
the input bucket, so the pod would sit `0/1 Ready`. But a NotReady pod is a thing
someone has to notice, and under plain Docker there are no probes at all.

### A stuck package no longer holds the queue: packages can be withdrawn

The queue is strict FCFS with a single consumer and, until now, no way out of it.
One object that could not make progress held up everyone behind it, and the only
remedy was `oc exec` and `mc mv`.

`POST /api/cancel`, surfaced as a **Withdraw** button on each upload card, handles
both a queued object and one already mid-scrub.

**Cancel has to reach the object, not the queue.** `Queue.Sync()` rebuilds the
pending set wholesale from a bucket listing on every poll, so removing a key from
memory withdraws nothing — the next listing puts it straight back. The durable
disposition *is* the cancel: the input moves to `CANCELLED_PREFIX` (or is deleted
under `PROCESSED_ACTION=delete`, honouring the deployment's retention policy). The
in-memory mark only covers the seconds before that lands.

**The walk had no way to be interrupted.** Nothing on the pipeline path takes a
`context` — not `ProcessBlob`, `handleZip`, `handleTar`, `handleCompressed` or
`handleLeaf` — so cancelling a context reaches only the object-storage calls that
bracket the walk, and the multi-minute middle runs to completion regardless. The
engine now polls an abort predicate between members. It is deliberately *not* wired
to a context: shutdown cancels that context, and a predicate shutdown can trip
would turn every SIGTERM into a silently discarded scrub.

**An aborted walk must not repack, and this is the part worth reading twice.** The
obvious implementation — each blob returns "unchanged" once the abort trips — is
actively dangerous inside a container: members before the abort have been rewritten
and members after it have not, so `changed` is still true, the container repacks,
and a well-formed archive of a few scrubbed members and many **raw** ones goes to
the output bucket under the ordinary key with a report that makes it look like a
normal run. That is the worst outcome this service can produce. So an aborted
container returns its **original input**, at every level, and `changed` collapses to
false all the way up — even a bug in the worker's own check would then write the
untouched input rather than a mixed bundle. Pinned by `TestAbortedWalkNeverRepacks`.

**The commit is one atomic transition.** `commit(key)` answers "was this cancelled?"
and closes the door to further cancels in a single critical section. Split in two, a
cancel landing in the gap is answered "aborting" while the object it named is
already being published — and the shutdown-detach branch would then finish it
anyway. After `commit` returns true a concurrent cancel is truthfully told
`too-late` (409), never 200.

**Security, stated plainly.** The browser API has no authentication. `/api/queue`
returns up to 50 live pending keys and `/api/history` returns every recent input
key, so an unscoped cancel endpoint is a two-line loop that durably evacuates the
queue for every user, with no way back short of moving objects by hand. Therefore:

- `/api/uploads` now issues a `cancel_token` — an HMAC over the key with a
  per-process secret — and `/api/cancel` requires it. Not authentication, but it
  reduces the blast radius from "every key the API prints" to "keys this browser
  uploaded", with no identity plumbing the service does not have.
- `ALLOW_CANCEL_ANY` (default **false**) drops that requirement. It exists because
  clearing someone else's stuck object is the operator's actual need. It should
  only be enabled behind real authentication.
- `Content-Type: application/json` is required, so a cross-origin form POST cannot
  fire the endpoint; keys containing `/` are rejected, so a caller cannot name an
  object under `processed/`, `review/` or `cancelled/`.

Verified end to end against a real service: an in-flight scrub of a 1.37 GiB zip
aborted **2.2s** after the request, wrote no output, left its input intact at
`cancelled/second.zip`, drained `/work` to zero and freed the queue; a queued object
was withdrawn to `cancelled/` and never ran. The token gate returns 403 without a
token, and a form content type returns 415.

### A stalled transfer is retryable, not a failure

A stall set `job.Status = "error"`, which the upload page treats as terminal: it
stopped polling and went red. But the object stays in the input bucket and *is*
retried, so a transient backend blip showed as a permanent failure for work that
completed a minute later, with nothing to tell the user it had. It is now
`retrying`, carrying `retry_in_seconds`, and the page keeps polling.

### A stalled object no longer retakes the head of the queue

Backoff was only applied to failed *finalizes*. A stalled object got none, and
because ordering is by `LastModified` — by definition the oldest in the bucket — it
returned to the **head** every cycle, so everything behind it paid the stall timeout
again on every round. One unreadable object could throttle everybody. The existing
backoff now covers both paths (`deferRetry`, renamed from `noteFinalizeFailed`).

### Listings get their own timeout

`LIST_TIMEOUT` (default 90s), separate from `TRANSFER_STALL_TIMEOUT`. It was derived
as 10× the stall timeout, which put it at **ten minutes** by default — long enough
that a dead backend looked idle rather than broken. A listing's honest duration
scales with the bucket, not the network, so it deserves its own number.

---

## Image 0.6.0 — nothing waits forever, and the caps follow the pod

Everything below came out of one report: a 300 MB zip "stuck at unpacking 95% for
over 1200 seconds". Chasing it turned up a display that could not distinguish slow
from wedged, a service tuned for exactly one pod size, and — underneath both — a
set of object-storage calls with no upper bound at all.

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

### Object-storage transfers could wait forever

**The bug.** Every MinIO call ran on the worker's long-lived context with no bound
of its own. A connection that was established and then went quiet — a dropped path
with no RST, a backend that stops writing mid-body, a load balancer blackholing an
established flow — blocked the single consumer indefinitely.

Nothing upstream noticed. `/healthz` is a pure liveness signal, `/readyz` reports a
*new* connection succeeding, and every per-file counter is pinned at 0 because no
file has been read yet. One such object wedged the whole queue behind it while the
pod stayed live and ready. This is the shape a "stuck at unpacking" report takes
when it is not actually unpacking.

**Fixed** with a stall guard rather than a deadline. A deadline is the wrong tool:
a large object over a congested link legitimately takes minutes, and any deadline
generous enough to allow that is too generous to catch a hang worth catching. What
separates slow from stalled is not elapsed time but whether *anything* is still
arriving, so that is what is measured — `TRANSFER_STALL_TIMEOUT` (default 60s) of
complete inactivity abandons the transfer.

The guard's timer starts on construction rather than on the first byte, so a
request that never produces a response header is caught by the same mechanism as
one that dies halfway through the body.

Applied to every path, not just the download that was reported:

- **Reads** (`Get`, `GetLimited`, `GetLimitedTo`) watch bytes written out.
- **Writes** (`Put`, `PutStream`) watch bytes read in — on an upload the payload is
  already in hand, so the observable signal is the client no longer draining it.
  This one matters more than it looks: it hangs *after* the object is scrubbed, so
  the work is done, uncommitted, and the queue is blocked behind it.
- **Metadata calls** (stat, copy, delete, bucket checks) get a flat deadline, since
  they move no payload and have no progress to watch. Listings get 10× that, as
  they paginate and the input bucket includes `processed/`.

A stall is reported as its own thing, not a generic error: `store.ErrStalled`, the
metric label `scrubber_objects_total{status="stalled"}`, and a log line saying the
object stays in the input bucket and is retried on a later poll. Distinguishing it
from an ordinary cancellation matters — both surface as `context.Canceled` from the
copy, and reporting a shutdown as a backend stall, or the reverse, sends whoever
reads the log to the wrong system.

**Verified against a frozen backend** — `docker pause` on MinIO, which holds the
connection open and simply stops moving bytes, which is the exact failure the guard
is for. MinIO was frozen mid-scrub so the write landed on a dead backend, with
`TRANSFER_STALL_TIMEOUT=10s`:

```
"msg":"object storage transfer stalled and was abandoned; the object stays in the
       input bucket and is retried on a later poll"
"err":"put output: transfer stalled after 1310720 bytes: nothing moved for the
       stall timeout: Put \"http://.../scrub-output/med.zip\": context canceled"
scrubber_objects_total{status="stalled"} 1
```

It fired 10s after the scrub completed and the write went nowhere, naming how far
the upload had got. The input listing separately failed with `context deadline
exceeded` at exactly 100s (10s × the listing factor). Before this change both would
have waited forever.

**The pod stayed `Up` and `/healthz` answered `ok` for the entire run.** That is the
whole reason this needed its own metric: nothing about the pod's own health ever
indicated a fault, and it never would have.

### The browser API now has a latency budget, not just per-call bounds

Bounding each storage call stops any one of them hanging forever but says nothing
about their sum. A status poll makes up to three in series; a history page fans out
to `HISTORY_MAX` digest reads eight at a time. With the backend down those answered
in multiples of the per-call timeout — measured at 45s for one status poll with a
15s setting, so ~180s at the 60s default, and roughly 13× that for a history page.
For a request a browser repeats every second, a slow true answer is worse than a
fast honest one.

`API_STORAGE_BUDGET` (default 5s) is now a single deadline shared by every storage
call one HTTP request makes, hung off the request context so a client that gives up
also cancels the work it started. The per-call bounds remain as the safety net; this
is the latency contract.

What each endpoint does when it expires matters as much as the bound:

- **`/api/status`** returns `status: processing` with `backend: "unreachable"`, and
  the page shows "Storage not responding — retrying…". Falling through to `queued`
  would be a guess, and it is the guess that reads as normal; `unknown` would make
  the UI give up on an object that may be scrubbing perfectly well.
- **`/api/history`** returns whatever it gathered with `partial: true`. A page that
  silently shows six of twenty runs looks like the other fourteen never happened.
  Entries lost to the budget are marked `unavailable`, not `unreadable` — the latter
  is a claim about the run, and repeated across a page it reads as data loss.
- **`/api/report`** returns 504, not 404. A missing report and an unreachable one
  are different, and 404 tells the UI to stop asking for a report that exists.

Measured against a frozen backend, per-call bound 60s, budget 5s:

| Request | Before | After |
| --- | --- | --- |
| `/api/status` poll | 45s | **5.0s** |
| `/api/history?n=50` | minutes | **5.0s** |

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
| `SPILL_RESIDENT_MAX` | — | **64Mi** (this is what bounds memory now — see note below) |
| `GOMEMLIMIT` | 900MiB | **1200MiB** |
| `/work` emptyDir | no limit | **`sizeLimit: 4Gi`** |
| `WORKERS` | 4 | **1** (clamped) |

> **Superseded in 0.8.0.** `SPILL_RESIDENT_MAX` bounds every payload the spill policy
> sees, but not the leaf the matcher is working on: `spill.Blob.Bytes` reads that one
> back off disk outside the resident reservation. It takes `MAX_LEAF_BYTES` alongside
> it to bound RSS.

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
  (Bounded since 0.8.0 by `MAX_LEAF_BYTES`: the member is passed through and flagged
  `leaf-cap` instead of OOM-killing the pod. Still not *scrubbed*.)
- **`/work` must have a `sizeLimit`.** It is load-bearing now that members spill there; an
  unbounded emptyDir can eat node ephemeral storage and get the pod evicted.
- **The image is single-arch (`linux/amd64`).** Building on Apple silicon for an x86
  cluster needs `--platform linux/amd64`, or the loaded image fails to start.
