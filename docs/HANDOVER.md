# Handover — what to verify on your side

A checklist for taking a new image into your own environment. For *what changed and
why*, see [CHANGELOG.md](CHANGELOG.md). For the full reference, see
[MANUAL.md](MANUAL.md).

---

## 1. Build the image and export it

```sh
git pull
docker build -f deploy/Containerfile -t scrubberd:0.8.2 .
docker save -o dist/scrubberd-0.8.2.tar scrubberd:0.8.2
```

On the isolated side:

```sh
docker load -i scrubberd-0.8.2.tar
```

If your air-gapped registry mirrors its own base images, build with them instead — the
Containerfile takes them as build args:

```sh
docker build -f deploy/Containerfile \
  --build-arg BASE_BUILD_IMAGE=<artifactory>/docker-public/golang:1.25 \
  --build-arg BASE_RUNTIME_IMAGE=<artifactory>/docker-public/ubi9/ubi-micro:latest \
  --build-arg GOPROXY=https://<artifactory>/artifactory/api/go/go-remote \
  -t <artifactory>/docker-local/scrubberd:0.8.2 .
```

> **Architecture.** The image is single-arch. Add `--platform linux/amd64` if you are
> building on an Apple-silicon Mac for an x86 cluster — a `docker save` of an arm64 image
> will load fine and then fail to start there.

---

## 2. Confirm it satisfies the `restricted-v2` SCC

OpenShift runs the container as an arbitrary non-root UID in group 0, with a read-only
root filesystem and no capabilities. You can reproduce all of that locally before you
apply anything to a cluster:

```sh
docker run --rm \
  --user 1000670000:0 \
  --read-only --tmpfs /work \
  --cap-drop ALL --security-opt no-new-privileges \
  -v "$PWD/deploy/policies:/etc/scrubber/policies:ro" \
  -e MINIO_ENDPOINT=... -e MINIO_ACCESS_KEY=... -e MINIO_SECRET_KEY=... \
  -e INPUT_BUCKET=scrub-input -e OUTPUT_BUCKET=scrub-output -e REPORTS_BUCKET=scrub-reports \
  -e DEFAULT_POLICY=default \
  scrubberd:0.8.2
```

Expect `loaded policies`, then `control server listening`. `/healthz` and `/readyz` should
both return 200. If it fails here it will fail on the cluster for the same reason.

This run declares no scratch volume and no memory ceiling, so the caps derive from the
built-in 4Gi fallback — `scratch_source: "default (undeclared)"` in the startup line is
expected here, not a fault. Section 4 is where those numbers have to be right.

---

## 3. Run it under the real resource constraint

`scripts/run-local.sh` mirrors the pod — `--memory=4g --cpus=1`, and the same two
*declarations* the manifest makes: `SCRATCH_BYTES=14Gi` and
`POD_MEMORY_LIMIT` — so a local pass actually means something:

```sh
./scripts/run-local.sh
# UI:            http://localhost:8080
# MinIO console: http://localhost:9002   (minioadmin / minioadmin)
# Memory:        docker stats scrubberd
```

Note what the script does **not** set. `MAX_EXPAND_BYTES`, `MAX_OBJECT_BYTES`,
`MAX_LEAF_BYTES`, the `SPILL_*` pair and `GOMEMLIMIT` are all derived by the service
from those two declarations, exactly as they are in the pod. The script used to hardcode
them, which made the one command people run to "check it like production" the one command
that bypassed production's sizing — and it drifted. Declare the inputs, let the service
derive the outputs, and a local run can actually disagree with you.

Any of them can still be exported to override, exactly as in the ConfigMap.

---

## 4. Read the `resource limits` line

One line tells you whether the pod is sized the way you think it is:

```sh
docker logs scrubberd | grep 'resource limits'    # oc logs deploy/scrubberd on a cluster
```

Two ceilings, two resources, and they are not interchangeable:

| What it bounds | Which resource bounds it | Key in the line |
| --- | --- | --- |
| How large a bundle may **expand** | ephemeral storage — the `/work` volume | `max_expand_bytes` |
| How large one **file** may be scrubbed | `limits.memory` | `max_leaf_bytes` |

`limits.memory` does **not** affect how large a bundle can expand. Size an expansion cap
from it and the pod is evicted for ephemeral-storage; size a per-file cap from the volume
and it is OOM-killed. The expansion cap is no longer compiled in — it is derived at
startup as `SCRATCH_BYTES / 3.5`, so raising the declaration in the manifest raises the
cap on the next rollout and there is no constant to edit. Full derivation in
[MANUAL.md → The caps size themselves against the pod](MANUAL.md#the-caps-size-themselves-against-the-pod).

On the shipped manifest — `/work` 14Gi, `limits.memory` 4Gi — it carries (reformatted
out of the JSON):

```
max_expand_bytes        4294967296    4.00 GiB   <- 14Gi / 3.5
max_object_bytes        1789569706    1707 MiB   <- 41.7% of the expansion cap
max_leaf_bytes           201326592     192 MiB   <- 96Mi x (limits.memory / 2Gi)
spill_threshold            8388608       8 MiB
spill_resident_max       134217728     128 MiB
est_peak_rss_bytes                    ~2083 MiB  against a 60% gate of 2458 MiB
scratch_bytes                        14.00 GiB   == the 14Gi declared
scratch_declared_bytes 15032385536      14 GiB
scratch_source          SCRATCH_BYTES
```

(`GOMEMLIMIT` is derived too, at 2400 MiB, and logged on its own line just above.)

What to check, in order:

- **`scratch_source`.** Read this first whenever `max_expand_bytes` is not what you
  expected. `SCRATCH_BYTES` means the ConfigMap told the pod; `downward API
  POD_EPHEMERAL_LIMIT` means the Deployment's own `resources` block did; `default
  (undeclared)` means nothing did, so the pod sized itself from the built-in 4Gi and
  derived a 1.14 GiB cap — however large the volume actually is.
- **`scratch_declared_bytes` against the manifest.** **Four** declarations describe the
  same volume and must carry the same number:

  | Declaration | What reads it |
  | --- | --- |
  | `/work` emptyDir `sizeLimit` | what the kubelet **enforces** |
  | `resources.limits.ephemeral-storage` | what the kubelet **evicts against** |
  | `resources.requests.ephemeral-storage` | what the scheduler **reserves on the node** |
  | `SCRATCH_BYTES` | what the **process** sizes its budget from |

  Forgetting `requests` is the one that bites late rather than at rollout: the pod is
  placed on a node with the old headroom and evicts under load. All four accept
  Kubernetes quantities, so write `14Gi` in all four and they can be diffed by eye.
- **`scratch_bytes` against `scratch_declared_bytes`.** `scratch_bytes` is the peak disk
  one object can occupy, and it is normally the declaration again — the budget was derived
  by dividing that same ceiling by 3.5. They diverge exactly when someone pinned
  `MAX_EXPAND_BYTES` by hand.
- **`est_peak_rss_bytes` against `limits.memory`.** Under 60% of it, which is the same
  gate `scripts/memory-matrix.sh` fails on.

> **Do not drop `limits.ephemeral-storage` from the Deployment.** The pod projects its own
> `resources` block back to itself with the Downward API (`POD_MEMORY_LIMIT` and
> `POD_EPHEMERAL_LIMIT`, `divisor: "1"`, `containerName: scrubberd`). If a container
> declares no ephemeral-storage limit, Kubernetes does not fail that reference — it
> resolves it to the **node's** allocatable storage, a number far larger than the pod's
> share, and the pod derives an expansion cap that gets it evicted. The manifest declares
> the limit explicitly, and `SCRATCH_BYTES` overrides it anyway.

**The direction has changed.** The emptyDir used to be an output: you read `scratch_bytes`
and sized the volume from it. It is now an **input** — you declare the volume and the
expansion cap follows, and `scratch_bytes` is a check that the arithmetic closes rather
than an instruction. Still never size anything from `budget_bytes`.

Rule of thumb when you are picking a volume size: **`/work` = 3.5x the expanded content
you need.**

| `/work` | Expanded content it buys |
| --- | --- |
| 4Gi | 1.14 GiB |
| 10Gi | 2.86 GiB |
| 14Gi | **4.00 GiB** (shipped) |
| 20Gi | 5.71 GiB |

### The two warnings

Both ways of getting this wrong are named at startup rather than left to be discovered as
an OOM or an eviction under load. Neither stops the pod; both mean the sizing is wrong.

- **`estimated peak RSS is above the safe share of the pod's memory`** — the arithmetic
  says a worst-case object will not fit `limits.memory`. It logs `leaf_term_bytes`
  alongside `est_peak_rss_bytes`, because that term dominates the estimate and is the one
  an operator is likely to have disabled: `MAX_LEAF_BYTES=0` turns the per-file cap off,
  and the estimate then falls back to the whole expansion budget, which no pod can hold
  contiguously. Lower `MAX_LEAF_BYTES` / `SPILL_RESIDENT_MAX` / `SPILL_THRESHOLD` /
  `MAX_MEMBERS`, or raise `limits.memory`. Ignored, it buys an OOM mid-object: the pod
  dies, restarts, picks the same object up, and dies again.
- **`scratch needed for one object exceeds the declared ephemeral-storage ceiling`** —
  `scratch_bytes` is larger than what the manifest declared, which is what pinning
  `MAX_EXPAND_BYTES` above what the volume allows does. It names `scratch_source` and
  `max_expand_bytes` so you can see which of the two to move. Ignored, it buys an
  ephemeral-storage eviction, which kills a pod as dead as an OOM and looks nothing like
  its cause in the events.

There is a third, quieter one: **`MAX_EXPAND_BYTES is well below what the declared scratch
allows`**. Nothing crashes — the pod simply keeps refusing bundles it now has the disk
for, because someone grew the volume and left the cap pinned in the ConfigMap. Refusing
means emitting them **unscrubbed** and flagged, which looks like success in the UI. Unset
`MAX_EXPAND_BYTES` and let it derive.

---

## 5. The four checks that matter

### a. A real bundle of yours

New in 0.8.2, and worth checking on a **nested** bundle specifically — a `.zip` holding
other `.zip`s, or a `.tar.gz` of archives:

- **The progress bar must reach the end.** It used to top out short of it and stay
  there: every nested container, and every directory entry, inflated `files_total`
  without ever filing an entry against it, so a bundle of five nested zips pinned the
  card at **92%** for the whole run and read as wedged. `file N of M` should now finish
  at `M of M`.
- **Watch the card on a narrow window too.** The filename, the status and the
  **Withdraw** button used to fight for one row: a long object key pushed Withdraw out
  of the card and under the *Active policy* panel, which is where it was when someone
  wanted to press it. They now wrap. Nothing on the page should render outside its box
  or make the page scroll sideways, at any width.
- **A bundle that runs past `SCRUB_TIMEOUT` (default `1h`) must FAIL, not hang.** The
  card should show an error naming the phase it stopped in, how many files of how many
  were done, and the last one finished. Check the input moved to `processed/` — it is
  deliberately **not** retried. If your legitimate bundles need longer, raise
  `SCRUB_TIMEOUT` rather than leaving it to fail: the startup log warns when the budget
  cannot plausibly cover `MAX_EXPAND_BYTES`, and `scrubber_objects_total{status="timeout"}`
  is the series to alert on.


The point of the whole thing. Upload one of the ~500 MiB packages that used to be too
large to scrub, and watch `docker stats scrubberd` while it runs.

- **Expect:** `scrubbed`, `passthrough: 0`, and RSS comfortably under the 60% gate
  (2458 MiB on a 4 GiB pod). `est_peak_rss_bytes` is the worst case the arithmetic
  allows, not a prediction of this run.
- If it comes back **`skipped (too large)`**, the object is over `MAX_OBJECT_BYTES`
  (1707Mi compressed on the shipped manifest) — report the size rather than raising the
  cap blind. Note that it was still transferred: the object is streamed to scratch up to
  the cap plus one byte before it is turned away. It is not kept, but the bandwidth and
  the disk were spent, so a client retrying an oversized upload is not free.
- If it comes back **scrubbed but with a passthrough count above 0**, part of the bundle
  left uninspected. That is the failure mode worth catching: it looks like success in the
  UI. The report names the paths and the reason.

Two guard trips are worth telling apart when you read that report, because they cost you
very different amounts of the bundle:

- **`guard-tripped` / `leaf-cap`** (new) — one file was larger than `MAX_LEAF_BYTES`
  (192 MiB here) and was passed through unchanged. **The rest of the archive is still
  scrubbed.** The matcher needs a payload contiguous in memory and holds three to four
  copies of it while working, so this cap is what stands between one oversized log and an
  OOM crash-loop on a pod whose expansion budget now follows the volume. Raise it by
  raising `limits.memory`. The CLI leaves it off (`--max-leaf-bytes 0`): a workstation has
  the memory for one large log and no kubelet to answer to.
- **an expansion-budget trip** — the container exceeded `MAX_EXPAND_BYTES`, and **every
  member of that container** is emitted unscrubbed. Exceeding this cap does not reject the
  upload; only `MAX_OBJECT_BYTES` turns one away.

### b. Five users at once

Upload five bundles from five browser tabs, roughly together.

- **Expect:** each shows a queue position, positions count down, and they finish in upload
  order. Exactly one is `processing` at a time.
- `curl localhost:8080/api/queue` shows the in-flight key plus the pending list.

### c. Scratch space

During a large scrub:

```sh
docker exec scrubberd sh -c 'ls /work | wc -l; du -sh /work'
```

Expect the count to rise during the member phase and fall to **0** when the object
finishes. A file count that only grows across objects is a leak.

`du -sh /work` is also how you check the 3.5x factor is honest on your own bundles: an
object at the full 4 GiB expansion cap can stage close to the whole 14Gi at its peak,
because a `.tar.gz` holds the decompressed container, the member bodies and the repacked
result at once. If your storage class cannot give the pod that much, lower
`limits.ephemeral-storage`, `requests.ephemeral-storage`, the `sizeLimit` and
`SCRATCH_BYTES` together and let the expansion cap come down with them. That is the safe
direction — a smaller cap means oversized bundles come back flagged and unscrubbed, which
you can see, where an undersized volume evicts the pod mid-object with no report at all.

A many-member archive briefly creates one file per member (up to `MAX_MEMBERS`, 100000).
That is by design, but if your storage class is unhappy about inode churn, say so and small
members can be batched.

### d. Restart mid-scrub

`docker restart scrubberd` while a bundle is in flight.

- **Expect:** the object is re-listed and scrubbed from the start after the restart,
  `/work` comes back empty, and nothing is stuck in `processing` forever.

---

## 6. Coverage behaviour

Upload a bundle containing an image, and one containing something the scrubber cannot read
(a 7z, or a log that is malformed in the encoding it claims — UTF-32 itself is scrubbed
now, see [CHANGELOG.md](CHANGELOG.md)).

- The first should stay in the normal output, flagged `incomplete`.
- The second should land under `review/` with the download gated behind an explicit
  acknowledgement.

Both scripted end to end:

```sh
./scripts/coverage-check.sh    # verdicts and diversion
./scripts/encoding-check.sh    # UTF-16 / UTF-32 handling
```

---

## 7. Re-deriving the memory numbers yourself

Needs a `minio` server binary and `jq`; it builds and drives everything else:

```sh
./scripts/memory-matrix.sh                      # both shapes, ~6 min
SHAPES=big BIG_MIB=500 ./scripts/memory-matrix.sh
SCRATCH_MIB=4096 LIMIT_MIB=2048 ./scripts/memory-matrix.sh   # the old 2Gi pod
```

It declares the same two inputs the pod does — `LIMIT_MIB` 4096 and `SCRATCH_MIB` 14336 —
and lets the service derive every cap from them. It used to pin `EXPAND_MIB`,
`OBJECT_MIB`, `GOMEMLIMIT_MIB` and both `SPILL_*` values instead, which meant the gate
could not validate the derivation it exists to guard: it would have passed cleanly with
the derivation deleted outright. Set one explicitly only to probe a specific
configuration.

It fails on five conditions, not three: a status other than `scrubbed`; any passthrough;
**zero matches**, which means the payload was never scrubbed and is the failure that most
looks like a memory pass; peak RSS over 60% of `LIMIT_MIB`; and a temp file left behind in
`TMPDIR`, which would fill the `/work` emptyDir over days and get the pod evicted for a
reason that looks nothing like its cause.

**Changing `SCRATCH_BYTES`, `limits.memory` or the `/work` `sizeLimit` means re-running
this** — those are the inputs every cap is now derived from.

> **Treat RSS figures published before v0.8.0 as measurements, not as expectations.** They
> were taken on a 2 GiB pod at caps of 1536Mi expansion / 640Mi object — a configuration
> the shipped manifest did not in fact produce, since with `SCRATCH_BYTES=4Gi` the old code
> derived 1638Mi and 682.7Mi. Re-derive with the command above rather than carrying the
> old numbers forward.

---

## Deploying

Once the checks above pass, follow
[MANUAL.md → Deploying on OpenShift](MANUAL.md#deploying-on-openshift). The prerequisites
are a MinIO credentials Secret, a `scrubber-policies` ConfigMap, the three buckets, and
CORS on MinIO allowing the scrubber Route origin.
