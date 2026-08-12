# Handover — what to verify on your side

A checklist for taking a new image into your own environment. For *what changed and
why*, see [CHANGELOG.md](CHANGELOG.md). For the full reference, see
[MANUAL.md](MANUAL.md).

---

## 1. Build the image and export it

```sh
git pull
docker build -f deploy/Containerfile -t scrubberd:0.6.0 .
docker save -o dist/scrubberd-0.6.0.tar scrubberd:0.6.0
```

On the isolated side:

```sh
docker load -i scrubberd-0.6.0.tar
```

If your air-gapped registry mirrors its own base images, build with them instead — the
Containerfile takes them as build args:

```sh
docker build -f deploy/Containerfile \
  --build-arg BASE_BUILD_IMAGE=<artifactory>/docker-public/golang:1.25 \
  --build-arg BASE_RUNTIME_IMAGE=<artifactory>/docker-public/ubi9/ubi-micro:latest \
  --build-arg GOPROXY=https://<artifactory>/artifactory/api/go/go-remote \
  -t <artifactory>/docker-local/scrubberd:0.6.0 .
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
  scrubberd:0.6.0
```

Expect `loaded policies`, then `control server listening`. `/healthz` and `/readyz` should
both return 200. If it fails here it will fail on the cluster for the same reason.

---

## 3. Run it under the real resource constraint

`scripts/run-local.sh` mirrors the pod — `--memory=2g --cpus=1` and the same caps as the
manifest — so a local pass actually means something:

```sh
./scripts/run-local.sh
# UI:            http://localhost:8080
# MinIO console: http://localhost:9002   (minioadmin / minioadmin)
# Memory:        docker stats scrubberd
```

Check the startup line first:

```sh
docker logs scrubberd | grep 'resource limits'
```

`est_peak_rss_bytes` should read ~538 MB against your 2 GiB limit, and `scratch_bytes`
~4.0 GB against the `/work` `sizeLimit`. Size `limits.memory` from the first and the
emptyDir `sizeLimit` from the second — **not** from `budget_bytes`.

---

## 4. The four checks that matter

### a. A real bundle of yours

The point of the whole thing. Upload one of the ~500 MiB packages that used to be
rejected, and watch `docker stats scrubberd` while it runs.

- **Expect:** `scrubbed`, `passthrough: 0`, RSS well under 1 GiB.
- If it comes back **`skipped (too large)`**, the object is over `MAX_OBJECT_BYTES`
  (640Mi compressed) — report the size rather than raising the cap blind.
- If it comes back **scrubbed but with a passthrough count above 0**, part of the bundle
  left uninspected. That is the failure mode worth catching: it looks like success in the
  UI. The report names the paths and the reason.

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

A many-member archive briefly creates one file per member (up to `MAX_MEMBERS`, 100000).
That is by design, but if your storage class is unhappy about inode churn, say so and small
members can be batched.

### d. Restart mid-scrub

`docker restart scrubberd` while a bundle is in flight.

- **Expect:** the object is re-listed and scrubbed from the start after the restart,
  `/work` comes back empty, and nothing is stuck in `processing` forever.

---

## 5. Coverage behaviour

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

## 6. Re-deriving the memory numbers yourself

Needs a `minio` server binary and `jq`; it builds and drives everything else:

```sh
./scripts/memory-matrix.sh                      # both shapes, ~6 min
SHAPES=big BIG_MIB=500 ./scripts/memory-matrix.sh
```

It fails on peak RSS over 60% of 2 GiB, on any passthrough, or on a leaked temp file.
**Changing any cap in the manifest means re-running this.**

---

## Deploying

Once the checks above pass, follow
[MANUAL.md → Deploying on OpenShift](MANUAL.md#deploying-on-openshift). The prerequisites
are a MinIO credentials Secret, a `scrubber-policies` ConfigMap, the three buckets, and
CORS on MinIO allowing the scrubber Route origin.
