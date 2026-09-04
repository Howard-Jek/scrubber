# Outstanding work

What is left from the adversarial pass over 0.8.3, in the order I would do it.
Each item names the finding ID from that pass so it maps back to the reasoning,
and the file it lives in. Nothing here is a regression from 0.8.4 — these are
pre-existing behaviours that pass found and 0.8.4 did not get to.

The audit deliberately skipped security. That sweep has not been done.

---

## 1. The queue can still be held by one bad object

**F1 · `internal/worker/worker.go`, the generic branch of `fail` and the panic
recovery.** Neither calls `deferRetry` nor disposes of the input. `attempts`
stays 0, so `orderKey` returns the object's `LastModified` — by definition the
oldest key in the bucket — and it sorts to **position 1** on the next poll. A
permanent error therefore re-downloads and re-walks the same object ahead of
every newer upload, forever, flapping `error → processing → error`. The panic
path is worse: the panic is deterministic for the same object, so it is a
guaranteed loop with a stack trace on every cycle.

Reachable through: `PutStream` denied, a non-404 error on the `.terms.json`
sidecar, `PREFIX_POLICY_MAP` naming a policy that is not loaded, `spill.Create`
on a full `/work`.

The `stalled` and `timeout` branches beside it document exactly why they do the
opposite. Fix: `deferRetry` on both, and `finish` the input aside for errors
that cannot succeed on a retry (policy resolution, unknown override policy).

## 2. A successful scrub can be reported as lost

**F3 · `worker.go`, the report and digest writes.** Both are `Warn`-only, and
the input is `finish`ed regardless. If the output PUT succeeds and the reports
bucket write fails, a restart leaves `/api/status` with nothing to find: job log
empty → no digest → no report → `Stat` on the input returns not-found → the UI
says *"no result recorded for this upload"* while the fully scrubbed output sits
in the bucket under a key the user cannot discover, possibly renamed by
`SCRUB_FILENAMES`.

Fix: a failed report or digest write means `deferRetry` and no `finish` — the
output PUT is idempotent, so re-running is safe. The `apiStatus` "unknown"
branch should also consult the output bucket before declaring loss.

**F4 · same file.** `timedOutExit` writes no digest, so a timed-out object's only
trace is the in-memory job record, lost on the next restart. `stalledExit` has
the same gap. Fix: write a digest carrying `Status` and `Error` — the fields are
already on `report.Digest`, added in 0.8.4 and currently unused.

## 3. Configuration that is ignored in silence

**F13 · `cmd/scrubberd/main.go`.** `envDuration`, `envInt`, `envBool` and
`PROCESSED_ACTION` all fall back to their default on an unparseable value
without saying so. The consequences are not cosmetic:

- `SCRUB_TIMEOUT: "3600"` (no unit — the natural thing to write next to
  `POLL_INTERVAL`) is silently 1h.
- `MINIO_USE_TLS: "True"` silently **disables TLS**. `envBool` accepts exactly
  `1`, `true`, `TRUE`, `yes`.
- `PROCESSED_ACTION: "DELETE"` silently means *move*, so a deployment that asked
  for its inputs to be destroyed quietly retains them.
- `MAX_DEPTH: "0"` is passed through as 0, so `depth > 0` trips at the first
  container and **every archive is refused**.

`envInt64` was rewritten to fix exactly this class and records a fault through
`probs` explaining what to write. Its neighbours never were. Fix: route them all
through `probs`; make `envBool` case-insensitive and accept `on`/`off`/`y`/`n`.

## 4. Status and history tell the user the wrong thing

- **F10 · `internal/server/server.go`.** `staleAfter` is 30s and keyed on the
  job's *start* timestamp, which never advances. Every scrub longer than 30
  seconds therefore costs two failed object reads per client poll — roughly
  3,800 for a 19-minute bundle. Judge freshness on `ProgressSince`, which the
  record already carries and which now advances during transfers and rebuilds.
- **F8 · `server.go` / `index.html`.** The server distinguishes `unreadable`
  (a corrupt digest) from `unavailable` (the request budget expired); the UI
  branches only on `unreadable`, so `unavailable` falls through to the green
  "0 redacted" badge. Runs nobody could read are shown as clean. The
  `partial` and `error` fields on `/api/history` are never read either.
- **F9 · `worker.go`.** Cancelling a *queued* key writes no job record, so any
  second observer gets `unknown` and the UI paints a red "Failed" for an object
  that was withdrawn cleanly.
- **F11 · `worker.go`.** `endInflight` discards the `committed` flag. If
  `finish` failed, a cancel arriving afterwards takes the not-in-flight path,
  finds the input still present, and answers `withdrawn` for an object whose
  output was published — the exact claim `CancelTooLate` exists to prevent.
- **F15 · `worker.go` / `server.go`.** `rep.Output` is not updated when a result
  is diverted to `review/`, so the stored report names a key that does not
  exist. `digestStatusPayload` sets `files_done` to the *total* and omits
  `files_total`, so the two payload shapes are not interchangeable as claimed.

## 5. Coverage gaps worth closing

- **S8 · no version check on the input.** `store.Object` carries no ETag and
  `Move` is an unconditional copy-then-delete. An object re-PUT under the same
  key mid-scrub is moved to `processed/` **unscrubbed** while the output holds
  the scrub of the old bytes. Not reachable from the bundled UI (keys carry a
  random prefix), but any external producer writing stable key names hits it.
  Fix: capture the ETag at list time and pass it as a precondition to `Move`;
  `minio.CopyObject` supports `MatchETag`.
- **S9 · encodings the matcher cannot see.** base64
  ([#15](https://github.com/Howard-Jek/scrubber/issues/15)), percent-encoding,
  HTML entities, JSON `\uXXXX`, quoted-printable. All of these are plain ASCII,
  so the file is not flagged binary either — **the run reports clean**. That is
  the dangerous quadrant: the binaries at least get named.
- **Formats not detected at all**: lz4, brotli, lzma, `.Z`, cpio. They fall
  through to a binary skip, which is safe but silent about *why*.
- **Documents.** PDF is opaque (its text lives in Flate streams). Office files
  are handled structurally as zips of XML and are untested; Word splits text
  runs, so an address is routinely `bob@acme` + `.com` in two elements and no
  regex will see it. `.msg` is OLE. There is no docx/xlsx/PDF fixture anywhere
  in the repo. These need format-aware decoders and are a different tier of
  product — record them as out of scope rather than leave them implied.

## 6. Throughput (was "PR 2")

Measured drain is ~6 MiB/s per core and a scrub cannot use more than one core,
so this is the only lever left after `requests.cpu: 1`.

- **P2 · match sink.** `Scrub` builds a 64-byte `Match` for every hit, and the
  report caps *retention* at 1000/20000 only after the slice exists — ~2.9 GB of
  churn on the 18.9M-match shape. `AUDIT_LEVEL=off` does not bound it, because
  the slice is built upstream of the setting. Give `Scrub` a sink so the report
  counts and keeps only what it retains. Also lets `residual.Scan` count without
  building a replacement string it discards (**P6**).
- **P3 · `klauspost/compress`** for gzip/zlib/flate. Already a dependency;
  1.5–2× at the same level, ~20% of wall clock on a `.tar.gz`. (The zip half of
  P3 — not re-deflating unchanged members — landed in 0.8.4.)
- **P4 · one header read.** `Head(512)` then `Head(8192)` is two `os.Open`s per
  spilled member plus an 8 KiB allocation each, even for a 100-byte file.
- **P5 · UTF-8 identity path.** `string(data)` and `[]byte(text)` are two
  full-payload copies of the commonest case. This is why `leafCopies = 3` and
  why `MAX_LEAF_BYTES` is 96 MiB per 2 GiB. Re-run the memory matrix and raise
  `maxLeafBaseline` to whatever the measurement supports.
- **P7 · `strings.Clone` on retained originals.** `Match.Original` is a
  substring, so one retained match pins the whole decoded member. Bites at
  `AuditFull`, which is the CLI default.
- **P9.** `displayPath` re-runs `ScrubName` on every path the pipeline already
  scrubbed; `log.Debug` boxes six args per member before the level check.
- **P10 · architectural, a week each.** `ReadZip`/`ReadTar` materialise every
  member before the first is scrubbed (this is the 3.5 scratch factor; a
  streaming walk would admit ~3× the bundle on the same volume). The leaf
  matcher needs the whole file as one string (this is `leaf-cap`; a
  newline-chunked scrub would remove it). No byte-set prefilter before the
  combined regex, so sparse logs pay exactly what dense ones do — plausibly
  3–10× on real bundles, and the single biggest win on this list.

## 7. Dead code

All grep-verified, zero non-test references: `Engine.ResidualFindings` and its
write-only `residualHits`/`residualLabels` (the live count is
`Summary.ResidualHits`) · `JobLog.Add` · `queue.truncated` (assigned, never
read; the caller uses the return value) · `store.Client.GetLimited` (interface
and impl, superseded by `GetLimitedTo`) · `verChip` in `index.html` ·
`case "queued"` in `failure.go` (never a phase value).

Keep: `runOnce`, `AllStatuses`, `Resident`, `Spilled`, `isCancelled`,
`RuleCount` are test seams; `--max-ratio` is a deprecation shim; `Resolve`'s
`overrideName` branch is a dormant object-tag feature; the `maxExpandCeiling`
branch is self-documented as unreachable and deliberately redundant.

## 8. Tests and docs

- Corpus rows: zip with an encrypted member, with an `ErrAlgorithm` member
  (method 14), with a bad-CRC member — each asserting the *other* members are
  still scrubbed; truncated tar; a tar whose first entry name is zlib-shaped.
- Worker tests for every item in §1 and §4.
- `scripts/coverage-check.sh` should gain the encrypted-zip case now that
  `review/` diversion covers it.
- README: a "what it cannot see" section (§5), and the preset table needs the
  0.8.4 `ipv6`/`phone_us`/`credit_card` changes.
- MANUAL: the five env vars that are read and documented nowhere —
  `ENSURE_BUCKETS`, `JOBS_HISTORY`, `MINIO_REGION`, `PROCESSED_PREFIX`,
  `SCRATCH_RECLAIM`.
- `deploy/openshift-manifests.yaml`: the ConfigMap is still missing
  `AUDIT_LEVEL`, `REVIEW_PREFIX`, `RESIDUAL_BUDGET`, `VERIFY_OUTPUT`.
- `examples/app.log` is referenced by nothing.
- No lifecycle rule ships for aborting incomplete multipart uploads in the
  output bucket; a pod killed mid-PUT leaves parts that count against quota and
  are invisible to `ListObjects`.

## 9. Known and accepted

- **One silent stretch remains** in the walk: expanding a container, before its
  first member is scrubbed. Everything else heartbeats. It is local-disk bound
  and capped by `MAX_EXPAND_BYTES`, so `STALL_ABORT_AFTER` at 45m has enormous
  margin — but do not set that below ~10m without measuring this on real
  bundles.
- **`STALL_ABORT_AFTER` is cooperative.** An object blocked in a syscall never
  reaches a poll site and cannot be abandoned. `WORKERS > 1` is what keeps the
  rest of the queue draining when that happens; the wedged consumer is only
  freed by a restart.
- **`replicas: 1` is a correctness requirement**, not a capacity choice — the
  queue lives in the pod. Scaling out needs a distributed object claim, or
  partitioning by `INPUT_PREFIX` plus upload routing the API does not yet do.
- **Strict FCFS has no per-tenant fairness.** One user's large batch holds up
  everyone behind it. Round-robin needs a tenant identity and there is no app
  auth.
