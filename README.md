# scrubber — recursive log sanitizer

`scrubber` takes a log bundle — an archive, a compressed file, a directory, or a
single file — recursively unpacks it, replaces sensitive terms in **every text
document inside (regardless of file extension)**, and repacks everything back into
its **original form**: same format, structure, filenames, and metadata. It is a
single self-contained binary that runs identically on Windows and Linux, and the
same engine runs as an OpenShift service (`scrubberd`) driven by MinIO/S3 buckets.

The design rule behind everything below: **a file that was not inspected is never
reported as clean.** Anything the tool declines to read is named, given a
machine-readable reason code, and — if it turns out to contain sensitive data —
routed away from your finished output entirely.

**Documentation**

| Document | What's in it |
| --- | --- |
| This page | Install, run, write a policy, read the codes |
| [docs/MANUAL.md](docs/MANUAL.md) | Full reference: every flag and env var, the coverage contract, sizing and memory, metrics, the web UI, benchmarking |
| [docs/CHANGELOG.md](docs/CHANGELOG.md) | Fix records — what broke, why, and what changed, per image version |
| [docs/HANDOVER.md](docs/HANDOVER.md) | Deployment checklist: what to verify on your own cluster |

---

## Install

Requires **Go 1.25+** (see `go.mod`).

```sh
go build -o scrubber ./cmd/scrubber
```

Cross-compile a static binary — nothing is needed on the target:

```sh
GOOS=linux   GOARCH=amd64 go build -o scrubber-linux-amd64     ./cmd/scrubber
GOOS=windows GOARCH=amd64 go build -o scrubber-windows-amd64.exe ./cmd/scrubber
```

The service binary is `./cmd/scrubberd`.

---

## Quick start

Scrub a bundle:

```sh
scrubber --terms examples/terms.json --in bundle.tar.gz --out bundle.clean.tar.gz --report report.json
```

Scrub a directory tree (structure is mirrored into `--out`):

```sh
scrubber --terms terms.json --in ./logs --out ./logs-clean --report report.json
```

Preview without writing anything:

```sh
scrubber --terms terms.json --in bundle.zip --dry-run --verbose
```

Fail the build if anything was left uninspected:

```sh
scrubber --terms terms.json --in bundle.zip --out clean.zip --fail-on-unscrubbed
```

### As a service

One command brings up MinIO plus the service, under the same memory and CPU ceiling as
the production pod, and declaring the same scratch space:

```sh
./scripts/run-local.sh
```

It no longer hardcodes the caps. It sets the *inputs* the pod sets — `MEM`,
`SCRATCH_BYTES`, `POD_MEMORY_LIMIT` — and lets the service derive `MAX_EXPAND_BYTES`
and the rest the way it does in the cluster, so a local run exercises production's
sizing instead of bypassing it.

Then open <http://localhost:8080>. Drop a bundle in, get a scrubbed bundle and a
report back. To stop:

```sh
docker rm -f scrubberd scrubber-minio && docker network rm scrubnet
```

For OpenShift, see [docs/MANUAL.md](docs/MANUAL.md#deploying-on-openshift).

### How big a bundle fits

Two ceilings, against two different resources. How large a bundle may **expand** is
bounded by the scratch volume: `MAX_EXPAND_BYTES` is derived at startup from the
ephemeral storage the pod declares, at roughly `/work ÷ 3.5`, so the shipped manifest's
14Gi volume yields a 4.00 GiB expansion cap. How large a **single file** may be scrubbed
is bounded by memory: the matcher needs one payload contiguous in heap, so
`MAX_LEAF_BYTES` scales with `limits.memory` — 192 MiB at the shipped 4Gi — and a file
over it is passed through unchanged and flagged `leaf-cap` while the rest of the archive
is still scrubbed. Raising `limits.memory` does not let a larger bundle through, and
sizing the expansion cap from memory rather than from the volume gets the pod evicted
for ephemeral-storage.

Neither of those two turns an upload away: over the expansion budget the bundle is
emitted unscrubbed and flagged, over the leaf cap one file is. `MAX_OBJECT_BYTES` is the
only cap that refuses an object outright, and even that is not a free rejection: the
object is streamed to scratch up to the cap plus one byte before it is turned away, then
discarded. The arithmetic, the derived values and what each startup warning means are in
[docs/MANUAL.md](docs/MANUAL.md#sizing-the-pod). The CLI
leaves the leaf cap off by default (`--max-leaf-bytes 0`): a workstation has the memory
for one large log and no kubelet to answer to.

---

## Writing a policy

A policy (also called a terms file) is JSON. Every section is optional, but at least
one rule must be present.

```json
{
  "default_replacement": "[REDACTED]",
  "literals": [
    { "value": "AcmeCorp", "replacement": "[COMPANY]", "case_insensitive": true },
    { "value": "hunter2", "whole_word": true }
  ],
  "regex": [
    { "pattern": "Bearer\\s+[A-Za-z0-9._-]+", "replacement": "[TOKEN]" }
  ],
  "presets": ["email", "ipv4", "ipv6", "aws_key", "jwt"]
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
| `presets[]` | Built-in PII patterns to enable. |

Precedence is **literals → regex → presets**, in file order. When two rules could
match the same span, the earlier one wins.

### Built-in presets

| Name | Matches | Replacement |
|---|---|---|
| `email` | Email addresses | `[EMAIL]` |
| `ipv4` / `ipv6` | IP addresses | `[IPV4]` / `[IPV6]` |
| `credit_card` | 13–19 digit card numbers, **Luhn-validated** | `[CARD]` |
| `ssn` | US SSNs (`###-##-####`) | `[SSN]` |
| `aws_key` | AWS access key IDs (`AKIA…`/`ASIA…`) | `[AWS_KEY]` |
| `jwt` | JSON Web Tokens | `[JWT]` |
| `phone_us` | US phone numbers | `[PHONE]` |
| `windows_account` | `DOMAIN\user` (e.g. `ACME\jsmith`) | `[ACCOUNT]` |
| `upn` | `user@domain` logins | `[UPN]` |
| `fqdn` | Host names (e.g. `db-prod-01.internal.acme.com`); skips filenames like `app.log` | `[FQDN]` |
| `hostname` | Short single-label hosts; requires a digit or hyphen so plain words aren't matched | `[HOST]` |

> **Prefer exact strings where you have them.** `literals` are false-positive-free.
> `fqdn` and especially `hostname` match by *shape* and are the noisiest — anchoring
> to your own naming with a regex is more accurate:
> `{ "pattern": "[a-z0-9-]+\\.(internal|corp|acme)\\.com", "replacement": "[HOST]" }`

A policy that **cannot converge** is rejected when it loads, before any input is
touched. If a rule replaced `secret` with `secret-[REDACTED]`, the output would still
contain the term and every file would come out half-scrubbed while reporting success.
That is a property of the policy, so it fails fast with exit `2`.

---

## Reading the result

Four different codes answer four different questions. This is the part worth
understanding before you trust an output bundle.

### 1. Exit codes — did the run succeed?

| Code | Meaning |
|---|---|
| `0` | Success. |
| `1` | Fatal I/O error (e.g. input unreadable). Output may not have been written. |
| `2` | Invalid usage, or an invalid/non-converging terms file. **No input was touched.** |
| `3` | Completed, but some files were emitted without being inspected. Only ever returned with `--fail-on-unscrubbed` or `--fail-on-risky`. |

### 2. Per-file status — what happened to this file?

| Status | Inspected? | Meaning |
|---|---|---|
| `scrubbed` | yes | Matched and rewritten. |
| `unchanged` | yes | Read and matched against; nothing to replace. |
| `binary-skipped` | **no** | Classified as binary by content, passed through untouched. |
| `passthrough-error` | **no** | Unreadable, corrupt or encrypted; emitted byte-for-byte. |
| `unsupported-format` | **no** | A container we can read but not rewrite (7z, rar, bzip2). |
| `guard-tripped` | **no** | A size, depth or member-count guard refused to expand it, or the file was over `MAX_LEAF_BYTES`. |
| `residual-match` | **no** | Scrubbed, but the policy still matches the result. |
| `cancelled` | **no** | Withdrawn from the queue by request. No output, report or digest is produced. |

### 3. Reason codes — *why* was it not inspected?

Free text is for humans; this code is what metrics label, the UI groups by, and you
alert on. Every uninspected file carries exactly one.

| Code | What it means |
| --- | --- |
| `binary` | Not text — correctly skipped. |
| `encoding-unsupported` | Text that cannot be round-tripped (malformed UTF-16 or UTF-32). |
| `unsupported-format` | A container we can read but not rewrite (7z, rar, bzip2). |
| `malformed` | Corrupt, truncated or encrypted. |
| `expansion-budget` | Would exceed `MAX_EXPAND_BYTES`. Every member of that container is emitted unscrubbed. **Fix:** raise the `/work` volume (and both `ephemeral-storage` values and `SCRATCH_BYTES`) — 3.5x the expanded size you need. Not memory. |
| `leaf-cap` | One **file** larger than `MAX_LEAF_BYTES` — too large to hold contiguously in heap. Only that file is passed through; the rest of the archive is still scrubbed. **Fix:** raise `limits.memory` — the cap scales at 96 MiB per 2 GiB of pod, so 4Gi admits 192 MiB files and 8Gi admits 384 MiB — or scrub that one file with the CLI, which has no leaf cap. Not the volume. |
| `member-cap` | Archive exceeds `MAX_MEMBERS`. |
| `depth-cap` | Nesting exceeds `MAX_DEPTH`. |
| `scratch-unavailable` | Could not spill to disk. |
| `repack-failed` | Scrubbed, then could not be rebuilt — rolled back and emitted verbatim. |
| `residual-after-scrub` | Scrubbed, and the policy still matches the result (only with `VERIFY_OUTPUT`). |
| `unclassified` | **A tripwire.** Never written deliberately — it marks a hole whose author did not say why. The conformance corpus asserts zero of these. |

### 4. Run verdict — can I ship this bundle?

| Verdict | Meaning | Where the output goes |
| --- | --- | --- |
| `complete` | Everything was inspected. | Normal output |
| `incomplete` | Something was skipped, and scanning it found nothing sensitive. | Normal output, named and flagged |
| `incomplete-risky` | Something was skipped **and it contains policy matches**. | Diverted to `review/` |

Diversion is the point. A flag only helps somebody who reads it; a key under `review/`
cannot be picked up by a process looking for finished work. Harmless skips deliberately
do **not** divert — if every bundle containing an image landed in the review queue,
nobody would read it.

Whatever gets skipped is **looked inside anyway**: a separate scan pulls printable runs
straight out of the raw bytes at one-, two- and four-byte stride, either byte order, and
runs the policy over them without knowing or caring what the format is. That is what
promotes `incomplete` to `incomplete-risky`. See
[the coverage contract](docs/MANUAL.md#coverage-what-was-not-inspected).

### The report

`--report report.json` records every replacement with its location inside the
(possibly nested) bundle:

```json
{
  "source": "bundle.tar.gz",
  "files": [
    { "path": "bundle.tar.gz!logs/app.log", "status": "scrubbed",
      "matches": [ { "rule": "preset:email", "line": 3, "offset": 180,
                     "original": "bob@acme.test", "replacement": "[EMAIL]" } ] }
  ],
  "summary": { "files_total": 4, "files_scrubbed": 2, "total_matches": 10 }
}
```

> ⚠️ **The default report contains the cleartext values you just removed.** Treat it as
> sensitive. Use `--redact-report` for salted hashes, or `--audit=counts`/`off` to omit
> the values entirely. The service defaults to `AUDIT_LEVEL=counts`; the CLI defaults to
> `--audit full`.

Match lists are capped so a pathological bundle cannot inflate the report; counts are
never capped, and truncation is always flagged with `matches_truncated`.

---

## What it can read

| Format | Read | Repack (scrub) | Notes |
|---|---|---|---|
| zip | ✅ | ✅ | Per-entry method/mode/time preserved |
| tar | ✅ | ✅ | Headers, modes, symlinks preserved |
| gzip / zlib / raw deflate | ✅ | ✅ | |
| xz | ✅ | ✅ | |
| zstd | ✅ | ✅ | |
| bzip2 | ✅ | ❌ | Read-only → passed through unchanged |
| 7z / rar | ❌ | ❌ | Passed through unchanged, flagged `unsupported-format` |

Nested containers are handled recursively — `outer.tar.gz!inner.zip!app.log`.

**Text encodings.** Leaves are classified by content, never by extension. UTF-8 (with
or without BOM), ASCII and Latin-1 scrub directly. **UTF-16 and UTF-32** in either byte
order, with or without a BOM, are decoded, scrubbed and written back *in the same
encoding*, so the file keeps working wherever it was going. Text that is malformed in
the encoding it claims is refused rather than repaired — repairing would rewrite bytes
no match touched — and reported as `encoding-unsupported`.

**Known gap:** base64-encoded content is not decoded, so secrets inside it pass through
and the run still reports clean. Tracked in
[#15](https://github.com/Howard-Jek/scrubber/issues/15).

---

## Common flags

The full table is in [docs/MANUAL.md](docs/MANUAL.md#cli-reference).

| Flag | Default | Description |
|---|---|---|
| `--terms` | — | Path to the policy JSON (required). |
| `--in` / `--out` | — | Input and output paths. |
| `--in-place` | `false` | Overwrite the input atomically. |
| `--dry-run` | `false` | Analyze and report without writing. |
| `--report` | — | Write the JSON run report here. |
| `--audit` | `full` | Report detail: `off` \| `counts` \| `full`. |
| `--redact-report` | `false` | Store salted hashes instead of cleartext originals. |
| `--fail-on-unscrubbed` | `false` | Exit `3` if **any** file was left uninspected. |
| `--fail-on-risky` | `false` | Exit `3` only if uninspected content contains matches. |
| `--verbose` | `false` | Print the per-rule breakdown to stderr. |

---

## License

MIT — see [LICENSE](LICENSE). Third-party dependencies are listed in
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md), regenerated with
`scripts/gen-notices.sh`. All current dependencies are permissively licensed (MIT,
BSD-2/3-Clause, Apache-2.0).

The web UI has no external assets — icons are an inline SVG sprite, with no CDN, font,
or script fetches — so it renders correctly in an air-gapped cluster.
