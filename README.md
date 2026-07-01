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
- **Fail-safe passthrough.** Any file that can't be opened — corrupted, truncated,
  encrypted, or in a format we can read but not rewrite — is emitted **byte-for-byte
  unchanged** and flagged in the report, never half-processed.
- **Binaries are left alone.** Files are classified by *content*, not extension;
  binary files pass through untouched so byte-substitution can't break their format.
- **Bomb/quine resistant.** Recursion depth, expansion ratio, decompressed size, and
  archive member count are all capped.
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
| `--max-ratio` | `200` | Maximum decompression expansion ratio per stream. |
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

**Policies ("both"):** named policy files (same schema as the terms file) are mounted
from a ConfigMap at `/etc/scrubber/policies/*.json` and hot-reloaded on change.
Resolution per object, highest precedence first:
1. per-object override `"<key>.terms.json"` sibling in the input bucket,
2. longest matching `PREFIX_POLICY_MAP` prefix → named policy,
3. `DEFAULT_POLICY`.

**Config (env / ConfigMap + Secret):** `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`/
`MINIO_SECRET_KEY`, `MINIO_USE_TLS`, `MINIO_CA_CERT`, `INPUT_BUCKET`, `OUTPUT_BUCKET`,
`REPORTS_BUCKET`, `INPUT_PREFIX`, `DEFAULT_POLICY`, `PREFIX_POLICY_MAP` (JSON),
`PROCESSED_ACTION` (`move`|`delete`), `POLL_INTERVAL`, `WORKERS`, `MAX_OBJECT_BYTES`,
`REDACT_REPORTS` (default `true`), `PORT` (default `8080`).

**Build & deploy:**
```sh
# build the container (air-gap: override BASE_*_IMAGE / GOPROXY to Artifactory mirrors)
podman build -f deploy/Containerfile -t <artifactory>/docker-local/scrubberd:0.1.0 .
podman push <artifactory>/docker-local/scrubberd:0.1.0

# prereqs: MinIO creds Secret + named-policy ConfigMap
oc create secret generic scrubber-secret \
  --from-literal=MINIO_ACCESS_KEY=... --from-literal=MINIO_SECRET_KEY=...
oc create configmap scrubber-policies --from-file=deploy/policies/

# edit <PLACEHOLDERS>, then apply
oc apply -f deploy/openshift-manifests.yaml
```

The image runs as an arbitrary non-root UID (group 0), `readOnlyRootFilesystem` with
an emptyDir `/work` for temp, drops all capabilities, and ships with `replicas: 1`
(single-writer; horizontal scale-out is a documented follow-up).

### Web front page

`scrubberd` serves a small self-contained upload page at `/` plus a thin browser API.
Crucially, **no bundle bytes pass through the service**: the browser uploads straight
to MinIO and downloads straight from it, using short-lived presigned URLs that the
service mints.

Flow: browser `POST /api/uploads {name}` → gets a presigned PUT + object key → PUTs the
file directly to the input bucket → polls `GET /api/status?key=…` until `scrubbed` → gets
the label-only match breakdown for the "active policy" panel → `GET /api/downloads?key=…`
for a presigned GET of the scrubbed output.

Browser-facing responses expose **only replacement labels and preset names** (`[EMAIL]`,
`email`) — never literal values or matched originals, so the sensitive terms you're
scrubbing don't leak back out over the API.

Extra env for the UI:
- `MINIO_PUBLIC_ENDPOINT` / `MINIO_PUBLIC_TLS` — the browser-reachable MinIO host, used to
  rewrite presigned URLs when the in-cluster endpoint differs from the external one.
- `UPLOAD_EXPIRY` — presigned URL lifetime (default `15m`).

Two deployment requirements for the browser path:
- MinIO must be reachable by the browser (its own Route/ingress) and have **CORS** allowing
  the scrubber page origin (presigned PUT/GET are cross-origin to MinIO).
- Under **network-only** auth the browser API is unauthenticated — anyone who can reach the
  Route can mint upload/download URLs for those buckets. That's acceptable only on a locked-
  down internal network; for genuine external exposure, put auth in front (e.g. OpenShift
  OAuth proxy) — the endpoints are structured so this can be added without app changes.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. |
| `1` | Fatal I/O error (e.g. input unreadable). Output may not have been written. |
| `2` | Invalid usage or invalid terms file. **No input was touched.** |

## Notes & limitations (v1)

- Text is handled as UTF-8 (with or without BOM) and ASCII/Latin-1. UTF-16/UTF-32
  files contain NUL bytes and are therefore treated as binary and passed through.
- Processing is in-memory per stream, bounded by `--max-ratio` and a 2 GiB
  decompressed-size cap per stream.
- Shelling out to a system `7z`/`xz`, and length-preserving / hashing replacement
  modes, are intentionally out of scope for v1.
