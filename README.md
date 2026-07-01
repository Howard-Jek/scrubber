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
