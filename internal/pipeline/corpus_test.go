package pipeline

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/howard/scrubber/internal/config"
	"github.com/howard/scrubber/internal/report"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// The conformance corpus: one row per shape the scrubber can meet, each declaring
// what should happen to it.
//
// This table is the answer to "stop patching one edge case at a time". Three bugs
// shipped because a shape reached the pipeline that nobody had written down — UTF-16
// text, text that looked like a zlib stream, text beginning "BZh" — and each was
// invisible afterwards because the outcome landed in a summary bucket nothing read.
// Adding a format or an encoding now means adding rows here, and a row that cannot be
// expressed (because the outcome has no reason code) is the design telling you the
// case is unclassified.
//
// Every row asserts the three things that were wrong before: the status, whether the
// content was inspected, and — when it was not — the machine-readable reason.

const corpusSecret = "2026-06-12T09:00:00Z INFO user bob@acme.test from 10.1.2.3 org=AcmeCorp\n"

type corpusRow struct {
	name string
	body func(*testing.T) []byte
	// want describes the single FileEntry the walk should produce for a leaf, or the
	// entry for the container when the container itself is the outcome.
	wantStatus report.Status
	wantDisp   report.Disposition
	wantReason report.Reason // only checked when wantDisp is NotInspected
	// residual is whether the safety net should find the policy inside content the
	// walk declined to inspect.
	wantResidual bool
	// wantOpaque is whether this shape is a container the safety net could not see
	// INTO at all -- encrypted, an unsupported codec, a stream cut off before its
	// content. A clean scan of one of those is the absence of a scan, so it makes
	// the run risky on its own, with or without hits.
	wantOpaque bool
	limits     *Limits
}

func corpusUTF16(t *testing.T, s string, be, bom bool) []byte {
	t.Helper()
	if bom {
		s = "\ufeff" + s
	}
	units := utf16.Encode([]rune(s))
	out := make([]byte, 2*len(units))
	for i, u := range units {
		if be {
			out[2*i], out[2*i+1] = byte(u>>8), byte(u)
		} else {
			out[2*i], out[2*i+1] = byte(u), byte(u>>8)
		}
	}
	return out
}

// corpusUTF32 is the four-byte-per-code-point form, i.e. `iconv -t UTF-32LE`.
func corpusUTF32(t *testing.T, s string, be, bom bool) []byte {
	t.Helper()
	if bom {
		s = "\ufeff" + s
	}
	runes := []rune(s)
	out := make([]byte, 4*len(runes))
	for i, r := range runes {
		u := uint32(r)
		if be {
			out[4*i], out[4*i+1], out[4*i+2], out[4*i+3] = byte(u>>24), byte(u>>16), byte(u>>8), byte(u)
		} else {
			out[4*i], out[4*i+1], out[4*i+2], out[4*i+3] = byte(u), byte(u>>8), byte(u>>16), byte(u>>24)
		}
	}
	return out
}

func corpusTarGz(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var raw bytes.Buffer
	zw := gzip.NewWriter(&raw)
	tw := tar.NewWriter(zw)
	if err := tw.WriteHeader(&tar.Header{Name: name, Size: int64(len(body)), Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	zw.Close()
	return raw.Bytes()
}

func corpusRows() []corpusRow {
	text := strings.Repeat(corpusSecret, 8)
	clean := strings.Repeat("nothing sensitive on this line at all\n", 8)
	tight := &Limits{MaxDepth: 16, MaxTotalBytes: 64, MaxMembers: 100}

	return []corpusRow{
		// --- text encodings: every one of these must be inspected ---
		{name: "utf-8", body: raw(text), wantStatus: report.StatusScrubbed, wantDisp: report.Inspected},
		{name: "utf-8 with BOM", body: raw("\ufeff" + text), wantStatus: report.StatusScrubbed, wantDisp: report.Inspected},
		{name: "utf-8 no matches", body: raw(clean), wantStatus: report.StatusUnchanged, wantDisp: report.Inspected},
		{name: "latin-1", body: raw("caf\xe9 " + text), wantStatus: report.StatusScrubbed, wantDisp: report.Inspected},
		{
			name:       "utf-16le with BOM", // the reported bug
			body:       func(t *testing.T) []byte { return corpusUTF16(t, text, false, true) },
			wantStatus: report.StatusScrubbed, wantDisp: report.Inspected,
		},
		{
			name:       "utf-16le no BOM",
			body:       func(t *testing.T) []byte { return corpusUTF16(t, text, false, false) },
			wantStatus: report.StatusScrubbed, wantDisp: report.Inspected,
		},
		{
			name:       "utf-16be with BOM",
			body:       func(t *testing.T) []byte { return corpusUTF16(t, text, true, true) },
			wantStatus: report.StatusScrubbed, wantDisp: report.Inspected,
		},
		{
			name:       "utf-16be no BOM",
			body:       func(t *testing.T) []byte { return corpusUTF16(t, text, true, false) },
			wantStatus: report.StatusScrubbed, wantDisp: report.Inspected,
		},

		// --- UTF-32, now round-tripped like UTF-16 rather than skipped ---
		{
			name: "utf-32le with BOM",
			body: func(t *testing.T) []byte {
				return corpusUTF32(t, text, false, true)
			},
			wantStatus: report.StatusScrubbed, wantDisp: report.Inspected,
		},
		{
			name: "utf-32le no BOM",
			body: func(t *testing.T) []byte { return corpusUTF32(t, text, false, false) },
			// The shape most easily mistaken for UTF-16LE: every odd byte is NUL.
			wantStatus: report.StatusScrubbed, wantDisp: report.Inspected,
		},
		{
			name:       "utf-32be with BOM",
			body:       func(t *testing.T) []byte { return corpusUTF32(t, text, true, true) },
			wantStatus: report.StatusScrubbed, wantDisp: report.Inspected,
		},
		{
			name:       "utf-32be no BOM",
			body:       func(t *testing.T) []byte { return corpusUTF32(t, text, true, false) },
			wantStatus: report.StatusScrubbed, wantDisp: report.Inspected,
		},

		// --- text encodings we still cannot handle: skipped, named, caught by the net ---
		{
			name: "malformed utf-32 (past U+10FFFF)",
			body: func(t *testing.T) []byte {
				// Well-formed UTF-32 apart from one out-of-range code point. Decode
				// must refuse the whole payload rather than repair that one unit,
				// and the residual scan still reads the addresses at four-byte
				// stride — the pipeline being unable to help is exactly when
				// something else must look.
				return append(corpusUTF32(t, text, false, true), 0x00, 0x00, 0x11, 0x00)
			},
			wantStatus: report.StatusBinarySkip, wantDisp: report.NotInspected,
			wantReason: report.ReasonEncoding, wantResidual: true,
		},
		{
			name: "malformed utf-16 (lone surrogate)",
			body: func(t *testing.T) []byte {
				return append(corpusUTF16(t, text, false, true), 0x00, 0xd8)
			},
			wantStatus: report.StatusBinarySkip, wantDisp: report.NotInspected,
			wantReason: report.ReasonEncoding, wantResidual: true,
		},

		// --- genuinely binary: skipped is correct, and the net stays quiet ---
		{
			name: "png",
			body: func(t *testing.T) []byte {
				return append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0x01, 0x02, 0x03, 0x7f}, 400)...)
			},
			wantStatus: report.StatusBinarySkip, wantDisp: report.NotInspected,
			wantReason: report.ReasonBinary,
		},

		// --- containers we can rewrite: the member inside must be inspected ---
		{name: "gzip", body: comp(text, "gzip"), wantStatus: report.StatusScrubbed, wantDisp: report.Inspected},
		{name: "zlib", body: comp(text, "zlib"), wantStatus: report.StatusScrubbed, wantDisp: report.Inspected},
		{name: "xz", body: comp(text, "xz"), wantStatus: report.StatusScrubbed, wantDisp: report.Inspected},
		{name: "zstd", body: comp(text, "zstd"), wantStatus: report.StatusScrubbed, wantDisp: report.Inspected},
		{
			name:       "tar.gz",
			body:       func(t *testing.T) []byte { return corpusTarGz(t, "logs/app.log", []byte(text)) },
			wantStatus: report.StatusScrubbed, wantDisp: report.Inspected,
		},
		{
			name: "zip",
			body: func(t *testing.T) []byte {
				var buf bytes.Buffer
				zw := zip.NewWriter(&buf)
				w, _ := zw.Create("logs/app.log")
				w.Write([]byte(text))
				zw.Close()
				return buf.Bytes()
			},
			wantStatus: report.StatusScrubbed, wantDisp: report.Inspected,
		},
		{
			name:       "tar.gz holding a utf-16 member",
			body:       func(t *testing.T) []byte { return corpusTarGz(t, "logs/win.txt", corpusUTF16(t, text, false, true)) },
			wantStatus: report.StatusScrubbed, wantDisp: report.Inspected,
		},

		// --- containers we cannot rewrite: skipped, named, and the net sees inside ---
		{
			name:       "bzip2 (read-only format)",
			body:       raw("BZh9" + text), // not real bzip2; DetectFormat only reads the header
			wantStatus: report.StatusUnsupported, wantDisp: report.NotInspected,
			wantReason: report.ReasonUnsupported, wantResidual: true, wantOpaque: true,
		},
		{
			name:       "7z",
			body:       raw("7z\xbc\xaf\x27\x1c" + text),
			wantStatus: report.StatusUnsupported, wantDisp: report.NotInspected,
			wantReason: report.ReasonUnsupported, wantResidual: true, wantOpaque: true,
		},
		{
			name:       "rar",
			body:       raw("Rar!\x1a\x07\x00" + text),
			wantStatus: report.StatusUnsupported, wantDisp: report.NotInspected,
			wantReason: report.ReasonUnsupported, wantResidual: true, wantOpaque: true,
		},

		// --- magic-byte false positives: plain text that looks like a container ---
		{name: `text starting "x "`, body: raw("x " + text), wantStatus: report.StatusScrubbed, wantDisp: report.Inspected},
		{name: `text starting "H,"`, body: raw("H," + text), wantStatus: report.StatusScrubbed, wantDisp: report.Inspected},
		{name: `text starting "h$"`, body: raw("h$" + text), wantStatus: report.StatusScrubbed, wantDisp: report.Inspected},
		{name: `text starting "BZhang"`, body: raw("BZhang, Wei\n" + text), wantStatus: report.StatusScrubbed, wantDisp: report.Inspected},

		// --- guards: each trips with its own reason, none of them "unclassified" ---
		{
			// The budget trips before the WALK decompresses it, but the safety net has
			// its own bounded budget and decompresses it anyway -- which is the whole
			// point: a bundle refused for being too big used to leave as merely
			// "incomplete", scanned as gzip bytes that contain no text at any stride,
			// and landed in the normal output beside genuinely clean work.
			name:       "expansion budget exceeded",
			body:       func(t *testing.T) []byte { return corpusTarGz(t, "logs/app.log", []byte(text)) },
			limits:     tight,
			wantStatus: report.StatusGuardTripped, wantDisp: report.NotInspected,
			wantReason: report.ReasonExpandBudget, wantResidual: true,
		},
		{
			name: "member cap exceeded",
			body: func(t *testing.T) []byte {
				var raw bytes.Buffer
				zw := gzip.NewWriter(&raw)
				tw := tar.NewWriter(zw)
				for i := 0; i < 6; i++ {
					b := []byte(text)
					tw.WriteHeader(&tar.Header{Name: fmt.Sprintf("l/%d.log", i), Size: int64(len(b)), Mode: 0o644})
					tw.Write(b)
				}
				tw.Close()
				zw.Close()
				return raw.Bytes()
			},
			limits:     &Limits{MaxDepth: 16, MaxTotalBytes: 8 << 20, MaxMembers: 2},
			wantStatus: report.StatusGuardTripped, wantDisp: report.NotInspected,
			wantReason: report.ReasonMemberCap, wantResidual: true,
		},
		{
			// The cap trips on the decompressed payload, which the scan can therefore
			// read — and it is full of matches. Risky is the right answer: we declined
			// to scrub content we can demonstrate holds the data the policy removes.
			name:       "depth cap exceeded",
			body:       comp(text, "gzip"),
			limits:     &Limits{MaxDepth: 0, MaxTotalBytes: 8 << 20, MaxMembers: 100},
			wantStatus: report.StatusGuardTripped, wantDisp: report.NotInspected,
			wantReason: report.ReasonDepthCap, wantResidual: true,
		},

		// --- malformed containers ---
		{
			name:       "truncated gzip",
			body:       func(t *testing.T) []byte { b := comp(text, "gzip")(t); return b[:len(b)/2] },
			wantStatus: report.StatusPassthrough, wantDisp: report.NotInspected,
			wantReason: report.ReasonMalformed,
		},
	}
}

func raw(s string) func(*testing.T) []byte {
	return func(*testing.T) []byte { return []byte(s) }
}

func comp(s, kind string) func(*testing.T) []byte {
	return func(t *testing.T) []byte {
		t.Helper()
		var buf bytes.Buffer
		var w interface {
			Write([]byte) (int, error)
			Close() error
		}
		switch kind {
		case "gzip":
			w = gzip.NewWriter(&buf)
		case "zlib":
			w = zlib.NewWriter(&buf)
		case "xz":
			xw, err := xz.NewWriter(&buf)
			if err != nil {
				t.Fatal(err)
			}
			w = xw
		case "zstd":
			zw, err := zstd.NewWriter(&buf)
			if err != nil {
				t.Fatal(err)
			}
			w = zw
		}
		if _, err := w.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
}

func TestCorpus(t *testing.T) {
	for _, tc := range corpusRows() {
		t.Run(tc.name, func(t *testing.T) {
			lim := Limits{MaxDepth: 16, MaxTotalBytes: 8 << 20, MaxMembers: 100}
			if tc.limits != nil {
				lim = *tc.limits
			}
			_, rep := run(t, tc.body(t), lim)

			if len(rep.Files) == 0 {
				t.Fatal("the walk recorded nothing at all")
			}
			// The outcome under test is the last entry: for a leaf that is the leaf,
			// and for a container failure the rollback collapses the subtree into one.
			got := rep.Files[len(rep.Files)-1]
			if got.Status != tc.wantStatus {
				t.Errorf("status = %q, want %q (detail: %s)", got.Status, tc.wantStatus, got.Detail)
			}
			if got.Status.Disposition() != tc.wantDisp {
				t.Errorf("disposition = %v, want %v", got.Status.Disposition(), tc.wantDisp)
			}

			if tc.wantDisp == report.Inspected {
				if rep.Summary.FilesNotInspected != 0 {
					t.Errorf("an inspected shape still reported %d uninspected file(s): %+v",
						rep.Summary.FilesNotInspected, rep.Summary.NotInspected)
				}
				if v := rep.Summary.Verdict(); v != report.VerdictComplete {
					t.Errorf("verdict = %q, want complete", v)
				}
				return
			}

			if rep.Summary.FilesNotInspected == 0 {
				t.Fatal("a skipped shape did not register as a coverage hole")
			}
			note := rep.Summary.NotInspected[len(rep.Summary.NotInspected)-1]
			if note.Code != tc.wantReason {
				t.Errorf("reason = %q, want %q", note.Code, tc.wantReason)
			}
			// The tripwire. A hole recorded without a reason means some call site took
			// the shortcut this whole design exists to remove.
			if note.Code == report.ReasonUnclassified {
				t.Error("hole recorded through Record instead of Skip — it has no reason code")
			}
			if got, want := rep.Summary.ResidualHits > 0, tc.wantResidual; got != want {
				t.Errorf("residual scan found hits = %v, want %v (hits=%d, samples=%v)",
					got, want, rep.Summary.ResidualHits, rep.Summary.ResidualSamples)
			}
			if got, want := rep.Summary.UnscannableHoles > 0, tc.wantOpaque; got != want {
				t.Errorf("hole the scan could not see into = %v, want %v (unscannable=%d)",
					got, want, rep.Summary.UnscannableHoles)
			}
			wantVerdict := report.VerdictIncomplete
			if tc.wantResidual || tc.wantOpaque {
				wantVerdict = report.VerdictIncompleteRisky
			}
			if v := rep.Summary.Verdict(); v != wantVerdict {
				t.Errorf("verdict = %q, want %q", v, wantVerdict)
			}
		})
	}
}

// Every status must be classified. A new one added without a disposition would
// otherwise inherit whichever switch arm it happened to fall into — which is exactly
// how a binary skip came to be a problem to the worker's log and not a problem to
// HasUnscrubbed at the same time.
func TestEveryStatusIsClassified(t *testing.T) {
	seen := map[report.Disposition]int{}
	for _, s := range report.AllStatuses {
		if s == "" {
			t.Error("empty status in AllStatuses")
		}
		seen[s.Disposition()]++
	}
	if seen[report.Inspected] == 0 || seen[report.NotInspected] == 0 {
		t.Fatalf("expected both dispositions to be represented, got %v", seen)
	}
	if got := seen[report.Inspected] + seen[report.NotInspected]; got != len(report.AllStatuses) {
		t.Errorf("classified %d statuses, AllStatuses has %d", got, len(report.AllStatuses))
	}
}

// The accounting identity. If this drifts, a summary is telling somebody a bundle was
// more thoroughly handled than it was, which is the one direction a transparency
// report must never be wrong in.
func TestCoverageAccountingHolds(t *testing.T) {
	for _, tc := range corpusRows() {
		t.Run(tc.name, func(t *testing.T) {
			lim := Limits{MaxDepth: 16, MaxTotalBytes: 8 << 20, MaxMembers: 100}
			if tc.limits != nil {
				lim = *tc.limits
			}
			_, rep := run(t, tc.body(t), lim)
			s := rep.Summary

			if s.FilesInspected+s.FilesNotInspected != s.FilesTotal {
				t.Errorf("inspected(%d) + not-inspected(%d) != total(%d)",
					s.FilesInspected, s.FilesNotInspected, s.FilesTotal)
			}
			// Recount from the entries themselves: the summary must agree with the
			// list it claims to summarise.
			var inspected, holes int
			for _, f := range rep.Files {
				if f.Status.Disposition() == report.Inspected {
					inspected++
				} else {
					holes++
				}
			}
			if inspected != s.FilesInspected || holes != s.FilesNotInspected {
				t.Errorf("summary says %d/%d inspected/holes, entries say %d/%d",
					s.FilesInspected, s.FilesNotInspected, inspected, holes)
			}
			for _, n := range s.NotInspected {
				if n.Code == "" {
					t.Errorf("note for %q carries no reason code", n.Path)
				}
			}
			if got := sumMap(s.ByReason); got != s.FilesNotInspected && len(s.NotInspected) == s.FilesNotInspected {
				t.Errorf("by_reason totals %d, want %d", got, s.FilesNotInspected)
			}
		})
	}
}

func sumMap(m map[report.Reason]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

// The load-time convergence check, and the runtime post-condition behind it.
//
// A policy whose replacement is itself matched by a rule never finishes the job: the
// "redacted" result still contains the term, and every surface reports the file as
// scrubbed. That is a half-scrubbed document. It is a property of the policy rather
// than of any file, so it is rejected when the policy loads — before any data is
// touched — instead of by re-scanning every leaf, which measured ~70% of the drain
// rate on a one-CPU pod.
func TestNonConvergentPolicyIsRejectedAtLoad(t *testing.T) {
	cfg := config.Config{
		DefaultReplacement: "[REDACTED]",
		// The replacement still contains the term it is meant to remove.
		Literals: []config.Term{{Value: "secret", Replacement: "secret-[REDACTED]"}},
	}
	_, err := cfg.Compile()
	if err == nil {
		t.Fatal("a policy that cannot converge was accepted; every file it touches " +
			"would be emitted only partly redacted and reported as scrubbed")
	}
	for _, want := range []string{"converge", "secret-[REDACTED]"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should name the problem and the offending replacement, got: %v", err)
		}
	}
}

// The runtime post-condition is defence in depth against a bug in the matcher itself,
// which is why it cannot be triggered by any policy that loads. What can be tested —
// and what would actually bite — is the opposite: that switching it on does not start
// flagging ordinary files.
func TestVerifyOutputDoesNotFireOnGoodPolicies(t *testing.T) {
	rep := report.New("in", "out", report.AuditFull, false, "test")
	eng := &Engine{Matcher: testMatcher(t), Report: rep, Limits: Limits{
		MaxDepth: 16, MaxTotalBytes: 8 << 20, MaxMembers: 100, VerifyOutput: true,
	}}
	data := []byte(strings.Repeat(corpusSecret, 20))

	out := eng.Process("bundle", data, 0)
	if bytes.Equal(out, data) {
		t.Fatal("nothing was scrubbed")
	}
	if rep.Summary.FilesNotInspected != 0 {
		t.Errorf("verification flagged a correctly scrubbed file: %+v", rep.Summary.NotInspected)
	}
	if rep.Summary.FilesScrubbed != 1 {
		t.Errorf("expected one scrubbed file, got %+v", rep.Summary)
	}
}
