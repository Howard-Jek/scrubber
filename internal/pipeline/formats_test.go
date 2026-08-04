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
	"time"

	"github.com/howard/scrubber/internal/report"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// ---- fixtures ----

// repetitiveLog returns a log body of n identical-shaped lines. This is what the
// tool is actually pointed at in production, and it compresses at 200:1+ — the
// exact profile that the old expansion-ratio guard rejected.
func repetitiveLog(n int) []byte {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("2026-07-01T10:00:00Z INFO request served for AcmeCorp user bob@acme.test from 192.168.1.1 status=200 latency=12ms\n")
	}
	return []byte(b.String())
}

func gz(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	mustWrite(t, w, b)
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func tarOf(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatalf("tar header: %v", err)
	}
	mustWrite(t, tw, body)
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	return buf.Bytes()
}

func zipOf(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create: %v", err)
		}
		mustWrite(t, w, body)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func mustWrite(t *testing.T, w interface{ Write([]byte) (int, error) }, b []byte) {
	t.Helper()
	if _, err := w.Write(b); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func run(t *testing.T, data []byte, lim Limits) ([]byte, *report.Report) {
	t.Helper()
	rep := report.New("in", "out", report.AuditFull, false, "test")
	eng := &Engine{Matcher: testMatcher(t), Report: rep, Limits: lim}
	return eng.Process("bundle", data, 0), rep
}

// ---- regression: the silent-passthrough bug ----

// TestRealisticLogsAreScrubbed is the regression test for the defect where a
// highly compressible log tripped the 200:1 expansion-ratio guard and was
// emitted UNSCRUBBED while the UI reported success. Both a bare .gz and a
// .tar.gz of the same payload were affected (247:1 and 226:1 respectively).
func TestRealisticLogsAreScrubbed(t *testing.T) {
	log := repetitiveLog(2000)

	cases := []struct {
		name string
		data []byte
	}{
		{"plain .gz", gz(t, log)},
		{"tar.gz", gz(t, tarOf(t, "logs/app.log", log))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ratio := len(log) / len(tc.data)
			out, rep := run(t, tc.data, DefaultLimits())

			if rep.Summary.TotalMatches == 0 {
				t.Fatalf("compressed at %d:1 and produced ZERO matches — the payload was passed through unscrubbed", ratio)
			}
			if bytes.Equal(out, tc.data) {
				t.Fatalf("compressed at %d:1 and output is byte-identical to input", ratio)
			}
			if rep.HasUnscrubbed() {
				t.Errorf("reported unscrubbed files for an ordinary log: %+v", rep.Summary.Passthroughs)
			}
			t.Logf("%d:1 compression, %d matches, %d -> %d bytes", ratio, rep.Summary.TotalMatches, len(tc.data), len(out))
		})
	}
}

// TestFormatMatrix exercises every format the README advertises as read+repack.
func TestFormatMatrix(t *testing.T) {
	log := repetitiveLog(500)

	cases := []struct {
		name string
		data []byte
	}{
		{"raw text", log},
		{"gzip", gz(t, log)},
		{"tar", tarOf(t, "app.log", log)},
		{"tar.gz", gz(t, tarOf(t, "app.log", log))},
		{"zip", zipOf(t, map[string][]byte{"app.log": log})},
		{"zip.gz", gz(t, zipOf(t, map[string][]byte{"app.log": log}))},
		{"zlib", func() []byte {
			var b bytes.Buffer
			w := zlib.NewWriter(&b)
			mustWrite(t, w, log)
			w.Close()
			return b.Bytes()
		}()},
		{"xz", func() []byte {
			var b bytes.Buffer
			w, err := xz.NewWriter(&b)
			if err != nil {
				t.Fatalf("xz writer: %v", err)
			}
			mustWrite(t, w, log)
			w.Close()
			return b.Bytes()
		}()},
		{"zstd", func() []byte {
			var b bytes.Buffer
			w, err := zstd.NewWriter(&b)
			if err != nil {
				t.Fatalf("zstd writer: %v", err)
			}
			mustWrite(t, w, log)
			w.Close()
			return b.Bytes()
		}()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, rep := run(t, tc.data, DefaultLimits())
			if rep.Summary.TotalMatches == 0 {
				t.Errorf("no matches — %s was not scrubbed", tc.name)
			}
			if bytes.Equal(out, tc.data) {
				t.Errorf("output identical to input — %s was not rewritten", tc.name)
			}
			if rep.HasUnscrubbed() {
				t.Errorf("unexpected passthrough: %+v", rep.Summary.Passthroughs)
			}
		})
	}
}

// TestNestedFormats covers the recursive path the README advertises.
func TestNestedFormats(t *testing.T) {
	inner := zipOf(t, map[string][]byte{"deep/app.log": repetitiveLog(100)})
	bundle := gz(t, tarOf(t, "logs/inner.zip", inner))

	out, rep := run(t, bundle, DefaultLimits())
	if rep.Summary.TotalMatches == 0 {
		t.Fatalf("nested tar.gz!zip!log was not scrubbed")
	}
	if bytes.Equal(out, bundle) {
		t.Fatalf("nested bundle was not rewritten")
	}
	// The report path should name the full chain so a reviewer can locate the file.
	var found bool
	for _, f := range rep.Files {
		if strings.Contains(f.Path, "inner.zip") && strings.Contains(f.Path, "app.log") {
			found = true
		}
	}
	if !found {
		t.Errorf("report does not record the nested path; got %d entries", len(rep.Files))
	}
}

// ---- round-trip integrity ----

// TestGzipRoundTrip confirms a scrubbed .gz is still a valid .gz whose body no
// longer contains the sensitive term.
func TestGzipRoundTrip(t *testing.T) {
	log := repetitiveLog(50)
	out, _ := run(t, gz(t, log), DefaultLimits())

	zr, err := gzip.NewReader(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("output is not valid gzip: %v", err)
	}
	defer zr.Close()
	var got bytes.Buffer
	if _, err := got.ReadFrom(zr); err != nil {
		t.Fatalf("output gzip body unreadable: %v", err)
	}
	if strings.Contains(got.String(), "AcmeCorp") {
		t.Errorf("sensitive term survived inside the repacked .gz")
	}
	if !strings.Contains(got.String(), "[COMPANY]") {
		t.Errorf("replacement missing from repacked .gz body")
	}
}

// TestGzipHeaderPreserved checks that repacking keeps the gzip header metadata
// (original filename, mtime) rather than silently dropping it.
func TestGzipHeaderPreserved(t *testing.T) {
	mtime := time.Unix(1751371200, 0).UTC()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Name = "app.log"
	w.Comment = "rotated by logrotate"
	w.ModTime = mtime
	mustWrite(t, w, repetitiveLog(50))
	w.Close()

	out, _ := run(t, buf.Bytes(), DefaultLimits())

	zr, err := gzip.NewReader(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("output is not valid gzip: %v", err)
	}
	defer zr.Close()
	if zr.Name != "app.log" {
		t.Errorf("gzip Name lost: got %q want %q", zr.Name, "app.log")
	}
	if zr.Comment != "rotated by logrotate" {
		t.Errorf("gzip Comment lost: got %q", zr.Comment)
	}
	if !zr.ModTime.Equal(mtime) {
		t.Errorf("gzip ModTime lost: got %v want %v", zr.ModTime, mtime)
	}
}

// TestMultiStreamGzip covers concatenated gzip members, which log rotation and
// pigz produce routinely.
func TestMultiStreamGzip(t *testing.T) {
	part := []byte("AcmeCorp line bob@acme.test 192.168.1.1\n")
	multi := append(gz(t, part), gz(t, part)...)
	_, rep := run(t, multi, DefaultLimits())
	if rep.Summary.TotalMatches == 0 {
		t.Fatalf("multistream gzip was not scrubbed")
	}
}

// ---- resource guards ----

// TestExpansionBudgetStopsBomb checks that a stream expanding far beyond the
// budget is refused, and — critically — that the refusal is *recorded* rather
// than silently emitting the original bytes as if they were clean.
func TestExpansionBudgetStopsBomb(t *testing.T) {
	bomb := gz(t, bytes.Repeat([]byte{'A'}, 8<<20)) // 8 MiB of zeros-ish, tiny compressed
	lim := DefaultLimits()
	lim.MaxTotalBytes = 1 << 20 // 1 MiB budget

	out, rep := run(t, bomb, lim)
	if !bytes.Equal(out, bomb) {
		t.Errorf("over-budget stream should be passed through verbatim")
	}
	if !rep.HasUnscrubbed() {
		t.Fatalf("over-budget stream was passed through WITHOUT being recorded as unscrubbed")
	}
	if got := rep.Summary.Passthroughs[0].Status; got != report.StatusGuardTripped {
		t.Errorf("status = %q, want %q", got, report.StatusGuardTripped)
	}
	t.Logf("recorded: %s", rep.Summary.Passthroughs[0].Reason)
}

// TestZipBudgetStopsBomb covers the zip path specifically: entries are
// individually compressed, so a small archive can expand to many GB. Before the
// budget existed, ReadZip called io.ReadAll per entry with no ceiling at all.
func TestZipBudgetStopsBomb(t *testing.T) {
	entries := map[string][]byte{}
	for i := 0; i < 8; i++ {
		entries[fmt.Sprintf("bomb%d.bin", i)] = bytes.Repeat([]byte{'A'}, 2<<20)
	}
	bomb := zipOf(t, entries)

	lim := DefaultLimits()
	lim.MaxTotalBytes = 1 << 20

	out, rep := run(t, bomb, lim)
	if !bytes.Equal(out, bomb) {
		t.Errorf("over-budget zip should be passed through verbatim")
	}
	if !rep.HasUnscrubbed() {
		t.Fatalf("over-budget zip was passed through WITHOUT being recorded")
	}
}

// TestMemberCountGuard checks the archive entry-count limit still trips.
func TestMemberCountGuard(t *testing.T) {
	entries := map[string][]byte{}
	for i := 0; i < 50; i++ {
		entries[fmt.Sprintf("f%d.log", i)] = []byte("AcmeCorp\n")
	}
	lim := DefaultLimits()
	lim.MaxMembers = 10

	_, rep := run(t, zipOf(t, entries), lim)
	if !rep.HasUnscrubbed() {
		t.Fatalf("member-count guard did not record a passthrough")
	}
}

// TestDepthGuard checks that deep nesting is refused and recorded.
func TestDepthGuard(t *testing.T) {
	data := repetitiveLog(10)
	for i := 0; i < 6; i++ {
		data = gz(t, data)
	}
	lim := DefaultLimits()
	lim.MaxDepth = 2

	_, rep := run(t, data, lim)
	if !rep.HasUnscrubbed() {
		t.Fatalf("depth guard did not record a passthrough")
	}
}

// TestBudgetIsCumulativeAcrossMembers verifies the budget spans the whole object
// rather than resetting per stream — otherwise N members each just under the cap
// still exhaust memory.
func TestBudgetIsCumulativeAcrossMembers(t *testing.T) {
	body := bytes.Repeat([]byte("AcmeCorp filler line\n"), 40000) // ~840 KB each
	entries := map[string][]byte{}
	for i := 0; i < 6; i++ {
		entries[fmt.Sprintf("f%d.log", i)] = body
	}
	lim := DefaultLimits()
	lim.MaxTotalBytes = 2 << 20 // fits ~2 members, not 6

	_, rep := run(t, zipOf(t, entries), lim)
	if !rep.HasUnscrubbed() {
		t.Fatalf("cumulative budget not enforced across members")
	}
}

// TestBudgetResetsPerObject guards against budget leaking between top-level
// calls when an Engine is reused (the CLI walks a directory with one Engine).
func TestBudgetResetsPerObject(t *testing.T) {
	rep := report.New("in", "out", report.AuditFull, false, "test")
	lim := DefaultLimits()
	lim.MaxTotalBytes = 4 << 20
	eng := &Engine{Matcher: testMatcher(t), Report: rep, Limits: lim}

	payload := gz(t, repetitiveLog(2000))
	for i := 0; i < 5; i++ {
		out := eng.Process(fmt.Sprintf("file%d", i), payload, 0)
		if bytes.Equal(out, payload) {
			t.Fatalf("object %d was not scrubbed — budget leaked from a previous object", i)
		}
	}
}

// ---- unsupported formats stay loud ----

// TestUnsupportedFormatsRecorded confirms 7z/rar are passed through AND recorded,
// so the operator learns their contents were never inspected.
func TestUnsupportedFormatsRecorded(t *testing.T) {
	cases := map[string][]byte{
		"7z":  append([]byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}, bytes.Repeat([]byte{1}, 64)...),
		"rar": append([]byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x01, 0x00}, bytes.Repeat([]byte{1}, 64)...),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			out, rep := run(t, data, DefaultLimits())
			if !bytes.Equal(out, data) {
				t.Errorf("%s should be passed through verbatim", name)
			}
			if !rep.HasUnscrubbed() {
				t.Fatalf("%s passed through WITHOUT being recorded as unscrubbed", name)
			}
			if got := rep.Summary.Passthroughs[0].Status; got != report.StatusUnsupported {
				t.Errorf("status = %q, want %q", got, report.StatusUnsupported)
			}
		})
	}
}

// TestCorruptArchiveRecorded confirms a malformed container is distinguished
// from a resource guard and still reported as unscrubbed.
func TestCorruptArchiveRecorded(t *testing.T) {
	corrupt := append([]byte("PK\x03\x04"), []byte("not actually a zip")...)
	out, rep := run(t, corrupt, DefaultLimits())
	if !bytes.Equal(out, corrupt) {
		t.Errorf("corrupt zip should be passed through verbatim")
	}
	if !rep.HasUnscrubbed() {
		t.Fatalf("corrupt zip passed through WITHOUT being recorded")
	}
	if got := rep.Summary.Passthroughs[0].Status; got != report.StatusPassthrough {
		t.Errorf("status = %q, want %q", got, report.StatusPassthrough)
	}
}
