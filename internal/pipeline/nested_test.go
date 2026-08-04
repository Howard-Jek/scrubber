package pipeline

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/howard/scrubber/internal/report"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// A real bzip2 stream. Go can read bzip2 but not write it, so the pipeline must
// pass a bzip2 member through untouched rather than corrupt it — this fixture
// exercises that path from *inside* a container.
var bzip2Blob = []byte{
	0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0xb1, 0x00, 0x8c, 0xbd, 0x00, 0x00,
	0x0a, 0x5d, 0x80, 0x00, 0x10, 0x40, 0x01, 0x31, 0x60, 0x68, 0x00, 0x3e, 0x23, 0xdc, 0x10, 0x20,
	0x00, 0x48, 0x6a, 0x83, 0x0d, 0x4f, 0x53, 0x6a, 0x1e, 0x51, 0xfa, 0x84, 0x28, 0x00, 0x1a, 0x06,
	0x4c, 0x89, 0x60, 0xfc, 0xe8, 0x16, 0x90, 0xba, 0x2a, 0x5a, 0xb6, 0xd5, 0xd9, 0x3a, 0x3c, 0x08,
	0x79, 0x91, 0x02, 0x29, 0x92, 0x2f, 0xbb, 0x5f, 0x12, 0x6e, 0x46, 0x41, 0xaf, 0xc5, 0xdc, 0x91,
	0x4e, 0x14, 0x24, 0x2c, 0x40, 0x23, 0x2f, 0x40,
}

// ---- compression helpers (gz/tarOf/zipOf live in formats_test.go) ----

func xzOf(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := xz.NewWriter(&buf)
	if err != nil {
		t.Fatalf("xz writer: %v", err)
	}
	mustWrite(t, w, b)
	if err := w.Close(); err != nil {
		t.Fatalf("xz close: %v", err)
	}
	return buf.Bytes()
}

func zstdOf(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	mustWrite(t, w, b)
	if err := w.Close(); err != nil {
		t.Fatalf("zstd close: %v", err)
	}
	return buf.Bytes()
}

func zlibOf(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	mustWrite(t, w, b)
	if err := w.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	return buf.Bytes()
}

// tarOfMany builds a tar from several named members, in order.
func tarOfMany(t *testing.T, entries [][2]any) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		name, body := e[0].(string), e[1].([]byte)
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("tar header %s: %v", name, err)
		}
		mustWrite(t, tw, body)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	return buf.Bytes()
}

// ---- unpack helpers for verifying the *output* is still a real bundle ----

func ungz(t *testing.T, b []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("output is not valid gzip: %v", err)
	}
	defer zr.Close()
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gzip body unreadable: %v", err)
	}
	return out
}

func untar(t *testing.T, b []byte) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(b))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("output is not a valid tar: %v", err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("tar member %s unreadable: %v", h.Name, err)
		}
		out[h.Name] = body
	}
	return out
}

func unzip(t *testing.T, b []byte) map[string][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("output is not a valid zip: %v", err)
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("zip member %s: %v", f.Name, err)
		}
		body, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("zip member %s unreadable: %v", f.Name, err)
		}
		out[f.Name] = body
	}
	return out
}

// secretLog is a payload carrying one of each term the test policy matches.
func secretLog(tag string) []byte {
	return []byte(fmt.Sprintf(
		"%s: AcmeCorp user bob@acme.test from 192.168.1.1\nfiller %s line to vary content\n", tag, tag))
}

func assertClean(t *testing.T, what string, b []byte) {
	t.Helper()
	s := string(b)
	for _, term := range []string{"AcmeCorp", "bob@acme.test", "192.168.1.1"} {
		if strings.Contains(s, term) {
			t.Errorf("%s still contains %q", what, term)
		}
	}
	if !strings.Contains(s, "[COMPANY]") {
		t.Errorf("%s missing replacement token; got %q", what, s)
	}
}

// ---- the reported case: a .gz inside a .tar.gz ----

// TestGzInsideTarGz is the specific shape asked about: a compressed file nested
// inside a compressed archive. Both layers must be unpacked, the leaf scrubbed,
// and every layer rebuilt so the result is still openable.
func TestGzInsideTarGz(t *testing.T) {
	inner := gz(t, secretLog("inner"))
	bundle := gz(t, tarOfMany(t, [][2]any{
		{"logs/app.log", secretLog("plain")},
		{"logs/rotated.log.gz", inner},
	}))

	out, rep := run(t, bundle, DefaultLimits())
	if rep.HasUnscrubbed() {
		t.Fatalf("unexpected passthrough: %+v", rep.Summary.Passthroughs)
	}

	// Peel the output apart the same way a user would.
	members := untar(t, ungz(t, out))
	if len(members) != 2 {
		t.Fatalf("expected 2 tar members, got %d: %v", len(members), keysOf(members))
	}
	assertClean(t, "plain member", members["logs/app.log"])
	assertClean(t, "nested .gz member", ungz(t, members["logs/rotated.log.gz"]))

	t.Logf("matches=%d, report paths=%v", rep.Summary.TotalMatches, reportPaths(rep))
}

// TestDeepChain nests four container layers over a leaf and checks the whole
// stack is unwound, scrubbed, and rebuilt:
//
//	outer.tar.gz ! mid.zip ! inner.tar.gz ! deep.log.gz ! app.log
func TestDeepChain(t *testing.T) {
	deep := gz(t, secretLog("deep"))
	innerTarGz := gz(t, tarOfMany(t, [][2]any{{"deep.log.gz", deep}}))
	midZip := zipOf(t, map[string][]byte{"inner.tar.gz": innerTarGz})
	bundle := gz(t, tarOfMany(t, [][2]any{{"mid.zip", midZip}}))

	out, rep := run(t, bundle, DefaultLimits())
	if rep.HasUnscrubbed() {
		t.Fatalf("unexpected passthrough: %+v", rep.Summary.Passthroughs)
	}

	lvl1 := untar(t, ungz(t, out))
	lvl2 := unzip(t, lvl1["mid.zip"])
	lvl3 := untar(t, ungz(t, lvl2["inner.tar.gz"]))
	leaf := ungz(t, lvl3["deep.log.gz"])
	assertClean(t, "leaf 4 layers down", leaf)

	t.Logf("matches=%d through 4 container layers", rep.Summary.TotalMatches)
}

// TestNestedFormatMatrix embeds every writable single-stream format inside a
// .tar.gz and checks each is unpacked, scrubbed, and repacked in place.
func TestNestedFormatMatrix(t *testing.T) {
	cases := []struct {
		name string
		wrap func(*testing.T, []byte) []byte
	}{
		{"gz", gz},
		{"xz", xzOf},
		{"zstd", zstdOf},
		{"zlib", zlibOf},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			member := "logs/payload." + tc.name
			bundle := gz(t, tarOfMany(t, [][2]any{{member, tc.wrap(t, secretLog(tc.name))}}))

			out, rep := run(t, bundle, DefaultLimits())
			if rep.HasUnscrubbed() {
				t.Fatalf("unexpected passthrough: %+v", rep.Summary.Passthroughs)
			}
			if rep.Summary.TotalMatches == 0 {
				t.Fatalf("nested %s was not scrubbed", tc.name)
			}
			// The rebuilt member must still be readable as that format.
			got := untar(t, ungz(t, out))[member]
			if got == nil {
				t.Fatalf("member %s missing from the rebuilt tar", member)
			}
			plain, _, err := decompressForTest(t, tc.name, got)
			if err != nil {
				t.Fatalf("rebuilt %s member is not valid: %v", tc.name, err)
			}
			assertClean(t, "nested "+tc.name, plain)
		})
	}
}

func decompressForTest(t *testing.T, kind string, b []byte) ([]byte, string, error) {
	t.Helper()
	switch kind {
	case "gz":
		return ungz(t, b), kind, nil
	case "xz":
		r, err := xz.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, kind, err
		}
		out, err := io.ReadAll(r)
		return out, kind, err
	case "zstd":
		r, err := zstd.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, kind, err
		}
		defer r.Close()
		out, err := io.ReadAll(r)
		return out, kind, err
	case "zlib":
		r, err := zlib.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, kind, err
		}
		defer r.Close()
		out, err := io.ReadAll(r)
		return out, kind, err
	}
	return nil, kind, fmt.Errorf("unknown kind %q", kind)
}

// TestNestedZipInTarInZip covers container-in-container (no compression wrapper
// between them), which exercises the archive rebuild paths rather than the
// single-stream ones.
func TestNestedZipInTarInZip(t *testing.T) {
	innerZip := zipOf(t, map[string][]byte{"deep/app.log": secretLog("deep")})
	midTar := tarOfMany(t, [][2]any{{"nested/inner.zip", innerZip}})
	bundle := zipOf(t, map[string][]byte{"mid.tar": midTar})

	out, rep := run(t, bundle, DefaultLimits())
	if rep.HasUnscrubbed() {
		t.Fatalf("unexpected passthrough: %+v", rep.Summary.Passthroughs)
	}
	lvl1 := unzip(t, out)
	lvl2 := untar(t, lvl1["mid.tar"])
	lvl3 := unzip(t, lvl2["nested/inner.zip"])
	assertClean(t, "zip!tar!zip leaf", lvl3["deep/app.log"])
}

// TestNestedBzip2IsPassedThroughAndReported checks a format we can read but not
// write survives *inside* a container: the member must come out byte-identical,
// the rest of the bundle must still be scrubbed, and the skip must be recorded
// so it cannot pass silently.
func TestNestedBzip2IsPassedThroughAndReported(t *testing.T) {
	bundle := gz(t, tarOfMany(t, [][2]any{
		{"logs/app.log", secretLog("plain")},
		{"logs/old.log.bz2", bzip2Blob},
	}))

	out, rep := run(t, bundle, DefaultLimits())

	members := untar(t, ungz(t, out))
	assertClean(t, "sibling plain member", members["logs/app.log"])
	if !bytes.Equal(members["logs/old.log.bz2"], bzip2Blob) {
		t.Errorf("bzip2 member was modified; it must be passed through byte-identical")
	}
	if !rep.HasUnscrubbed() {
		t.Fatalf("bzip2 member passed through WITHOUT being recorded as unscrubbed")
	}
	var found bool
	for _, p := range rep.Summary.Passthroughs {
		if strings.Contains(p.Path, "old.log.bz2") {
			found = true
			t.Logf("recorded: %s (%s) %s", p.Path, p.Status, p.Reason)
		}
	}
	if !found {
		t.Errorf("passthrough list does not name the bzip2 member: %+v", rep.Summary.Passthroughs)
	}
}

// TestNestedReportPathsNameTheChain checks a reviewer can locate a nested hit:
// the report path must spell out the containers it passed through.
func TestNestedReportPathsNameTheChain(t *testing.T) {
	bundle := gz(t, tarOfMany(t, [][2]any{
		{"svc/logs/app.log.gz", gz(t, secretLog("x"))},
	}))
	_, rep := run(t, bundle, DefaultLimits())

	var found bool
	for _, f := range rep.Files {
		if strings.Contains(f.Path, "!svc/logs/app.log.gz") {
			found = true
		}
	}
	if !found {
		t.Errorf("no report path names the nested member; got %v", reportPaths(rep))
	}
}

// ---- guards under nesting ----

// TestDeepNestingTripsDepthGuardLoudly builds a chain past MaxDepth and checks it
// is refused *and recorded*, rather than silently emitted as if it were clean.
func TestDeepNestingTripsDepthGuardLoudly(t *testing.T) {
	data := secretLog("bottom")
	for i := 0; i < 12; i++ {
		data = gz(t, data)
	}
	lim := DefaultLimits()
	lim.MaxDepth = 4

	out, rep := run(t, data, lim)
	if !bytes.Equal(out, data) {
		t.Errorf("a bundle that tripped the depth guard should be passed through verbatim")
	}
	if !rep.HasUnscrubbed() {
		t.Fatalf("depth guard tripped WITHOUT recording an unscrubbed file")
	}
	if got := rep.Summary.Passthroughs[0].Status; got != report.StatusGuardTripped {
		t.Errorf("status = %q, want %q", got, report.StatusGuardTripped)
	}
}

// TestNestedBudgetIsCumulative confirms the expansion budget spans the whole
// nested walk rather than resetting per layer — otherwise deep nesting is an
// unbounded memory amplifier.
func TestNestedBudgetIsCumulative(t *testing.T) {
	big := bytes.Repeat([]byte("AcmeCorp padding line\n"), 30000) // ~660 KB each
	bundle := gz(t, tarOfMany(t, [][2]any{
		{"a.log.gz", gz(t, big)},
		{"b.log.gz", gz(t, big)},
		{"c.log.gz", gz(t, big)},
		{"d.log.gz", gz(t, big)},
	}))

	lim := DefaultLimits()
	lim.MaxTotalBytes = 1 << 20 // far less than the members sum to

	out, rep := run(t, bundle, DefaultLimits())
	if rep.HasUnscrubbed() {
		t.Fatalf("generous budget should scrub everything: %+v", rep.Summary.Passthroughs)
	}
	_ = out

	_, repTight := run(t, bundle, lim)
	if !repTight.HasUnscrubbed() {
		t.Fatalf("tight budget was not enforced across the nested members")
	}
	t.Logf("tight-budget refusal: %s", repTight.Summary.Passthroughs[0].Reason)
}

// TestNestedNoChangeIsByteIdentical checks the fidelity guarantee under nesting:
// when nothing inside matches, every layer must be returned as the original
// bytes rather than re-compressed (which would change the file for no reason).
func TestNestedNoChangeIsByteIdentical(t *testing.T) {
	clean := []byte("nothing sensitive here\njust ordinary log lines\n")
	bundle := gz(t, tarOfMany(t, [][2]any{{"logs/clean.log.gz", gz(t, clean)}}))

	out, rep := run(t, bundle, DefaultLimits())
	if rep.Summary.TotalMatches != 0 {
		t.Fatalf("fixture should contain no matches, got %d", rep.Summary.TotalMatches)
	}
	if !bytes.Equal(out, bundle) {
		t.Errorf("an unchanged nested bundle must be returned byte-identical")
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func reportPaths(rep *report.Report) []string {
	out := make([]string, 0, len(rep.Files))
	for _, f := range rep.Files {
		out = append(out, f.Path)
	}
	return out
}

// countTerm counts occurrences of a sensitive term across every text leaf of the
// output bundle, unpacking each layer.
func countRemaining(t *testing.T, b []byte, term string) int {
	t.Helper()
	n := 0
	var walk func([]byte)
	walk = func(d []byte) {
		head := d
		if len(head) > 512 {
			head = head[:512]
		}
		switch {
		case bytes.HasPrefix(head, []byte{0x1f, 0x8b}):
			walk(ungz(t, d))
		case bytes.HasPrefix(head, []byte("PK\x03\x04")):
			for _, v := range unzip(t, d) {
				walk(v)
			}
		case len(head) >= 262 && bytes.Equal(head[257:262], []byte("ustar")):
			for _, v := range untar(t, d) {
				walk(v)
			}
		default:
			n += bytes.Count(d, []byte(term))
		}
	}
	walk(b)
	return n
}

// TestReportedMatchesEqualMatchesApplied is the invariant that matters most in a
// transparency report: the number it claims to have redacted must be the number
// actually redacted. A bundle containing a bzip2 member exercises the case that
// broke it — the pipeline could decompress and scrub the member, then fail to
// re-encode it, discard the scrubbed bytes, and leave those matches counted.
func TestReportedMatchesEqualMatchesApplied(t *testing.T) {
	const perFile = 50
	body := func(tag string) []byte {
		return []byte(strings.Repeat(tag+" AcmeCorp line\n", perFile))
	}
	bundle := gz(t, tarOfMany(t, [][2]any{
		{"logs/a.log", body("a")},
		{"logs/b.log.gz", gz(t, body("b"))},
		{"logs/old.log.bz2", bzip2Blob}, // readable, not writable
	}))

	out, rep := run(t, bundle, DefaultLimits())

	// Two scrubbable files, one match each per line.
	const wantApplied = 2 * perFile
	if rep.Summary.TotalMatches != wantApplied {
		t.Errorf("report claims %d matches, but only %d were applied",
			rep.Summary.TotalMatches, wantApplied)
	}
	if got := rep.Summary.MatchesByLabel["[COMPANY]"]; got != wantApplied {
		t.Errorf("by-label count = %d, want %d", got, wantApplied)
	}
	// The bz2 body still holds its secret, and the report must say so.
	if !rep.HasUnscrubbed() {
		t.Error("bzip2 member should be reported as unscrubbed")
	}
	// Cross-check against the actual output bytes: the only surviving occurrences
	// should be the ones inside the bzip2 member we could not rewrite.
	members := untar(t, ungz(t, out))
	if !bytes.Equal(members["logs/old.log.bz2"], bzip2Blob) {
		t.Error("bzip2 member must be byte-identical")
	}
	if n := countRemaining(t, ungz(t, out), "AcmeCorp"); n != 0 {
		t.Errorf("%d occurrences survived outside the bzip2 member", n)
	}
}

// TestUnwritableFormatIsNotDescendedInto checks the pipeline does not waste work
// scrubbing a container it cannot repack, and records exactly one entry for it
// rather than one per file inside.
func TestUnwritableFormatIsNotDescendedInto(t *testing.T) {
	_, rep := run(t, bzip2Blob, DefaultLimits())

	if rep.Summary.TotalMatches != 0 {
		t.Errorf("matches = %d, want 0: an unwritable stream must not be scrubbed",
			rep.Summary.TotalMatches)
	}
	if len(rep.Files) != 1 {
		t.Errorf("recorded %d entries, want 1 (no descent): %v", len(rep.Files), reportPaths(rep))
	}
	if rep.Files[0].Status != report.StatusUnsupported {
		t.Errorf("status = %q, want %q", rep.Files[0].Status, report.StatusUnsupported)
	}
}

// TestRollbackRestoresSummaryExactly drives Report.Rollback directly, including
// the passthrough-note bookkeeping, at an audit level where per-match detail is
// not retained.
func TestRollbackRestoresSummaryExactly(t *testing.T) {
	for _, lvl := range []report.AuditLevel{report.AuditFull, report.AuditCounts, report.AuditOff} {
		rep := report.New("in", "out", lvl, false, "t")
		m := testMatcher(t)

		_, keep := m.Scrub("AcmeCorp stays bob@acme.test")
		rep.Record("keep.log", report.StatusScrubbed, "", 10, 10, keep)
		before := rep.Summary

		mark := rep.Mark()
		_, drop := m.Scrub("AcmeCorp goes away 10.0.0.1")
		rep.Record("gone.log", report.StatusScrubbed, "", 10, 10, drop)
		rep.Record("gone2.log", report.StatusUnsupported, "nope", 10, 10, nil)
		rep.Rollback(mark, "container", report.StatusUnsupported, "cannot rewrite", 10, 10)

		if rep.Summary.TotalMatches != before.TotalMatches {
			t.Errorf("audit=%v: TotalMatches = %d, want %d", lvl, rep.Summary.TotalMatches, before.TotalMatches)
		}
		if rep.Summary.FilesScrubbed != before.FilesScrubbed {
			t.Errorf("audit=%v: FilesScrubbed = %d, want %d", lvl, rep.Summary.FilesScrubbed, before.FilesScrubbed)
		}
		for label, n := range before.MatchesByLabel {
			if rep.Summary.MatchesByLabel[label] != n {
				t.Errorf("audit=%v: label %s = %d, want %d", lvl, label, rep.Summary.MatchesByLabel[label], n)
			}
		}
		// The rollback entry itself replaces the discarded ones.
		if len(rep.Files) != 2 || rep.Files[1].Path != "container" {
			t.Errorf("audit=%v: files = %v, want [keep.log container]", lvl, reportPaths(rep))
		}
		if rep.Summary.FilesPassthrough != 1 {
			t.Errorf("audit=%v: FilesPassthrough = %d, want 1", lvl, rep.Summary.FilesPassthrough)
		}
		if n := len(rep.Summary.Passthroughs); n != 1 || rep.Summary.Passthroughs[0].Path != "container" {
			t.Errorf("audit=%v: passthrough notes = %+v, want just the container", lvl, rep.Summary.Passthroughs)
		}
	}
}
