package pipeline

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"strings"
	"testing"

	"github.com/howard/scrubber/internal/config"
	"github.com/howard/scrubber/internal/report"
	"github.com/howard/scrubber/internal/scrub"
)

func testMatcher(t *testing.T) *scrub.Matcher {
	t.Helper()
	cfg := config.Config{
		DefaultReplacement: "[REDACTED]",
		Literals: []config.Term{
			{Value: "AcmeCorp", Replacement: "[COMPANY]"},
		},
		Presets: []string{"email", "ipv4"},
	}
	m, err := cfg.Compile()
	if err != nil {
		t.Fatalf("compile config: %v", err)
	}
	return m
}

// buildFixture creates a .tar.gz containing a scrubin-able log, a binary blob, a
// corrupted inner zip, and a nested clean zip with another log inside.
func buildFixture(t *testing.T) []byte {
	t.Helper()

	// nested clean zip with an inner log
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	w, _ := zw.Create("inner/app2.log")
	w.Write([]byte("contact admin@acme.test from 10.0.0.5\n"))
	zw.Close()

	corruptedZip := append([]byte("PK\x03\x04"), []byte("totally not a real zip body")...)

	binaryBlob := append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 64)...)

	files := []struct {
		name string
		body []byte
	}{
		{"logs/app.log", []byte("user reached AcmeCorp; email bob@acme.test ip 192.168.1.1\n")},
		{"logs/image.png", binaryBlob},
		{"logs/broken.zip", corruptedZip},
		{"logs/nested.zip", zbuf.Bytes()},
	}

	var tbuf bytes.Buffer
	tw := tar.NewWriter(&tbuf)
	for _, f := range files {
		tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body)), Typeflag: tar.TypeReg})
		tw.Write(f.body)
	}
	tw.Close()

	var gbuf bytes.Buffer
	gw := gzip.NewWriter(&gbuf)
	gw.Write(tbuf.Bytes())
	gw.Close()
	return gbuf.Bytes()
}

func TestScrubNamesRenamesMembers(t *testing.T) {
	// tar with a sensitive term in both a directory name and a file name.
	var tbuf bytes.Buffer
	tw := tar.NewWriter(&tbuf)
	body := []byte("nothing sensitive in here\n")
	tw.WriteHeader(&tar.Header{Name: "AcmeCorp/report.log", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
	tw.Write(body)
	tw.Close()

	rep := report.New("b.tar", "out.tar", report.AuditFull, false, "salt")
	eng := &Engine{Matcher: testMatcher(t), Report: rep, Limits: DefaultLimits(), ScrubNames: true}
	out := eng.Process("b.tar", tbuf.Bytes(), 0)

	tr := tar.NewReader(bytes.NewReader(out))
	h, err := tr.Next()
	if err != nil {
		t.Fatalf("read rebuilt tar: %v", err)
	}
	if h.Name != "[COMPANY]/report.log" {
		t.Errorf("member name not scrubbed, got %q", h.Name)
	}
	if strings.Contains(h.Name, "AcmeCorp") {
		t.Errorf("sensitive term left in name: %q", h.Name)
	}

	// With ScrubNames off, the name is preserved.
	rep2 := report.New("b.tar", "out.tar", report.AuditFull, false, "salt")
	eng2 := &Engine{Matcher: testMatcher(t), Report: rep2, Limits: DefaultLimits(), ScrubNames: false}
	out2 := eng2.Process("b.tar", tbuf.Bytes(), 0)
	tr2 := tar.NewReader(bytes.NewReader(out2))
	h2, _ := tr2.Next()
	if h2.Name != "AcmeCorp/report.log" {
		t.Errorf("name should be untouched when ScrubNames off, got %q", h2.Name)
	}
}

func TestProcessNestedBundle(t *testing.T) {
	fixture := buildFixture(t)
	rep := report.New("fixture.tar.gz", "out.tar.gz", report.AuditFull, false, "salt")
	eng := &Engine{Matcher: testMatcher(t), Report: rep, Limits: DefaultLimits()}

	out := eng.Process("fixture.tar.gz", fixture, 0)

	// Output must still be a valid gzip->tar.
	gz, err := gzip.NewReader(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("output is not gzip: %v", err)
	}
	tr := tar.NewReader(gz)
	got := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		b, _ := io.ReadAll(tr)
		got[h.Name] = b
	}

	// app.log: literal + presets applied.
	app := string(got["logs/app.log"])
	for _, want := range []string{"[COMPANY]", "[EMAIL]", "[IPV4]"} {
		if !strings.Contains(app, want) {
			t.Errorf("app.log missing %s: %q", want, app)
		}
	}
	if strings.Contains(app, "AcmeCorp") || strings.Contains(app, "bob@acme.test") {
		t.Errorf("app.log still contains a secret: %q", app)
	}

	// binary blob: byte-identical passthrough.
	if !bytes.Equal(got["logs/image.png"], append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 64)...)) {
		t.Errorf("binary blob was modified")
	}

	// corrupted zip: byte-identical passthrough.
	wantCorrupt := append([]byte("PK\x03\x04"), []byte("totally not a real zip body")...)
	if !bytes.Equal(got["logs/broken.zip"], wantCorrupt) {
		t.Errorf("corrupted zip was modified")
	}

	// nested zip: inner log scrubbed.
	zr, err := zip.NewReader(bytes.NewReader(got["logs/nested.zip"]), int64(len(got["logs/nested.zip"])))
	if err != nil {
		t.Fatalf("nested zip unreadable: %v", err)
	}
	f, _ := zr.File[0].Open()
	inner, _ := io.ReadAll(f)
	if strings.Contains(string(inner), "admin@acme.test") || strings.Contains(string(inner), "10.0.0.5") {
		t.Errorf("nested inner log not scrubbed: %q", inner)
	}

	// report must flag the corrupted zip as passthrough.
	var sawPassthrough bool
	for _, fe := range rep.Files {
		if strings.Contains(fe.Path, "broken.zip") && fe.Status == report.StatusPassthrough {
			sawPassthrough = true
		}
	}
	if !sawPassthrough {
		t.Errorf("report did not flag broken.zip as passthrough")
	}
}
