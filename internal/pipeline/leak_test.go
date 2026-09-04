package pipeline

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"testing"

	"github.com/howard/scrubber/internal/report"
	"github.com/howard/scrubber/internal/spill"
)

// Spilled blobs are temp files that only Close removes, and the pod's scratch volume
// is an emptyDir with a sizeLimit. One leaked file per object fills it in a few days
// and the kubelet evicts the pod for ephemeral-storage — a failure that looks nothing
// like the bug that caused it. So every walk must leave the scratch directory as it
// found it, on the success path and on each of the failure paths.

// leakEnv redirects the temp directory these tests inspect.
//
// os.TempDir consults TMPDIR on unix but TMP then TEMP on Windows, so setting only
// TMPDIR left spilled files in the real temp dir while the assertions below read an
// empty directory — a leak test that passes because it is looking somewhere else is
// worse than one that fails. Set all three.
func leakEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	t.Setenv("TMP", dir)
	t.Setenv("TEMP", dir)
	return dir
}

func leftovers(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read scratch dir: %v", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names
}

// spillEngine builds an engine whose thresholds are small enough that the fixtures
// below actually spill without needing to be large.
func spillEngine(t *testing.T, limits Limits) *Engine {
	t.Helper()
	if limits.Spill == (spill.Policy{}) {
		limits.Spill = spill.Policy{Threshold: 4 << 10, ResidentMax: 16 << 10}
	}
	return &Engine{
		Matcher: testMatcher(t),
		Report:  report.New("in", "out", report.AuditFull, false, "test"),
		Limits:  limits,
	}
}

// gzTar builds gz(tar(n members)) whose members are large enough to spill.
func gzTar(t *testing.T, n, per int) []byte {
	t.Helper()
	line := []byte("2024-01-01 INFO bob@acme.test 10.1.2.3 AcmeCorp\n")
	body := bytes.Repeat(line, per/len(line)+1)
	var raw bytes.Buffer
	zw := gzip.NewWriter(&raw)
	tw := tar.NewWriter(zw)
	for i := 0; i < n; i++ {
		h := &tar.Header{Name: fmt.Sprintf("logs/%02d.log", i), Size: int64(len(body)), Mode: 0o644}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatalf("tar header: %v", err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatalf("tar body: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return raw.Bytes()
}

func spillZip(t *testing.T, n, per int) []byte {
	t.Helper()
	line := []byte("2024-01-01 INFO bob@acme.test 10.1.2.3 AcmeCorp\n")
	body := bytes.Repeat(line, per/len(line)+1)
	var raw bytes.Buffer
	zw := zip.NewWriter(&raw)
	for i := 0; i < n; i++ {
		w, err := zw.Create(fmt.Sprintf("logs/%02d.log", i))
		if err != nil {
			t.Fatalf("zip create: %v", err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatalf("zip write: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return raw.Bytes()
}

func TestSpillLeavesNoTempFiles(t *testing.T) {
	cases := []struct {
		name   string
		data   func(*testing.T) []byte
		limits Limits
	}{
		{
			name:   "gz tar, everything scrubs",
			data:   func(t *testing.T) []byte { return gzTar(t, 4, 32<<10) },
			limits: Limits{MaxDepth: 16, MaxTotalBytes: 8 << 20, MaxMembers: 100},
		},
		{
			name: "gz tar, nothing to scrub",
			data: func(t *testing.T) []byte {
				var raw bytes.Buffer
				zw := gzip.NewWriter(&raw)
				tw := tar.NewWriter(zw)
				body := bytes.Repeat([]byte("nothing sensitive here at all\n"), 2000)
				h := &tar.Header{Name: "logs/clean.log", Size: int64(len(body)), Mode: 0o644}
				if err := tw.WriteHeader(h); err != nil {
					t.Fatal(err)
				}
				if _, err := tw.Write(body); err != nil {
					t.Fatal(err)
				}
				tw.Close()
				zw.Close()
				return raw.Bytes()
			},
			limits: Limits{MaxDepth: 16, MaxTotalBytes: 8 << 20, MaxMembers: 100},
		},
		{
			name:   "zip, everything scrubs",
			data:   func(t *testing.T) []byte { return spillZip(t, 4, 32<<10) },
			limits: Limits{MaxDepth: 16, MaxTotalBytes: 8 << 20, MaxMembers: 100},
		},
		{
			name:   "expansion budget trips mid-archive",
			data:   func(t *testing.T) []byte { return gzTar(t, 8, 32<<10) },
			limits: Limits{MaxDepth: 16, MaxTotalBytes: 96 << 10, MaxMembers: 100},
		},
		{
			name:   "member cap trips",
			data:   func(t *testing.T) []byte { return gzTar(t, 8, 8<<10) },
			limits: Limits{MaxDepth: 16, MaxTotalBytes: 8 << 20, MaxMembers: 3},
		},
		{
			name:   "depth cap trips",
			data:   func(t *testing.T) []byte { return gzTar(t, 2, 32<<10) },
			limits: Limits{MaxDepth: 0, MaxTotalBytes: 8 << 20, MaxMembers: 100},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := leakEnv(t)
			data := tc.data(t)
			eng := spillEngine(t, tc.limits)

			in, err := spill.FromBytes(data, eng.Limits.Spill)
			if err != nil {
				t.Fatalf("stage input: %v", err)
			}
			out, changed := eng.ProcessBlob("k", in, 0)
			if changed {
				if _, err := out.Bytes(); err != nil {
					t.Fatalf("read result: %v", err)
				}
				out.Close()
			}
			in.Close()

			if names := leftovers(t, dir); len(names) != 0 {
				t.Fatalf("scratch not empty after the walk: %v", names)
			}
		})
	}
}

// A panic anywhere in the walk unwinds through the worker's recover, and every blob
// staged so far has to be released on the way out — otherwise one hostile bundle that
// trips a bug leaves its whole expansion on disk.
//
// Unlike the cases above, which prove the normal paths clean up after themselves, this
// one exercises Engine.Release: the deferred backstop a ProcessBlob caller is required
// to register, and which the worker registers for exactly this reason.
func TestSpillCleansUpOnPanic(t *testing.T) {
	dir := leakEnv(t)
	data := gzTar(t, 4, 32<<10)
	eng := spillEngine(t, Limits{MaxDepth: 16, MaxTotalBytes: 8 << 20, MaxMembers: 100})

	// Panic from the report callback, which fires from deep inside the member loop:
	// members are staged, the decompressed container is staged, nothing is repacked.
	eng.Report.OnFile(func(f report.FileEntry, _ int) {
		panic("boom")
	})

	in, err := spill.FromBytes(data, eng.Limits.Spill)
	if err != nil {
		t.Fatalf("stage input: %v", err)
	}
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("expected the injected panic to propagate")
			}
		}()
		defer in.Close()
		defer eng.Release()
		eng.ProcessBlob("k", in, 0)
	}()

	if names := leftovers(t, dir); len(names) != 0 {
		t.Fatalf("scratch not empty after a panic: %v", names)
	}
}

// Process is the byte-slice wrapper the CLI uses. It stages its own input blob, so it
// owns cleanup for the whole walk.
func TestProcessLeavesNoTempFiles(t *testing.T) {
	dir := leakEnv(t)
	data := gzTar(t, 4, 32<<10)
	eng := spillEngine(t, Limits{MaxDepth: 16, MaxTotalBytes: 8 << 20, MaxMembers: 100})

	if got := eng.Process("k", data, 0); bytes.Equal(got, data) {
		t.Fatal("expected the payload to be scrubbed")
	}
	if names := leftovers(t, dir); len(names) != 0 {
		t.Fatalf("scratch not empty after Process: %v", names)
	}
}
