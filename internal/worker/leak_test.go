package worker

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/howard/scrubber/internal/pipeline"
	"github.com/howard/scrubber/internal/report"
	"github.com/howard/scrubber/internal/spill"
	"github.com/howard/scrubber/internal/store"
)

// The worker stages every upload on scratch storage, so each object it handles
// creates at least one temp file. Those files are removed only by Blob.Close, and in
// the pod /work is an emptyDir with a sizeLimit — one file left behind per object
// fills it within days and the kubelet evicts for ephemeral-storage, which looks
// nothing like the bug that caused it. So the scratch directory has to come back
// empty after every object, whatever the outcome.

// scratchEnv redirects the temp directory these tests inspect.
//
// os.TempDir consults TMPDIR on unix but TMP then TEMP on Windows, so setting only
// TMPDIR left staged files in the real temp dir while the assertions below read an
// empty directory — the leak check then passes for the wrong reason. Set all three.
func scratchEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	t.Setenv("TMP", dir)
	t.Setenv("TEMP", dir)
	return dir
}

func scratchFiles(t *testing.T, dir string) []string {
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

// spillingBundle is gz(tar(n members)) whose members exceed the spill threshold the
// leak tests use, so the walk really does put payloads on disk.
func spillingBundle(t *testing.T, n, per int) []byte {
	t.Helper()
	line := []byte("hi from AcmeCorp, mail bob@acme.test\n")
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

func leakTestWorker(t *testing.T, ms *memStore, lim pipeline.Limits) *Worker {
	t.Helper()
	w := newTestWorker(t, ms)
	w.cfg.Limits = lim
	return w
}

func TestWorkerLeavesNoScratchFiles(t *testing.T) {
	lim := pipeline.Limits{
		MaxDepth: 16, MaxTotalBytes: 8 << 20, MaxMembers: 100,
		Spill: spill.Policy{Threshold: 4 << 10, ResidentMax: 16 << 10},
	}
	cases := []struct {
		name string
		data []byte
	}{
		{"archive that scrubs", nil}, // filled below; needs *testing.T
		{"plain leaf", []byte("hi from AcmeCorp, mail bob@acme.test\n")},
		{"nothing to scrub", []byte("nothing sensitive in here at all\n")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := scratchEnv(t)
			data := tc.data
			if data == nil {
				data = spillingBundle(t, 4, 32<<10)
			}
			ms := newMemStore("input", "output", "reports")
			ms.Put(context.Background(), "input", "bundle.tar.gz", data, "")

			w := leakTestWorker(t, ms, lim)
			w.runOnce(context.Background())

			if !ms.has("input", "processed/bundle.tar.gz") {
				t.Fatal("object was not processed")
			}
			if names := scratchFiles(t, dir); len(names) != 0 {
				t.Fatalf("scratch not empty after the object completed: %v", names)
			}
		})
	}
}

// An object the worker refuses is still an object it staged a temp file for.
func TestWorkerLeavesNoScratchFilesWhenOversized(t *testing.T) {
	dir := scratchEnv(t)
	ms := newMemStore("input", "output", "reports")
	ms.Put(context.Background(), "input", "big.log", bytes.Repeat([]byte("x"), 4096), "")

	w := newTestWorker(t, ms)
	w.cfg.MaxObjectBytes = 128
	w.runOnce(context.Background())

	if !ms.has("input", "processed/big.log") {
		t.Fatal("oversized object was not moved aside")
	}
	if names := scratchFiles(t, dir); len(names) != 0 {
		t.Fatalf("scratch not empty after an oversized object: %v", names)
	}
}

// A panic mid-scrub is recovered so the service survives, which means the recovery
// path — not the normal one — is what has to release the scratch files.
func TestWorkerLeavesNoScratchFilesAfterPanic(t *testing.T) {
	dir := scratchEnv(t)
	ms := newMemStore("input", "output", "reports")
	ms.Put(context.Background(), "input", "bundle.tar.gz", spillingBundle(t, 4, 32<<10), "")

	w := leakTestWorker(t, ms, pipeline.Limits{
		MaxDepth: 16, MaxTotalBytes: 8 << 20, MaxMembers: 100,
		Spill: spill.Policy{Threshold: 4 << 10, ResidentMax: 16 << 10},
	})
	w.store = panicOnPut{ObjectStore: ms}
	w.runOnce(context.Background())

	if names := scratchFiles(t, dir); len(names) != 0 {
		t.Fatalf("scratch not empty after a recovered panic: %v", names)
	}
}

// panicOnPut fails the way a bug would: after the whole bundle has been expanded and
// scrubbed, with every intermediate blob still live.
type panicOnPut struct{ store.ObjectStore }

func (p panicOnPut) PutStream(_ context.Context, _, _ string, _ io.Reader, _ int64, _ string) error {
	panic("injected failure while writing the scrubbed output")
}

// The failure handler: a result whose uninspected content contains policy matches
// must not land where a consumer looks for finished work. Flagging alone was already
// tried and is not enough — a flag only helps somebody who reads it.
func TestRiskyResultIsDivertedForReview(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	// A UTF-32 log that is malformed part way through, and full of live secrets.
	// Well-formed UTF-32 is scrubbed now, so the shape that still exercises this
	// path is one Decode must refuse rather than repair: it is skipped, the
	// residual scan reads the addresses at four-byte stride anyway, and that is
	// what should move the output.
	var utf32 []byte
	utf32 = append(utf32, 0xff, 0xfe, 0x00, 0x00)
	for _, r := range strings.Repeat("hi from AcmeCorp, mail bob@acme.test\n", 20) {
		utf32 = append(utf32, byte(r), byte(r>>8), byte(r>>16), byte(r>>24))
	}
	utf32 = append(utf32, 0x00, 0x00, 0x11, 0x00) // a code point past U+10FFFF
	ms.Put(context.Background(), "input", "lux.txt", utf32, "")

	w := newTestWorker(t, ms)
	w.runOnce(context.Background())

	if ms.has("output", "lux.txt") {
		t.Error("a risky result was written to the normal output key")
	}
	if !ms.has("output", "review/lux.txt") {
		t.Fatal("expected the result under the review prefix")
	}

	jobs := w.jobs.Recent()
	if len(jobs) == 0 {
		t.Fatal("no job recorded")
	}
	j := jobs[0]
	if j.Verdict != report.VerdictIncompleteRisky {
		t.Errorf("verdict = %q, want %q", j.Verdict, report.VerdictIncompleteRisky)
	}
	if j.ResidualHits == 0 {
		t.Error("the residual scan should have found the addresses inside the skipped file")
	}
	if j.OutputKey != "review/lux.txt" {
		t.Errorf("output key = %q; the client must be told where it actually landed", j.OutputKey)
	}
}

// A bundle that skips only genuinely harmless content stays in the normal output.
// If every bundle containing an image diverted, the review prefix would fill with
// noise and stop meaning anything.
func TestHarmlessSkipIsNotDiverted(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	// Genuinely binary: a PNG header and pseudo-random bytes, with nothing in it
	// the policy would match under any reading.
	body := []byte("\x89PNG\r\n\x1a\n")
	for i := 0; i < 4096; i++ {
		body = append(body, byte(i*7+i/3))
	}
	ms.Put(context.Background(), "input", "logo.png", body, "")

	w := newTestWorker(t, ms)
	w.runOnce(context.Background())

	if !ms.has("output", "logo.png") {
		t.Error("a harmless skip should stay in the normal output")
	}
	if ms.has("output", "review/logo.png") {
		t.Error("a harmless skip must not be diverted, or the review prefix becomes noise")
	}
}
