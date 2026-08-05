package spill

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// isolate points the temp directory at a per-test directory so leak checks can
// assert on it and so a failing test cannot litter the real temp dir.
//
// os.TempDir consults different variables per platform: TMPDIR on unix, TMP then
// TEMP on Windows. Setting only TMPDIR silently redirected nothing on Windows, so
// spilled files landed in the real temp dir and the leak assertions inspected an
// empty directory. Set all three.
func isolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	setTempDir(t, dir)
	return dir
}

func setTempDir(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("TMPDIR", dir)
	t.Setenv("TMP", dir)
	t.Setenv("TEMP", dir)
}

func leftovers(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "scrubber-") {
			names = append(names, e.Name())
		}
	}
	return names
}

func TestSmallPayloadStaysInMemory(t *testing.T) {
	dir := isolate(t)
	b, err := FromBytes([]byte("hello"), Policy{Threshold: 1024, ResidentMax: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if b.Spilled() {
		t.Error("a payload under the threshold should not touch the filesystem")
	}
	if n := len(leftovers(t, dir)); n != 0 {
		t.Errorf("%d temp files created for an in-memory blob", n)
	}
	got, _ := b.Bytes()
	if string(got) != "hello" {
		t.Errorf("Bytes = %q", got)
	}
}

func TestLargePayloadSpills(t *testing.T) {
	dir := isolate(t)
	payload := bytes.Repeat([]byte("x"), 4096)
	b, err := FromBytes(payload, Policy{Threshold: 1024, ResidentMax: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if !b.Spilled() {
		t.Fatal("a payload over the threshold should spill")
	}
	if n := len(leftovers(t, dir)); n != 1 {
		t.Fatalf("expected 1 temp file, found %d", n)
	}
	got, err := b.Bytes()
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("round-trip failed: err=%v len=%d", err, len(got))
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if n := len(leftovers(t, dir)); n != 0 {
		t.Errorf("Close left %d temp files behind", n)
	}
}

// TestResidentMaxForcesSpill is the case a single size threshold misses: each
// payload is individually small, but together they would hold the whole bundle on
// the heap. This is the shape the pipeline's memory matrix ranks worst.
func TestResidentMaxForcesSpill(t *testing.T) {
	isolate(t)
	p := Policy{Threshold: 1024, ResidentMax: 4096}
	var blobs []*Blob
	defer func() {
		for _, b := range blobs {
			b.Close()
		}
	}()

	spilledAt := -1
	for i := 0; i < 20; i++ {
		b, err := FromBytes(bytes.Repeat([]byte("y"), 1000), p)
		if err != nil {
			t.Fatal(err)
		}
		blobs = append(blobs, b)
		if b.Spilled() && spilledAt < 0 {
			spilledAt = i
		}
	}
	if spilledAt < 0 {
		t.Fatal("aggregate budget never forced a spill; 20 small payloads stayed resident")
	}
	if got := Resident(); got > p.ResidentMax {
		t.Errorf("resident = %d, above the ResidentMax of %d", got, p.ResidentMax)
	}
}

func TestCloseReturnsResidentBudget(t *testing.T) {
	isolate(t)
	p := Policy{Threshold: 4096, ResidentMax: 1 << 20}
	before := Resident()
	b, err := FromBytes(bytes.Repeat([]byte("z"), 2048), p)
	if err != nil {
		t.Fatal(err)
	}
	if Resident() <= before {
		t.Fatal("an in-memory blob should consume resident budget")
	}
	b.Close()
	if got := Resident(); got != before {
		t.Errorf("resident = %d after Close, want the pre-blob %d", got, before)
	}
}

func TestCloseIsIdempotentAndNilSafe(t *testing.T) {
	isolate(t)
	var nilBlob *Blob
	if err := nilBlob.Close(); err != nil {
		t.Errorf("Close on nil returned %v", err)
	}
	b, _ := FromBytes(bytes.Repeat([]byte("q"), 4096), Policy{Threshold: 16})
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Errorf("second Close returned %v; the pipeline's defer paths overlap", err)
	}
}

func TestFromReaderEnforcesBudgetWhileReading(t *testing.T) {
	isolate(t)
	// 1MiB of data under a 4KiB budget: must fail, and must not have buffered it.
	src := bytes.NewReader(bytes.Repeat([]byte("a"), 1<<20))
	_, err := FromReader(src, 4096, Policy{Threshold: 512})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}

// TestFromReaderZeroBudgetIsTooLarge pins the readCapped edge the guard tests rely
// on: once a shrinking budget reaches zero, the next member is rejected even if it
// is empty.
func TestFromReaderZeroBudgetIsTooLarge(t *testing.T) {
	isolate(t)
	if _, err := FromReader(bytes.NewReader(nil), 0, Policy{}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge for a zero budget", err)
	}
}

func TestFromReaderRoundTrips(t *testing.T) {
	isolate(t)
	for _, size := range []int{0, 1, 4095, 4096, 4097, 1 << 18} {
		payload := bytes.Repeat([]byte("m"), size)
		b, err := FromReader(bytes.NewReader(payload), 1<<20, Policy{Threshold: 4096, ResidentMax: 1 << 20})
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if b.Size() != int64(size) {
			t.Errorf("size %d: Size() = %d", size, b.Size())
		}
		got, err := b.Bytes()
		if err != nil || !bytes.Equal(got, payload) {
			t.Errorf("size %d: round-trip mismatch (err=%v)", size, err)
		}
		b.Close()
	}
}

func TestReaderAndReaderAt(t *testing.T) {
	isolate(t)
	payload := bytes.Repeat([]byte("r"), 8192)
	for _, threshold := range []int64{16, 1 << 20} { // spilled, then in-memory
		b, err := FromBytes(append([]byte(nil), payload...), Policy{Threshold: threshold, ResidentMax: 1 << 20})
		if err != nil {
			t.Fatal(err)
		}
		rc, err := b.Reader()
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(rc)
		rc.Close()
		if !bytes.Equal(got, payload) {
			t.Errorf("threshold %d: Reader mismatch", threshold)
		}

		ra, closer, err := b.ReaderAt()
		if err != nil {
			t.Fatal(err)
		}
		tail := make([]byte, 4)
		if _, err := ra.ReadAt(tail, 8188); err != nil {
			t.Errorf("threshold %d: ReadAt: %v", threshold, err)
		}
		closer.Close()
		b.Close()
	}
}

// TestHeadDoesNotMaterialise covers format sniffing and binary detection, which need
// only a prefix and must not pull a spilled member back onto the heap.
func TestHeadDoesNotMaterialise(t *testing.T) {
	isolate(t)
	payload := append([]byte("MAGIC"), bytes.Repeat([]byte("p"), 1<<16)...)
	b, err := FromBytes(payload, Policy{Threshold: 16})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if !b.Spilled() {
		t.Fatal("expected a spilled blob")
	}
	head, err := b.Head(5)
	if err != nil {
		t.Fatal(err)
	}
	if string(head) != "MAGIC" {
		t.Errorf("Head = %q, want MAGIC", head)
	}
	short, err := b.Head(1 << 20) // more than the payload
	if err != nil || len(short) != len(payload) {
		t.Errorf("Head past EOF: len=%d err=%v", len(short), err)
	}
}

func TestCreateStreamsOut(t *testing.T) {
	dir := isolate(t)
	b, f, err := Create()
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("w"), 5000)
	n, err := f.Write(payload)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	b.Done(int64(n))

	if b.Size() != int64(len(payload)) {
		t.Errorf("Size = %d, want %d", b.Size(), len(payload))
	}
	got, _ := b.Bytes()
	if !bytes.Equal(got, payload) {
		t.Error("Create round-trip mismatch")
	}
	b.Close()
	if n := len(leftovers(t, dir)); n != 0 {
		t.Errorf("Close left %d files", n)
	}
}

// TestSpillFailureIsDistinguishable is what stops a full disk being reported as a
// corrupt bundle. The pipeline classifies on this error, and the two cases call for
// completely different operator responses.
func TestSpillFailureIsDistinguishable(t *testing.T) {
	// Make the temp location unusable in a way that holds on every platform: point
	// it at a regular file, so creating a file *inside* it cannot succeed. A
	// mode-0500 directory does not work here — Windows does not derive directory
	// permissions from unix mode bits, and root ignores them on unix.
	dir := t.TempDir()
	notADir := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	setTempDir(t, notADir)

	_, err := FromBytes(bytes.Repeat([]byte("x"), 4096), Policy{Threshold: 16})
	if !errors.Is(err, ErrSpill) {
		t.Fatalf("err = %v, want ErrSpill", err)
	}
	if errors.Is(err, ErrTooLarge) {
		t.Error("a disk failure must not be reported as an oversized payload")
	}
}
