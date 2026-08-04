package worker

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/howard/scrubber/internal/metrics"
	"github.com/howard/scrubber/internal/pipeline"
	"github.com/howard/scrubber/internal/policy"
	"github.com/howard/scrubber/internal/store"
	"github.com/prometheus/client_golang/prometheus"
)

// memStore is an in-memory ObjectStore for tests.
type memStore struct {
	mu      sync.Mutex
	buckets map[string]map[string][]byte
}

func newMemStore(names ...string) *memStore {
	m := &memStore{buckets: map[string]map[string][]byte{}}
	for _, n := range names {
		m.buckets[n] = map[string][]byte{}
	}
	return m
}

func (m *memStore) List(_ context.Context, bucket, prefix string) ([]store.Object, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Object
	for k, v := range m.buckets[bucket] {
		if strings.HasPrefix(k, prefix) {
			out = append(out, store.Object{Key: k, Size: int64(len(v))})
		}
	}
	return out, nil
}

func (m *memStore) Get(_ context.Context, bucket, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.buckets[bucket][key]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), v...), nil
}

func (m *memStore) GetLimited(_ context.Context, bucket, key string, max int64) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.buckets[bucket][key]
	if !ok {
		return nil, os.ErrNotExist
	}
	if int64(len(v)) > max {
		return nil, store.ErrTooLarge
	}
	return append([]byte(nil), v...), nil
}

func (m *memStore) Exists(_ context.Context, bucket, key string) (bool, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.buckets[bucket][key]
	if !ok {
		return false, nil, nil
	}
	return true, append([]byte(nil), v...), nil
}

func (m *memStore) Put(_ context.Context, bucket, key string, data []byte, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.buckets[bucket] == nil {
		m.buckets[bucket] = map[string][]byte{}
	}
	m.buckets[bucket][key] = append([]byte(nil), data...)
	return nil
}

func (m *memStore) Move(_ context.Context, bucket, src, dst string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.buckets[bucket][src]
	if !ok {
		return os.ErrNotExist
	}
	m.buckets[bucket][dst] = v
	delete(m.buckets[bucket], src)
	return nil
}

func (m *memStore) Delete(_ context.Context, bucket, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.buckets[bucket], key)
	return nil
}

func (m *memStore) has(bucket, key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.buckets[bucket][key]
	return ok
}

func testRegistry(t *testing.T) *policy.Registry {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "default.json"),
		[]byte(`{"literals":[{"value":"AcmeCorp","replacement":"[CO]"}],"presets":["email"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := policy.New(dir, "default", nil)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func newTestWorker(t *testing.T, ms *memStore) *Worker {
	t.Helper()
	m := metrics.New(prometheus.NewRegistry())
	jl := metrics.NewJobLog(10)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := Config{
		InputBucket: "input", OutputBucket: "output", ReportsBucket: "reports",
		Action: ActionMove, PollInterval: time.Hour, Workers: 2, RedactReports: true,
		Limits: pipeline.DefaultLimits(),
	}
	return New(ms, testRegistry(t), m, jl, cfg, log)
}

func TestWorkerScrubsAndMoves(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	ms.Put(context.Background(), "input", "app.log", []byte("hi from AcmeCorp email bob@acme.test\n"), "")

	w := newTestWorker(t, ms)
	w.pollOnce(context.Background())

	out, err := ms.Get(context.Background(), "output", "app.log")
	if err != nil {
		t.Fatalf("no output written: %v", err)
	}
	if strings.Contains(string(out), "AcmeCorp") || strings.Contains(string(out), "bob@acme.test") {
		t.Errorf("output not scrubbed: %q", out)
	}
	if !strings.Contains(string(out), "[CO]") || !strings.Contains(string(out), "[EMAIL]") {
		t.Errorf("expected replacements missing: %q", out)
	}
	if !ms.has("reports", "app.log.report.json") {
		t.Error("report not written")
	}
	if ms.has("input", "app.log") {
		t.Error("input not moved out of the way")
	}
	if !ms.has("input", "processed/app.log") {
		t.Error("input not moved to processed/ prefix")
	}
}

func TestWorkerSkipsOversizedWithoutCrashing(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	big := bytes.Repeat([]byte("x"), 1024)
	ms.Put(context.Background(), "input", "huge.log", big, "")

	w := newTestWorker(t, ms)
	w.cfg.MaxObjectBytes = 256 // smaller than the object

	w.pollOnce(context.Background()) // must not OOM/crash

	if ms.has("output", "huge.log") {
		t.Error("oversized object should not have produced output")
	}
	if ms.has("input", "huge.log") {
		t.Error("oversized input should be moved aside so it isn't retried")
	}
	if !ms.has("input", "processed/huge.log") {
		t.Error("oversized input should be moved to processed/")
	}
}

func TestWorkerScrubsFilenames(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	ms.Put(context.Background(), "input", "AcmeCorp-dump.log", []byte("inner has AcmeCorp too\n"), "")

	w := newTestWorker(t, ms)
	w.cfg.ScrubNames = true
	w.pollOnce(context.Background())

	if !ms.has("output", "[CO]-dump.log") {
		t.Errorf("output object key should be scrubbed to [CO]-dump.log")
	}
	if ms.has("output", "AcmeCorp-dump.log") {
		t.Errorf("output should not carry the sensitive filename")
	}
}

func TestWorkerPerObjectOverride(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	ms.Put(context.Background(), "input", "x.log", []byte("keep AcmeCorp but hide zzz-secret\n"), "")
	// override policy: only scrub the literal zzz-secret, leave AcmeCorp
	ms.Put(context.Background(), "input", "x.log.terms.json",
		[]byte(`{"literals":[{"value":"zzz-secret","replacement":"[GONE]"}]}`), "")

	w := newTestWorker(t, ms)
	w.pollOnce(context.Background())

	out, _ := ms.Get(context.Background(), "output", "x.log")
	if strings.Contains(string(out), "zzz-secret") {
		t.Errorf("override rule not applied: %q", out)
	}
	if !strings.Contains(string(out), "AcmeCorp") {
		t.Errorf("override should not apply default rules: %q", out)
	}
	if ms.has("input", "x.log.terms.json") {
		t.Error("override sidecar should be consumed")
	}
}

func TestWorkerSkipsCorruptWithoutCrashing(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	// a "zip" that isn't valid -> pipeline passes it through unchanged
	ms.Put(context.Background(), "input", "broken.zip", append([]byte("PK\x03\x04"), []byte("nope")...), "")

	w := newTestWorker(t, ms)
	w.pollOnce(context.Background()) // must not panic

	out, err := ms.Get(context.Background(), "output", "broken.zip")
	if err != nil {
		t.Fatalf("corrupt object should still produce output: %v", err)
	}
	if string(out) != "PK\x03\x04nope" {
		t.Errorf("corrupt object should pass through byte-identical, got %q", out)
	}
}

// panicStore wraps a memStore and panics on Put, simulating a bug anywhere in
// the per-object path.
type panicStore struct {
	*memStore
	panicOn string
}

func (p *panicStore) Put(ctx context.Context, bucket, key string, data []byte, ct string) error {
	if bucket == p.panicOn {
		panic("simulated bug in the object path")
	}
	return p.memStore.Put(ctx, bucket, key, data, ct)
}

// TestWorkerSurvivesPanic checks that a panic costs one object rather than the
// whole service. Without recovery the goroutine takes the process down, which
// orphans every in-flight upload and wipes the in-memory job history — the
// failure mode behind "stuck forever while MinIO shows the object finished".
func TestWorkerSurvivesPanic(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	ms.Put(context.Background(), "input", "boom.log", []byte("AcmeCorp\n"), "")
	ms.Put(context.Background(), "input", "fine.log", []byte("AcmeCorp\n"), "")

	ps := &panicStore{memStore: ms, panicOn: "output"}
	w := newTestWorker(t, ms)
	w.store = ps

	// Must return normally rather than taking the test process down.
	w.pollOnce(context.Background())

	var sawError bool
	for _, j := range w.jobs.Recent() {
		if j.Status == "error" && strings.Contains(j.Error, "panic") {
			sawError = true
		}
	}
	if !sawError {
		t.Error("panic should be recorded as a job error so the UI stops waiting")
	}
}

// TestWorkerReportsUnscrubbedFiles checks that an object containing a member the
// pipeline could not inspect is reported with a non-zero passthrough count, so
// the UI can warn instead of showing a green check.
func TestWorkerReportsUnscrubbedFiles(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	sevenZip := append([]byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}, bytes.Repeat([]byte{1}, 64)...)
	ms.Put(context.Background(), "input", "vendor.7z", sevenZip, "")

	w := newTestWorker(t, ms)
	w.pollOnce(context.Background())

	jobs := w.jobs.Recent()
	if len(jobs) == 0 {
		t.Fatal("no job recorded")
	}
	j := jobs[len(jobs)-1]
	if j.Status != "scrubbed" {
		t.Fatalf("status = %q, want scrubbed", j.Status)
	}
	if j.Passthrough == 0 {
		t.Error("passthrough count should be non-zero for an uninspectable container")
	}
	if len(j.PassthroughPaths) == 0 {
		t.Error("passthrough paths should name the uninspected file")
	}
}
