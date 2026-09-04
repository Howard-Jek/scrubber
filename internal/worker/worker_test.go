package worker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/howard/scrubber/internal/scrub"
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

// memStoreEpoch is the fake clock's origin. Object times are assigned from a
// monotonically advancing counter rather than time.Now() so ordering assertions are
// deterministic: Put means "arrived after everything already stored".
var memStoreEpoch = time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

// memStore is an in-memory ObjectStore for tests.
type memStore struct {
	mu      sync.Mutex
	buckets map[string]map[string][]byte
	at      map[string]time.Time // "bucket/key" -> LastModified
	clock   time.Time
	// stallReads makes every object read fail as store.ErrStalled, modelling a
	// backend that accepts the request and then goes quiet.
	stallReads bool
}

func newMemStore(names ...string) *memStore {
	m := &memStore{
		buckets: map[string]map[string][]byte{},
		at:      map[string]time.Time{},
		clock:   memStoreEpoch,
	}
	for _, n := range names {
		m.buckets[n] = map[string][]byte{}
	}
	return m
}

func stamp(bucket, key string) string { return bucket + "/" + key }

// putAt stores an object with an explicit arrival time. Tests that assert ordering
// use this; plain Put keeps assigning increasing times, so existing tests are
// unaffected.
func (m *memStore) putAt(bucket, key string, data []byte, at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.buckets[bucket] == nil {
		m.buckets[bucket] = map[string][]byte{}
	}
	m.buckets[bucket][key] = append([]byte(nil), data...)
	m.at[stamp(bucket, key)] = at
}

func (m *memStore) List(_ context.Context, bucket, prefix string) ([]store.Object, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Object
	for k, v := range m.buckets[bucket] {
		if strings.HasPrefix(k, prefix) {
			out = append(out, store.Object{
				Key: k, Size: int64(len(v)), LastModified: m.at[stamp(bucket, k)],
			})
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

func (m *memStore) PutStream(ctx context.Context, bucket, key string, r io.Reader, _ int64, ct string) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return m.Put(ctx, bucket, key, data, ct)
}

func (m *memStore) Stat(_ context.Context, bucket, key string) (store.Object, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.buckets[bucket][key]
	if !ok {
		return store.Object{}, false, nil
	}
	return store.Object{Key: key, Size: int64(len(v)), LastModified: m.at[stamp(bucket, key)]}, true, nil
}

func (m *memStore) GetLimitedTo(_ context.Context, w io.Writer, bucket, key string, max int64) (int64, error) {
	m.mu.Lock()
	v, ok := m.buckets[bucket][key]
	stall := m.stallReads
	m.mu.Unlock()
	if stall {
		return 0, fmt.Errorf("%w after 0 bytes: nothing moved for the stall timeout", store.ErrStalled)
	}
	if !ok {
		return 0, os.ErrNotExist
	}
	if int64(len(v)) > max {
		return 0, store.ErrTooLarge
	}
	n, err := w.Write(v)
	return int64(n), err
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
	m.clock = m.clock.Add(time.Millisecond)
	m.at[stamp(bucket, key)] = m.clock
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
	m.at[stamp(bucket, dst)] = m.at[stamp(bucket, src)]
	delete(m.buckets[bucket], src)
	delete(m.at, stamp(bucket, src))
	return nil
}

func (m *memStore) Delete(_ context.Context, bucket, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.buckets[bucket], key)
	delete(m.at, stamp(bucket, key))
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
		Action: ActionMove, PollInterval: time.Hour, Workers: 1, RedactReports: true,
		Limits: pipeline.DefaultLimits(),
	}
	return New(ms, testRegistry(t), m, jl, cfg, log)
}

// TestStalledReadIsRetryableAndStepsAside covers both halves of how a stalled
// transfer must behave, because getting either one wrong is silently bad.
//
// It must be RETRYABLE: the object is still in the input bucket and will be picked
// up again, so recording it as a terminal error made the upload page give up and
// show a permanent failure for work that then completed on the next attempt.
//
// And it must STEP ASIDE: without a backoff the object keeps its original
// LastModified, which is by definition the oldest in the bucket, so it returns to
// the head of the queue and every upload behind it pays the stall timeout again on
// every cycle. One unreadable object would throttle everybody.
func TestStalledReadIsRetryableAndStepsAside(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	ms.Put(context.Background(), "input", "big.zip", []byte("hi from AcmeCorp\n"), "")
	ms.stallReads = true

	m := metrics.New(prometheus.NewRegistry())
	jl := metrics.NewJobLog(10)
	w := New(ms, testRegistry(t), m, jl,
		Config{
			InputBucket: "input", OutputBucket: "output", ReportsBucket: "reports",
			Action: ActionMove, PollInterval: time.Hour, Workers: 1,
			Limits: pipeline.DefaultLimits(),
		},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	w.runOnce(context.Background())

	j, ok := jl.Get("big.zip")
	if !ok {
		t.Fatal("no job recorded for the stalled object")
	}
	if j.Status != "retrying" {
		t.Errorf("status = %q, want retrying (a stall is the backend's fault, not the object's)", j.Status)
	}
	if j.Done() {
		t.Error("a retrying job must not be terminal, or the client stops waiting on work that will complete")
	}
	if j.RetryInSeconds <= 0 {
		t.Errorf("RetryInSeconds = %d, want > 0 so the page can say when", j.RetryInSeconds)
	}

	// Still in the input bucket: nothing was moved aside, so it will be retried.
	if !ms.has("input", "big.zip") {
		t.Error("stalled input was consumed; it must stay for the retry")
	}
	if ms.has("output", "big.zip") {
		t.Error("a stalled read must not produce output")
	}

	// And it is held back rather than immediately re-eligible at the head.
	if w.eligible(store.Object{Key: "big.zip"}, time.Now()) {
		t.Error("stalled object is immediately eligible again; it will retake the head of the queue " +
			"every cycle and stall everything behind it")
	}
}

func TestWorkerScrubsAndMoves(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	ms.Put(context.Background(), "input", "app.log", []byte("hi from AcmeCorp email bob@acme.test\n"), "")

	w := newTestWorker(t, ms)
	w.runOnce(context.Background())

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

	w.runOnce(context.Background()) // must not OOM/crash

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
	w.runOnce(context.Background())

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
	w.runOnce(context.Background())

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
	w.runOnce(context.Background()) // must not panic

	// It is diverted, and that is the point. Nothing inside this object could be
	// read, so nothing can vouch for it: a container the safety net cannot open
	// scores a clean scan for the same reason a locked box does. It used to land
	// in the normal output bucket beside genuinely scrubbed work, flagged only as
	// "incomplete" -- the same word a bundle containing one PNG gets.
	if ms.has("output", "broken.zip") {
		t.Error("a corrupt container was delivered as ordinary output; it is unreadable, " +
			"so it must not sit where a consumer looks for finished work")
	}
	out, err := ms.Get(context.Background(), "output", "review/broken.zip")
	if err != nil {
		t.Fatalf("corrupt object should still be emitted, under review/: %v", err)
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

// PutStream is the path the worker actually takes for the scrubbed output; without
// it the panic would never be injected.
func (p *panicStore) PutStream(ctx context.Context, bucket, key string, r io.Reader, size int64, ct string) error {
	if bucket == p.panicOn {
		panic("simulated bug in the object path")
	}
	return p.memStore.PutStream(ctx, bucket, key, r, size, ct)
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
	w.runOnce(context.Background())

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
	w.runOnce(context.Background())

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

// failMoveStore fails Move a fixed number of times, then succeeds.
type failMoveStore struct {
	*memStore
	failures int
	calls    int
}

func (f *failMoveStore) Move(ctx context.Context, bucket, src, dst string) error {
	f.calls++
	if f.calls <= f.failures {
		return errors.New("simulated copy failure")
	}
	return f.memStore.Move(ctx, bucket, src, dst)
}

// TestFinalizeFailureBacksOff covers the re-processing loop: when an input
// cannot be moved to processed/ it stays in the input bucket, so the next poll
// picks it up again. Unbounded, that re-scrubs the same object forever, rewrites
// the same output, and churns the job ring so unrelated records are evicted.
func TestFinalizeFailureBacksOff(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	ms.Put(context.Background(), "input", "stuck.log", []byte("AcmeCorp\n"), "")

	fs := &failMoveStore{memStore: ms, failures: 99} // never succeeds
	w := newTestWorker(t, ms)
	w.store = fs

	w.runOnce(context.Background())
	if fs.calls != 1 {
		t.Fatalf("first poll should attempt the move once, got %d", fs.calls)
	}

	// Immediately polling again must NOT re-process: the key is in backoff.
	w.runOnce(context.Background())
	if fs.calls != 1 {
		t.Errorf("object was re-processed during backoff (move attempts = %d)", fs.calls)
	}

	// Once the backoff expires it is retried rather than abandoned.
	w.mu.Lock()
	w.deferUntil["stuck.log"] = time.Now().Add(-time.Second)
	w.mu.Unlock()
	w.runOnce(context.Background())
	if fs.calls != 2 {
		t.Errorf("object should be retried after backoff, move attempts = %d", fs.calls)
	}
}

// TestFinalizeSuccessClearsBackoff checks the backoff state does not leak for
// keys that eventually succeed.
func TestFinalizeSuccessClearsBackoff(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	ms.Put(context.Background(), "input", "ok.log", []byte("AcmeCorp\n"), "")

	fs := &failMoveStore{memStore: ms, failures: 1}
	w := newTestWorker(t, ms)
	w.store = fs

	w.runOnce(context.Background()) // fails, backs off
	w.mu.Lock()
	w.deferUntil["ok.log"] = time.Now().Add(-time.Second)
	w.mu.Unlock()
	w.runOnce(context.Background()) // succeeds

	w.mu.Lock()
	_, held := w.deferUntil["ok.log"]
	_, tried := w.attempts["ok.log"]
	w.mu.Unlock()
	if held || tried {
		t.Error("backoff state should be cleared once the object finalizes")
	}
}

// --- queue behaviour ---

// serialProbe brackets each object's processing. GetLimited is always the first
// store call for an object and Move the last on the success path, so the bracket
// records both the order objects were started in and how many ran at once. The
// sleep widens the window: without it a genuine fan-out could interleave so briefly
// that the counter never observes a depth above one.
type serialProbe struct {
	*memStore
	mu       sync.Mutex
	order    []string
	depth    int
	maxDepth int
}

func (p *serialProbe) GetLimitedTo(ctx context.Context, w io.Writer, bucket, key string, max int64) (int64, error) {
	p.mu.Lock()
	p.depth++
	if p.depth > p.maxDepth {
		p.maxDepth = p.depth
	}
	p.order = append(p.order, key)
	p.mu.Unlock()
	time.Sleep(2 * time.Millisecond)
	return p.memStore.GetLimitedTo(ctx, w, bucket, key, max)
}

func (p *serialProbe) Move(ctx context.Context, bucket, src, dst string) error {
	err := p.memStore.Move(ctx, bucket, src, dst)
	p.mu.Lock()
	p.depth--
	p.mu.Unlock()
	return err
}

func (p *serialProbe) started() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.order...)
}

func newProbeWorker(t *testing.T, ms *memStore) (*Worker, *serialProbe) {
	t.Helper()
	p := &serialProbe{memStore: ms}
	w := newTestWorker(t, ms)
	w.store = p
	return w, p
}

func wantOrder(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("processing order = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("processing order = %v, want %v", got, want)
		}
	}
}

// TestWorkerProcessesOneObjectAtATime is the core guarantee: on a one-CPU pod with
// a memory budget sized for a single object, two concurrent scrubs only slow each
// other down and push resident memory toward the container limit.
func TestWorkerProcessesOneObjectAtATime(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	for i := 0; i < 10; i++ {
		ms.Put(context.Background(), "input", "f"+string(rune('0'+i))+".log", []byte("AcmeCorp\n"), "")
	}

	w, p := newProbeWorker(t, ms)
	w.runOnce(context.Background())

	if p.maxDepth != 1 {
		t.Errorf("max concurrent objects = %d, want 1", p.maxDepth)
	}
	if n := len(p.started()); n != 10 {
		t.Errorf("processed %d objects, want 10", n)
	}
}

// TestWorkerProcessesInArrivalOrder pins first-come-first-serve. The keys sort in
// the exact reverse of their arrival times, and memStore.List iterates a Go map, so
// a pass proves the order comes from the queue rather than from the listing.
func TestWorkerProcessesInArrivalOrder(t *testing.T) {
	// Repeated because map iteration order is random: a single pass could get the
	// right answer by luck.
	for round := 0; round < 5; round++ {
		ms := newMemStore("input", "output", "reports")
		ms.putAt("input", "zz-first.log", []byte("AcmeCorp\n"), memStoreEpoch.Add(1*time.Second))
		ms.putAt("input", "mm-second.log", []byte("AcmeCorp\n"), memStoreEpoch.Add(2*time.Second))
		ms.putAt("input", "aa-third.log", []byte("AcmeCorp\n"), memStoreEpoch.Add(3*time.Second))

		w, p := newProbeWorker(t, ms)
		w.runOnce(context.Background())

		wantOrder(t, p.started(), []string{"zz-first.log", "mm-second.log", "aa-third.log"})
	}
}

// TestWorkerMultiTenantInterleavedArrivalOrder is the reported scenario: five people
// uploading five packages each, all landing at once. Every upload must be served in
// the order it arrived regardless of who sent it.
func TestWorkerMultiTenantInterleavedArrivalOrder(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	var want []string
	tick := 0
	for f := 1; f <= 5; f++ {
		for u := 1; u <= 5; u++ {
			tick++
			key := "user" + string(rune('0'+u)) + "-file" + string(rune('0'+f)) + ".log"
			ms.putAt("input", key, []byte("AcmeCorp\n"), memStoreEpoch.Add(time.Duration(tick)*time.Second))
			want = append(want, key)
		}
	}

	w, p := newProbeWorker(t, ms)
	w.runOnce(context.Background())

	wantOrder(t, p.started(), want)
	if p.maxDepth != 1 {
		t.Errorf("max concurrent objects = %d, want 1", p.maxDepth)
	}
}

// TestWorkerRetriedObjectDoesNotJumpTheQueue guards the head-of-line failure mode.
// A key whose move to processed/ keeps failing has the oldest LastModified in the
// bucket, so ordering retries by arrival would put it at position 0 on every backoff
// expiry — one unmovable object would then re-scrub itself ahead of every real
// upload, once a minute, forever.
func TestWorkerRetriedObjectDoesNotJumpTheQueue(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	ms.putAt("input", "stuck.log", []byte("AcmeCorp\n"), memStoreEpoch)

	fs := &failMoveStore{memStore: ms, failures: 99} // never finalizes
	w := newTestWorker(t, ms)
	w.store = fs
	w.runOnce(context.Background()) // stuck.log runs once, then backs off

	// Three uploads land while it is held back.
	for i, k := range []string{"b.log", "c.log", "d.log"} {
		ms.putAt("input", k, []byte("AcmeCorp\n"), memStoreEpoch.Add(time.Duration(i+1)*time.Second))
	}

	p := &serialProbe{memStore: ms}
	w.store = &probeThenFailMove{serialProbe: p}

	// Expire the backoff so stuck.log is eligible again on the next discovery.
	w.mu.Lock()
	w.deferUntil["stuck.log"] = time.Now().Add(-time.Second)
	w.mu.Unlock()
	w.runOnce(context.Background())

	wantOrder(t, p.started(), []string{"b.log", "c.log", "d.log", "stuck.log"})
}

// probeThenFailMove records the processing bracket while still failing every Move,
// so the retried object stays un-finalized for the duration of the test.
type probeThenFailMove struct {
	*serialProbe
}

func (p *probeThenFailMove) Move(_ context.Context, _, _, _ string) error {
	p.serialProbe.mu.Lock()
	p.serialProbe.depth--
	p.serialProbe.mu.Unlock()
	return errors.New("simulated copy failure")
}

func TestWorkerQueueExcludesSidecarsAndProcessed(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	ms.Put(context.Background(), "input", "x.log", []byte("AcmeCorp\n"), "")
	ms.Put(context.Background(), "input", "x.log.terms.json", []byte(`{"literals":[]}`), "")
	ms.Put(context.Background(), "input", "processed/old.log", []byte("AcmeCorp\n"), "")

	w := newTestWorker(t, ms)
	w.discoverOnce(context.Background(), "test")

	if got := w.q.Depth(); got != 1 {
		inflight, pending := w.q.Snapshot(0)
		t.Errorf("queue depth = %d, want 1 (inflight=%v pending=%v)", got, inflight, pending)
	}
}

// TestWorkerDeferralStateSweptForVanishedKeys covers a leak that matters more now
// that orderKey reads deferUntil: a key that disappears while in backoff would keep
// its attempt count forever, and a later object reusing that key would be ordered as
// a retry rather than as the new arrival it is.
func TestWorkerDeferralStateSweptForVanishedKeys(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	ms.Put(context.Background(), "input", "gone.log", []byte("AcmeCorp\n"), "")

	fs := &failMoveStore{memStore: ms, failures: 99}
	w := newTestWorker(t, ms)
	w.store = fs
	w.runOnce(context.Background()) // populates deferUntil/attempts

	w.mu.Lock()
	_, held := w.deferUntil["gone.log"]
	w.mu.Unlock()
	if !held {
		t.Fatal("expected backoff state after a failed finalize")
	}

	ms.Delete(context.Background(), "input", "gone.log")
	w.discoverOnce(context.Background(), "test")

	w.mu.Lock()
	nDefer, nAttempts := len(w.deferUntil), len(w.attempts)
	w.mu.Unlock()
	if nDefer != 0 || nAttempts != 0 {
		t.Errorf("backoff state not swept: deferUntil=%d attempts=%d", nDefer, nAttempts)
	}
}

// TestWorkerRunStopsPullingOnCancel checks that shutdown stops taking new work
// rather than draining the backlog. Starting a fresh object moments before SIGKILL
// wastes the whole scrub.
func TestWorkerRunStopsPullingOnCancel(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	for i := 0; i < 20; i++ {
		ms.Put(context.Background(), "input", "f"+string(rune('a'+i))+".log", []byte("AcmeCorp\n"), "")
	}

	w, p := newProbeWorker(t, ms)
	w.cfg.PollInterval = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()

	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
	if n := len(p.started()); n >= 20 {
		t.Errorf("started %d of 20 objects; cancellation should have stopped the consumer early", n)
	}
	if p.maxDepth != 1 {
		t.Errorf("max concurrent objects = %d, want 1", p.maxDepth)
	}
}

// ctxStore refuses writes once its context is cancelled, the way a real store does.
type ctxStore struct{ *memStore }

func (c *ctxStore) Put(ctx context.Context, bucket, key string, data []byte, ct string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.memStore.Put(ctx, bucket, key, data, ct)
}

func (c *ctxStore) Move(ctx context.Context, bucket, src, dst string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.memStore.Move(ctx, bucket, src, dst)
}

// TestWorkerFinalizesUnderCancelledContext checks that an object which finished
// scrubbing still gets its result persisted when the process is shutting down.
// Without the detached write the scrub is thrown away and has to be redone after the
// restart — the expensive half of the work, discarded at the cheap half's expense.
func TestWorkerFinalizesUnderCancelledContext(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	ms.Put(context.Background(), "input", "late.log", []byte("AcmeCorp bob@acme.test\n"), "")

	w := newTestWorker(t, ms)
	w.store = &ctxStore{memStore: ms}

	ctx, cancel := context.WithCancel(context.Background())
	w.discoverOnce(ctx, "test") // list while the context is still live
	cancel()                    // SIGTERM arrives mid-object

	it, ok := w.q.TryNext()
	if !ok {
		t.Fatal("expected a queued object")
	}
	w.handle(ctx, it)

	if !ms.has("output", "late.log") {
		t.Error("scrubbed output was discarded on shutdown")
	}
	if !ms.has("reports", "late.log.report.json") {
		t.Error("report was discarded on shutdown")
	}
	if !ms.has("reports", "late.log.summary.json") {
		t.Error("digest was discarded on shutdown")
	}
	if !ms.has("input", "processed/late.log") {
		t.Error("input was not finalized on shutdown, so it will be scrubbed again")
	}
}

// TestWorkerRecordsQueueMetrics checks the wait and end-to-end latency observations
// that the benchmark harness reads.
func TestWorkerRecordsQueueMetrics(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	for _, k := range []string{"a.log", "b.log", "c.log"} {
		ms.Put(context.Background(), "input", k, []byte("AcmeCorp\n"), "")
	}

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	w := New(ms, testRegistry(t), m, metrics.NewJobLog(10), Config{
		InputBucket: "input", OutputBucket: "output", ReportsBucket: "reports",
		Action: ActionMove, PollInterval: time.Hour, Workers: 1,
		Limits: pipeline.DefaultLimits(),
	}, log)
	w.runOnce(context.Background())

	for _, name := range []string{"scrubber_queue_wait_seconds", "scrubber_object_latency_seconds"} {
		if got := countHistogram(t, reg, name); got != 3 {
			t.Errorf("%s sample count = %d, want 3", name, got)
		}
	}
}

func countHistogram(t *testing.T, g prometheus.Gatherer, name string) uint64 {
	t.Helper()
	families, err := g.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		var n uint64
		for _, mm := range f.GetMetric() {
			n += mm.GetHistogram().GetSampleCount()
		}
		return n
	}
	t.Fatalf("metric %q not registered", name)
	return 0
}

// TestWorkerClampsConcurrency guards the config: honouring a larger WORKERS would
// let one line reintroduce the concurrent scrubs this queue exists to remove.
func TestWorkerClampsConcurrency(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	w := newTestWorker(t, ms)
	w.cfg.Workers = 8
	w2 := New(ms, testRegistry(t), w.metrics, w.jobs, w.cfg, w.log)
	if w2.cfg.Workers != 1 {
		t.Errorf("Workers = %d, want 1", w2.cfg.Workers)
	}
}

// TestDisplayPathRedactsMemberNames is a disclosure test, not a formatting one.
//
// Member paths are recorded UNSCRUBBED on purpose — the report is an audit record in
// an internal bucket and an operator verifying a scrub needs the real name. But
// /api/status is unauthenticated, served on the external Route, and polled every
// second by the browser, and SCRUB_FILENAMES defaults to true precisely because a
// path carries the same class of data as a file body. Sending the original down that
// channel would have the tool broadcast live exactly what it was asked to remove.
//
// Verified against the real pipeline before this existed: a member named
// "logs/AcmeCorp-prod/alice@acme.test-session.log" is scrubbed in the emitted bundle
// and was still reported verbatim in current_file.
func TestDisplayPathRedactsMemberNames(t *testing.T) {
	m, err := scrub.NewMatcher("[REDACTED]", []scrub.Rule{
		{ID: "literal:AcmeCorp", Replacement: "[COMPANY]", Pattern: `AcmeCorp`},
		{ID: "email", Replacement: "[EMAIL]", Pattern: `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`},
	})
	if err != nil {
		t.Fatalf("matcher: %v", err)
	}

	const raw = "abc123-bundle.tar!logs/AcmeCorp-prod/alice@acme.test-session.log"
	got := displayPath(m, raw)

	for _, leak := range []string{"AcmeCorp", "alice@acme.test"} {
		if strings.Contains(got, leak) {
			t.Errorf("displayPath leaked %q into an unauthenticated field: %s", leak, got)
		}
	}
	if !strings.Contains(got, "[COMPANY]") || !strings.Contains(got, "[EMAIL]") {
		t.Errorf("displayPath = %q, want the policy's labels in place of the matches", got)
	}
	// The structure has to survive, or the display stops being useful. Note the
	// email rule greedily takes "-session.log" with it, since that suffix is still
	// inside the domain pattern -- over-redacting a filename is the safe direction,
	// so the assertion is on the path's SHAPE rather than on any surviving segment.
	if !strings.Contains(got, "bundle.tar!") || !strings.Contains(got, "logs/") {
		t.Errorf("displayPath = %q, want the path shape preserved", got)
	}
}

// TestDisplayPathPassesCleanPathsThrough: the common case must be untouched, or every
// ordinary filename would render as noise.
func TestDisplayPathPassesCleanPathsThrough(t *testing.T) {
	m, err := scrub.NewMatcher("[REDACTED]", []scrub.Rule{
		{ID: "literal:AcmeCorp", Replacement: "[COMPANY]", Pattern: `AcmeCorp`},
	})
	if err != nil {
		t.Fatalf("matcher: %v", err)
	}
	const clean = "bundle.tar!logs/service/application.log"
	if got := displayPath(m, clean); got != clean {
		t.Errorf("displayPath(%q) = %q, want it unchanged", clean, got)
	}
	// A nil matcher must not panic — the CLI path builds jobs without one.
	if got := displayPath(nil, clean); got != clean {
		t.Errorf("displayPath with a nil matcher = %q, want %q", got, clean)
	}
}
