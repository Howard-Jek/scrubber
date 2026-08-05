package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/howard/scrubber/internal/metrics"
	"github.com/howard/scrubber/internal/report"
	"github.com/howard/scrubber/internal/store"
	"github.com/prometheus/client_golang/prometheus"
)

// fakeArchive is an in-memory stand-in for the object store.
type fakeArchive struct {
	objs map[string]map[string][]byte // bucket -> key -> body
	at   map[string]time.Time         // key -> LastModified
	err  error
	// gets counts object reads so a test can assert a path did no storage I/O.
	// Atomic because apiHistory reads digests through a bounded goroutine fan-out.
	gets atomic.Int64
}

// fakeQueue is a fixed QueueView answer.
type fakeQueue struct {
	pos, depth int
	ok         bool
	inflight   []string
	pending    []string
}

func (f fakeQueue) Position(string) (int, int, bool)  { return f.pos, f.depth, f.ok }
func (f fakeQueue) Snapshot(int) ([]string, []string) { return f.inflight, f.pending }
func (f fakeQueue) Depth() int                        { return f.depth }

func newArchive() *fakeArchive {
	return &fakeArchive{objs: map[string]map[string][]byte{}, at: map[string]time.Time{}}
}

func (f *fakeArchive) put(bucket, key string, body []byte, at time.Time) {
	if f.objs[bucket] == nil {
		f.objs[bucket] = map[string][]byte{}
	}
	f.objs[bucket][key] = body
	f.at[bucket+"/"+key] = at
}

func (f *fakeArchive) List(_ context.Context, bucket, prefix string) ([]store.Object, error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []store.Object
	for k, v := range f.objs[bucket] {
		out = append(out, store.Object{Key: k, Size: int64(len(v)), LastModified: f.at[bucket+"/"+k]})
	}
	return out, nil
}

func (f *fakeArchive) Get(_ context.Context, bucket, key string) ([]byte, error) {
	f.gets.Add(1)
	b, ok := f.objs[bucket][key]
	if !ok {
		return nil, os.ErrNotExist
	}
	return b, nil
}

func (f *fakeArchive) Stat(_ context.Context, bucket, key string) (store.Object, bool, error) {
	b, ok := f.objs[bucket][key]
	if !ok {
		return store.Object{}, false, nil
	}
	return store.Object{Key: key, Size: int64(len(b))}, true, nil
}

type fakePresigner struct{}

func (fakePresigner) PresignPut(_ context.Context, b, k string, _ time.Duration) (string, error) {
	return "https://example.invalid/" + b + "/" + k + "?put", nil
}
func (fakePresigner) PresignGet(_ context.Context, b, k string, _ time.Duration) (string, error) {
	return "https://example.invalid/" + b + "/" + k + "?get", nil
}

// storedDigest builds the compact record the API reads.
func storedDigest(t *testing.T, inKey, outKey string, matches, passthrough int) []byte {
	t.Helper()
	var notes []report.PassthroughNote
	for i := 0; i < passthrough; i++ {
		notes = append(notes, report.PassthroughNote{
			Path: fmt.Sprintf("blob%d.7z", i), Status: report.StatusUnsupported, Code: report.ReasonUnsupported, Detail: "read-only format"})
	}
	b, err := json.Marshal(report.Digest{
		InputKey: inKey, OutputKey: outKey, Matches: matches,
		FilesTotal: matches + passthrough, Passthrough: passthrough, Passthroughs: notes,
		BytesIn: 1000, BytesOut: 900,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func storedReport(t *testing.T, inKey, outKey string, matches, passthrough int) []byte {
	t.Helper()
	rep := report.New(inKey, outKey, report.AuditFull, false, "test")
	rep.InputKey = inKey
	rep.OutputKey = outKey
	rep.BytesIn = 1000
	rep.BytesOut = 900
	for i := 0; i < matches; i++ {
		rep.Record(fmt.Sprintf("f%d.log", i), report.StatusScrubbed, "", 10, 10, nil)
		rep.Summary.TotalMatches++
	}
	for i := 0; i < passthrough; i++ {
		rep.Record(fmt.Sprintf("blob%d.7z", i), report.StatusUnsupported, "read-only format", 10, 10, nil)
	}
	b, err := rep.JSON()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newTestServer(jobs *metrics.JobLog, arc Archive) http.Handler {
	return newTestServerQ(jobs, arc, nil, nil)
}

// newTestServerQ is newTestServer with the queue and nudge hooks wired.
func newTestServerQ(jobs *metrics.JobLog, arc Archive, q QueueView, nudge func()) http.Handler {
	return New(Deps{
		Policies:      nil,
		Jobs:          jobs,
		Prom:          prometheus.NewRegistry(),
		Presigner:     fakePresigner{},
		Archive:       arc,
		Queue:         q,
		Nudge:         nudge,
		InputBucket:   "input",
		OutputBucket:  "output",
		ReportsBucket: "reports",
		HistoryMax:    50,
	}).Handler()
}

func getJSON(t *testing.T, h http.Handler, path string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	var out map[string]any
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
	}
	return rec.Code, out
}

// TestStatusRecoversFromStorageAfterRestart is the regression test for the bug
// where the UI waited forever. The job log is per-process; after a restart it is
// empty even though the object finished and its report is in the bucket. The API
// must answer from storage rather than reporting "processing" indefinitely.
func TestStatusRecoversFromStorageAfterRestart(t *testing.T) {
	arc := newArchive()
	arc.put("reports", "abc123-bundle.tar.gz"+report.DigestSuffix,
		storedDigest(t, "abc123-bundle.tar.gz", "abc123-bundle.tar.gz", 7, 0), time.Now())

	// Empty job log == a process that has just restarted.
	h := newTestServer(metrics.NewJobLog(10), arc)

	code, body := getJSON(t, h, "/api/status?key=abc123-bundle.tar.gz")
	if code != http.StatusOK {
		t.Fatalf("status code = %d", code)
	}
	if body["status"] != "scrubbed" {
		t.Fatalf("status = %v, want scrubbed (recovered from the stored report)", body["status"])
	}
	if body["from"] != "storage" {
		t.Errorf("expected the answer to come from storage, got %v", body["from"])
	}
	if got := body["matches"]; got != float64(7) {
		t.Errorf("matches = %v, want 7", got)
	}
}

// TestStatusUnknownWhenNothingRecorded checks the client is told to stop waiting
// when neither the job log nor storage knows the key, instead of being handed a
// permanent "processing".
func TestStatusUnknownWhenNothingRecorded(t *testing.T) {
	h := newTestServer(metrics.NewJobLog(10), newArchive())

	_, body := getJSON(t, h, "/api/status?key=never-existed")
	if body["status"] != "unknown" {
		t.Fatalf("status = %v, want unknown", body["status"])
	}
	if body["error"] == nil || body["error"] == "" {
		t.Error("unknown status should explain itself")
	}
}

// TestStatusQueuedWhileInputPresent distinguishes "not started yet" from "lost".
func TestStatusQueuedWhileInputPresent(t *testing.T) {
	arc := newArchive()
	arc.put("input", "pending.log", []byte("data"), time.Now())
	h := newTestServer(metrics.NewJobLog(10), arc)

	_, body := getJSON(t, h, "/api/status?key=pending.log")
	if body["status"] != "processing" {
		t.Fatalf("status = %v, want processing", body["status"])
	}
	if body["phase"] != "queued" {
		t.Errorf("phase = %v, want queued", body["phase"])
	}
}

// TestStatusReportsLiveProgress checks in-flight progress reaches the client.
func TestStatusReportsLiveProgress(t *testing.T) {
	jobs := metrics.NewJobLog(10)
	jobs.Upsert(metrics.Job{Key: "big.tar.gz", Status: "processing", Phase: "scrubbing",
		FilesDone: 42, CurrentFile: "logs/app.log", Timestamp: time.Now()})

	h := newTestServer(jobs, newArchive())
	_, body := getJSON(t, h, "/api/status?key=big.tar.gz")

	if body["status"] != "processing" {
		t.Fatalf("status = %v", body["status"])
	}
	if body["files_done"] != float64(42) {
		t.Errorf("files_done = %v, want 42", body["files_done"])
	}
	if body["current_file"] != "logs/app.log" {
		t.Errorf("current_file = %v", body["current_file"])
	}
}

// TestStaleProcessingRecordFallsBackToStorage covers the case where this process
// still believes an object is in flight — a worker that died mid-write, or one
// re-processing the same object every poll because finalizing the input failed —
// while the finished report is already in storage. Without the staleness check
// the client would poll that stale record forever.
func TestStaleProcessingRecordFallsBackToStorage(t *testing.T) {
	jobs := metrics.NewJobLog(10)
	jobs.Upsert(metrics.Job{Key: "wedged.tar.gz", Status: "processing", Phase: "scrubbing",
		Timestamp: time.Now().Add(-10 * time.Minute)})

	arc := newArchive()
	arc.put("reports", "wedged.tar.gz"+report.DigestSuffix,
		storedDigest(t, "wedged.tar.gz", "wedged.tar.gz", 5, 0), time.Now())

	h := newTestServer(jobs, arc)
	_, body := getJSON(t, h, "/api/status?key=wedged.tar.gz")
	if body["status"] != "scrubbed" {
		t.Fatalf("status = %v, want scrubbed (stale record must not mask the stored result)", body["status"])
	}
}

// TestStatusSurfacesPassthroughWarning verifies an unscrubbed member reaches the
// client so the UI can warn rather than show success.
func TestStatusSurfacesPassthroughWarning(t *testing.T) {
	arc := newArchive()
	arc.put("reports", "x.zip"+report.DigestSuffix, storedDigest(t, "x.zip", "x.zip", 3, 2), time.Now())
	h := newTestServer(metrics.NewJobLog(10), arc)

	_, body := getJSON(t, h, "/api/status?key=x.zip")
	if body["passthrough"] != float64(2) {
		t.Fatalf("passthrough = %v, want 2", body["passthrough"])
	}
	paths, _ := body["passthrough_paths"].([]any)
	if len(paths) != 2 {
		t.Errorf("passthrough_paths length = %d, want 2", len(paths))
	}
}

// TestJobLogEvictionDoesNotStrandClient covers the ring overflowing while a
// client is still polling: the durable report must still answer.
func TestJobLogEvictionDoesNotStrandClient(t *testing.T) {
	jobs := metrics.NewJobLog(2)
	jobs.Upsert(metrics.Job{Key: "old.log", Status: "processing"})
	jobs.Upsert(metrics.Job{Key: "n1", Status: "scrubbed"})
	jobs.Upsert(metrics.Job{Key: "n2", Status: "scrubbed"}) // evicts old.log

	arc := newArchive()
	arc.put("reports", "old.log"+report.DigestSuffix, storedDigest(t, "old.log", "old.log", 1, 0), time.Now())

	h := newTestServer(jobs, arc)
	_, body := getJSON(t, h, "/api/status?key=old.log")
	if body["status"] != "scrubbed" {
		t.Fatalf("status = %v, want scrubbed after eviction", body["status"])
	}
}

// ---- history ----

func TestHistoryReturnsRecentRunsNewestFirst(t *testing.T) {
	arc := newArchive()
	base := time.Now()
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("run%d.log", i)
		arc.put("reports", key+report.DigestSuffix, storedDigest(t, key, key, i, 0),
			base.Add(time.Duration(i)*time.Minute))
	}
	h := newTestServer(metrics.NewJobLog(10), arc)

	_, body := getJSON(t, h, "/api/history")
	runs, _ := body["runs"].([]any)
	if len(runs) != 5 {
		t.Fatalf("runs = %d, want 5", len(runs))
	}
	first, _ := runs[0].(map[string]any)
	if first["key"] != "run4.log" {
		t.Errorf("newest run = %v, want run4.log", first["key"])
	}
}

func TestHistoryRespectsN(t *testing.T) {
	arc := newArchive()
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("r%d.log", i)
		arc.put("reports", key+report.DigestSuffix, storedDigest(t, key, key, 1, 0),
			time.Now().Add(time.Duration(i)*time.Minute))
	}
	h := newTestServer(metrics.NewJobLog(10), arc)

	_, body := getJSON(t, h, "/api/history?n=3")
	runs, _ := body["runs"].([]any)
	if len(runs) != 3 {
		t.Fatalf("runs = %d, want 3", len(runs))
	}
}

// TestHistoryCapsN prevents a client asking for an unbounded fan-out of reads.
func TestHistoryCapsN(t *testing.T) {
	arc := newArchive()
	for i := 0; i < 60; i++ {
		key := fmt.Sprintf("r%d.log", i)
		arc.put("reports", key+report.DigestSuffix, storedDigest(t, key, key, 1, 0), time.Now())
	}
	h := newTestServer(metrics.NewJobLog(10), arc) // HistoryMax 50

	_, body := getJSON(t, h, "/api/history?n=100000")
	runs, _ := body["runs"].([]any)
	if len(runs) > 50 {
		t.Fatalf("runs = %d, should be capped at HistoryMax=50", len(runs))
	}
}

func TestHistoryRejectsBadN(t *testing.T) {
	h := newTestServer(metrics.NewJobLog(10), newArchive())
	code, _ := getJSON(t, h, "/api/history?n=-4")
	if code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", code)
	}
}

// TestHistoryIgnoresNonReportObjects guards against sidecars or stray keys in
// the reports bucket becoming phantom history rows.
func TestHistoryIgnoresNonReportObjects(t *testing.T) {
	arc := newArchive()
	arc.put("reports", "real.log"+report.DigestSuffix, storedDigest(t, "real.log", "real.log", 1, 0), time.Now())
	arc.put("reports", "stray.txt", []byte("not a report"), time.Now())
	h := newTestServer(metrics.NewJobLog(10), arc)

	_, body := getJSON(t, h, "/api/history")
	runs, _ := body["runs"].([]any)
	if len(runs) != 1 {
		t.Fatalf("runs = %d, want 1 (stray objects must be ignored)", len(runs))
	}
}

// ---- downloads ----

// TestDownloadResolvesScrubbedOutputKeyFromReport covers downloading after a
// restart when filename scrubbing renamed the output: the mapping lives only in
// the stored report at that point.
func TestDownloadResolvesScrubbedOutputKeyFromReport(t *testing.T) {
	arc := newArchive()
	arc.put("reports", "AcmeCorp-dump.log"+report.DigestSuffix,
		storedDigest(t, "AcmeCorp-dump.log", "[CO]-dump.log", 2, 0), time.Now())
	h := newTestServer(metrics.NewJobLog(10), arc)

	_, body := getJSON(t, h, "/api/downloads?key=AcmeCorp-dump.log")
	url, _ := body["url"].(string)
	if url == "" {
		t.Fatal("no download URL minted")
	}
	if want := "output/[CO]-dump.log"; !contains(url, want) {
		t.Errorf("url = %q, want it to reference %q", url, want)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestStatusFallsBackToFullReportWhenDigestMissing covers runs recorded before
// digests existed: the compact record is absent, so the API must still recover
// the outcome from the full report rather than declaring the key unknown.
func TestStatusFallsBackToFullReportWhenDigestMissing(t *testing.T) {
	arc := newArchive()
	arc.put("reports", "legacy.tar.gz"+report.ObjectSuffix,
		storedReport(t, "legacy.tar.gz", "legacy-out.tar.gz", 4, 1), time.Now())

	h := newTestServer(metrics.NewJobLog(10), arc)
	_, body := getJSON(t, h, "/api/status?key=legacy.tar.gz")

	if body["status"] != "scrubbed" {
		t.Fatalf("status = %v, want scrubbed from the full report", body["status"])
	}
	if body["matches"] != float64(4) {
		t.Errorf("matches = %v, want 4", body["matches"])
	}
	if body["passthrough"] != float64(1) {
		t.Errorf("passthrough = %v, want 1", body["passthrough"])
	}
	if body["output_key"] != "legacy-out.tar.gz" {
		t.Errorf("output_key = %v", body["output_key"])
	}
}

// TestHistoryIgnoresFullReports guards the listing against reading the large
// per-match audit objects: only digests may drive the list, or rendering N rows
// would parse megabytes per run.
func TestHistoryIgnoresFullReports(t *testing.T) {
	arc := newArchive()
	arc.put("reports", "x.log"+report.DigestSuffix, storedDigest(t, "x.log", "x.log", 2, 0), time.Now())
	arc.put("reports", "x.log"+report.ObjectSuffix, storedReport(t, "x.log", "x.log", 2, 0), time.Now())

	h := newTestServer(metrics.NewJobLog(10), arc)
	_, body := getJSON(t, h, "/api/history")
	runs, _ := body["runs"].([]any)
	if len(runs) != 1 {
		t.Fatalf("runs = %d, want 1 (the full report must not add a second row)", len(runs))
	}
	first, _ := runs[0].(map[string]any)
	if first["key"] != "x.log" {
		t.Errorf("key = %v, want x.log", first["key"])
	}
}

// --- queue-aware status ---

func TestStatusReportsQueuePosition(t *testing.T) {
	arc := newArchive()
	arc.put("input", "waiting.tar.gz", []byte("x"), time.Now())
	h := newTestServerQ(metrics.NewJobLog(10), arc, fakeQueue{pos: 3, depth: 7, ok: true}, nil)

	code, body := getJSON(t, h, "/api/status?key=waiting.tar.gz")
	if code != 200 {
		t.Fatalf("status = %d, want 200", code)
	}
	if body["status"] != "processing" || body["phase"] != "queued" {
		t.Fatalf("payload = %v, want processing/queued", body)
	}
	if got := body["queue_position"]; got != float64(3) {
		t.Errorf("queue_position = %v, want 3", got)
	}
	if got := body["queue_depth"]; got != float64(7) {
		t.Errorf("queue_depth = %v, want 7", got)
	}
}

// TestStatusQueuedAnswerSkipsStorage is a load guard, not a correctness check. A
// queued key has no digest yet, so falling through to storage costs two failed
// object reads per client poll — with a full queue and second-scale polling that is
// dozens of pointless MinIO round-trips per second for the whole drain.
func TestStatusQueuedAnswerSkipsStorage(t *testing.T) {
	arc := newArchive()
	arc.put("input", "waiting.log", []byte("x"), time.Now())
	arc.put("reports", "waiting.log.summary.json", storedDigest(t, "waiting.log", "waiting.log", 1, 0), time.Now())
	h := newTestServerQ(metrics.NewJobLog(10), arc, fakeQueue{pos: 1, depth: 4, ok: true}, nil)

	if _, body := getJSON(t, h, "/api/status?key=waiting.log"); body["phase"] != "queued" {
		t.Fatalf("payload = %v, want phase queued", body)
	}
	if n := arc.gets.Load(); n != 0 {
		t.Errorf("queued status did %d object reads, want 0", n)
	}
}

// TestStatusTerminalJobBeatsQueuePosition pins the fall-through order. An object
// whose finalize failed is queued again for a retry, but its output already exists,
// so the client must be told it finished rather than sent back to waiting.
func TestStatusTerminalJobBeatsQueuePosition(t *testing.T) {
	jobs := metrics.NewJobLog(10)
	jobs.Upsert(metrics.Job{Key: "done.log", Status: "scrubbed", Matches: 2, Timestamp: time.Now()})
	h := newTestServerQ(jobs, newArchive(), fakeQueue{pos: 2, depth: 5, ok: true}, nil)

	_, body := getJSON(t, h, "/api/status?key=done.log")
	if body["status"] != "scrubbed" {
		t.Errorf("status = %v, want scrubbed", body["status"])
	}
	if _, present := body["queue_position"]; present {
		t.Error("a finished object should not report a queue position")
	}
}

func TestStatusWithoutQueueUnchanged(t *testing.T) {
	arc := newArchive()
	arc.put("input", "pending.log", []byte("x"), time.Now())
	h := newTestServer(metrics.NewJobLog(10), arc) // nil Queue and nil Nudge

	code, body := getJSON(t, h, "/api/status?key=pending.log")
	if code != 200 || body["status"] != "processing" || body["phase"] != "queued" {
		t.Fatalf("payload = %d %v, want 200 processing/queued", code, body)
	}
	if _, present := body["queue_position"]; present {
		t.Error("no queue wired: position must be omitted rather than reported as 0")
	}
}

// TestStatusNudgesOnUnseenUpload covers the discovery shortcut: the browser starts
// polling the moment its upload lands, so this request is the signal that new work
// exists. Without it a single upload into an idle bucket waits out a whole poll
// interval before anything happens.
func TestStatusNudgesOnUnseenUpload(t *testing.T) {
	arc := newArchive()
	arc.put("input", "fresh.log", []byte("x"), time.Now())
	var nudged int
	h := newTestServerQ(metrics.NewJobLog(10), arc, fakeQueue{ok: false}, func() { nudged++ })

	if _, body := getJSON(t, h, "/api/status?key=fresh.log"); body["phase"] != "queued" {
		t.Fatalf("payload = %v, want phase queued", body)
	}
	if nudged != 1 {
		t.Errorf("nudged %d times, want 1", nudged)
	}
}

// TestStatusDoesNotNudgeForKnownKeys guards against a nudge storm: every client
// poll for an already-tracked key must not ask the worker to re-list.
func TestStatusDoesNotNudgeForKnownKeys(t *testing.T) {
	jobs := metrics.NewJobLog(10)
	jobs.Upsert(metrics.Job{Key: "done.log", Status: "scrubbed", Timestamp: time.Now()})
	arc := newArchive()
	arc.put("input", "queued.log", []byte("x"), time.Now())

	var nudged int
	h := newTestServerQ(jobs, arc, fakeQueue{pos: 1, depth: 2, ok: true}, func() { nudged++ })

	getJSON(t, h, "/api/status?key=done.log")   // terminal
	getJSON(t, h, "/api/status?key=queued.log") // queued
	if nudged != 0 {
		t.Errorf("nudged %d times for known keys, want 0", nudged)
	}
}

// TestStatusUnknownKeyStillReportsUnknown checks the nudge did not swallow the
// "we have lost track of this" answer that stops the UI polling forever.
func TestStatusUnknownKeyStillReportsUnknown(t *testing.T) {
	var nudged int
	h := newTestServerQ(metrics.NewJobLog(10), newArchive(), fakeQueue{ok: false}, func() { nudged++ })

	_, body := getJSON(t, h, "/api/status?key=ghost.log")
	if body["status"] != "unknown" {
		t.Errorf("status = %v, want unknown", body["status"])
	}
	if nudged != 0 {
		t.Errorf("nudged %d times for a key with no object, want 0", nudged)
	}
}

func TestQueueEndpoint(t *testing.T) {
	q := fakeQueue{depth: 3, inflight: []string{"running.log"}, pending: []string{"a.log", "b.log"}}
	h := newTestServerQ(metrics.NewJobLog(10), newArchive(), q, nil)

	code, body := getJSON(t, h, "/api/queue")
	if code != 200 {
		t.Fatalf("status = %d, want 200", code)
	}
	if got := body["depth"]; got != float64(3) {
		t.Errorf("depth = %v, want 3", got)
	}
	inflight, _ := body["inflight"].([]any)
	if len(inflight) != 1 || inflight[0] != "running.log" {
		t.Errorf("inflight = %v, want [running.log]", body["inflight"])
	}
	pending, _ := body["pending"].([]any)
	if len(pending) != 2 {
		t.Errorf("pending = %v, want 2 entries", body["pending"])
	}
}

func TestQueueEndpointWithoutQueue(t *testing.T) {
	h := newTestServer(metrics.NewJobLog(10), newArchive())
	code, body := getJSON(t, h, "/api/queue")
	if code != 200 || body["depth"] != float64(0) {
		t.Errorf("code=%d body=%v, want 200 with depth 0", code, body)
	}
}

// A file skipped as binary has to reach the client. It never did: the digest carried
// no field for it, so /api/status reported passthrough 0 and the UI drew a green
// check over a bundle containing a log that was never inspected.
func TestStatusReportsBinarySkips(t *testing.T) {
	arc := newArchive()
	b, err := json.Marshal(report.Digest{
		InputKey: "k-bundle.tar.gz", OutputKey: "k-bundle.tar.gz",
		Matches: 12, FilesTotal: 2, BytesIn: 1000, BytesOut: 900,
		BinarySkip: 1,
		BinarySkips: []report.PassthroughNote{{
			Path: "logs/lux.txt", Status: report.StatusBinarySkip, Code: report.ReasonBinary, Detail: "detected binary content"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	arc.put("reports", "k-bundle.tar.gz"+report.DigestSuffix, b, time.Now())

	_, body := getJSON(t, newTestServer(metrics.NewJobLog(10), arc), "/api/status?key=k-bundle.tar.gz")
	if got := body["binary_skipped"]; got != float64(1) {
		t.Fatalf("binary_skipped = %v, want 1 — a skipped file the client cannot see is a silent leak", got)
	}
	paths, _ := body["binary_skip_paths"].([]any)
	if len(paths) != 1 {
		t.Fatalf("binary_skip_paths = %v, want the one skipped file named", body["binary_skip_paths"])
	}
	if p, _ := paths[0].(map[string]any); p["path"] != "logs/lux.txt" {
		t.Errorf("wrong path surfaced: %v", paths[0])
	}
}
