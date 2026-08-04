package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
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
}

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
			Path: fmt.Sprintf("blob%d.7z", i), Status: report.StatusUnsupported, Reason: "read-only format"})
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
	return New(Deps{
		Policies:      nil,
		Jobs:          jobs,
		Prom:          prometheus.NewRegistry(),
		Presigner:     fakePresigner{},
		Archive:       arc,
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
