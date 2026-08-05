// Package server exposes the control/observability plane plus a thin browser API.
// No bundle *bytes* pass through the service: uploads/downloads happen directly
// between the browser and MinIO via presigned URLs that this server mints. The API
// serves the operator preparing logs (an insider), so it does surface the policy —
// including literal terms — so they can verify what will be scrubbed. Keep the Route
// on a trusted network (see deploy notes); the scrubbed log content is what must not
// leave, and that is enforced by the scrubbing itself, not by hiding the policy.
package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/howard/scrubber/internal/metrics"
	"github.com/howard/scrubber/internal/policy"
	"github.com/howard/scrubber/internal/report"
	"github.com/howard/scrubber/internal/scrub"
	"github.com/howard/scrubber/internal/store"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Presigner mints presigned object URLs (implemented by store.Client).
type Presigner interface {
	PresignPut(ctx context.Context, bucket, key string, expiry time.Duration) (string, error)
	PresignGet(ctx context.Context, bucket, key string, expiry time.Duration) (string, error)
}

// Archive is the read-only object access the API needs to answer questions the
// in-memory job log cannot: whether an object finished, and what the last N runs
// were. Object storage is the durable record; the job log is only a cache.
type Archive interface {
	List(ctx context.Context, bucket, prefix string) ([]store.Object, error)
	Get(ctx context.Context, bucket, key string) ([]byte, error)
	Stat(ctx context.Context, bucket, key string) (store.Object, bool, error)
}

// QueueView is the read-only view of the scrub queue the API needs. It is declared
// here rather than imported so the server keeps no dependency on the worker.
type QueueView interface {
	// Position reports a key's 1-based place in line and the queue's depth. ok is
	// false for a key that is already being scrubbed or is not queued at all — the
	// job log owns those, because it carries live per-file progress.
	Position(key string) (pos, depth int, ok bool)
	// Snapshot returns the in-flight keys and up to limit pending keys, in order.
	Snapshot(limit int) (inflight, pending []string)
	Depth() int
}

// Deps are the server's dependencies.
type Deps struct {
	Policies  *policy.Registry
	Jobs      *metrics.JobLog
	Prom      *prometheus.Registry
	Ready     func() bool
	Presigner Presigner
	Archive   Archive
	// Queue answers "where in line is this key?" from memory. Optional: when nil
	// the status endpoint behaves exactly as it did before the queue existed.
	Queue QueueView
	// Nudge tells the worker that new work may have landed, so an object uploaded
	// moments ago is discovered on the next second rather than the next poll
	// interval. Optional; must be non-blocking and safe from any goroutine.
	Nudge         func()
	DefaultPolicy string // policy shown/edited in the UI
	AllowEdit     bool   // permit PUT /api/policy from the UI
	InputBucket   string
	OutputBucket  string
	ReportsBucket string
	UploadExpiry  time.Duration
	// HistoryMax caps the N a caller may request from /api/history.
	HistoryMax int
}

// staleAfter is how long an in-flight job record is trusted on its own before
// the API also consults storage. It bounds how long a client can wait on a
// record whose worker died or is re-processing the same object in a loop.
const staleAfter = 30 * time.Second

// queueSnapshotMax caps how many pending keys /api/queue lists, so an operator
// poking at a large backlog cannot pull a megabyte of key names.
const queueSnapshotMax = 50

// Server holds the dependencies for the endpoints.
type Server struct{ d Deps }

// New builds a server from its dependencies.
func New(d Deps) *Server {
	if d.UploadExpiry == 0 {
		d.UploadExpiry = 15 * time.Minute
	}
	if d.HistoryMax <= 0 {
		d.HistoryMax = 100
	}
	return &Server{d: d}
}

// Handler returns the routed HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Control plane.
	mux.HandleFunc("/healthz", s.healthz)
	mux.HandleFunc("/readyz", s.readyz)
	mux.Handle("/metrics", promhttp.HandlerFor(s.d.Prom, promhttp.HandlerOpts{}))
	mux.HandleFunc("/policies", s.listPolicies)
	mux.HandleFunc("/jobs", s.listJobs)
	// Browser API (URL-minting only; bytes go browser <-> MinIO).
	mux.HandleFunc("/api/policy", s.apiPolicy)
	mux.HandleFunc("/api/uploads", s.apiUpload)
	mux.HandleFunc("/api/status", s.apiStatus)
	mux.HandleFunc("/api/downloads", s.apiDownload)
	mux.HandleFunc("/api/history", s.apiHistory)
	mux.HandleFunc("/api/report", s.apiReport)
	mux.HandleFunc("/api/queue", s.apiQueue)
	// Static front page.
	mux.HandleFunc("/", s.index)
	return mux
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) readyz(w http.ResponseWriter, _ *http.Request) {
	if s.d.Ready != nil && !s.d.Ready() {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}

func (s *Server) listPolicies(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"policies": s.d.Policies.Names()})
}

func (s *Server) listJobs(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"jobs": s.d.Jobs.Recent()})
}

// apiPolicy serves the operator's policy view. GET returns the rule summary
// (kind, matched term, replacement label) plus the source terms.json. PUT/POST
// validates + compiles a new terms.json and activates it live.
func (s *Server) apiPolicy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		var rules []scrub.RuleInfo
		if m, ok := s.d.Policies.Get(s.d.DefaultPolicy); ok {
			rules = m.Rules()
		}
		src, _ := s.d.Policies.Raw(s.d.DefaultPolicy)
		writeJSON(w, map[string]any{"name": s.d.DefaultPolicy, "rules": rules, "source": string(src)})
	case http.MethodPut, http.MethodPost:
		if !s.d.AllowEdit {
			writeJSONStatus(w, http.StatusForbidden, map[string]any{"error": "policy editing is disabled (ALLOW_POLICY_EDIT=false)"})
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			writeJSONStatus(w, http.StatusBadRequest, map[string]any{"error": "request body too large"})
			return
		}
		if err := s.d.Policies.Set(s.d.DefaultPolicy, body); err != nil {
			writeJSONStatus(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		m, _ := s.d.Policies.Get(s.d.DefaultPolicy)
		src, _ := s.d.Policies.Raw(s.d.DefaultPolicy)
		writeJSON(w, map[string]any{"name": s.d.DefaultPolicy, "rules": m.Rules(), "source": string(src)})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// apiUpload mints a presigned PUT URL for a new input object.
func (s *Server) apiUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil || body.Name == "" {
		http.Error(w, "expected JSON {\"name\": ...}", http.StatusBadRequest)
		return
	}
	key := newKey(body.Name)
	url, err := s.d.Presigner.PresignPut(r.Context(), s.d.InputBucket, key, s.d.UploadExpiry)
	if err != nil {
		http.Error(w, "could not mint upload URL", http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]any{"key": key, "url": url, "method": "PUT"})
}

// apiStatus reports the outcome of a previously uploaded key (browser-safe fields).
//
// The in-memory job log is consulted first because it carries live progress, but
// it is only a cache: it is per-process and lost on restart. When it has no
// terminal answer the durable record in object storage is consulted, so a client
// is never told "processing" forever for an object that actually finished.
func (s *Server) apiStatus(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "missing key", http.StatusBadRequest)
		return
	}

	j, known := s.d.Jobs.Get(key)
	if known && j.Done() {
		writeJSON(w, jobStatusPayload(j))
		return
	}

	// A queued object is answered from the queue, before any storage access. This
	// is both the only place the real position is known and a load guard: a queued
	// key has no digest yet, so letting it fall through would cost two failed
	// object reads per client poll — with a full queue and second-scale polling
	// that is dozens of pointless MinIO round-trips per second for the whole drain.
	// It is checked before the freshness test below because a key still waiting in
	// line has not been processed in this process's lifetime, so any non-terminal
	// job record for it belongs to an earlier attempt.
	if s.d.Queue != nil {
		if pos, depth, ok := s.d.Queue.Position(key); ok {
			writeJSON(w, queuedPayload(pos, depth))
			return
		}
	}

	// A job this process is actively working on answers from memory: it has live
	// progress and storage has nothing yet. Consulting storage on every poll would
	// mean a failed object read per client per second for the whole run.
	if known && time.Since(j.Timestamp) < staleAfter {
		writeJSON(w, jobStatusPayload(j))
		return
	}

	// Either this process has no record (restarted, or the entry was evicted) or
	// its record has been in-flight implausibly long (a wedged or re-looping
	// object). Storage is authoritative — check it before reporting in-flight, so
	// a client is never stranded on an object that actually completed.
	if d, ok := s.digestFor(r.Context(), key); ok {
		writeJSON(w, digestStatusPayload(d))
		return
	}
	if known {
		writeJSON(w, jobStatusPayload(j)) // still working, just slow
		return
	}

	// No record anywhere. Distinguish "still queued" from "we have lost track of
	// it" so the UI can stop waiting instead of polling indefinitely.
	if s.d.Archive != nil {
		if _, found, err := s.d.Archive.Stat(r.Context(), s.d.InputBucket, key); err == nil && !found {
			writeJSON(w, map[string]any{
				"status": "unknown",
				"error":  "no result recorded for this key; it may have expired or never been uploaded",
			})
			return
		}
	}

	// The object is sitting in the input bucket and nothing knows about it yet, so
	// the worker has not listed since it landed. This request is a reliable signal
	// that new work exists — the browser starts polling the moment its upload
	// completes — which is what keeps a single upload into an idle bucket from
	// waiting out a whole poll interval. The worker coalesces and rate-limits these.
	if s.d.Nudge != nil {
		s.d.Nudge()
	}
	writeJSON(w, queuedPayload(0, 0))
}

// queuedPayload renders an object that is waiting its turn. Position and depth are
// omitted when the queue cannot place the key, so the UI falls back to a plain
// "Queued…" rather than rendering a meaningless "0 of 0".
func queuedPayload(pos, depth int) map[string]any {
	m := map[string]any{"status": "processing", "phase": "queued", "files_done": 0}
	if pos > 0 {
		m["queue_position"] = pos
		m["queue_depth"] = depth
	}
	return m
}

// apiQueue reports the current queue for operators. Keys only — no object contents
// and no policy detail.
func (s *Server) apiQueue(w http.ResponseWriter, r *http.Request) {
	if s.d.Queue == nil {
		writeJSON(w, map[string]any{"depth": 0, "inflight": []string{}, "pending": []string{}})
		return
	}
	inflight, pending := s.d.Queue.Snapshot(queueSnapshotMax)
	writeJSON(w, map[string]any{
		"depth":    s.d.Queue.Depth(),
		"inflight": inflight,
		"pending":  pending,
	})
}

// digestFor fetches the compact durable record for an input key.
//
// It prefers the small digest object and only falls back to the full report,
// which carries every match and can be megabytes, when the digest is absent —
// e.g. for runs recorded before digests existed.
func (s *Server) digestFor(ctx context.Context, key string) (*report.Digest, bool) {
	if s.d.Archive == nil || s.d.ReportsBucket == "" {
		return nil, false
	}
	if raw, err := s.d.Archive.Get(ctx, s.d.ReportsBucket, key+report.DigestSuffix); err == nil {
		var d report.Digest
		if json.Unmarshal(raw, &d) == nil {
			return &d, true
		}
	}
	rep, ok := s.reportFor(ctx, key)
	if !ok {
		return nil, false
	}
	d := rep.Digest()
	return &d, true
}

// reportFor fetches and decodes the full durable run report for an input key.
func (s *Server) reportFor(ctx context.Context, key string) (*report.Report, bool) {
	if s.d.Archive == nil || s.d.ReportsBucket == "" {
		return nil, false
	}
	raw, err := s.d.Archive.Get(ctx, s.d.ReportsBucket, key+report.ObjectSuffix)
	if err != nil {
		return nil, false
	}
	var rep report.Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, false
	}
	return &rep, true
}

// apiHistory lists the most recent completed runs, newest first, reconstructed
// from the reports bucket. This is what survives a page refresh or a restart.
func (s *Server) apiHistory(w http.ResponseWriter, r *http.Request) {
	if s.d.Archive == nil || s.d.ReportsBucket == "" {
		writeJSON(w, map[string]any{"runs": []any{}})
		return
	}
	n := s.d.HistoryMax
	if v := r.URL.Query().Get("n"); v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil || parsed <= 0 {
			http.Error(w, "n must be a positive integer", http.StatusBadRequest)
			return
		}
		if parsed < n {
			n = parsed
		}
	}

	objs, err := s.d.Archive.List(r.Context(), s.d.ReportsBucket, "")
	if err != nil {
		writeJSONStatus(w, http.StatusBadGateway, map[string]any{"error": "could not list reports"})
		return
	}
	// List by digest, never by full report: the full report grows with match count
	// and reading N of them to render a list would mean parsing hundreds of
	// megabytes of audit detail per page load.
	digests := objs[:0]
	for _, o := range objs {
		if strings.HasSuffix(o.Key, report.DigestSuffix) {
			digests = append(digests, o)
		}
	}
	sort.Slice(digests, func(i, j int) bool { return digests[i].LastModified.After(digests[j].LastModified) })
	if len(digests) > n {
		digests = digests[:n]
	}

	runs := make([]map[string]any, len(digests))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8) // bounded fan-out
	for i, o := range digests {
		wg.Add(1)
		go func(i int, o store.Object) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			key := strings.TrimSuffix(o.Key, report.DigestSuffix)
			entry := map[string]any{"key": key, "at": o.LastModified}
			raw, err := s.d.Archive.Get(r.Context(), s.d.ReportsBucket, o.Key)
			if err != nil {
				entry["status"] = "unreadable"
				runs[i] = entry
				return
			}
			var d report.Digest
			if err := json.Unmarshal(raw, &d); err != nil {
				entry["status"] = "unreadable"
				runs[i] = entry
				return
			}
			for k, v := range digestStatusPayload(&d) {
				entry[k] = v
			}
			runs[i] = entry
		}(i, o)
	}
	wg.Wait()

	writeJSON(w, map[string]any{"runs": runs, "n": n, "max": s.d.HistoryMax})
}

// apiReport returns the full stored report for a key, for the detail view.
func (s *Server) apiReport(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "missing key", http.StatusBadRequest)
		return
	}
	rep, ok := s.reportFor(r.Context(), key)
	if !ok {
		writeJSONStatus(w, http.StatusNotFound, map[string]any{"error": "no report stored for this key"})
		return
	}
	writeJSON(w, rep)
}

// digestStatusPayload renders a stored digest in the same shape as a live job so
// the UI can consume either without branching.
func digestStatusPayload(d *report.Digest) map[string]any {
	return map[string]any{
		"status":            "scrubbed",
		"matches":           d.Matches,
		"by_label":          d.ByLabel,
		"passthrough":       d.Passthrough,
		"passthrough_paths": d.Passthroughs,
		"binary_skipped":    d.BinarySkip,
		"binary_skip_paths": d.BinarySkips,
		"files_done":        d.FilesTotal,
		"output_key":        d.OutputKey,
		"bytes_in":          d.BytesIn,
		"bytes_out":         d.BytesOut,
		"from":              "storage",
	}
}

// apiDownload mints a presigned GET URL for the scrubbed output object.
func (s *Server) apiDownload(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "missing key", http.StatusBadRequest)
		return
	}
	// The scrubbed output may live under a different key if filename scrubbing
	// renamed it. Resolve via the live job record, falling back to the stored
	// report so a download still works after a restart cleared the job log.
	outKey := key
	if j, ok := s.d.Jobs.Get(key); ok && j.OutputKey != "" {
		outKey = j.OutputKey
	} else if d, ok := s.digestFor(r.Context(), key); ok && d.OutputKey != "" {
		outKey = d.OutputKey
	}
	url, err := s.d.Presigner.PresignGet(r.Context(), s.d.OutputBucket, outKey, s.d.UploadExpiry)
	if err != nil {
		http.Error(w, "could not mint download URL", http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]any{"url": url})
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(indexHTML)
}

// jobStatusPayload renders a job for the browser. It always includes the
// passthrough fields so the UI can distinguish a fully scrubbed bundle from one
// that contains files the pipeline never inspected.
func jobStatusPayload(j metrics.Job) map[string]any {
	return map[string]any{
		"status":            j.Status,
		"policy":            j.Policy,
		"matches":           j.Matches,
		"bytes_in":          j.BytesIn,
		"bytes_out":         j.BytesOut,
		"by_label":          j.ByLabel,
		"error":             j.Error,
		"passthrough":       j.Passthrough,
		"passthrough_paths": j.PassthroughPaths,
		"binary_skipped":    j.BinarySkipped,
		"binary_skip_paths": j.BinarySkipPaths,
		"files_done":        j.FilesDone,
		"current_file":      j.CurrentFile,
		"phase":             j.Phase,
		"output_key":        j.OutputKey,
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false) // keep presigned URLs (with &) intact for all clients
	_ = enc.Encode(v)
}

func writeJSONStatus(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
