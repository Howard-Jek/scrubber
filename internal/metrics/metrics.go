// Package metrics holds the Prometheus collectors and a small in-memory ring of
// recent job outcomes surfaced by the control server's /jobs endpoint. Kept in its
// own package so both the worker (writer) and server (reader) depend on it without
// an import cycle.
package metrics

import (
	"sync"
	"time"

	"github.com/howard/scrubber/internal/report"
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics bundles the collectors updated as objects are processed.
type Metrics struct {
	Objects     *prometheus.CounterVec // by status
	Matches     prometheus.Counter
	Passthrough prometheus.Counter
	Errors      prometheus.Counter
	BytesIn     prometheus.Counter
	BytesOut    prometheus.Counter
	Duration    prometheus.Histogram

	// QueueWait is how long an object sat in the queue before its scrub started.
	QueueWait prometheus.Histogram
	// Latency is arrival-to-finished: queue wait plus processing. This is the
	// number a user actually experiences, and the one to watch when comparing
	// throughput before and after a scheduling change — Duration alone cannot show
	// it, because it starts counting only once an object reaches the front.
	Latency prometheus.Histogram
}

// New registers and returns the collectors on reg.
func New(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		Objects: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "scrubber_objects_total", Help: "Objects processed, by outcome status.",
		}, []string{"status"}),
		Matches:     prometheus.NewCounter(prometheus.CounterOpts{Name: "scrubber_matches_total", Help: "Total replacements made."}),
		Passthrough: prometheus.NewCounter(prometheus.CounterOpts{Name: "scrubber_passthrough_total", Help: "Files passed through unchanged (binary/corrupt/unsupported)."}),
		Errors:      prometheus.NewCounter(prometheus.CounterOpts{Name: "scrubber_errors_total", Help: "Objects that failed processing at the top level."}),
		BytesIn:     prometheus.NewCounter(prometheus.CounterOpts{Name: "scrubber_bytes_in_total", Help: "Total input bytes read."}),
		BytesOut:    prometheus.NewCounter(prometheus.CounterOpts{Name: "scrubber_bytes_out_total", Help: "Total output bytes written."}),
		Duration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "scrubber_process_seconds", Help: "Per-object processing time.",
			Buckets: prometheus.ExponentialBuckets(0.01, 3, 8),
		}),
		// Queue waits are measured in seconds-to-minutes, not the sub-second range
		// Duration covers, so these get their own scale: 1s .. ~17min.
		QueueWait: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "scrubber_queue_wait_seconds", Help: "Time an object waited in the queue before processing began.",
			Buckets: prometheus.ExponentialBuckets(1, 2, 10),
		}),
		Latency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "scrubber_object_latency_seconds", Help: "Time from an object's arrival in the bucket to its completion.",
			Buckets: prometheus.ExponentialBuckets(1, 2, 10),
		}),
	}
	reg.MustRegister(m.Objects, m.Matches, m.Passthrough, m.Errors, m.BytesIn, m.BytesOut,
		m.Duration, m.QueueWait, m.Latency)
	return m
}

// RegisterQueue attaches gauges that read the live queue.
//
// It is separate from New because the queue does not exist until the worker is
// constructed, and because a GaugeFunc reads through to the real depth rather than
// tracking it with paired increments that can drift when a path returns early.
func RegisterQueue(reg prometheus.Registerer, depth, inflight func() float64) {
	reg.MustRegister(
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "scrubber_queue_depth", Help: "Objects waiting to be scrubbed, plus the one in flight.",
		}, depth),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "scrubber_inflight_objects", Help: "Objects being scrubbed right now (0 or 1).",
		}, inflight),
	)
}

// SinceClamped returns the elapsed time from t to now, never negative.
//
// Arrival times come from the object store's clock and the elapsed time is computed
// against the pod's, so a small skew can make a fresh object look like it arrived in
// the future. A negative observation would corrupt the histogram, so clamp it.
func SinceClamped(t time.Time) time.Duration {
	d := time.Since(t)
	if d < 0 {
		return 0
	}
	return d
}

// Job records a single object's outcome for the /jobs endpoint. It contains only
// non-sensitive summary data — never original values or matched content.
type Job struct {
	Key       string    `json:"key"`
	Policy    string    `json:"policy"`
	Status    string    `json:"status"`
	Matches   int       `json:"matches"`
	BytesIn   int       `json:"bytes_in"`
	BytesOut  int       `json:"bytes_out"`
	Error     string    `json:"error,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	// ByLabel is the browser-safe match breakdown keyed by replacement label.
	ByLabel map[string]int `json:"by_label,omitempty"`
	// OutputKey is where the scrubbed object was written (may differ from Key when
	// filename scrubbing renamed it).
	OutputKey string `json:"output_key,omitempty"`
	// Passthrough counts files inside the bundle that were emitted WITHOUT being
	// scrubbed. Non-zero means the result is not fully sanitized and a human must
	// review it, so it is surfaced as a warning rather than a success.
	Passthrough int `json:"passthrough"`
	// PassthroughPaths names those files and why, for display.
	PassthroughPaths []report.PassthroughNote `json:"passthrough_paths,omitempty"`
	// BinarySkipped counts files skipped as binary, and BinarySkipPaths names them.
	// Skipping a PNG is routine; skipping what turns out to be a text log is a leak,
	// and a bare count cannot tell an operator which one happened.
	BinarySkipped   int                      `json:"binary_skipped"`
	BinarySkipPaths []report.PassthroughNote `json:"binary_skip_paths,omitempty"`

	// FilesDone and CurrentFile give live progress while Status is "processing",
	// so the UI can report what is actually happening instead of animating a bar
	// on a timer.
	FilesDone   int    `json:"files_done"`
	CurrentFile string `json:"current_file,omitempty"`
	// Phase is a coarse label for the current stage: "reading", "scrubbing",
	// "writing". Empty once the job is finished.
	Phase string `json:"phase,omitempty"`
}

// Done reports whether the job reached a terminal state.
func (j Job) Done() bool {
	return j.Status == "scrubbed" || j.Status == "error" || j.Status == "skipped"
}

// JobLog is a fixed-size ring of recent jobs, keyed by input object key so an
// in-flight job can be updated in place as it progresses.
//
// This is a cache, not the record of truth: it is per-process and does not
// survive a restart. The API falls back to object storage when a key is missing
// here, which is what keeps a client from waiting forever on a job whose record
// was lost.
type JobLog struct {
	mu   sync.Mutex
	buf  []Job
	idx  map[string]int // Key -> index into buf
	size int
}

// NewJobLog creates a ring holding the most recent size jobs.
func NewJobLog(size int) *JobLog {
	if size <= 0 {
		size = 100
	}
	return &JobLog{size: size, idx: map[string]int{}}
}

// Add appends a job, evicting the oldest when full.
func (l *JobLog) Add(j Job) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.appendLocked(j)
}

// Upsert replaces the entry for j.Key if present, otherwise appends. Used to
// publish a "processing" record before work starts and refine it as the job
// advances, so a client polling mid-flight sees real progress rather than an
// indistinguishable "not found".
func (l *JobLog) Upsert(j Job) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if i, ok := l.idx[j.Key]; ok {
		l.buf[i] = j
		return
	}
	l.appendLocked(j)
}

// Get returns the recorded job for key.
func (l *JobLog) Get(key string) (Job, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	i, ok := l.idx[key]
	if !ok {
		return Job{}, false
	}
	return l.buf[i], true
}

func (l *JobLog) appendLocked(j Job) {
	l.buf = append(l.buf, j)
	if len(l.buf) > l.size {
		l.buf = l.buf[len(l.buf)-l.size:]
		l.reindexLocked()
		return
	}
	l.idx[j.Key] = len(l.buf) - 1
}

func (l *JobLog) reindexLocked() {
	l.idx = make(map[string]int, len(l.buf))
	for i, j := range l.buf {
		l.idx[j.Key] = i
	}
}

// Recent returns the recorded jobs, newest last.
func (l *JobLog) Recent() []Job {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Job, len(l.buf))
	copy(out, l.buf)
	return out
}
