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
	Objects      *prometheus.CounterVec // by status
	Verdicts     *prometheus.CounterVec // by coverage verdict
	NotInspected *prometheus.CounterVec // files not covered by the scrub, by reason
	Residual     prometheus.Counter
	Matches      prometheus.Counter
	Passthrough  prometheus.Counter
	Errors       prometheus.Counter
	// DiscoveryFailures counts failed listings of the input bucket.
	//
	// It is separate from Errors, which is per-object: a discovery failure means no
	// object was even seen, so every per-object counter stays flat and the service
	// looks idle rather than broken. Without this the only evidence was a log line
	// repeating on the poll interval, which is invisible to alerting and easy to
	// mistake for noise — a misconfigured bucket name can sit in that state
	// indefinitely, accepting uploads that are never scrubbed.
	DiscoveryFailures prometheus.Counter

	BytesIn  prometheus.Counter
	BytesOut prometheus.Counter
	Duration prometheus.Histogram

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
		// Verdicts is the series to alert on. objects_total{status} says whether
		// processing succeeded; this says whether the *result* is trustworthy, which
		// is a different question and the one that went unanswered for three bugs.
		Verdicts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "scrubber_object_verdict_total", Help: "Objects by coverage verdict (complete|incomplete|incomplete-risky).",
		}, []string{"verdict"}),
		// NotInspected breaks the coverage holes down by reason code. A reason
		// appearing here that nobody has seen before is the signal that a new failure
		// mode exists — which previously required a human to notice a file looked odd.
		NotInspected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "scrubber_files_not_inspected_total", Help: "Files emitted without being covered by the scrub, by reason.",
		}, []string{"reason"}),
		Residual: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "scrubber_residual_hits_total", Help: "Policy matches found inside content that was NOT inspected."}),
		Matches:     prometheus.NewCounter(prometheus.CounterOpts{Name: "scrubber_matches_total", Help: "Total replacements made."}),
		Passthrough: prometheus.NewCounter(prometheus.CounterOpts{Name: "scrubber_passthrough_total", Help: "Files passed through unchanged (binary/corrupt/unsupported)."}),
		Errors:      prometheus.NewCounter(prometheus.CounterOpts{Name: "scrubber_errors_total", Help: "Objects that failed processing at the top level."}),
		DiscoveryFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "scrubber_discovery_failures_total",
			Help: "Failed listings of the input bucket. Rising steadily means no work is " +
				"being discovered at all, while every per-object metric stays flat.",
		}),
		BytesIn:  prometheus.NewCounter(prometheus.CounterOpts{Name: "scrubber_bytes_in_total", Help: "Total input bytes read."}),
		BytesOut: prometheus.NewCounter(prometheus.CounterOpts{Name: "scrubber_bytes_out_total", Help: "Total output bytes written."}),
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
	// Seed the label sets so a dashboard shows a zero rather than a missing series:
	// "no incomplete runs" and "this metric does not exist yet" look identical
	// otherwise, and the second one is what you get on a fresh pod.
	for _, v := range []report.Verdict{report.VerdictComplete, report.VerdictIncomplete, report.VerdictIncompleteRisky} {
		m.Verdicts.WithLabelValues(string(v)).Add(0)
	}
	for _, r := range report.AllReasons {
		m.NotInspected.WithLabelValues(string(r)).Add(0)
	}
	// Object statuses need the same treatment, and had been missed. The operator
	// guidance is to alert on scrubber_objects_total{status="stalled"} and
	// {status="too_large"} — but an unseeded CounterVec emits no series at all
	// until the label first fires, so those alerts would sit on a metric that does
	// not exist and would look identical to "nothing has gone wrong".
	for _, s := range ObjectStatuses {
		m.Objects.WithLabelValues(s).Add(0)
	}
	reg.MustRegister(m.Objects, m.Verdicts, m.NotInspected, m.Residual,
		m.Matches, m.Passthrough, m.Errors, m.DiscoveryFailures, m.BytesIn, m.BytesOut,
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

// RegisterProgress publishes how long the in-flight object has been in its
// current stage, and 0 when nothing is in flight.
//
// This is the series that distinguishes a slow object from a wedged one, and
// until it existed there was no way to tell them apart from outside the process.
// A liveness probe cannot: /healthz answers 200 whatever the worker is doing, and
// making it fail on a long scrub would kill legitimate work — a large bundle
// genuinely takes minutes. Per-file progress cannot either, because the stage
// where objects actually wedge (expanding a container, or a backend read that
// never returns) is precisely the one that reports no files.
//
// A GaugeFunc rather than a tracked value on purpose: a stalled worker updates
// nothing, so a gauge it has to push would freeze at its last value and look
// healthy. This one is read at scrape time and keeps climbing.
//
// Alert on it above the slowest scrub you are willing to call normal.
// RegisterBuildInfo publishes the running version as a labelled constant gauge.
//
// The value is always 1; the information is in the label. That is the standard
// build-info shape (kube-state-metrics, node_exporter, Go's own collector) and it
// exists so a dashboard can join version onto any other series -- "did the drain
// rate change when 0.8.0 rolled out?" -- and so "which version is in this
// namespace?" is a query rather than an oc exec.
func RegisterBuildInfo(reg prometheus.Registerer, version string) {
	reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name:        "scrubber_build_info",
		Help:        "Build information. Always 1; read the version label.",
		ConstLabels: prometheus.Labels{"version": version},
	}, func() float64 { return 1 }))
}

func RegisterProgress(reg prometheus.Registerer, phaseSeconds func() float64) {
	reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "scrubber_inflight_phase_seconds",
		Help: "Seconds the in-flight object has spent in its current phase (0 when idle). " +
			"Climbing without bound means a stalled object, not a slow one.",
	}, phaseSeconds))
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
	// Verdict is the coverage answer for the whole object, and NotInspected names
	// every file behind it. The UI keys its warning and its download gate on these.
	Verdict         report.Verdict `json:"verdict,omitempty"`
	NotInspected    int            `json:"files_not_inspected"`
	NotInspectedSet []report.Note  `json:"not_inspected,omitempty"`
	ResidualHits    int            `json:"residual_hits"`
	ResidualSamples []string       `json:"residual_samples,omitempty"`

	// FilesDone and CurrentFile give live progress while Status is "processing",
	// so the UI can report what is actually happening instead of animating a bar
	// on a timer.
	FilesDone int `json:"files_done"`
	// FilesTotal is how many archive members have been DISCOVERED so far, or 0 when
	// the object is not an archive or nothing has been opened yet.
	//
	// It can rise mid-run when a nested archive is opened, so a client must treat it
	// as a running denominator rather than a fixed one.
	FilesTotal  int    `json:"files_total,omitempty"`
	CurrentFile string `json:"current_file,omitempty"`
	// Phase is a coarse label for the current stage: "reading", "unpacking",
	// "scrubbing", "writing". Empty once the job is finished.
	//
	// "unpacking" exists because it is the one stage that reports no per-file
	// progress: a container is fully expanded before its first member can be
	// scrubbed, so FilesDone stays 0 throughout however long it takes. Without a
	// name for it the client could not tell "expanding a large archive" from
	// "wedged", and invented a timer-driven bar to cover the gap.
	Phase string `json:"phase,omitempty"`
	// PhaseSince is when Phase was last set. It is what makes a stalled object
	// diagnosable: a phase that has not changed for far longer than its work
	// should take is the signal, and it is the only one available while
	// FilesDone is pinned at 0.
	PhaseSince time.Time `json:"-"`
	// ProgressSince is when this object last did anything OBSERVABLE -- changed
	// phase, or finished another file.
	//
	// PhaseSince alone cannot answer "is it stuck?", and reading it as though it
	// could produced a false alarm on every healthy long run: the phase is set once
	// when scrubbing starts and never again, so a 19-minute scrub advancing steadily
	// through 60 files logged "may be stalled" three times while files_done climbed
	// 25 -> 40 -> 55. A warning that fires on correct behaviour is worse than no
	// warning, because it trains the reader to ignore the real one.
	ProgressSince time.Time `json:"-"`
	// RetryInSeconds is how long the object is held back before its next attempt,
	// set alongside Status "retrying". It is what lets the page say "retrying in
	// 8s" instead of either giving up or claiming progress it cannot see.
	RetryInSeconds int `json:"retry_in_seconds,omitempty"`
}

// PhaseSeconds reports how long the job has been in its current phase.
//
// Zero when there is no phase to time: a finished job (Phase is cleared on
// completion) or a record from a process that predates the stamp. Without the
// Phase check a completed job keeps reporting a number that climbs forever, which
// is exactly the kind of meaningless-but-plausible figure this field was added to
// get rid of.
func (j Job) PhaseSeconds() float64 {
	if j.Phase == "" || j.PhaseSince.IsZero() {
		return 0
	}
	return time.Since(j.PhaseSince).Seconds()
}

// ProgressSeconds reports how long it has been since this object last showed any
// observable movement. It is the number to judge "stalled" on; PhaseSeconds is the
// number to judge "how long has this stage taken".
//
// They differ precisely when an object is working steadily inside one long phase,
// which is the normal case for a large bundle and exactly where the two get
// confused.
func (j Job) ProgressSeconds() float64 {
	if j.Phase == "" {
		return 0
	}
	if j.ProgressSince.IsZero() {
		// A record from a process that predates the stamp: fall back rather than
		// report a false zero, which would read as "just moved".
		return j.PhaseSeconds()
	}
	return time.Since(j.ProgressSince).Seconds()
}

// ObjectStatuses is every value scrubber_objects_total{status} can take.
//
// Declared rather than left implicit at the increment sites so the series can be
// seeded at startup: a CounterVec emits nothing for a label combination until it
// first fires, and an alert on a series that does not exist yet looks exactly like
// an alert on a series that is healthily zero.
var ObjectStatuses = []string{
	"scrubbed",  // completed and delivered
	"error",     // failed processing at the top level
	"stalled",   // an object-storage transfer went quiet and was abandoned
	"cancelled", // withdrawn from the queue by request
	// the walk outran SCRUB_TIMEOUT and was abandoned. Distinct from "error"
	// because the response is different: an error usually means the object is bad,
	// this means the budget or the CPU is too small for the bundles being sent.
	// Alert on it separately -- a rising rate here is a capacity signal.
	"timeout",
	// above MAX_OBJECT_BYTES. Not kept, but not free either: GetLimitedTo streams
	// the object to scratch up to the cap plus one byte before refusing it — the
	// extra byte is how "exactly at the limit" is told from "over it".
	"too_large",
	"panic", // a bug in the pipeline; the object is skipped, the service continues
	// delivered, but NOTHING in it was inspected: the top-level payload itself was
	// the hole. A lone binary, or a container that could not be opened. Counted
	// apart from "scrubbed" because an operator reading that series as "bundles
	// sanitized" would be wrong about every one of these.
	"unscrubbed",
}

// Done reports whether the job reached a terminal state.
//
// "retrying" is deliberately not terminal. The object is still in the input bucket
// and will be picked up again after its backoff, so a client must keep waiting on
// it; treating a transient backend stall as terminal showed a permanent failure for
// work that then completed a minute later, with nothing to tell the user it had.
//
// "cancelled" is terminal: nothing further will ever be recorded for the key, so
// answering from storage would only ever cost two failed reads per poll.
func (j Job) Done() bool {
	return j.Status == "scrubbed" || j.Status == "error" || j.Status == "skipped" || j.Status == "cancelled"
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
