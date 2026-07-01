// Package metrics holds the Prometheus collectors and a small in-memory ring of
// recent job outcomes surfaced by the control server's /jobs endpoint. Kept in its
// own package so both the worker (writer) and server (reader) depend on it without
// an import cycle.
package metrics

import (
	"sync"
	"time"

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
	}
	reg.MustRegister(m.Objects, m.Matches, m.Passthrough, m.Errors, m.BytesIn, m.BytesOut, m.Duration)
	return m
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
}

// JobLog is a fixed-size ring buffer of recent jobs.
type JobLog struct {
	mu   sync.Mutex
	buf  []Job
	size int
}

// NewJobLog creates a ring holding the most recent size jobs.
func NewJobLog(size int) *JobLog {
	if size <= 0 {
		size = 100
	}
	return &JobLog{size: size}
}

// Add appends a job, evicting the oldest when full.
func (l *JobLog) Add(j Job) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf = append(l.buf, j)
	if len(l.buf) > l.size {
		l.buf = l.buf[len(l.buf)-l.size:]
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
