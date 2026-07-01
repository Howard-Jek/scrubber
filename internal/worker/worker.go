// Package worker runs the bucket-driven data plane: poll the input bucket, scrub
// each new object with its resolved policy, write the scrubbed bundle + report to
// the output/reports buckets, and mark the input processed. Every object is
// isolated — one failure is recorded and skipped, never crashing the loop.
package worker

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/howard/scrubber/internal/metrics"
	"github.com/howard/scrubber/internal/pipeline"
	"github.com/howard/scrubber/internal/policy"
	"github.com/howard/scrubber/internal/report"
	"github.com/howard/scrubber/internal/store"
)

// ProcessedAction decides what happens to an input object after success.
type ProcessedAction string

const (
	ActionMove   ProcessedAction = "move"   // copy to processed/ prefix, delete original
	ActionDelete ProcessedAction = "delete" // delete original
)

// Config configures the worker loop.
type Config struct {
	InputBucket   string
	OutputBucket  string
	ReportsBucket string
	InputPrefix   string
	ProcessedPrefix string // where moved inputs land (default "processed/")
	Action        ProcessedAction
	PollInterval  time.Duration
	Workers       int
	MaxObjectBytes int64
	RedactReports bool
	Limits        pipeline.Limits
}

// termsSuffix marks a per-object override file: "<key>.terms.json".
const termsSuffix = ".terms.json"

// Worker ties together the store, policy registry, metrics and config.
type Worker struct {
	store    store.ObjectStore
	policies *policy.Registry
	metrics  *metrics.Metrics
	jobs     *metrics.JobLog
	cfg      Config
	log      *slog.Logger
}

// New constructs a Worker.
func New(s store.ObjectStore, p *policy.Registry, m *metrics.Metrics, jl *metrics.JobLog, cfg Config, log *slog.Logger) *Worker {
	if cfg.ProcessedPrefix == "" {
		cfg.ProcessedPrefix = "processed/"
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	return &Worker{store: s, policies: p, metrics: m, jobs: jl, cfg: cfg, log: log}
}

// Run polls until ctx is cancelled.
func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.cfg.PollInterval)
	defer ticker.Stop()
	w.pollOnce(ctx) // process immediately on startup
	for {
		select {
		case <-ctx.Done():
			w.log.Info("worker stopping")
			return
		case <-ticker.C:
			w.pollOnce(ctx)
		}
	}
}

// pollOnce lists the input bucket and processes each eligible object with a
// bounded pool of workers.
func (w *Worker) pollOnce(ctx context.Context) {
	objs, err := w.store.List(ctx, w.cfg.InputBucket, w.cfg.InputPrefix)
	if err != nil {
		w.log.Error("list input bucket", "err", err)
		return
	}
	sem := make(chan struct{}, w.cfg.Workers)
	var wg sync.WaitGroup
	for _, o := range objs {
		if !w.eligible(o) {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		obj := o
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			w.processObject(ctx, obj)
		}()
	}
	wg.Wait()
}

// eligible filters out override sidecar files and already-processed keys.
func (w *Worker) eligible(o store.Object) bool {
	if strings.HasSuffix(o.Key, termsSuffix) {
		return false // sidecar, consumed alongside its bundle
	}
	if strings.HasPrefix(o.Key, w.cfg.ProcessedPrefix) {
		return false
	}
	if w.cfg.MaxObjectBytes > 0 && o.Size > w.cfg.MaxObjectBytes {
		w.log.Warn("object exceeds MaxObjectBytes; skipping", "key", o.Key, "size", o.Size)
		return false
	}
	return true
}

func (w *Worker) processObject(ctx context.Context, o store.Object) {
	start := time.Now()
	job := metrics.Job{Key: o.Key, Timestamp: start}

	fail := func(err error) {
		w.metrics.Errors.Inc()
		w.metrics.Objects.WithLabelValues("error").Inc()
		job.Status = "error"
		job.Error = err.Error()
		w.jobs.Add(job)
		w.log.Error("process object", "key", o.Key, "err", err)
	}

	data, err := w.store.Get(ctx, w.cfg.InputBucket, o.Key)
	if err != nil {
		fail(fmt.Errorf("get: %w", err))
		return
	}

	// Per-object override file, if present.
	_, overrideTerms, err := w.store.Exists(ctx, w.cfg.InputBucket, o.Key+termsSuffix)
	if err != nil {
		fail(fmt.Errorf("check override: %w", err))
		return
	}

	res, err := w.policies.Resolve(o.Key, overrideTerms, "")
	if err != nil {
		fail(fmt.Errorf("resolve policy: %w", err))
		return
	}
	job.Policy = res.Name

	rep := report.New(o.Key, path.Join(w.cfg.OutputBucket, o.Key), auditLevel(w.cfg.RedactReports), w.cfg.RedactReports, "scrubber")
	eng := &pipeline.Engine{Matcher: res.Matcher, Report: rep, Limits: w.cfg.Limits}
	out := eng.Process(o.Key, data, 0)

	// Write scrubbed output.
	if err := w.store.Put(ctx, w.cfg.OutputBucket, o.Key, out, ""); err != nil {
		fail(fmt.Errorf("put output: %w", err))
		return
	}
	// Write report (best-effort: a report failure must not lose the scrubbed output).
	if reportBytes, jerr := rep.JSON(); jerr == nil {
		if err := w.store.Put(ctx, w.cfg.ReportsBucket, o.Key+".report.json", reportBytes, "application/json"); err != nil {
			w.log.Warn("put report", "key", o.Key, "err", err)
		}
	}
	// Mark input processed.
	if err := w.finish(ctx, o.Key); err != nil {
		w.log.Warn("finalize input", "key", o.Key, "err", err)
	}
	// Consume the override sidecar if it existed.
	if len(overrideTerms) > 0 {
		_ = w.store.Delete(ctx, w.cfg.InputBucket, o.Key+termsSuffix)
	}

	// Metrics + job record.
	sum := rep.Summary
	w.metrics.Matches.Add(float64(sum.TotalMatches))
	w.metrics.Passthrough.Add(float64(sum.FilesPassthrough))
	w.metrics.BytesIn.Add(float64(len(data)))
	w.metrics.BytesOut.Add(float64(len(out)))
	w.metrics.Objects.WithLabelValues("scrubbed").Inc()
	w.metrics.Duration.Observe(time.Since(start).Seconds())

	job.Status = "scrubbed"
	job.Matches = sum.TotalMatches
	job.BytesIn = len(data)
	job.BytesOut = len(out)
	w.jobs.Add(job)
	w.log.Info("scrubbed", "key", o.Key, "policy", res.Name, "matches", sum.TotalMatches,
		"passthrough", sum.FilesPassthrough, "changed", !bytes.Equal(out, data))
}

func (w *Worker) finish(ctx context.Context, key string) error {
	switch w.cfg.Action {
	case ActionDelete:
		return w.store.Delete(ctx, w.cfg.InputBucket, key)
	default: // move
		return w.store.Move(ctx, w.cfg.InputBucket, key, w.cfg.ProcessedPrefix+key)
	}
}

func auditLevel(redact bool) report.AuditLevel {
	// Reports always keep per-match locations; redaction hashes the original value.
	_ = redact
	return report.AuditFull
}
