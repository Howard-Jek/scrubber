// Package worker runs the bucket-driven data plane: poll the input bucket, scrub
// each new object with its resolved policy, write the scrubbed bundle + report to
// the output/reports buckets, and mark the input processed. Every object is
// isolated — one failure is recorded and skipped, never crashing the loop.
package worker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"runtime/debug"
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
	ScrubNames    bool // also scrub archive member names/paths and the output object key
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
	if cfg.MaxObjectBytes <= 0 {
		cfg.MaxObjectBytes = 512 << 20 // never 0/unbounded: the read cap prevents OOM
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
	// Size is enforced in processObject via a bounded read (GetLimited), so an
	// object whose listed size is unknown or wrong still can't OOM the pod.
	return true
}

func (w *Worker) processObject(ctx context.Context, o store.Object) {
	start := time.Now()
	job := metrics.Job{Key: o.Key, Timestamp: start}

	// recorded guards against double-recording a job when a panic unwinds after
	// the normal path already logged its outcome.
	recorded := false
	record := func(j metrics.Job) {
		if recorded {
			return
		}
		recorded = true
		w.jobs.Add(j)
	}

	// A panic in the pipeline must cost one object, not the whole service: without
	// this the goroutine takes the process down, every in-flight upload is orphaned,
	// and the in-memory job history is lost.
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		w.metrics.Errors.Inc()
		w.metrics.Objects.WithLabelValues("panic").Inc()
		job.Status = "error"
		job.Error = fmt.Sprintf("internal error while processing (panic: %v)", r)
		record(job)
		w.log.Error("panic while processing object; object skipped, service continues",
			"key", o.Key, "panic", r, "stack", string(debug.Stack()))
	}()

	fail := func(err error) {
		w.metrics.Errors.Inc()
		w.metrics.Objects.WithLabelValues("error").Inc()
		job.Status = "error"
		job.Error = err.Error()
		record(job)
		w.log.Error("process object", "key", o.Key, "err", err)
	}

	data, err := w.store.GetLimited(ctx, w.cfg.InputBucket, o.Key, w.cfg.MaxObjectBytes)
	if err != nil {
		if errors.Is(err, store.ErrTooLarge) {
			// Backstop against OOM: skip the object and move it aside so the loop
			// keeps running and doesn't re-download it every poll.
			w.metrics.Objects.WithLabelValues("too_large").Inc()
			job.Status = "skipped"
			job.Error = fmt.Sprintf("object exceeds MaxObjectBytes (%d); skipped", w.cfg.MaxObjectBytes)
			record(job)
			w.log.Warn("object too large; skipping", "key", o.Key, "limit", w.cfg.MaxObjectBytes)
			if ferr := w.finish(ctx, o.Key); ferr != nil {
				w.log.Warn("move oversized input aside", "key", o.Key, "err", ferr)
			}
			return
		}
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

	// Scrub the object's own name too (so a sensitive term in the filename doesn't
	// leak via the output key). Falls back to the original key if nothing matched.
	outKey := o.Key
	if w.cfg.ScrubNames {
		if nk, nameMatches := res.Matcher.ScrubName(o.Key); len(nameMatches) > 0 {
			outKey = nk
		}
	}
	job.OutputKey = outKey

	rep := report.New(o.Key, path.Join(w.cfg.OutputBucket, outKey), auditLevel(w.cfg.RedactReports), w.cfg.RedactReports, "scrubber")
	eng := &pipeline.Engine{Matcher: res.Matcher, Report: rep, Limits: w.cfg.Limits, ScrubNames: w.cfg.ScrubNames}
	out := eng.Process(o.Key, data, 0)

	// Write scrubbed output under the (possibly scrubbed) key.
	if err := w.store.Put(ctx, w.cfg.OutputBucket, outKey, out, ""); err != nil {
		fail(fmt.Errorf("put output: %w", err))
		return
	}
	// Write report (best-effort: a report failure must not lose the scrubbed output).
	if reportBytes, jerr := rep.JSON(); jerr == nil {
		if err := w.store.Put(ctx, w.cfg.ReportsBucket, outKey+".report.json", reportBytes, "application/json"); err != nil {
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
	job.ByLabel = sum.MatchesByLabel
	job.Passthrough = sum.FilesPassthrough
	job.PassthroughPaths = sum.Passthroughs
	record(job)

	if sum.FilesPassthrough > 0 {
		// Not a clean result: part of the bundle left the pipeline uninspected.
		// Log it at warn with the offending paths so it is visible without having
		// to open the report object.
		paths := make([]string, 0, len(sum.Passthroughs))
		for _, p := range sum.Passthroughs {
			paths = append(paths, fmt.Sprintf("%s (%s: %s)", p.Path, p.Status, p.Reason))
		}
		w.log.Warn("scrubbed WITH UNSCRUBBED FILES; manual review required",
			"key", o.Key, "policy", res.Name, "matches", sum.TotalMatches,
			"unscrubbed_files", sum.FilesPassthrough, "paths", strings.Join(paths, "; "))
		return
	}
	w.log.Info("scrubbed", "key", o.Key, "policy", res.Name, "matches", sum.TotalMatches,
		"binary_skipped", sum.FilesBinarySkip, "changed", !bytes.Equal(out, data))
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
