// Package worker runs the bucket-driven data plane: poll the input bucket, scrub
// each new object with its resolved policy, write the scrubbed bundle + report to
// the output/reports buckets, and mark the input processed. Every object is
// isolated — one failure is recorded and skipped, never crashing the loop.
//
// Scheduling is split in two. A producer lists the bucket on a ticker and hands the
// eligible objects to an arrival-ordered queue; a single consumer takes them one at
// a time. That serialization is deliberate: the pod has one CPU and a memory budget
// sized for one object, so running several scrubs at once trades throughput for
// nothing and pushes resident memory toward the container limit. The poll interval
// governs how quickly *new* work is discovered, not how fast the queue drains — the
// consumer takes the next object the instant it finishes one.
package worker

import (
	"context"
	"encoding/json"
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
	"github.com/howard/scrubber/internal/queue"
	"github.com/howard/scrubber/internal/report"
	"github.com/howard/scrubber/internal/spill"
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
	InputBucket     string
	OutputBucket    string
	ReportsBucket   string
	InputPrefix     string
	ProcessedPrefix string // where moved inputs land (default "processed/")
	Action          ProcessedAction
	// PollInterval is how often the input bucket is listed for *new* work. It does
	// not bound the drain rate: the consumer takes the next queued object as soon
	// as it finishes one.
	PollInterval time.Duration
	// Workers is retained for configuration compatibility and is clamped to 1.
	// Objects are processed one at a time, in arrival order; a higher value would
	// restore exactly the contention this queue exists to remove.
	Workers int
	// QueueMax bounds the in-memory pending set. Anything beyond it is still in the
	// bucket and is picked up by a later poll.
	QueueMax       int
	MaxObjectBytes int64
	// FinalizeGrace bounds the writes that persist a finished object's result when
	// the process is already shutting down. Keep it inside the pod's
	// terminationGracePeriodSeconds.
	FinalizeGrace time.Duration
	// Audit is how much per-match detail the stored report retains. See
	// ParseAuditLevel: this is a memory setting as much as a disclosure one.
	Audit         report.AuditLevel
	RedactReports bool
	ScrubNames    bool // also scrub archive member names/paths and the output object key
	Limits        pipeline.Limits
}

// termsSuffix marks a per-object override file: "<key>.terms.json".
const termsSuffix = ".terms.json"

// reportSuffix is appended to the *input* key to form the report object's key in
// the reports bucket.
const reportSuffix = report.ObjectSuffix

// Worker ties together the store, policy registry, metrics, queue and config.
type Worker struct {
	store    store.ObjectStore
	policies *policy.Registry
	metrics  *metrics.Metrics
	jobs     *metrics.JobLog
	q        *queue.Queue
	cfg      Config
	log      *slog.Logger

	// nudge asks the producer to list immediately instead of waiting out the
	// ticker. Buffered to 1 and never blocking, so it is safe to signal from an
	// HTTP handler on every client poll.
	nudge chan struct{}

	// deferUntil holds back objects whose finalization failed. Without it a key
	// that cannot be moved out of the input bucket is re-scrubbed on every poll
	// forever, burning CPU, rewriting the same output, and churning the job ring
	// so unrelated records are evicted.
	mu         sync.Mutex
	deferUntil map[string]time.Time
	attempts   map[string]int
}

// finalizeBackoff returns how long to hold an object back after n consecutive
// failures to mark it processed, capped so it still retries occasionally.
func finalizeBackoff(n int) time.Duration {
	d := time.Duration(1<<min(n, 6)) * time.Second // 2s .. 64s
	if d > time.Minute {
		d = time.Minute
	}
	return d
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// New constructs a Worker.
func New(s store.ObjectStore, p *policy.Registry, m *metrics.Metrics, jl *metrics.JobLog, cfg Config, log *slog.Logger) *Worker {
	if cfg.ProcessedPrefix == "" {
		cfg.ProcessedPrefix = "processed/"
	}
	// Clamped rather than defaulted. Honouring a larger value would let a single
	// config line reintroduce concurrent scrubs behind a queue that claims to have
	// removed them, and the pod's memory budget only covers one object.
	if cfg.Workers != 1 {
		if cfg.Workers > 1 {
			log.Warn("WORKERS is clamped to 1: objects are scrubbed one at a time in arrival order",
				"requested", cfg.Workers)
		}
		cfg.Workers = 1
	}
	if cfg.MaxObjectBytes <= 0 {
		cfg.MaxObjectBytes = 512 << 20 // never 0/unbounded: the read cap prevents OOM
	}
	if cfg.FinalizeGrace <= 0 {
		cfg.FinalizeGrace = 15 * time.Second
	}
	return &Worker{
		store: s, policies: p, metrics: m, jobs: jl, cfg: cfg, log: log,
		q:          queue.New(cfg.QueueMax),
		nudge:      make(chan struct{}, 1),
		deferUntil: map[string]time.Time{},
		attempts:   map[string]int{},
	}
}

// Queue exposes the pending set (used for metrics gauges).
func (w *Worker) Queue() *queue.Queue { return w.q }

// Nudge asks the producer to list the input bucket now rather than at the next
// tick. Non-blocking and coalescing, so an HTTP handler can call it freely.
//
// This is what keeps a single upload into an empty bucket from waiting out a whole
// poll interval: the browser starts polling for status the moment its PUT lands,
// and that first poll is a reliable "new work exists" signal.
func (w *Worker) Nudge() {
	select {
	case w.nudge <- struct{}{}:
	default:
	}
}

// Position reports a key's 1-based place in the queue and the queue's depth. ok is
// false unless the key is waiting — an object already being scrubbed is reported
// through the job log, which has live per-file progress the queue does not.
//
// Position, Depth and Snapshot together satisfy the API's queue view. They live on
// the Worker rather than being the queue's own methods so the boolean the HTTP layer
// wants does not flatten queue.State, which the queue's own tests rely on.
func (w *Worker) Position(key string) (pos, depth int, ok bool) {
	pos, depth, state := w.q.Position(key)
	return pos, depth, state == queue.StateQueued
}

// Depth is the number of objects waiting plus the one in flight.
func (w *Worker) Depth() int { return w.q.Depth() }

// Snapshot returns the in-flight keys and up to limit pending keys, in queue order.
func (w *Worker) Snapshot(limit int) (inflight, pending []string) { return w.q.Snapshot(limit) }

// Run starts the producer and the single consumer and returns once both have
// stopped, which happens after ctx is cancelled. Callers should wait for it during
// shutdown so the process does not exit while an object is mid-flight.
func (w *Worker) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); w.discover(ctx) }()
	go func() { defer wg.Done(); w.consume(ctx) }()
	wg.Wait()
	w.log.Info("worker stopped")
}

// minListInterval floors how often a nudge can trigger a listing. Without it, every
// browser polling /api/status for an undiscovered key would cause its own LIST.
const minListInterval = time.Second

// discover is the producer: list the input bucket, filter it, and hand the result to
// the queue. It runs on a ticker and on demand via Nudge.
func (w *Worker) discover(ctx context.Context) {
	ticker := time.NewTicker(w.cfg.PollInterval)
	defer ticker.Stop()

	var last time.Time
	list := func(reason string) {
		if time.Since(last) < minListInterval {
			return
		}
		last = time.Now()
		w.discoverOnce(ctx, reason)
	}

	list("startup")
	for {
		select {
		case <-ctx.Done():
			w.log.Info("worker discovery stopping")
			return
		case <-ticker.C:
			list("poll")
		case <-w.nudge:
			list("nudge")
		}
	}
}

// discoverOnce lists the input bucket once and syncs the queue to it.
func (w *Worker) discoverOnce(ctx context.Context, reason string) {
	objs, err := w.store.List(ctx, w.cfg.InputBucket, w.cfg.InputPrefix)
	if err != nil {
		if ctx.Err() == nil {
			w.log.Error("list input bucket", "err", err)
		}
		return
	}

	now := time.Now()
	present := make(map[string]struct{}, len(objs))
	items := make([]queue.Item, 0, len(objs))
	for _, o := range objs {
		present[o.Key] = struct{}{}
		if !w.eligible(o, now) {
			continue
		}
		items = append(items, queue.Item{Key: o.Key, Size: o.Size, At: w.orderKey(o, now)})
	}
	w.sweepDeferrals(present)

	if dropped := w.q.Sync(items); dropped > 0 {
		// Never let a capped queue read as "everything is queued": the dropped keys
		// are still in the bucket and will be picked up, but an operator watching
		// depth needs to know the number is a floor.
		w.log.Warn("input backlog exceeds the queue cap; the remainder is picked up on a later poll",
			"queued", w.q.Depth(), "deferred_to_next_poll", dropped)
	}
	w.log.Debug("discovered input objects", "reason", reason, "listed", len(objs), "queued", w.q.Depth())
}

// orderKey returns the value the queue sorts on.
//
// Normally that is the object's arrival time. For a key being retried after a failed
// finalize it is the moment the backoff expires instead. Using LastModified for a
// retry would sort it to the *head* of the queue — its upload is by definition the
// oldest still in the bucket — so one object that can never be moved out would
// re-scrub itself ahead of everyone else on every backoff expiry, forever.
func (w *Worker) orderKey(o store.Object, now time.Time) time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.attempts[o.Key] > 0 {
		if until, held := w.deferUntil[o.Key]; held {
			return until
		}
		return now
	}
	return o.LastModified
}

// sweepDeferrals drops backoff state for keys that are no longer in the bucket.
// Without it the maps grow for the life of the process, and a key that reappears
// later would inherit a stale attempt count and be ordered as a retry.
func (w *Worker) sweepDeferrals(present map[string]struct{}) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for k := range w.deferUntil {
		if _, ok := present[k]; !ok {
			delete(w.deferUntil, k)
			delete(w.attempts, k)
		}
	}
	for k := range w.attempts {
		if _, ok := present[k]; !ok {
			delete(w.attempts, k)
		}
	}
}

// consume is the single consumer: take the head of the queue, scrub it to
// completion, repeat. On cancellation it stops taking new work, which is what keeps
// the process from starting a minute-long object moments before it is killed.
func (w *Worker) consume(ctx context.Context) {
	for {
		it, ok := w.q.Next(ctx)
		if !ok {
			w.log.Info("worker consumer stopping")
			return
		}
		w.handle(ctx, it)
	}
}

// handle processes one queued item and releases its queue slot.
func (w *Worker) handle(ctx context.Context, it queue.Item) {
	defer w.q.Done(it.Key)
	w.metrics.QueueWait.Observe(metrics.SinceClamped(it.At).Seconds())
	w.processObject(ctx, store.Object{Key: it.Key, Size: it.Size, LastModified: it.At})
	w.metrics.Latency.Observe(metrics.SinceClamped(it.At).Seconds())
}

// runOnce lists the input bucket and drains the queue synchronously.
//
// Run does not use it: it is the seam that lets tests exercise discovery and
// execution together, deterministically, without racing the ticker.
func (w *Worker) runOnce(ctx context.Context) {
	w.discoverOnce(ctx, "once")
	for {
		it, ok := w.q.TryNext()
		if !ok {
			return
		}
		w.handle(ctx, it)
	}
}

// eligible filters out override sidecar files and already-processed keys.
func (w *Worker) eligible(o store.Object, now time.Time) bool {
	if strings.HasSuffix(o.Key, termsSuffix) {
		return false // sidecar, consumed alongside its bundle
	}
	if strings.HasPrefix(o.Key, w.cfg.ProcessedPrefix) {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if until, held := w.deferUntil[o.Key]; held && now.Before(until) {
		return false // finalization failed recently; wait out the backoff
	}
	// Size is enforced in processObject via a bounded read (GetLimited), so an
	// object whose listed size is unknown or wrong still can't OOM the pod.
	return true
}

// noteFinalized clears any backoff state for a key that completed cleanly.
func (w *Worker) noteFinalized(key string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.deferUntil, key)
	delete(w.attempts, key)
}

// noteFinalizeFailed records a failure and returns the backoff applied.
func (w *Worker) noteFinalizeFailed(key string) time.Duration {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.attempts[key]++
	d := finalizeBackoff(w.attempts[key])
	w.deferUntil[key] = time.Now().Add(d)
	return d
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
		w.jobs.Upsert(j)
	}

	// Publish the job as in-flight *before* any work. Previously the record was
	// written last, after the output object had already been stored, so a client
	// polling in that window — or after a restart that lost the record — saw
	// "not found" and waited forever while the finished object sat in the bucket.
	job.Status = "processing"
	job.Phase = "reading"
	w.jobs.Upsert(job)
	w.log.Info("processing object", "key", o.Key, "size", o.Size)

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

	// Stage the upload on scratch storage rather than the heap. For an
	// incompressible bundle the compressed object is most of its expanded size, so
	// holding it resident for the whole scrub was one of the copies that put a
	// few-hundred-MiB upload out of reach of this pod.
	input, w2, err := spill.Create()
	if err != nil {
		fail(fmt.Errorf("stage input: %w", err))
		return
	}
	inSize, err := w.store.GetLimitedTo(ctx, w2, w.cfg.InputBucket, o.Key, w.cfg.MaxObjectBytes)
	if cerr := w2.Close(); err == nil {
		err = cerr
	}
	input.Done(inSize)
	defer input.Close()
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
				d := w.noteFinalizeFailed(o.Key)
				w.log.Warn("could not move oversized input aside; deferring retry",
					"key", o.Key, "err", ferr, "retry_in", d)
			} else {
				w.noteFinalized(o.Key)
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

	rep := report.New(o.Key, path.Join(w.cfg.OutputBucket, outKey), w.cfg.Audit, w.cfg.RedactReports, "scrubber")
	rep.InputKey = o.Key
	rep.OutputKey = outKey
	rep.StartedAt = start

	// Stream per-file progress: log every file as it is handled and keep the job
	// record current so a polling client sees real movement through the bundle.
	job.Phase = "scrubbing"
	filesDone := 0
	rep.OnFile(func(f report.FileEntry) {
		filesDone++
		w.log.Debug("scrubbed file", "key", o.Key, "path", f.Path, "status", f.Status,
			"bytes_in", f.BytesIn, "bytes_out", f.BytesOut, "detail", f.Detail)
		if f.Status != report.StatusScrubbed && f.Status != report.StatusUnchanged {
			// Anything the pipeline could not fully handle is worth a line at info
			// even when debug logging is off.
			w.log.Info("file not scrubbed", "key", o.Key, "path", f.Path,
				"status", f.Status, "detail", f.Detail)
		}
		j := job
		j.FilesDone = filesDone
		j.CurrentFile = f.Path
		w.jobs.Upsert(j)
	})

	eng := &pipeline.Engine{Matcher: res.Matcher, Report: rep, Limits: w.cfg.Limits, ScrubNames: w.cfg.ScrubNames}
	// Release every blob the walk staged. This runs before the panic recovery
	// above (defers unwind last-registered-first), so a bug anywhere in the
	// pipeline costs one object rather than a temp file that outlives it.
	defer eng.Release()
	out, changed := eng.ProcessBlob(o.Key, input, 0)
	if changed {
		// ProcessBlob returns the input itself when nothing changed, so only close
		// the result when it is genuinely a separate payload.
		defer out.Close()
	}
	rep.EndedAt = time.Now()
	rep.BytesIn = int(inSize)
	rep.BytesOut = int(out.Size())

	job.Phase = "writing"
	job.FilesDone = filesDone
	w.jobs.Upsert(job)

	// The scrub is done; only bookkeeping remains. If the process is already
	// shutting down, finish that bookkeeping on a detached context rather than
	// letting the cancellation throw away work that is complete — otherwise a
	// SIGTERM landing here costs the whole object, which has to be scrubbed again
	// after the restart. Bounded so it cannot outlive the pod's grace period.
	if ctx.Err() != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.WithoutCancel(ctx), w.cfg.FinalizeGrace)
		defer cancel()
		w.log.Info("shutting down mid-object; persisting the finished result",
			"key", o.Key, "grace", w.cfg.FinalizeGrace)
	}

	// Write scrubbed output under the (possibly scrubbed) key, streaming from
	// scratch storage so the result never has to be whole on the heap.
	outRC, err := out.Reader()
	if err != nil {
		fail(fmt.Errorf("read scrubbed output: %w", err))
		return
	}
	// Close through a defer, not a following statement: a panic inside PutStream
	// would skip a trailing Close and leak the open handle. The blob's own Close
	// then unlinks a file that is still open, which on Linux removes the directory
	// entry but does NOT free the blocks until the process exits — invisible to
	// `ls /work` while still counting against the emptyDir sizeLimit.
	err = func() error {
		defer outRC.Close()
		return w.store.PutStream(ctx, w.cfg.OutputBucket, outKey, outRC, out.Size(), "")
	}()
	if err != nil {
		fail(fmt.Errorf("put output: %w", err))
		return
	}
	// Write the report under the *input* key. The client only ever knows the key
	// it uploaded; keying reports by the (possibly scrubbed) output name made them
	// unfindable from that side, which is why status could not be recovered from
	// storage. The report itself records where the output landed.
	if reportBytes, jerr := rep.JSON(); jerr == nil {
		if err := w.store.Put(ctx, w.cfg.ReportsBucket, o.Key+reportSuffix, reportBytes, "application/json"); err != nil {
			w.log.Warn("put report", "key", o.Key, "err", err)
		}
	} else {
		w.log.Warn("render report", "key", o.Key, "err", jerr)
	}
	// Compact companion record. The API answers status and history from this so
	// it never has to parse the full per-match audit detail, which grows with
	// match count and can reach megabytes for a small, repetitive log.
	if digestBytes, jerr := json.Marshal(rep.Digest()); jerr == nil {
		if err := w.store.Put(ctx, w.cfg.ReportsBucket, o.Key+report.DigestSuffix, digestBytes, "application/json"); err != nil {
			w.log.Warn("put digest", "key", o.Key, "err", err)
		}
	}
	// Mark input processed. If this fails the object is still sitting in the input
	// bucket and would otherwise be re-scrubbed on every poll forever, so hold it
	// back with an increasing backoff instead of spinning.
	if err := w.finish(ctx, o.Key); err != nil {
		d := w.noteFinalizeFailed(o.Key)
		w.log.Warn("could not mark input processed; deferring retry",
			"key", o.Key, "err", err, "retry_in", d)
	} else {
		w.noteFinalized(o.Key)
	}
	// Consume the override sidecar if it existed.
	if len(overrideTerms) > 0 {
		_ = w.store.Delete(ctx, w.cfg.InputBucket, o.Key+termsSuffix)
	}

	// Metrics + job record.
	sum := rep.Summary
	w.metrics.Matches.Add(float64(sum.TotalMatches))
	w.metrics.Passthrough.Add(float64(sum.FilesPassthrough))
	w.metrics.BytesIn.Add(float64(inSize))
	w.metrics.BytesOut.Add(float64(out.Size()))
	w.metrics.Objects.WithLabelValues("scrubbed").Inc()
	w.metrics.Duration.Observe(time.Since(start).Seconds())

	job.Status = "scrubbed"
	job.Phase = ""
	job.CurrentFile = ""
	job.FilesDone = filesDone
	job.Matches = sum.TotalMatches
	job.BytesIn = int(inSize)
	job.BytesOut = int(out.Size())
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
		"binary_skipped", sum.FilesBinarySkip, "changed", changed)
}

func (w *Worker) finish(ctx context.Context, key string) error {
	switch w.cfg.Action {
	case ActionDelete:
		return w.store.Delete(ctx, w.cfg.InputBucket, key)
	default: // move
		return w.store.Move(ctx, w.cfg.InputBucket, key, w.cfg.ProcessedPrefix+key)
	}
}

// Audit detail is configured through report.ParseAuditLevel (shared with the CLI's
// --audit flag) and carried on Config.Audit. The service defaults to counts rather
// than full: full retains every match's original value and replacement, so report
// memory grows with match count rather than input size, and MAX_EXPAND_BYTES does
// not bound it — a small, repetitive log can hit millions of terms. Counts keeps the
// rule and location, which is what an operator needs to verify a scrub, without
// holding the matched text.
