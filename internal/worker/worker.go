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
	"sync/atomic"
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
	// StallWarnAfter is how long the in-flight object may sit in one phase before
	// the worker starts logging that it may be stalled. Zero disables the check.
	//
	// It is a log threshold, never a kill: a large bundle legitimately spends many
	// minutes in one phase, so anything that acted on this automatically would
	// destroy real work. The judgement of what is too long belongs to whoever
	// knows the bundles, which is not this process.
	StallWarnAfter time.Duration
	// Audit is how much per-match detail the stored report retains. See
	// ParseAuditLevel: this is a memory setting as much as a disclosure one.
	Audit         report.AuditLevel
	RedactReports bool
	ScrubNames    bool // also scrub archive member names/paths and the output object key
	// ReviewPrefix is where a result lands when the residual scan finds policy
	// matches inside content the scrub did not inspect. Separating those physically
	// is the point: a key under this prefix cannot be picked up by something looking
	// for a finished bundle. Empty disables diversion and leaves the flagging alone.
	ReviewPrefix string
	// CancelledPrefix is where a cancelled input is moved, under Action "move".
	// Cancelling never destroys an upload on a move-configured deployment: the
	// bundle is the user's only copy of logs they were preparing to send out, and
	// the operator's reason for cancelling is usually that it is stuck, not that it
	// is unwanted. Under Action "delete" cancel deletes, because a deployment that
	// asked for inputs to be destroyed did not ask for an exception.
	//
	// Must not be empty: strings.HasPrefix(key, "") is true for every key, which
	// would make the eligibility check reject the entire bucket. New() defaults it
	// and eligible() re-checks defensively.
	CancelledPrefix string
	Limits          pipeline.Limits
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

	// cancelled marks keys an operator has withdrawn. It is consulted by
	// eligible(), which is the single chokepoint every key passes on every poll,
	// so it suppresses a key in the seconds between the cancel being accepted and
	// the durable move landing. It is NOT itself the cancel: it is per-process and
	// empty after a restart, so the durable disposition below is what actually
	// withdraws an object.
	cancelled map[string]time.Time
	// running describes the object being scrubbed right now, or nil when idle.
	// There is exactly one consumer, so this is a single value rather than a map.
	running *inflight
}

// inflight is the handle a cancel needs on the object currently being scrubbed.
type inflight struct {
	key string
	// abort cancels the object's context, which reaches the object-storage calls
	// bracketing the walk.
	abort context.CancelFunc
	// flag is the predicate the pipeline polls. It is separate from the context on
	// purpose: the walk takes no context and cannot be interrupted by one, and a
	// predicate wired to a context would let SIGTERM masquerade as a cancel and
	// silently discard finished work.
	flag *atomic.Bool
	// committed records that the scrubbed output has been written to the output
	// bucket. After that a cancel cannot un-deliver it, and saying otherwise would
	// tell an operator their data was withdrawn when it was published.
	committed bool
}

// retryBackoff returns how long to hold an object back after n consecutive
// failures to mark it processed, capped so it still retries occasionally.
func retryBackoff(n int) time.Duration {
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
	if cfg.ReviewPrefix == "" {
		cfg.ReviewPrefix = "review/"
	}
	// Never leave this empty: eligible() prefix-matches on it, and every string
	// has the empty string as a prefix, so an empty value would reject the whole
	// input bucket and the service would silently stop scrubbing anything.
	if cfg.CancelledPrefix == "" {
		cfg.CancelledPrefix = "cancelled/"
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
		cancelled:  map[string]time.Time{},
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

// InflightPhaseSeconds reports how long the object being scrubbed has been in its
// current phase, or 0 when nothing is in flight.
//
// Read on demand rather than published by the worker, because the case it exists
// to expose is the worker not running: a value the worker had to push would stop
// being updated by exactly the stall it is meant to reveal.
func (w *Worker) InflightPhaseSeconds() float64 {
	inflight, _ := w.q.Snapshot(0)
	if len(inflight) == 0 {
		return 0
	}
	j, ok := w.jobs.Get(inflight[0])
	if !ok || j.Done() {
		return 0
	}
	return j.PhaseSeconds()
}

// watchStalls logs when the in-flight object has sat in one phase longer than
// StallWarnAfter, and again on each subsequent interval until it moves.
//
// The metric alone is enough for someone already watching a dashboard. This is
// for the far more common case of reading the pod's logs after a user reports
// that an upload is stuck: without it the log's last line is "processing object",
// which is equally consistent with working and with wedged.
func (w *Worker) watchStalls(ctx context.Context) {
	every := w.cfg.StallWarnAfter
	if every <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	warned := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			inflight, _ := w.q.Snapshot(0)
			if len(inflight) == 0 {
				warned = ""
				continue
			}
			key := inflight[0]
			j, ok := w.jobs.Get(key)
			if !ok || j.Done() {
				continue
			}
			secs := j.PhaseSeconds()
			if secs < every.Seconds() {
				// Phase changed recently: it is moving, just not quickly.
				warned = ""
				continue
			}
			stamp := key + "|" + j.Phase
			level := "still"
			if warned != stamp {
				level = "now"
				warned = stamp
			}
			w.log.Warn("object has not changed phase for an unusually long time; "+
				"it may be stalled rather than slow",
				"key", key, "phase", j.Phase, "phase_seconds", int64(secs),
				"files_done", j.FilesDone, "state", level)
		}
	}
}

// Run starts the producer and the single consumer and returns once both have
// stopped, which happens after ctx is cancelled. Callers should wait for it during
// shutdown so the process does not exit while an object is mid-flight.
func (w *Worker) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); w.discover(ctx) }()
	go func() { defer wg.Done(); w.consume(ctx) }()
	go func() { defer wg.Done(); w.watchStalls(ctx) }()
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
	// Cancellation marks are swept on the same rule. Once the key is gone from the
	// listing the durable disposition has landed and the mark has done its job;
	// keeping it would mean a later upload that happens to reuse the key inherits
	// a withdrawal it never asked for and is silently never scrubbed.
	for k := range w.cancelled {
		if _, ok := present[k]; !ok {
			delete(w.cancelled, k)
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
	// A withdrawn object lives under this prefix. Guarded against an empty value
	// as well as defaulted in New, because every string has "" as a prefix and the
	// failure mode is the entire bucket silently becoming ineligible.
	if w.cfg.CancelledPrefix != "" && strings.HasPrefix(o.Key, w.cfg.CancelledPrefix) {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, off := w.cancelled[o.Key]; off {
		// Cancelled, but the durable move may not have landed yet. This is the only
		// thing covering that window: Sync() rebuilds the pending set wholesale from
		// the listing, so without it a discovery running between the mark and the
		// move re-queues the object and the consumer starts scrubbing it again.
		return false
	}
	if until, held := w.deferUntil[o.Key]; held && now.Before(until) {
		return false // finalization failed recently; wait out the backoff
	}
	// Size is enforced in processObject via a bounded read (GetLimited), so an
	// object whose listed size is unknown or wrong still can't OOM the pod.
	return true
}

// CancelOutcome is what a cancel request achieved. The distinction matters to the
// caller: an operator told "cancelled" and an operator told "too late" need to do
// different things next.
type CancelOutcome string

const (
	// CancelWithdrawn: the object was not being scrubbed. It is marked and its
	// input has been disposed of, so it will never run.
	CancelWithdrawn CancelOutcome = "withdrawn"
	// CancelAborting: the object was in flight and has been told to stop. The
	// worker disposes of the input once the walk unwinds, which is not instant —
	// the walk polls the abort predicate between members.
	CancelAborting CancelOutcome = "aborting"
	// CancelTooLate: the scrubbed output was already written to the output bucket.
	// Nothing is withdrawn, and claiming otherwise would tell an operator their
	// data was pulled back when it was published.
	CancelTooLate CancelOutcome = "too-late"
	// CancelNotFound: no such object in the input bucket.
	CancelNotFound CancelOutcome = "not-found"
)

// Cancel withdraws an object, whether it is queued or being scrubbed right now.
//
// The whole transition happens under one lock acquisition. Splitting it — read the
// state, decide, then act — is the bug this design exists to avoid: a cancel that
// lands between the worker's last cancellation check and its commit would be told
// "aborting" while the object it named was already on its way to the output bucket.
// One critical section means there is no third outcome to fall into.
// Cancel implements the server's Canceller. It returns a string rather than the
// typed outcome so the server package keeps no dependency on the worker.
func (w *Worker) Cancel(ctx context.Context, key string) (string, error) {
	o, err := w.cancel(ctx, key)
	return string(o), err
}

func (w *Worker) cancel(ctx context.Context, key string) (CancelOutcome, error) {
	w.mu.Lock()
	if w.running != nil && w.running.key == key {
		if w.running.committed {
			w.mu.Unlock()
			return CancelTooLate, nil
		}
		// Mark first, then signal. The mark is what stops discovery re-queueing the
		// key while the walk unwinds; the signal is what makes the walk unwind at
		// all. Disposal is deliberately left to the worker: two goroutines mutating
		// the same input object is how a cancel races a finalize.
		w.cancelled[key] = time.Now()
		w.running.flag.Store(true)
		abort := w.running.abort
		w.mu.Unlock()
		abort()
		w.log.Warn("cancel accepted for the object being scrubbed; aborting the walk", "key", key)
		return CancelAborting, nil
	}
	// Not in flight. Mark it before any I/O so that a discovery running right now
	// cannot queue it in the window before the input is disposed of.
	w.cancelled[key] = time.Now()
	w.mu.Unlock()

	if _, found, err := w.store.Stat(ctx, w.cfg.InputBucket, key); err != nil {
		return "", fmt.Errorf("check input: %w", err)
	} else if !found {
		// Nothing to withdraw. Do not keep the mark: a later upload reusing this
		// key would inherit it and be silently suppressed.
		w.unmarkCancelled(key)
		return CancelNotFound, nil
	}
	if err := w.disposeCancelled(ctx, key); err != nil {
		w.unmarkCancelled(key)
		return "", err
	}
	w.metrics.Objects.WithLabelValues("cancelled").Inc()
	w.log.Warn("object withdrawn from the queue by request", "key", key)
	return CancelWithdrawn, nil
}

// disposeCancelled makes the withdrawal durable. Until this lands the cancel is
// only a per-process marker that a restart would forget, leaving the object in the
// input bucket to be scrubbed as if nothing had happened.
//
// It honours Action rather than always moving: a deployment configured to delete
// its inputs did not ask for cancelled ones to be kept, and quietly retaining them
// would override the operator's own retention policy.
func (w *Worker) disposeCancelled(ctx context.Context, key string) error {
	if w.cfg.Action == ActionDelete {
		return w.store.Delete(ctx, w.cfg.InputBucket, key)
	}
	return w.store.Move(ctx, w.cfg.InputBucket, key, w.cfg.CancelledPrefix+key)
}

// isCancelled reports whether a withdrawal has been accepted for key.
func (w *Worker) isCancelled(key string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, ok := w.cancelled[key]
	return ok
}

func (w *Worker) unmarkCancelled(key string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.cancelled, key)
}

// beginInflight registers the running object so a cancel can reach it, and
// reports false if the key was already withdrawn while it sat in the queue.
func (w *Worker) beginInflight(key string, abort context.CancelFunc, flag *atomic.Bool) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, off := w.cancelled[key]; off {
		return false
	}
	w.running = &inflight{key: key, abort: abort, flag: flag}
	return true
}

// endInflight clears the registration.
func (w *Worker) endInflight() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.running = nil
}

// commit is the point of no return, and it is a single atomic transition on
// purpose: it answers "was this cancelled?" and closes the door to further cancels
// in one critical section. Checking and committing separately leaves a window in
// which a cancel is accepted for an object that then publishes anyway.
//
// Returns false if the object has been cancelled and must not be delivered.
func (w *Worker) commit(key string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, off := w.cancelled[key]; off {
		return false
	}
	if w.running != nil && w.running.key == key {
		w.running.committed = true
	}
	return true
}

// clearDeferral clears any backoff state for a key that completed cleanly.
func (w *Worker) clearDeferral(key string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.deferUntil, key)
	delete(w.attempts, key)
}

// deferRetry records a failure and returns the backoff applied.
func (w *Worker) deferRetry(key string) time.Duration {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.attempts[key]++
	d := retryBackoff(w.attempts[key])
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
	// Register before any work so a cancel arriving in the first millisecond finds
	// something to act on, and derive the object's own context so aborting it does
	// not disturb the worker's.
	//
	// The abort flag is deliberately NOT derived from this context. The walk takes
	// no context and polls the flag instead; wiring the flag to ctx.Done would make
	// SIGTERM indistinguishable from a cancel and silently discard finished scrubs
	// on every rollout.
	var aborted atomic.Bool
	ctx, abort := context.WithCancel(ctx)
	defer abort()
	if !w.beginInflight(o.Key, abort, &aborted) {
		// Withdrawn while it waited in the queue. Nothing has been read, so there is
		// nothing to undo; the input was already disposed of by Cancel.
		w.log.Info("skipping object withdrawn before it started", "key", o.Key)
		return
	}
	defer w.endInflight()

	job.Status = "processing"
	job.Phase = "reading"
	job.PhaseSince = time.Now()
	w.jobs.Upsert(job)
	w.log.Info("processing object", "key", o.Key, "size", o.Size)

	// cancelledExit records the withdrawal and disposes of the input. Called from
	// every point the walk can unwind after a cancel.
	cancelledExit := func() {
		w.metrics.Objects.WithLabelValues("cancelled").Inc()
		job.Status = "cancelled"
		job.Phase = ""
		job.Error = "withdrawn by request before the scrub completed"
		record(job)
		// Detached: the object's own context has just been cancelled by the abort,
		// so the disposal would fail immediately on it.
		dctx, dcancel := context.WithTimeout(context.WithoutCancel(ctx), w.cfg.FinalizeGrace)
		defer dcancel()
		if err := w.disposeCancelled(dctx, o.Key); err != nil {
			d := w.deferRetry(o.Key)
			w.log.Warn("could not dispose of a cancelled input; it stays in the bucket and is retried",
				"key", o.Key, "err", err, "retry_in", d)
			return
		}
		w.log.Warn("scrub aborted and input withdrawn", "key", o.Key)
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
		// A stalled transfer is counted under its own label, on whichever path it
		// happened. It is not a fault of the object — retrying it is the right
		// response, where an ordinary error usually means it will fail again — and
		// it is the failure mode that used to present as no failure at all: the
		// consumer blocked forever, every upload behind it queued, and the pod
		// stayed live and ready throughout. Alert on this label.
		//
		// The write path matters at least as much as the read: it stalls *after*
		// the object is scrubbed, so the work is done, uncommitted, and the queue
		// is blocked behind it.
		if errors.Is(err, store.ErrStalled) {
			// Held back with the same backoff a failed finalize gets. Without it the
			// object keeps its original LastModified — by definition the oldest in
			// the bucket — so it returns to the HEAD of the queue and every upload
			// behind it pays the stall timeout again on every cycle. One unreadable
			// object would throttle everybody.
			d := w.deferRetry(o.Key)
			w.metrics.Objects.WithLabelValues("stalled").Inc()
			// "retrying", not "error". The object is still in the input bucket and
			// will be picked up again; calling it an error makes the upload page
			// give up and show a permanent failure for something that is very
			// likely to succeed on the next attempt.
			job.Status = "retrying"
			job.RetryInSeconds = int(d.Round(time.Second).Seconds())
			job.Error = err.Error()
			record(job)
			w.log.Error("object storage transfer stalled and was abandoned; the object "+
				"stays in the input bucket and is retried after a backoff",
				"key", o.Key, "err", err, "retry_in", d)
			return
		}
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
				d := w.deferRetry(o.Key)
				w.log.Warn("could not move oversized input aside; deferring retry",
					"key", o.Key, "err", ferr, "retry_in", d)
			} else {
				w.clearDeferral(o.Key)
			}
			return
		}
		// A stall wrapped here still satisfies errors.Is, so fail classifies it.
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
	//
	// The phase starts at "unpacking", not "scrubbing". A container is expanded in
	// full before its first member reaches the matcher, so nothing can increment
	// FilesDone until that finishes — on a 1.4 GiB zip that window is seconds, but
	// on a stalled backend read it is unbounded. Claiming "scrubbing" through it
	// told a client the one thing that was certainly not happening, and left it
	// with no way to distinguish slow from wedged.
	job.Phase = "unpacking"
	job.PhaseSince = time.Now()
	w.jobs.Upsert(job)
	filesDone := 0
	rep.OnFile(func(f report.FileEntry) {
		filesDone++
		if filesDone == 1 {
			// First member out of the container: unpacking is demonstrably over.
			job.Phase = "scrubbing"
			job.PhaseSince = time.Now()
		}
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

	eng := &pipeline.Engine{
		Matcher: res.Matcher, Report: rep, Limits: w.cfg.Limits, ScrubNames: w.cfg.ScrubNames,
		// The only thing that can stop the walk. It polls this between members; an
		// aborted walk returns every container unchanged rather than a partial
		// rebuild, so `changed` collapses to false and there is nothing to deliver.
		Abort: aborted.Load,
	}
	// Release every blob the walk staged. This runs before the panic recovery
	// above (defers unwind last-registered-first), so a bug anywhere in the
	// pipeline costs one object rather than a temp file that outlives it.
	defer eng.Release()
	out, changed := eng.ProcessBlob(o.Key, input, 0)
	if eng.Aborted() {
		// Withdrawn mid-walk. Everything staged is released by the defers above; no
		// output, report or digest is written, and the verdict below is deliberately
		// never computed — a cancelled object has no coverage answer to give.
		cancelledExit()
		return
	}
	if changed {
		// ProcessBlob returns the input itself when nothing changed, so only close
		// the result when it is genuinely a separate payload.
		defer out.Close()
	}
	rep.EndedAt = time.Now()
	rep.BytesIn = int(inSize)
	rep.BytesOut = int(out.Size())

	// The verdict decides where this lands. A result whose skipped parts contain
	// policy matches goes to the review prefix rather than the place a consumer
	// looks for finished work — flagging alone has already been shown not to be
	// enough, because a flag only helps someone who reads it.
	verdict := rep.Summary.Verdict()
	if verdict.NeedsReview() && w.cfg.ReviewPrefix != "" {
		outKey = w.cfg.ReviewPrefix + outKey
		job.OutputKey = outKey
		rep.OutputKey = outKey
		w.log.Warn("result diverted for review: content that was NOT inspected contains policy matches",
			"key", o.Key, "output_key", outKey, "residual_hits", rep.Summary.ResidualHits,
			"samples", strings.Join(rep.Summary.ResidualSamples, "; "))
	}

	job.Phase = "writing"
	job.PhaseSince = time.Now()
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

	// The point of no return, and the last chance to honour a cancel.
	//
	// This is one atomic transition rather than a check followed by a write: a
	// cancel landing between a separate check and this point would be answered
	// "aborting" while the object it named was already being published. commit()
	// answers "not cancelled" and closes the door in the same critical section, so
	// after it returns true a concurrent Cancel is truthfully told "too late".
	//
	// It sits below the shutdown-detach branch on purpose. That branch exists so a
	// SIGTERM does not discard finished work — but it must not also resurrect an
	// object whose withdrawal was accepted moments earlier.
	if !w.commit(o.Key) {
		cancelledExit()
		return
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
		d := w.deferRetry(o.Key)
		w.log.Warn("could not mark input processed; deferring retry",
			"key", o.Key, "err", err, "retry_in", d)
	} else {
		w.clearDeferral(o.Key)
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
	job.BinarySkipped = sum.FilesBinarySkip
	job.BinarySkipPaths = sum.BinarySkips
	job.Verdict = verdict
	job.NotInspected = sum.FilesNotInspected
	job.NotInspectedSet = sum.NotInspected
	job.ResidualHits = sum.ResidualHits
	job.ResidualSamples = sum.ResidualSamples
	record(job)

	w.metrics.Verdicts.WithLabelValues(string(verdict)).Inc()
	w.metrics.Residual.Add(float64(sum.ResidualHits))
	for reason, n := range sum.ByReason {
		w.metrics.NotInspected.WithLabelValues(string(reason)).Add(float64(n))
	}

	// One line, keyed on the verdict. This used to be two conditions that classified
	// outcomes differently from HasUnscrubbed, which is how a run could log "file not
	// scrubbed" and still report itself clean.
	switch verdict {
	case report.VerdictComplete:
		w.log.Info("scrubbed", "key", o.Key, "policy", res.Name, "verdict", verdict,
			"matches", sum.TotalMatches, "changed", changed)
	case report.VerdictIncomplete:
		w.log.Warn("scrubbed WITH UNINSPECTED FILES; review before sharing",
			"key", o.Key, "policy", res.Name, "verdict", verdict, "matches", sum.TotalMatches,
			"not_inspected", sum.FilesNotInspected, "paths", noteList(sum.NotInspected))
	default:
		w.log.Error("scrubbed WITH UNINSPECTED FILES THAT CONTAIN MATCHES; diverted for review",
			"key", o.Key, "policy", res.Name, "verdict", verdict, "matches", sum.TotalMatches,
			"not_inspected", sum.FilesNotInspected, "residual_hits", sum.ResidualHits,
			"paths", noteList(sum.NotInspected))
	}
}

// noteList renders uninspected-file notes for a log line, leading with the reason
// code so the line greps cleanly and a new failure mode is visible as a new code.
func noteList(notes []report.Note) string {
	parts := make([]string, 0, len(notes))
	for _, p := range notes {
		s := fmt.Sprintf("%s [%s] %s", p.Path, p.Code, p.Detail)
		if p.Residual != "" {
			s += fmt.Sprintf(" — CONTAINS %s", p.Residual)
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, "; ")
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
