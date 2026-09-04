package worker

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"sync/atomic"

	"github.com/howard/scrubber/internal/metrics"
	"github.com/howard/scrubber/internal/pipeline"
	"github.com/howard/scrubber/internal/store"
	"github.com/prometheus/client_golang/prometheus"
)

func cancelWorker(t *testing.T, ms *memStore) (*Worker, *metrics.JobLog) {
	t.Helper()
	jl := metrics.NewJobLog(10)
	w := New(ms, testRegistry(t), metrics.New(prometheus.NewRegistry()), jl,
		Config{
			InputBucket: "input", OutputBucket: "output", ReportsBucket: "reports",
			Action: ActionMove, PollInterval: time.Hour, Workers: 1, RedactReports: true,
			Limits: pipeline.DefaultLimits(),
		},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	return w, jl
}

// TestCancelQueuedWithdrawsDurably is the core of the feature.
//
// The subtlety is that the queue is only a derived view: Sync() rebuilds the
// pending set wholesale from a bucket listing on every poll, so removing a key
// from memory withdraws nothing — the next listing puts it straight back. A cancel
// has to reach the object itself, and this asserts that it did.
func TestCancelQueuedWithdrawsDurably(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	ms.Put(context.Background(), "input", "big.zip", []byte("hi from AcmeCorp\n"), "")
	w, _ := cancelWorker(t, ms)

	out, err := w.cancel(context.Background(), "big.zip")
	if err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if out != CancelWithdrawn {
		t.Fatalf("outcome = %q, want %q", out, CancelWithdrawn)
	}

	if ms.has("input", "big.zip") {
		t.Error("input still at its original key; the next listing would re-queue it")
	}
	if !ms.has("input", "cancelled/big.zip") {
		t.Error("input was not moved to cancelled/; a withdrawal must not destroy the upload")
	}

	// Two guards, covering two different windows, and they are easy to confuse.
	//
	// The in-memory mark covers the gap between accepting the cancel and the move
	// landing, when the object is still at its original key and a discovery would
	// otherwise queue it.
	if w.eligible(store.Object{Key: "big.zip"}, time.Now()) {
		t.Error("the in-memory mark does not suppress the key; a discovery racing the " +
			"move would re-queue the object and start scrubbing it again")
	}

	// The durable guard is the prefix. This is the one that survives a restart,
	// and it is what actually withdraws the object.
	if w.eligible(store.Object{Key: "cancelled/big.zip"}, time.Now()) {
		t.Error("a withdrawn object under cancelled/ is eligible; it would be scrubbed anyway")
	}

	// End to end: a real discovery must leave the queue empty.
	w.discoverOnce(context.Background(), "test")
	if d := w.q.Depth(); d != 0 {
		t.Errorf("queue depth = %d after cancelling the only object, want 0", d)
	}

	// After that discovery the mark for the ORIGINAL key is swept, which is correct
	// and deliberate: the key has left the listing, so the withdrawal is durable and
	// the name is free again. A later upload reusing it is new work and must scrub.
	if w.isCancelled("big.zip") {
		t.Error("the mark outlived the durable move; a re-upload under this name would be suppressed")
	}
	ms.Put(context.Background(), "input", "big.zip", []byte("hi from AcmeCorp\n"), "")
	w.runOnce(context.Background())
	if !ms.has("output", "big.zip") {
		t.Error("a fresh upload reusing a previously cancelled key was not scrubbed")
	}
}

// TestCancelHonoursDeleteAction: a deployment configured to destroy its inputs did
// not ask for cancelled ones to be kept. Quietly retaining them would override the
// operator's own retention policy for data they chose not to keep.
func TestCancelHonoursDeleteAction(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	ms.Put(context.Background(), "input", "big.zip", []byte("data"), "")
	w, _ := cancelWorker(t, ms)
	w.cfg.Action = ActionDelete

	if _, err := w.cancel(context.Background(), "big.zip"); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if ms.has("input", "big.zip") || ms.has("input", "cancelled/big.zip") {
		t.Error("under ActionDelete a cancelled input must be deleted, not retained")
	}
}

// TestCancelUnknownKeyDoesNotPoisonTheKey. Marking a key that does not exist would
// leave a suppression behind, and a later upload reusing that name would be
// silently never scrubbed — a leak-shaped outcome from a no-op request.
func TestCancelUnknownKeyDoesNotPoisonTheKey(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	w, _ := cancelWorker(t, ms)

	out, err := w.cancel(context.Background(), "never-uploaded.zip")
	if err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if out != CancelNotFound {
		t.Fatalf("outcome = %q, want %q", out, CancelNotFound)
	}
	if w.isCancelled("never-uploaded.zip") {
		t.Fatal("a cancel for a missing key left a mark; a later upload reusing it would be suppressed")
	}
	// Prove it: upload under that key now and confirm it scrubs.
	ms.Put(context.Background(), "input", "never-uploaded.zip", []byte("AcmeCorp\n"), "")
	w.runOnce(context.Background())
	if !ms.has("output", "never-uploaded.zip") {
		t.Error("a key that was cancelled while absent is still suppressed after a real upload")
	}
}

// TestCancelledObjectIsSkippedIfItReachesTheConsumer covers the race where a key
// is cancelled after discovery queued it but before the consumer popped it.
func TestCancelledObjectIsSkippedIfItReachesTheConsumer(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	ms.Put(context.Background(), "input", "big.zip", []byte("AcmeCorp\n"), "")
	w, jl := cancelWorker(t, ms)

	// Queue it, then cancel, then let the consumer run: the object is in the
	// pending set at the moment the cancel lands.
	w.discoverOnce(context.Background(), "test")
	if _, err := w.cancel(context.Background(), "big.zip"); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	w.runOnce(context.Background())

	if ms.has("output", "big.zip") {
		t.Error("a cancelled object was scrubbed and delivered anyway")
	}
	if j, ok := jl.Get("big.zip"); ok && j.Status == "scrubbed" {
		t.Error("job recorded as scrubbed after being cancelled")
	}
}

// TestCancelledPrefixNeverEmpty. Every string has "" as a prefix, so an empty
// value would make eligible() reject the entire input bucket and the service would
// silently stop scrubbing anything at all.
func TestCancelledPrefixNeverEmpty(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	w := New(ms, testRegistry(t), metrics.New(prometheus.NewRegistry()), metrics.NewJobLog(4),
		Config{
			InputBucket: "input", OutputBucket: "output", ReportsBucket: "reports",
			CancelledPrefix: "", // explicitly empty
			Action:          ActionMove, PollInterval: time.Hour, Workers: 1,
			Limits: pipeline.DefaultLimits(),
		},
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	if w.cfg.CancelledPrefix == "" {
		t.Fatal("empty CancelledPrefix was not defaulted; eligible() would reject every key")
	}
	if !strings.HasSuffix(w.cfg.CancelledPrefix, "/") {
		t.Errorf("CancelledPrefix = %q, want a trailing slash", w.cfg.CancelledPrefix)
	}
	if !w.eligible(store.Object{Key: "ordinary.zip"}, time.Now()) {
		t.Error("an ordinary key is ineligible; the empty-prefix guard is not working")
	}
}

// TestCommitIsAtomicWithCancel pins the transition every race hazard turns on.
// commit() must answer "was this cancelled?" and close the door in ONE critical
// section: a cancel landing between a separate check and the write would be told
// "aborting" while the object it named was already being published.
func TestCommitIsAtomicWithCancel(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	w, _ := cancelWorker(t, ms)

	var flag, stalled atomic.Bool
	w.beginInflight("k", func() {}, &flag, &stalled)

	// Commit first: a cancel afterwards must be told it is too late.
	if !w.commit("k") {
		t.Fatal("commit refused an uncancelled object")
	}
	out, err := w.cancel(context.Background(), "k")
	if err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if out != CancelTooLate {
		t.Errorf("outcome = %q, want %q: the output was already written", out, CancelTooLate)
	}
	w.endInflight("k")

	// And the other order: cancel first, commit must refuse.
	ms.Put(context.Background(), "input", "k2", []byte("x"), "")
	var flag2, stalled2 atomic.Bool
	w.beginInflight("k2", func() {}, &flag2, &stalled2)
	if _, err := w.cancel(context.Background(), "k2"); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if w.commit("k2") {
		t.Error("commit allowed delivery of an object whose cancel was already accepted")
	}
}
