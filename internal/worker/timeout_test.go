package worker

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/howard/scrubber/internal/metrics"
	"github.com/howard/scrubber/internal/store"
)

// An object that outruns its budget must FAIL, publish nothing, and stop coming
// back.
//
// Before SCRUB_TIMEOUT existed nothing bounded the walk at all: STALL_WARN_AFTER
// only ever wrote a log line, and the transfer timeouts bound object-storage calls
// rather than the work between them. One bundle held the single consumer for over
// three hours with every upload behind it queued.
func TestScrubTimeoutFailsTheObject(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	ms.Put(context.Background(), "input", "bundle.tar.gz", spillingBundle(t, 8, 4<<10), "")

	w := newTestWorker(t, ms)
	// One nanosecond: the deadline is already past when the walk starts, so the
	// first abort poll trips it and the test does not race a real clock.
	w.cfg.ScrubTimeout = time.Nanosecond
	w.runOnce(context.Background())

	j, ok := w.jobs.Get("bundle.tar.gz")
	if !ok {
		t.Fatal("no job recorded for a timed-out object")
	}
	if j.Status != "error" {
		t.Fatalf("status = %q, want %q — a timeout is a failure, not a cancellation "+
			"and not a success", j.Status, "error")
	}
	if !j.Done() {
		t.Error("a timed-out job must be terminal; a client waiting on it would never stop")
	}

	// Nothing partial may reach a consumer.
	if ms.has("output", "bundle.tar.gz") {
		t.Error("an output object was written for a scrub that never finished")
	}
	if ms.has("reports", "bundle.tar.gz.report.json") {
		t.Error("a report was written for a scrub that never finished")
	}
	// And it must not come back: the same budget would fail it again, forever,
	// with the whole queue behind it.
	if ms.has("input", "bundle.tar.gz") {
		t.Error("the input is still at its original key; the next poll would retry it " +
			"and it would time out again")
	}
	if !ms.has("input", "processed/bundle.tar.gz") {
		t.Error("the input was not moved aside")
	}
}

// The error text is the whole deliverable of a failure: there is no underlying
// error to read, so anything it does not say, nobody learns.
func TestScrubTimeoutErrorSaysWhatAndWhy(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	ms.Put(context.Background(), "input", "bundle.tar.gz", spillingBundle(t, 8, 4<<10), "")

	w := newTestWorker(t, ms)
	w.cfg.ScrubTimeout = time.Nanosecond
	w.runOnce(context.Background())

	j, _ := w.jobs.Get("bundle.tar.gz")
	for _, want := range []string{
		"SCRUB_TIMEOUT", // which setting
		"NOT scrubbed",  // what the object is now
		"processed/",    // where the input went
		"re-upload",     // how to retry
		"more CPU",      // what to change
	} {
		if !strings.Contains(j.Error, want) {
			t.Errorf("timeout error does not mention %q; it reads:\n%s", want, j.Error)
		}
	}
}

// Zero is the old behaviour and must stay available: a deployment with no queue
// contention may legitimately want an object to run as long as it takes.
func TestScrubTimeoutZeroDoesNotBoundTheWalk(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	ms.Put(context.Background(), "input", "bundle.tar.gz", spillingBundle(t, 4, 4<<10), "")

	w := newTestWorker(t, ms)
	w.cfg.ScrubTimeout = 0
	w.runOnce(context.Background())

	j, ok := w.jobs.Get("bundle.tar.gz")
	if !ok {
		t.Fatal("no job recorded")
	}
	if j.Status != "scrubbed" {
		t.Fatalf("status = %q (%s), want %q", j.Status, j.Error, "scrubbed")
	}
}

// Every failure has to say where it happened. An operation name alone does not
// tell anyone whether the bundle was half-scrubbed or which member it stopped on,
// and those are the first questions asked of an object that did not come out.
func TestFailureDetailNamesThePosition(t *testing.T) {
	cases := []struct {
		name string
		at   position
		want []string
	}{
		{
			name: "mid-archive",
			at: position{phase: "scrubbing", filesDone: 37, filesTotal: 58,
				currentFile: "logs/app-036.log", noProgress: 12 * time.Minute},
			want: []string{"while scrubbing", "37 of 58 files finished",
				`"logs/app-036.log"`, "nothing had completed in the previous 12m0s"},
		},
		{
			name: "still expanding",
			at:   position{phase: "unpacking"},
			want: []string{"expanding the container", "before a single file had been finished"},
		},
		{
			name: "no phase yet",
			at:   position{},
			want: []string{"before any work had started"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.at.String()
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("position does not mention %q; it reads: %s", w, got)
				}
			}
		})
	}
}

// A member path is sensitive: the failure text is served from the unauthenticated
// /api/status, and a raw path discloses what the scrub exists to remove. The
// worker redacts it before it ever reaches a position; this asserts the field is
// carried through verbatim rather than re-derived from anything raw.
func TestPositionCarriesTheRedactedPath(t *testing.T) {
	p := position{phase: "scrubbing", filesDone: 1, currentFile: "logs/[COMPANY]/[REDACTED].log"}
	if !strings.Contains(p.String(), "[REDACTED]") {
		t.Fatalf("redacted path not carried through: %s", p.String())
	}
}

// The stall WARNING and the timeout answer different questions and must not be
// confused again: one says "look at this", the other ends the object. A job that
// has merely been slow is not failed by the warning threshold.
func TestStallWarnAfterDoesNotFailTheObject(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	ms.Put(context.Background(), "input", "bundle.tar.gz", spillingBundle(t, 4, 4<<10), "")

	w := newTestWorker(t, ms)
	w.cfg.StallWarnAfter = time.Nanosecond // would fire immediately if it were a kill
	w.cfg.ScrubTimeout = time.Hour
	w.runOnce(context.Background())

	j, _ := w.jobs.Get("bundle.tar.gz")
	if j.Status != "scrubbed" {
		t.Fatalf("status = %q (%s); STALL_WARN_AFTER is a log threshold, never a kill",
			j.Status, j.Error)
	}
}

// The timeout status is its own metric label, because the response differs: an
// "error" usually means the object is bad, a "timeout" means the budget or the CPU
// is too small for the bundles arriving.
func TestTimeoutIsADeclaredObjectStatus(t *testing.T) {
	for _, s := range metrics.ObjectStatuses {
		if s == "timeout" {
			return
		}
	}
	t.Fatal(`"timeout" is not in metrics.ObjectStatuses, so the series is not seeded ` +
		`and an alert on it cannot tell "healthily zero" from "does not exist"`)
}

// stallingStore latches the watchdog's verdict on an object as its bytes are read.
//
// The real watchdog fires from a ticker against a wall-clock budget, which a test
// can only reach by racing it. This reaches the same state by the same door --
// abortStalled, on an object already registered in flight -- so the walk aborts for
// exactly the reason STALL_ABORT_AFTER would have given it, deterministically.
// attemptsFor reads the retry counter under the lock, which is what several tests
// use to tell "backed off" from "will retake the head of the queue".
func attemptsFor(w *Worker, key string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.attempts[key]
}

type stallingStore struct {
	*memStore
	w   *Worker
	key string
	// moveErr, when set, refuses the set-aside. It models the deployment this most
	// concerns: one configured to delete its inputs, whose credentials therefore
	// need no write access to the input bucket at all.
	moveErr error
}

func (s *stallingStore) Move(ctx context.Context, bucket, src, dst string) error {
	if s.moveErr != nil {
		return s.moveErr
	}
	return s.memStore.Move(ctx, bucket, src, dst)
}

func (s *stallingStore) GetLimitedTo(ctx context.Context, dst io.Writer, bucket, key string, max int64) (int64, error) {
	n, err := s.memStore.GetLimitedTo(ctx, dst, bucket, key, max)
	if key == s.key {
		s.w.abortStalled(key)
	}
	return n, err
}

// A stalled input is MOVED aside under every Action, including delete.
//
// This is the one disposal that does not consult Action, and the reason is that the
// stall verdict is inferred rather than measured: it is reached from an absence of
// heartbeats, so it can land on healthy work. Nothing was published for this object
// -- no output, no report -- so deleting the input on that inference destroys what
// may be the only copy, and destroys it on a guess.
//
// The regression this pins is a message that contradicted its own code: stalledExit
// called finish(), which deletes under ActionDelete, and then told the operator the
// input had been preserved rather than deleted "because it may be the only copy".
// An operator reading that went looking in the bucket for an object the service had
// just destroyed.
func TestStalledInputIsMovedAsideUnderEveryAction(t *testing.T) {
	for _, action := range []ProcessedAction{ActionMove, ActionDelete} {
		t.Run(string(action), func(t *testing.T) {
			const key = "bundle.tar.gz"
			ms := newMemStore("input", "output", "reports")
			ms.Put(context.Background(), "input", key, spillingBundle(t, 8, 4<<10), "")

			w := newTestWorker(t, ms)
			w.cfg.Action = action
			w.cfg.StallAbortAfter = time.Minute // stood in for by stallingStore
			w.store = &stallingStore{memStore: ms, w: w, key: key}
			w.runOnce(context.Background())

			// The input survives, at a key the next poll will not pick up.
			if ms.has("input", key) {
				t.Error("the stalled input is still at its original key; the next poll " +
					"would wedge another consumer on it")
			}
			if !ms.has("input", "processed/"+key) {
				t.Fatal("the stalled input was destroyed rather than moved aside; the scrub " +
					"published nothing, so this may have been the only copy")
			}

			// Nothing partial reached a consumer.
			if ms.has("output", key) {
				t.Error("an output object was written for a scrub that never finished")
			}
			if ms.has("reports", key+".report.json") {
				t.Error("a report was written for a scrub that never finished")
			}

			j, ok := w.jobs.Get(key)
			if !ok {
				t.Fatal("no job recorded for a stalled object")
			}
			if j.Status != "error" {
				t.Errorf("status = %q, want error — a stall abort is a failure, not a "+
					"cancellation and not a success", j.Status)
			}
			if !j.Done() {
				t.Error("a stalled job must be terminal; a client waiting on it would never stop")
			}
			// Reached by the stall branch specifically, not by some other terminal
			// path that happens to move the input aside too.
			if !strings.Contains(j.Error, "STALL_ABORT_AFTER") {
				t.Fatalf("object did not fail as a stall; it reads:\n%s", j.Error)
			}
			// The failure text is the whole deliverable here, and it must describe the
			// disposal that actually happened.
			if !strings.Contains(j.Error, "moved to processed/"+key) {
				t.Errorf("error text does not say where the input went; it reads:\n%s", j.Error)
			}
			saysPreserved := strings.Contains(j.Error, "this deployment deletes finished inputs")
			if action == ActionDelete && !saysPreserved {
				t.Errorf("under %s the operator is not told the input was kept; it reads:\n%s",
					action, j.Error)
			}
			if action == ActionMove && saysPreserved {
				t.Errorf("under %s the text explains an exception that does not apply; "+
					"it reads:\n%s", action, j.Error)
			}
		})
	}
}

// A set-aside the bucket refuses must leave the object BACKED OFF, not at the head
// of the queue.
//
// This branch was unreachable for a delete deployment until stalled inputs started
// being moved rather than deleted, and reaching it without a deferral would have
// rebuilt the exact loop the stall abort exists to break: attempts stays 0, orderKey
// falls back to the object's LastModified — the oldest key in the bucket — and the
// object retakes the head of the next poll to wedge another consumer for another
// whole stall budget, forever.
func TestStalledInputThatCannotBeMovedAsideIsBackedOff(t *testing.T) {
	const key = "bundle.tar.gz"
	ms := newMemStore("input", "output", "reports")
	ms.Put(context.Background(), "input", key, spillingBundle(t, 8, 4<<10), "")

	w := newTestWorker(t, ms)
	w.cfg.Action = ActionDelete
	w.cfg.StallAbortAfter = time.Minute
	w.store = &stallingStore{memStore: ms, w: w, key: key,
		moveErr: errors.New("access denied")}
	w.runOnce(context.Background())

	if !ms.has("input", key) {
		t.Fatal("the input left the bucket even though the move was refused")
	}
	if attemptsFor(w, key) == 0 {
		t.Error("no attempt recorded: attempts stays 0, so orderKey returns the object's " +
			"LastModified and it retakes the head of the queue on the very next poll")
	}
	if w.eligible(store.Object{Key: key}, time.Now()) {
		t.Error("the object is immediately eligible again; it will wedge a consumer for " +
			"another full stall budget every cycle, with the queue behind it")
	}

	j, ok := w.jobs.Get(key)
	if !ok {
		t.Fatal("no job recorded")
	}
	// It must not claim a disposal that did not happen — an operator sent to
	// processed/ for an object still sitting at its own key learns nothing.
	if strings.Contains(j.Error, "was moved to") {
		t.Errorf("error text claims a move that was refused; it reads:\n%s", j.Error)
	}
	if !strings.Contains(j.Error, "attempted again in") {
		t.Errorf("error text does not say the object comes back, or when; it reads:\n%s", j.Error)
	}
}
