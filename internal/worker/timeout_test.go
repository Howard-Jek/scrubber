package worker

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/howard/scrubber/internal/metrics"
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
