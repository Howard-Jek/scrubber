package pipeline

import (
	"bytes"
	"strings"
	"testing"

	"github.com/howard/scrubber/internal/report"
)

// TestLateDeadlineDoesNotDiscardAFinishedWalk pins the difference between asking
// "did the walk stop?" and "has the deadline passed?".
//
// The worker used to ask the second question after the walk returned. A timer
// firing in that gap condemned a scrub that was already complete: the output was
// thrown away, the input was moved aside as a timeout, and it was never retried.
// An hour of work discarded at the moment it succeeded, and reported to the user
// as a bundle too big to process.
func TestLateDeadlineDoesNotDiscardAFinishedWalk(t *testing.T) {
	expired := false
	rep := report.New("in", "out", report.AuditFull, false, "test")
	eng := &Engine{
		Matcher: testMatcher(t),
		Report:  rep,
		Limits:  DefaultLimits(),
		Abort:   func() bool { return expired },
	}

	body := []byte("host AcmeCorp at 10.1.2.3 mail bob@acme.test\n")
	out := eng.Process("bundle.tar", tarOf(t, "logs/app.log", body), 0)

	// The walk finished. Now the deadline expires.
	expired = true

	if eng.WasAborted() {
		t.Error("a walk that ran to completion reported itself aborted because the deadline " +
			"passed afterwards; its finished output would be discarded")
	}
	if !eng.Aborted() {
		t.Error("Aborted must still poll the predicate — it is what stops the NEXT walk")
	}
	if bytes.Contains(out, []byte("AcmeCorp")) {
		t.Error("the completed walk did not actually scrub, so this test proves nothing")
	}
}

// TestRebuildingAContainerReportsProgress covers the stretch of the walk that
// files no report entry.
//
// Rebuilding a container and recompressing it happen after the last member has
// been recorded, and nothing on that path touched the report. So the progress
// stamp went stale and the last member that finished stayed on the record as the
// "current file" — which is how an object busily rebuilding a multi-gigabyte
// archive came to be reported as making no observable progress, naming a file it
// had already finished, for as long as the rebuild took.
func TestRebuildingAContainerReportsProgress(t *testing.T) {
	line := "2026-06-12T09:00:00Z INFO user bob@acme.test from 10.1.2.3 org=AcmeCorp\n"
	body := []byte(strings.Repeat(line, 4096))

	var stages []string
	var last int64
	rep := report.New("in", "out", report.AuditOff, false, "test")
	eng := &Engine{
		Matcher: testMatcher(t),
		Report:  rep,
		Limits:  DefaultLimits(),
		Progress: func(stage string, n int64) {
			stages = append(stages, stage)
			last = n
		},
	}

	out := eng.Process("bundle.tar", tarOf(t, "logs/app.log", body), 0)
	if bytes.Contains(out, []byte("AcmeCorp")) {
		t.Fatal("the member was not scrubbed, so no rebuild happened and this test proves nothing")
	}
	if len(stages) == 0 {
		t.Fatal("rebuilding a container reported no progress at all; a long rebuild is " +
			"indistinguishable from a wedged process, which is exactly what the stall " +
			"warning kept reporting")
	}
	if !strings.Contains(stages[0], "tar") {
		t.Errorf("progress stage = %q, want it to name what is being rebuilt", stages[0])
	}
	if last <= 0 {
		t.Errorf("progress reported %d bytes written", last)
	}
}

// TestRebuildIsInterruptible is the other half: the abort must be polled DURING a
// rebuild, not only before it. A container large enough to outlast the scrub
// budget used to finish rebuilding regardless, because the nearest poll was at the
// member loop it had already left.
func TestRebuildIsInterruptible(t *testing.T) {
	line := "2026-06-12T09:00:00Z INFO user bob@acme.test from 10.1.2.3 org=AcmeCorp\n"
	body := []byte(strings.Repeat(line, 4096))

	stop := false
	rep := report.New("in", "out", report.AuditOff, false, "test")
	eng := &Engine{
		Matcher: testMatcher(t),
		Report:  rep,
		Limits:  DefaultLimits(),
		// Trip the abort the moment the rebuild starts writing.
		Abort:    func() bool { return stop },
		Progress: func(string, int64) { stop = true },
	}

	in := tarOf(t, "logs/app.log", body)
	out := eng.Process("bundle.tar", in, 0)

	if !eng.WasAborted() {
		t.Fatal("the abort tripped during the rebuild and the walk did not notice")
	}
	if !bytes.Equal(out, in) {
		t.Error("an aborted rebuild returned something other than its input; a half-written " +
			"container must never reach an output")
	}
}
