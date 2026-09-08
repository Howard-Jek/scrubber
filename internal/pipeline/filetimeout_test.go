package pipeline

import (
	"bytes"
	"testing"
	"time"

	"github.com/howard/scrubber/internal/report"
)

// runEng is run() with the engine handed back, so a test can ask WasAborted --
// the difference between "one file was skipped" and "the whole walk collapsed".
func runEng(t *testing.T, data []byte, lim Limits) ([]byte, *report.Report, *Engine) {
	t.Helper()
	rep := report.New("in", "out", report.AuditFull, false, "test")
	eng := &Engine{Matcher: testMatcher(t), Report: rep, Limits: lim}
	return eng.Process("bundle", data, 0), rep, eng
}

// TestFileTimeoutCostsOneFileNotTheArchive is the contract for the per-file budget,
// and the whole reason it exists apart from SCRUB_TIMEOUT.
//
// Every other time budget here is scoped to the object: SCRUB_TIMEOUT condemns the
// whole bundle and publishes nothing, and STALL_ABORT_AFTER only fires when nothing
// at all is moving. Neither can express "this one member is pathological". So one
// dense file used to take a bundle of ordinary logs down with it.
//
// The discriminator in this test is real rather than mocked: ScrubAbortable polls
// its predicate every abortCheckMatches matches, so the large member reaches a poll
// and the small ones never do. With the budget already spent, the large one is
// abandoned at its first poll and its neighbours are scrubbed untouched.
func TestFileTimeoutCostsOneFileNotTheArchive(t *testing.T) {
	big := repetitiveLog(2000) // ~6000 matches: reaches a poll
	small := repetitiveLog(5)  // ~15 matches: never polls, must scrub normally

	data := tarOfMany(t, [][2]any{
		{"small-a.log", small},
		{"huge.log", big},
		{"small-b.log", small},
	})

	lim := DefaultLimits()
	lim.MaxFileTime = time.Nanosecond // already spent by the first poll

	out, rep, eng := runEng(t, data, lim)

	if eng.WasAborted() {
		t.Fatal("a per-file timeout must not abort the walk; that condemns the whole " +
			"object and publishes nothing, which is the failure this exists to avoid")
	}

	var hole *report.PassthroughNote
	for i := range rep.Summary.Passthroughs {
		if rep.Summary.Passthroughs[i].Code == report.ReasonFileTimeout {
			hole = &rep.Summary.Passthroughs[i]
		}
	}
	if hole == nil {
		t.Fatalf("no file-timeout hole recorded; got %+v", rep.Summary.Passthroughs)
	}
	if hole.Status != report.StatusGuardTripped {
		t.Errorf("status = %q, want %q", hole.Status, report.StatusGuardTripped)
	}
	t.Logf("recorded: %s — %s", hole.Path, hole.Detail)

	// The timed-out member keeps its original bytes...
	if !bytes.Contains(out, []byte("bob@acme.test")) {
		t.Error("the abandoned file should be present unscrubbed; it was not passed through")
	}
	// ...and its neighbours were still scrubbed, which is the entire point.
	if !bytes.Contains(out, []byte("[EMAIL]")) {
		t.Error("no member was scrubbed; one slow file took the whole archive down with it")
	}
}

// TestFileTimeoutZeroIsDisabled: zero must mean no cap, which is what shipped and
// what the CLI relies on.
func TestFileTimeoutZeroIsDisabled(t *testing.T) {
	body := repetitiveLog(2000)
	lim := DefaultLimits()
	lim.MaxFileTime = 0

	out, rep := run(t, body, lim)
	for _, p := range rep.Summary.Passthroughs {
		if p.Code == report.ReasonFileTimeout {
			t.Fatal("MaxFileTime=0 abandoned a file; zero must disable the check")
		}
	}
	if bytes.Contains(out, []byte("bob@acme.test")) {
		t.Error("payload not scrubbed with the check disabled")
	}
}

// TestFileTimeoutGenerousBudgetScrubsNormally guards against the check firing on
// healthy work: a budget no real file would exhaust must leave the run untouched.
func TestFileTimeoutGenerousBudgetScrubsNormally(t *testing.T) {
	body := repetitiveLog(2000)
	lim := DefaultLimits()
	lim.MaxFileTime = time.Hour

	out, rep := run(t, body, lim)
	if rep.HasUnscrubbed() {
		t.Errorf("a generous per-file budget recorded a hole: %+v", rep.Summary.Passthroughs)
	}
	if bytes.Contains(out, []byte("bob@acme.test")) {
		t.Error("payload not scrubbed under a generous budget")
	}
}
