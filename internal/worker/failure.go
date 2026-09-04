package worker

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// position is how far into an object the worker had got at some moment of interest:
// the moment it failed, or the moment its deadline expired.
//
// It exists because an operation name is not a diagnosis. "put output: connection
// reset by peer" does not say whether the bundle was half-scrubbed, which member it
// was on, or whether it had been moving at all — and those are the first questions
// asked of any object that did not come out the other side. Every terminal failure
// carries one of these.
//
// currentFile must already be redacted (see displayPath). Failure text is served
// from /api/status, which is unauthenticated, so a raw member path here would
// disclose exactly what the scrub exists to remove.
type position struct {
	phase       string
	filesDone   int
	filesTotal  int
	currentFile string
	// noProgress is how long the object had gone without finishing a file. Zero when
	// that is unknown or meaningless (nothing has started).
	noProgress time.Duration
}

// String renders the position as a clause that reads after "failed" or "abandoned".
func (p position) String() string {
	if p.phase == "" {
		return "before any work had started"
	}
	s := "while " + phaseDescription(p.phase)
	switch {
	case p.filesDone == 0:
		s += ", before a single file had been finished"
	case p.filesTotal > 0:
		s += fmt.Sprintf(", %d of %d files finished", p.filesDone, p.filesTotal)
	default:
		s += fmt.Sprintf(", %d finished", p.filesDone)
	}
	if p.currentFile != "" {
		s += fmt.Sprintf(", last of them %s", strconv.Quote(p.currentFile))
	}
	if p.noProgress >= time.Second {
		s += fmt.Sprintf(", and nothing had completed in the previous %s", roundDur(p.noProgress))
	}
	return s
}

// phaseDescription spells out a phase label for someone who does not know the
// internal vocabulary. The labels themselves stay short because the API reports
// them as data; this is the prose form.
func phaseDescription(phase string) string {
	switch phase {
	case "queued":
		return "waiting in the queue"
	case "reading":
		return "reading the object from storage"
	case "unpacking":
		return "expanding the container, before any file could be scrubbed"
	case "scrubbing":
		return "scrubbing"
	case "repacking":
		return "rebuilding the container after scrubbing its members"
	case "writing":
		return "writing the result back to storage"
	default:
		return "in phase " + strconv.Quote(phase)
	}
}

// roundDur formats a duration for a human: whole seconds, because sub-second
// precision on a multi-minute scrub is noise.
//
// Never rounds to "0s". A budget or an elapsed time reported as zero reads as
// "unset" and sends the reader looking for a different problem, which is exactly
// what a very small configured value would produce.
func roundDur(d time.Duration) string {
	switch {
	case d >= time.Second:
		return d.Round(time.Second).String()
	case d >= time.Millisecond:
		return d.Round(time.Millisecond).String()
	default:
		return d.String()
	}
}

// failureDetail states what failed, where it failed, and how long it had been
// running, in that order.
func failureDetail(err error, at position, elapsed time.Duration) string {
	return fmt.Sprintf("%v — failed after %s, %s", err, roundDur(elapsed), at)
}

// timeoutDetail explains an object abandoned on its own deadline.
//
// It is deliberately long. A timeout is the one failure with no underlying error to
// read, so everything an operator needs has to be stated: that the object was NOT
// scrubbed, where the budget ran out, that nothing was published, what happened to
// the input, and which knob to turn. Leaving any of those out sends someone hunting
// for a corrupt upload when the real answer is that the pod has one CPU.
func timeoutDetail(budget, elapsed time.Duration, at position, disposition string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "scrub abandoned after %s: the object exceeded its %s SCRUB_TIMEOUT budget. ",
		roundDur(elapsed), roundDur(budget))
	fmt.Fprintf(&b, "The deadline expired %s. ", at)
	b.WriteString("This object was NOT scrubbed: no output and no report were written, " +
		"so nothing partial has been published. ")
	if disposition != "" {
		fmt.Fprintf(&b, "%s ", disposition)
	}
	b.WriteString("A timeout is a time limit, not a fault in the bundle — the walk is " +
		"single-threaded, so a large or deeply nested archive on a CPU-limited pod can " +
		"legitimately need longer. Raise SCRUB_TIMEOUT or give the pod more CPU if this " +
		"bundle has to complete.")
	return b.String()
}
