// Package report collects what the scrubber did and renders it for the user.
// It is the transparency layer: every replacement can be traced to a rule, a file
// path within the bundle, and a location. Because that detail includes the original
// (sensitive) values, the report supports redaction and audit-level controls.
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/howard/scrubber/internal/scrub"
)

// ObjectSuffix is appended to an *input* object key to form the key its run
// report is stored under. Keying reports by input means a client that knows only
// the key it uploaded can always locate the outcome, even when filename scrubbing
// renamed the output.
const ObjectSuffix = ".report.json"

// DetailFilenameScrubbed is the Detail on the entry a scrubbed FILENAME files.
//
// Named rather than repeated as a literal because two packages have to agree on it:
// the pipeline writes it, and the worker's progress counter skips it. A filename is
// an annotation on a member, not a member of its own, and counting it made a
// 10-member archive report "12 files" to the person watching.
const DetailFilenameScrubbed = "filename scrubbed"

// DigestSuffix is the companion compact record, keyed the same way.
//
// The full report carries every match with its location and original value, so
// it scales with match count rather than input size: a 1 KiB log that hits 12000
// terms produces a multi-megabyte report. The status and history endpoints only
// need counts, so they read this instead — otherwise listing the last 100 runs
// would mean parsing hundreds of megabytes of audit detail on a page load.
const DigestSuffix = ".summary.json"

// Digest is the small, browser-safe view of a run.
type Digest struct {
	InputKey     string            `json:"input_key"`
	OutputKey    string            `json:"output_key,omitempty"`
	Matches      int               `json:"matches"`
	ByLabel      map[string]int    `json:"by_label,omitempty"`
	FilesTotal   int               `json:"files_total"`
	Passthrough  int               `json:"passthrough"`
	Passthroughs []PassthroughNote `json:"passthroughs,omitempty"`
	BinarySkip   int               `json:"binary_skipped"`
	BinarySkips  []PassthroughNote `json:"binary_skips,omitempty"`
	// Verdict and the coverage fields are what every surface reads. The per-status
	// counts above are kept for continuity with reports written before them.
	Verdict         Verdict        `json:"verdict"`
	NotInspected    int            `json:"files_not_inspected"`
	NotInspectedSet []Note         `json:"not_inspected,omitempty"`
	ByReason        map[Reason]int `json:"by_reason,omitempty"`
	ResidualHits    int            `json:"residual_hits"`
	ResidualSamples []string       `json:"residual_samples,omitempty"`
	BytesIn         int            `json:"bytes_in"`
	BytesOut        int            `json:"bytes_out"`
	StartedAt       time.Time      `json:"started_at,omitempty"`
	EndedAt         time.Time      `json:"ended_at,omitempty"`
}

// Digest renders the compact view of this report.
func (r *Report) Digest() Digest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Digest{
		InputKey:        r.InputKey,
		OutputKey:       r.OutputKey,
		Matches:         r.Summary.TotalMatches,
		ByLabel:         r.Summary.MatchesByLabel,
		FilesTotal:      r.Summary.FilesTotal,
		Passthrough:     r.Summary.FilesPassthrough,
		Passthroughs:    r.Summary.Passthroughs,
		BinarySkip:      r.Summary.FilesBinarySkip,
		BinarySkips:     r.Summary.BinarySkips,
		Verdict:         r.Summary.Verdict(),
		NotInspected:    r.Summary.FilesNotInspected,
		NotInspectedSet: r.Summary.NotInspected,
		ByReason:        r.Summary.ByReason,
		ResidualHits:    r.Summary.ResidualHits,
		ResidualSamples: r.Summary.ResidualSamples,
		BytesIn:         r.BytesIn,
		BytesOut:        r.BytesOut,
		StartedAt:       r.StartedAt,
		EndedAt:         r.EndedAt,
	}
}

// Verdict is the whole object's answer, derived from the per-file dispositions and
// what the residual scan found. It is the single thing an operator, the UI, and the
// output routing all key on, so that "is this result safe to share?" has one answer
// rather than one per surface.
type Verdict string

const (
	// VerdictComplete: every file was inspected. Nothing to review.
	VerdictComplete Verdict = "complete"
	// VerdictIncomplete: something was not inspected, but scanning it found nothing
	// resembling the policy. An image inside a bundle lands here — worth naming,
	// not worth blocking, and deliberately not treated as a failure so the alarm
	// that does matter keeps its meaning.
	VerdictIncomplete Verdict = "incomplete"
	// VerdictIncompleteRisky: something was not inspected AND it contains matches
	// for the policy. The tool skipped content that demonstrably holds the data it
	// exists to remove. This is the one that diverts the output for review.
	VerdictIncompleteRisky Verdict = "incomplete-risky"
)

// Verdict computes the object-level answer from the coverage counts.
func (s Summary) Verdict() Verdict {
	switch {
	case s.FilesNotInspected == 0:
		return VerdictComplete
	case s.ResidualHits > 0:
		return VerdictIncompleteRisky
	default:
		return VerdictIncomplete
	}
}

// NeedsReview reports whether this result must not be mistaken for a clean one.
func (v Verdict) NeedsReview() bool { return v == VerdictIncompleteRisky }

// Status describes the outcome for a single file within the bundle.
type Status string

const (
	StatusScrubbed     Status = "scrubbed"           // text file, matches applied
	StatusUnchanged    Status = "unchanged"          // text file, no matches found
	StatusBinarySkip   Status = "binary-skipped"     // detected binary, passed through
	StatusPassthrough  Status = "passthrough-error"  // unreadable/corrupted/encrypted, passed through verbatim
	StatusUnsupported  Status = "unsupported-format" // container we can read but not rewrite, passed through
	StatusGuardTripped Status = "guard-tripped"      // size/ratio/depth guard, passed through
	// StatusResidualMatch means the file WAS scrubbed and the policy still matches
	// the result. That is a broken scrub, not a skipped file, and it is the only
	// outcome that says the tool's own output cannot be trusted.
	StatusResidualMatch Status = "residual-match"
)

// AllStatuses is every Status the report can carry. TestEveryStatusIsClassified
// walks it, so a new status that nobody classified fails the build rather than
// quietly inheriting whichever bucket a switch statement happened to fall into.
var AllStatuses = []Status{
	StatusScrubbed, StatusUnchanged, StatusBinarySkip,
	StatusPassthrough, StatusUnsupported, StatusGuardTripped, StatusResidualMatch,
}

// Disposition answers the only question that matters about a file: is its content
// covered by the scrub?
//
// This exists because it used to be answered in four different places that disagreed
// with each other — the summary buckets, the rollback switch, HasUnscrubbed, and the
// worker's per-file log — so whether a new failure mode was visible depended on which
// bucket its author picked. UTF-16 text read as binary was invisible for exactly that
// reason. Every surface now derives from this one function.
type Disposition int

const (
	// Inspected: the content reached the matcher and the output is clean.
	Inspected Disposition = iota
	// NotInspected: the content is not covered by the scrub. Either it never reached
	// the matcher, or it did and the result still matches the policy. Both mean a
	// human has to look at the file, which is what makes them one category.
	NotInspected
)

// Disposition classifies s. The switch is exhaustive on purpose and has no default:
// adding a Status without classifying it must be a compile error, not a silent
// default to "fine".
func (s Status) Disposition() Disposition {
	switch s {
	case StatusScrubbed, StatusUnchanged:
		return Inspected
	case StatusBinarySkip, StatusPassthrough, StatusUnsupported,
		StatusGuardTripped, StatusResidualMatch:
		return NotInspected
	}
	// Unreachable for a classified Status. An unknown one is treated as a hole,
	// because the safe answer to "I don't know what this is" is "review it".
	return NotInspected
}

// Reason is a stable, machine-readable code for why content was not inspected.
//
// Free-text detail is for humans and changes with the wording; this is what metrics
// label, what the UI groups by, and what an operator alerts on. A reason code
// appearing that nobody has seen before is the signal that a new failure mode exists.
type Reason string

const (
	ReasonBinary        Reason = "binary"               // not text, correctly skipped
	ReasonEncoding      Reason = "encoding-unsupported" // text in an encoding we cannot round-trip
	ReasonUnsupported   Reason = "unsupported-format"   // container we can read but not rewrite
	ReasonMalformed     Reason = "malformed"            // corrupt, truncated or encrypted
	ReasonExpandBudget  Reason = "expansion-budget"     // would exceed MAX_EXPAND_BYTES
	ReasonMemberCap     Reason = "member-cap"           // archive exceeds MAX_MEMBERS
	ReasonDepthCap      Reason = "depth-cap"            // nesting exceeds MAX_DEPTH
	ReasonScratch       Reason = "scratch-unavailable"  // could not spill to disk
	ReasonRepackFailed  Reason = "repack-failed"        // scrubbed, then could not be rebuilt
	ReasonResidualScrub Reason = "residual-after-scrub" // scrubbed, but the policy still matches
	// ReasonLeafCap marks one text file too large to scrub on this pod's memory,
	// which is a different failure from the archive around it being too large.
	//
	// The matcher needs its payload contiguous as a string, so a single leaf costs
	// several times its own size in heap — and unlike every other payload it is
	// materialised outside the spill accounting, so no SPILL_* setting bounds it.
	// Without this code such a file is not refused, it is an OOM: the pod dies
	// mid-object, the kubelet restarts it, the object is picked up again and it dies
	// again. Naming it turns a crash loop into one flagged file in a report.
	ReasonLeafCap Reason = "leaf-cap" // single file too large to scrub in memory
	// ReasonUnclassified is the tripwire. It is never written deliberately: it marks
	// a hole recorded through Record instead of Skip, i.e. one whose author did not
	// say why. The conformance corpus asserts zero of these, so the shortcut that
	// created this whole class of bug cannot be taken again.
	ReasonUnclassified Reason = "unclassified"
)

// AllReasons is every Reason a hole can carry, for the corpus test and for seeding
// the metric label set so a dashboard shows a zero rather than a missing series.
var AllReasons = []Reason{
	ReasonBinary, ReasonEncoding, ReasonUnsupported, ReasonMalformed,
	ReasonExpandBudget, ReasonMemberCap, ReasonDepthCap, ReasonScratch,
	ReasonRepackFailed, ReasonResidualScrub, ReasonLeafCap, ReasonUnclassified,
}

// AuditLevel controls how much per-match detail the report retains.
type AuditLevel int

const (
	AuditFull   AuditLevel = iota // rule + location + original + replacement
	AuditCounts                   // rule + location only (no cleartext)
	AuditOff                      // summary only
)

// ParseAuditLevel maps a flag string to an AuditLevel.
func ParseAuditLevel(s string) (AuditLevel, error) {
	switch s {
	case "full", "":
		return AuditFull, nil
	case "counts":
		return AuditCounts, nil
	case "off":
		return AuditOff, nil
	default:
		return AuditFull, fmt.Errorf("invalid --audit value %q (want off|counts|full)", s)
	}
}

// FileEntry is the per-file record in the report.
type FileEntry struct {
	Path     string        `json:"path"`
	Status   Status        `json:"status"`
	Detail   string        `json:"detail,omitempty"`
	BytesIn  int           `json:"bytes_in"`
	BytesOut int           `json:"bytes_out"`
	Matches  []scrub.Match `json:"matches,omitempty"`
	// MatchCount is the number of matches in this file. It stays exact even when
	// Matches has been truncated, so a reader can tell the difference between "12
	// replacements" and "12 replacements listed out of 2850816".
	MatchCount int `json:"match_count"`
	// MatchesTruncated marks a file whose itemised list was capped at
	// maxMatchesPerFile. It must be visible: a short list that looks complete
	// invites someone to conclude a bundle was barely touched when it was rewritten
	// millions of times.
	MatchesTruncated bool `json:"matches_truncated,omitempty"`
}

// Note identifies a file that was emitted WITHOUT being covered by the scrub, and
// why. These are the entries a reviewer must inspect by hand before sharing the
// bundle: the tool could not read them, could not rewrite them, refused to expand
// them, or rewrote them and found the policy still matched. Surfacing them is the
// difference between a safe failure and a silent leak, so they are carried all the
// way to the UI.
//
// Code is what machines use — metric labels, UI grouping, alerting. Detail is prose
// for a human and is free to change wording without breaking any of that.
type Note struct {
	Path   string `json:"path"`
	Status Status `json:"status"`
	Code   Reason `json:"code"`
	Detail string `json:"reason,omitempty"` // JSON name kept: the UI reads "reason"
	// Residual is a disclosure-safe summary of policy matches the residual scan
	// found inside this file — "[EMAIL]×3, [IPV4]×1". Non-empty means the tool
	// skipped something that demonstrably contains the data it exists to remove,
	// which is the difference between a skipped image and a leak.
	Residual string `json:"residual,omitempty"`
}

// PassthroughNote is the former name for Note, kept so existing callers compile.
type PassthroughNote = Note

// maxPassthroughNotes bounds the retained list so a pathological archive can't
// inflate the report; the count in FilesPassthrough stays exact regardless.
const maxPassthroughNotes = 100

// maxMatchesPerFile and maxMatchesPerReport bound the per-match detail retained.
//
// These are memory bounds, not cosmetic ones. Every retained match holds its rule ID,
// original value and replacement, so the report grows with match *count* rather than
// input size, and the expansion budget does not check it: that caps bytes read, not
// the report assembled from them.
//
// Both caps are needed, and the report-wide one is the load-bearing half. A per-file
// cap alone bounds nothing when the archive is the variable: a bundle of 18000
// members averaging 200 matches each sits under any sane per-file limit while still
// retaining 3.6 million matches in aggregate — measured at roughly 440 MiB of report
// on a pod with 2 GiB to spend. The per-file cap stops one pathological *file*; the
// report cap stops a pathological *bundle*.
//
// Counts stay exact throughout (FileEntry.MatchCount, Summary.TotalMatches and the
// by-rule and by-label breakdowns are all unaffected); only the itemised lists are
// truncated, and truncation is flagged per file.
const (
	maxMatchesPerFile   = 1000
	maxMatchesPerReport = 20000
)

// Summary aggregates totals across the whole run.
type Summary struct {
	FilesTotal       int            `json:"files_total"`
	FilesScrubbed    int            `json:"files_scrubbed"`
	FilesUnchanged   int            `json:"files_unchanged"`
	FilesBinarySkip  int            `json:"files_binary_skipped"`
	FilesPassthrough int            `json:"files_passthrough"`
	TotalMatches     int            `json:"total_matches"`
	MatchesByRule    map[string]int `json:"matches_by_rule"`
	// Passthroughs names the files counted by FilesPassthrough (capped at
	// maxPassthroughNotes entries).
	Passthroughs []PassthroughNote `json:"passthroughs,omitempty"`
	// BinarySkips names the files counted by FilesBinarySkip, same cap.
	//
	// A count alone is not enough, and that is what kept a real leak invisible:
	// UTF-16 text was misread as binary, so an ordinary .txt log was emitted with
	// every address still in it while the summary showed a bare "1 binary file
	// skipped" and the UI showed a green check. Skipping a PNG is correct and
	// skipping a log is a leak; you cannot tell those apart without the names.
	BinarySkips []PassthroughNote `json:"binary_skips,omitempty"`
	// MatchesByLabel is keyed by the replacement label (e.g. "[EMAIL]") rather than
	// the rule ID. Rule IDs can embed literal values, so this is the safe breakdown
	// to surface over a browser-facing / external API.
	MatchesByLabel map[string]int `json:"matches_by_label"`

	// --- coverage: the one view every surface derives from ---

	// FilesInspected and FilesNotInspected partition FilesTotal by Disposition.
	// FilesNotInspected is the number that decides the run's verdict; the per-status
	// counters above are labels on top of it, not independent judgements.
	FilesInspected    int `json:"files_inspected"`
	FilesNotInspected int `json:"files_not_inspected"`
	// NotInspected names every file in that second group, whatever the status —
	// the union of Passthroughs and BinarySkips plus anything added later. Code
	// paths that ask "what did we not cover?" must read this and nothing else.
	NotInspected []Note `json:"not_inspected,omitempty"`
	// ByReason counts the holes by reason code. A code appearing here that an
	// operator has never seen is the signal that a new failure mode exists — which
	// previously required somebody to notice a file looked wrong.
	ByReason map[Reason]int `json:"by_reason,omitempty"`
	// ResidualHits counts matches the residual scan found inside content that was
	// NOT inspected. Non-zero means the tool skipped something that demonstrably
	// contains the very data it exists to remove, and is what escalates a run from
	// "incomplete" to "incomplete-risky".
	ResidualHits int `json:"residual_hits"`
	// ResidualSamples shows a few of those hits, already replaced with their policy
	// labels so the report never quotes the sensitive value back.
	ResidualSamples []string `json:"residual_samples,omitempty"`
}

// Report is the full run record.
type Report struct {
	Source  string      `json:"source"`
	Output  string      `json:"output"`
	Files   []FileEntry `json:"files"`
	Summary Summary     `json:"summary"`

	// InputKey and OutputKey are the object keys this run read from and wrote to.
	// They are recorded explicitly so the report is self-describing: given only
	// the key a client uploaded, the service can find the report and learn where
	// the scrubbed object landed, even after a restart lost its in-memory state.
	InputKey  string    `json:"input_key,omitempty"`
	OutputKey string    `json:"output_key,omitempty"`
	StartedAt time.Time `json:"started_at,omitempty"`
	EndedAt   time.Time `json:"ended_at,omitempty"`
	// BytesIn/BytesOut are the top-level object sizes, recorded so a stored report
	// can reconstruct the full status view without the live job record.
	BytesIn  int `json:"bytes_in,omitempty"`
	BytesOut int `json:"bytes_out,omitempty"`

	mu sync.Mutex
	// membersSeen is the running count NoteMembers has been told about.
	membersSeen int
	audit       AuditLevel
	redact      bool
	salt        []byte
	onFile      func(FileEntry)
	// onMembers reports the running count of archive members DISCOVERED, so a client
	// can show "file 7 of 10" instead of a number with no denominator.
	//
	// Running, not final: whether a member is itself a container is decided from its
	// first bytes when the walk reaches it, so a nested archive raises the total
	// part-way through. A denominator that grows is honest; one fixed too early is
	// wrong in the flattering direction, pinning the bar at 100% while work continues.
	onMembers func(int)
	// deltas runs parallel to Files and holds each entry's exact contribution to
	// Summary, so a discarded subtree can be un-counted at any audit level (the
	// retained per-match detail is trimmed or absent below AuditFull).
	deltas []summaryDelta

	// retained counts matches itemised across the whole report, bounding it by
	// maxMatchesPerReport. Summary counts are unaffected.
	retained int
}

// summaryDelta is one entry's contribution to the running Summary.
type summaryDelta struct {
	status       Status
	matches      int
	byRule       map[string]int
	byLabel      map[string]int
	passthrough  bool // whether it appended a Passthroughs note
	binarySkip   bool // whether it appended a BinarySkips note
	notInspected bool // whether it appended a NotInspected note
	reason       Reason
	// detail is carried so a rollback can un-count exactly what the record counted:
	// the file tally skips filename-scrub entries, and both directions must agree or
	// a rolled-back subtree leaves the total off by the number of renames in it.
	detail       string
	residualHits int
	// retained is how much of the report-wide match budget this entry consumed, so
	// undoing the entry gives the budget back rather than permanently spending it on
	// a subtree that never reached the output.
	retained int
}

// countStatus applies one entry's contribution to the summary counters, with sign
// +1 to record and -1 to roll back.
//
// This is deliberately the ONLY place a status turns into a number. It used to be
// two switches — one in Record and a mirror in Rollback — plus two more ad-hoc
// classifications in HasUnscrubbed and the worker's per-file log, and they disagreed:
// a binary skip was a problem to the log and not a problem to HasUnscrubbed. That
// disagreement is how UTF-16 text left the pipeline unscrubbed while the run reported
// clean. One function, one answer, both directions.
func (r *Report) countStatus(status Status, reason Reason, detail string, sign int) {
	// A scrubbed FILENAME files its own entry, and it is right that it does -- the
	// audit record should show the rename. It is not a FILE, though, and counting it
	// as one made the same run report "10 of 10" while it was working and "12 files"
	// in its history, which is exactly the kind of disagreement that makes a reader
	// stop trusting both numbers. Its matches still count; only the file tally skips it.
	if detail != DetailFilenameScrubbed {
		r.Summary.FilesTotal += sign
	}
	switch status.Disposition() {
	case Inspected:
		r.Summary.FilesInspected += sign
	case NotInspected:
		r.Summary.FilesNotInspected += sign
		if reason != "" {
			if r.Summary.ByReason == nil {
				r.Summary.ByReason = map[Reason]int{}
			}
			if r.Summary.ByReason[reason] += sign; r.Summary.ByReason[reason] <= 0 {
				delete(r.Summary.ByReason, reason)
			}
		}
	}
	// The per-status counters below are labels on the coverage split above, kept
	// because reports and tests read them. They are derived here rather than
	// maintained separately, which is what stops them drifting from it.
	switch status {
	case StatusScrubbed:
		r.Summary.FilesScrubbed += sign
	case StatusUnchanged:
		r.Summary.FilesUnchanged += sign
	case StatusBinarySkip:
		r.Summary.FilesBinarySkip += sign
	default:
		r.Summary.FilesPassthrough += sign
	}
}

// NoteResidual attaches what the residual scan found to the entry just recorded.
//
// It amends the most recent entry rather than searching by path, because the two are
// always recorded together: the pipeline scans the payload at the moment it decides
// to skip it, while the blob is open and the path is in hand. Calling this at any
// other time would annotate the wrong file, so it is unexported behaviour in
// everything but name — the only callers are the two skip paths in the engine.
func (r *Report) NoteResidual(path string, reason Reason, hits int, summary string) {
	if hits <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	r.Summary.ResidualHits += hits
	if len(r.Summary.ResidualSamples) < maxResidualSamples {
		r.Summary.ResidualSamples = append(r.Summary.ResidualSamples, path+": "+summary)
	}
	if n := len(r.deltas); n > 0 {
		r.deltas[n-1].residualHits = hits
	}
	// Annotate the note in every list that carries this entry, so whichever one a
	// surface reads shows the same thing.
	for _, list := range [][]Note{r.Summary.NotInspected, r.Summary.Passthroughs, r.Summary.BinarySkips} {
		for i := len(list) - 1; i >= 0; i-- {
			if list[i].Path == path {
				list[i].Residual = summary
				break
			}
		}
	}
}

// maxResidualSamples bounds the retained residual summaries the same way the note
// lists are bounded; ResidualHits stays exact regardless.
const maxResidualSamples = 20

// Mark returns a checkpoint identifying the current end of the report.
func (r *Report) Mark() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.Files)
}

// Rollback discards everything recorded since mark and replaces it with a single
// entry describing why the work was thrown away.
//
// The pipeline sometimes scrubs a subtree and then cannot use the result — a
// container it can read but not rewrite, or a rebuild that fails. Those matches
// were never applied to the output, so leaving them counted would tell an
// operator that more was redacted than actually was. That is the one direction a
// transparency report must never be wrong in.
func (r *Report) Rollback(mark int, path string, status Status, reason Reason, detail string, bytesIn, bytesOut int) {
	r.mu.Lock()
	if mark < 0 || mark > len(r.Files) {
		r.mu.Unlock()
		return
	}
	for _, d := range r.deltas[mark:] {
		r.countStatus(d.status, d.reason, d.detail, -1)
		if d.passthrough && len(r.Summary.Passthroughs) > 0 {
			r.Summary.Passthroughs = r.Summary.Passthroughs[:len(r.Summary.Passthroughs)-1]
		}
		if d.binarySkip && len(r.Summary.BinarySkips) > 0 {
			r.Summary.BinarySkips = r.Summary.BinarySkips[:len(r.Summary.BinarySkips)-1]
		}
		if d.notInspected && len(r.Summary.NotInspected) > 0 {
			r.Summary.NotInspected = r.Summary.NotInspected[:len(r.Summary.NotInspected)-1]
		}
		r.retained -= d.retained
		r.Summary.ResidualHits -= d.residualHits
		r.Summary.TotalMatches -= d.matches
		for k, v := range d.byRule {
			if r.Summary.MatchesByRule[k] -= v; r.Summary.MatchesByRule[k] <= 0 {
				delete(r.Summary.MatchesByRule, k)
			}
		}
		for k, v := range d.byLabel {
			if r.Summary.MatchesByLabel[k] -= v; r.Summary.MatchesByLabel[k] <= 0 {
				delete(r.Summary.MatchesByLabel, k)
			}
		}
	}
	r.Files = r.Files[:mark]
	r.deltas = r.deltas[:mark]
	r.mu.Unlock()

	r.record(path, status, reason, detail, bytesIn, bytesOut, nil)
}

// OnFile registers a callback invoked for each file as it is recorded, so a
// caller can stream progress instead of waiting for the run to finish. It runs
// while the report lock is held: keep it cheap and non-blocking.
func (r *Report) OnFile(fn func(FileEntry)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onFile = fn
}

// OnMembers registers the members-discovered callback. Same contract as OnFile: it
// runs under the report lock, so it must be cheap and must not call back in.
func (r *Report) OnMembers(fn func(int)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onMembers = fn
}

// NoteMembers adjusts the running count of archive members expected to file a
// report entry, and reports the new total.
//
// Called once per container as it is opened, BEFORE any of its members is scrubbed,
// which is what makes a denominator available from the first file rather than only
// once the archive is finished.
//
// n is a DELTA and may be zero or negative. A container that is itself a member has
// already been counted by its parent and replaces itself with its own contents, so
// one holding a single file adds nothing and an empty one subtracts. Rejecting those
// as "not a discovery" is what left the total permanently above the number of entries
// that could ever arrive. The caller computes the delta; see pipeline.noteMembers.
func (r *Report) NoteMembers(n int) {
	if n == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.membersSeen += n
	if r.membersSeen < 0 {
		// Cannot happen from a consistent walk, and a negative denominator would
		// render as a nonsense percentage rather than fail visibly.
		r.membersSeen = 0
	}
	if r.onMembers != nil {
		r.onMembers(r.membersSeen)
	}
}

// New constructs a Report with the given transparency settings.
func New(source, output string, audit AuditLevel, redact bool, salt string) *Report {
	return &Report{
		Source:  source,
		Output:  output,
		audit:   audit,
		redact:  redact,
		salt:    []byte(salt),
		Summary: Summary{MatchesByRule: map[string]int{}, MatchesByLabel: map[string]int{}},
	}
}

// Record adds a file outcome, applying the configured audit level and redaction.
// Record files an outcome whose content WAS inspected, or an outcome from a caller
// that predates reason codes.
//
// A hole recorded through here gets ReasonUnclassified, which is a tripwire rather
// than a value: the conformance corpus asserts no run produces one. Skip is the way
// to record a hole, and it makes the reason a required argument precisely so that
// "add a status and move on" — the shortcut behind three shipped bugs — is no longer
// available.
func (r *Report) Record(path string, status Status, detail string, bytesIn, bytesOut int, matches []scrub.Match) {
	reason := Reason("")
	if status.Disposition() == NotInspected {
		reason = ReasonUnclassified
	}
	r.record(path, status, reason, detail, bytesIn, bytesOut, matches)
}

// Skip files a file whose content is not covered by the scrub, with the reason code
// that says why. Every such site in the pipeline goes through here.
func (r *Report) Skip(path string, status Status, reason Reason, detail string, bytesIn, bytesOut int) {
	r.record(path, status, reason, detail, bytesIn, bytesOut, nil)
}

func (r *Report) record(path string, status Status, reason Reason, detail string, bytesIn, bytesOut int, matches []scrub.Match) {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry := FileEntry{
		Path: path, Status: status, Detail: detail,
		BytesIn: bytesIn, BytesOut: bytesOut, MatchCount: len(matches),
	}

	// Retain at most maxMatchesPerFile from this file, and at most
	// maxMatchesPerReport across the whole run. The counts above and the summary
	// accounting below run over every match regardless, so truncating here costs
	// detail, never accuracy. The flag is only meaningful when a list is being kept
	// at all — under AuditOff there is nothing to truncate.
	keep := len(matches)
	if keep > maxMatchesPerFile {
		keep = maxMatchesPerFile
	}
	if remaining := maxMatchesPerReport - r.retained; keep > remaining {
		keep = max(remaining, 0)
	}
	if keep < len(matches) {
		entry.MatchesTruncated = r.audit != AuditOff
	}
	if r.audit != AuditOff {
		r.retained += keep
	}
	switch r.audit {
	case AuditOff:
		// keep counts in summary only
	case AuditCounts:
		entry.Matches = make([]scrub.Match, 0, keep)
		for _, m := range matches[:keep] {
			entry.Matches = append(entry.Matches, scrub.Match{RuleID: m.RuleID, Line: m.Line, Offset: m.Offset})
		}
	case AuditFull:
		entry.Matches = make([]scrub.Match, 0, keep)
		for _, m := range matches[:keep] {
			mm := m
			if r.redact {
				mm.Original = r.hash(m.Original)
			}
			entry.Matches = append(entry.Matches, mm)
		}
	}

	r.Files = append(r.Files, entry)

	// Summary accounting, mirrored into a delta so it can be undone exactly.
	delta := summaryDelta{status: status, reason: reason, detail: detail}
	if r.audit != AuditOff {
		delta.retained = keep
	}
	r.countStatus(status, reason, detail, +1)

	// Name every hole, once, in the list the verdict reads. Passthroughs and
	// BinarySkips are the older split of the same information, kept for reports and
	// callers that already read them; all three are appended from here so they
	// describe the same set.
	if status.Disposition() == NotInspected {
		note := Note{Path: path, Status: status, Code: reason, Detail: detail}
		if len(r.Summary.NotInspected) < maxPassthroughNotes {
			r.Summary.NotInspected = append(r.Summary.NotInspected, note)
			delta.notInspected = true
		}
		if status == StatusBinarySkip {
			if len(r.Summary.BinarySkips) < maxPassthroughNotes {
				r.Summary.BinarySkips = append(r.Summary.BinarySkips, note)
				delta.binarySkip = true
			}
		} else if len(r.Summary.Passthroughs) < maxPassthroughNotes {
			r.Summary.Passthroughs = append(r.Summary.Passthroughs, note)
			delta.passthrough = true
		}
	}
	for _, m := range matches {
		r.Summary.TotalMatches++
		r.Summary.MatchesByRule[m.RuleID]++
		r.Summary.MatchesByLabel[m.Replacement]++
		delta.matches++
		if delta.byRule == nil {
			delta.byRule, delta.byLabel = map[string]int{}, map[string]int{}
		}
		delta.byRule[m.RuleID]++
		delta.byLabel[m.Replacement]++
	}
	r.deltas = append(r.deltas, delta)

	if r.onFile != nil {
		// Hand out the summary fields only; per-match detail can contain cleartext
		// originals and progress callbacks feed browser-facing surfaces.
		r.onFile(FileEntry{
			Path: entry.Path, Status: entry.Status, Detail: entry.Detail,
			BytesIn: entry.BytesIn, BytesOut: entry.BytesOut,
		})
	}
}

func (r *Report) hash(s string) string {
	h := sha256.New()
	h.Write(r.salt)
	h.Write([]byte(s))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))[:12]
}

// JSON renders the report as indented JSON bytes.
func (r *Report) JSON() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return json.MarshalIndent(r, "", "  ")
}

// WriteJSON writes the report as indented JSON to path.
func (r *Report) WriteJSON(path string) error {
	b, err := r.JSON()
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// HasUnscrubbed reports whether any file was emitted without being scrubbed
// (guard-tripped, unreadable, or an unsupported container). Binary files are not
// counted: skipping them is intentional and safe, since byte-substitution would
// corrupt them.
// HasUnscrubbed reports whether any file was left uncovered by the scrub.
//
// It used to read FilesPassthrough, which excluded binary skips — so a UTF-16 log
// misread as binary left this false and --fail-on-unscrubbed silent. It now asks the
// coverage question directly, which is the whole point of Disposition existing.
func (r *Report) HasUnscrubbed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.Summary.FilesNotInspected > 0
}

// Banner returns the end-of-run transparency summary printed to stderr. When any
// file was emitted unscrubbed the banner says so first and names the files: a
// caller who reads only one line must not come away believing the bundle is
// clean when part of it was never inspected.
func (r *Report) Banner() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.Summary

	base := fmt.Sprintf("%s: redacted %d matches across %d rules in %d file(s); %d of %d file(s) NOT inspected",
		s.Verdict(), s.TotalMatches, len(s.MatchesByRule), s.FilesScrubbed,
		s.FilesNotInspected, s.FilesTotal)
	if s.FilesNotInspected == 0 {
		return base
	}

	var b strings.Builder
	// The residual finding comes first because it is the only line that says the
	// skipped content was checked and was NOT harmless.
	if s.ResidualHits > 0 {
		fmt.Fprintf(&b, "WARNING: content that was NOT inspected contains %d policy match(es):\n", s.ResidualHits)
		for _, sample := range s.ResidualSamples {
			fmt.Fprintf(&b, "  !! %s\n", sample)
		}
	}
	if s.FilesPassthrough > 0 {
		fmt.Fprintf(&b, "WARNING: %d file(s) were emitted UNSCRUBBED and must be reviewed by hand:\n", s.FilesPassthrough)
		listNotes(&b, "!", s.Passthroughs, s.FilesPassthrough)
	}
	// Named, not just counted. A skipped PNG is routine and a skipped log is a leak,
	// and a bare count cannot tell them apart — which is exactly how UTF-16 text went
	// out unscrubbed while the run looked clean.
	if s.FilesBinarySkip > 0 {
		fmt.Fprintf(&b, "%d file(s) were skipped as binary and NOT scrubbed:\n", s.FilesBinarySkip)
		listNotes(&b, "-", s.BinarySkips, s.FilesBinarySkip)
	}
	b.WriteString(base)
	return b.String()
}

func listNotes(b *strings.Builder, bullet string, notes []Note, total int) {
	for _, p := range notes {
		fmt.Fprintf(b, "  %s %s (%s", bullet, p.Path, p.Status)
		if p.Code != "" {
			fmt.Fprintf(b, "/%s", p.Code)
		}
		b.WriteString(")")
		if p.Detail != "" {
			fmt.Fprintf(b, ": %s", p.Detail)
		}
		b.WriteByte('\n')
	}
	if n := total - len(notes); n > 0 {
		fmt.Fprintf(b, "  ... and %d more\n", n)
	}
}

// RuleBreakdown returns the per-rule totals sorted by descending count, for the
// human-readable stderr table.
func (r *Report) RuleBreakdown() []string {
	type kv struct {
		rule  string
		count int
	}
	var rows []kv
	for k, v := range r.Summary.MatchesByRule {
		rows = append(rows, kv{k, v})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].count != rows[j].count {
			return rows[i].count > rows[j].count
		}
		return rows[i].rule < rows[j].rule
	})
	out := make([]string, len(rows))
	for i, row := range rows {
		out[i] = fmt.Sprintf("  %6d  %s", row.count, row.rule)
	}
	return out
}
