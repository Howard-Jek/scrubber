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
	BytesIn      int               `json:"bytes_in"`
	BytesOut     int               `json:"bytes_out"`
	StartedAt    time.Time         `json:"started_at,omitempty"`
	EndedAt      time.Time         `json:"ended_at,omitempty"`
}

// Digest renders the compact view of this report.
func (r *Report) Digest() Digest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Digest{
		InputKey:     r.InputKey,
		OutputKey:    r.OutputKey,
		Matches:      r.Summary.TotalMatches,
		ByLabel:      r.Summary.MatchesByLabel,
		FilesTotal:   r.Summary.FilesTotal,
		Passthrough:  r.Summary.FilesPassthrough,
		Passthroughs: r.Summary.Passthroughs,
		BytesIn:      r.BytesIn,
		BytesOut:     r.BytesOut,
		StartedAt:    r.StartedAt,
		EndedAt:      r.EndedAt,
	}
}

// Status describes the outcome for a single file within the bundle.
type Status string

const (
	StatusScrubbed     Status = "scrubbed"           // text file, matches applied
	StatusUnchanged    Status = "unchanged"          // text file, no matches found
	StatusBinarySkip   Status = "binary-skipped"     // detected binary, passed through
	StatusPassthrough  Status = "passthrough-error"  // unreadable/corrupted/encrypted, passed through verbatim
	StatusUnsupported  Status = "unsupported-format"  // container we can read but not rewrite, passed through
	StatusGuardTripped Status = "guard-tripped"       // size/ratio/depth guard, passed through
)

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
}

// PassthroughNote identifies a file that was emitted WITHOUT being scrubbed and
// why. These are the entries a reviewer must inspect by hand before sharing the
// bundle: the tool could not read them, could not rewrite them, or refused to
// expand them. Surfacing them is the difference between a safe failure and a
// silent leak, so they are carried all the way to the UI.
type PassthroughNote struct {
	Path   string `json:"path"`
	Status Status `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// maxPassthroughNotes bounds the retained list so a pathological archive can't
// inflate the report; the count in FilesPassthrough stays exact regardless.
const maxPassthroughNotes = 100

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
	// MatchesByLabel is keyed by the replacement label (e.g. "[EMAIL]") rather than
	// the rule ID. Rule IDs can embed literal values, so this is the safe breakdown
	// to surface over a browser-facing / external API.
	MatchesByLabel map[string]int `json:"matches_by_label"`
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

	mu     sync.Mutex
	audit  AuditLevel
	redact bool
	salt   []byte
	onFile func(FileEntry)
	// deltas runs parallel to Files and holds each entry's exact contribution to
	// Summary, so a discarded subtree can be un-counted at any audit level (the
	// retained per-match detail is trimmed or absent below AuditFull).
	deltas []summaryDelta
}

// summaryDelta is one entry's contribution to the running Summary.
type summaryDelta struct {
	status      Status
	matches     int
	byRule      map[string]int
	byLabel     map[string]int
	passthrough bool // whether it appended a PassthroughNote
}

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
func (r *Report) Rollback(mark int, path string, status Status, detail string, bytesIn, bytesOut int) {
	r.mu.Lock()
	if mark < 0 || mark > len(r.Files) {
		r.mu.Unlock()
		return
	}
	for _, d := range r.deltas[mark:] {
		r.Summary.FilesTotal--
		switch d.status {
		case StatusScrubbed:
			r.Summary.FilesScrubbed--
		case StatusUnchanged:
			r.Summary.FilesUnchanged--
		case StatusBinarySkip:
			r.Summary.FilesBinarySkip--
		case StatusPassthrough, StatusUnsupported, StatusGuardTripped:
			r.Summary.FilesPassthrough--
		}
		if d.passthrough && len(r.Summary.Passthroughs) > 0 {
			r.Summary.Passthroughs = r.Summary.Passthroughs[:len(r.Summary.Passthroughs)-1]
		}
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

	r.Record(path, status, detail, bytesIn, bytesOut, nil)
}

// OnFile registers a callback invoked for each file as it is recorded, so a
// caller can stream progress instead of waiting for the run to finish. It runs
// while the report lock is held: keep it cheap and non-blocking.
func (r *Report) OnFile(fn func(FileEntry)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onFile = fn
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
func (r *Report) Record(path string, status Status, detail string, bytesIn, bytesOut int, matches []scrub.Match) {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry := FileEntry{Path: path, Status: status, Detail: detail, BytesIn: bytesIn, BytesOut: bytesOut}

	switch r.audit {
	case AuditOff:
		// keep counts in summary only
	case AuditCounts:
		for _, m := range matches {
			entry.Matches = append(entry.Matches, scrub.Match{RuleID: m.RuleID, Line: m.Line, Offset: m.Offset})
		}
	case AuditFull:
		for _, m := range matches {
			mm := m
			if r.redact {
				mm.Original = r.hash(m.Original)
			}
			entry.Matches = append(entry.Matches, mm)
		}
	}

	r.Files = append(r.Files, entry)

	// Summary accounting, mirrored into a delta so it can be undone exactly.
	delta := summaryDelta{status: status}
	r.Summary.FilesTotal++
	switch status {
	case StatusScrubbed:
		r.Summary.FilesScrubbed++
	case StatusUnchanged:
		r.Summary.FilesUnchanged++
	case StatusBinarySkip:
		r.Summary.FilesBinarySkip++
	case StatusPassthrough, StatusUnsupported, StatusGuardTripped:
		r.Summary.FilesPassthrough++
		if len(r.Summary.Passthroughs) < maxPassthroughNotes {
			r.Summary.Passthroughs = append(r.Summary.Passthroughs,
				PassthroughNote{Path: path, Status: status, Reason: detail})
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
func (r *Report) HasUnscrubbed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.Summary.FilesPassthrough > 0
}

// Banner returns the end-of-run transparency summary printed to stderr. When any
// file was emitted unscrubbed the banner says so first and names the files: a
// caller who reads only one line must not come away believing the bundle is
// clean when part of it was never inspected.
func (r *Report) Banner() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.Summary

	base := fmt.Sprintf("redacted %d matches across %d rules in %d file(s); %d binary file(s) skipped",
		s.TotalMatches, len(s.MatchesByRule), s.FilesScrubbed, s.FilesBinarySkip)
	if s.FilesPassthrough == 0 {
		return base
	}

	var b strings.Builder
	fmt.Fprintf(&b, "WARNING: %d file(s) were emitted UNSCRUBBED and must be reviewed by hand:\n", s.FilesPassthrough)
	for _, p := range s.Passthroughs {
		fmt.Fprintf(&b, "  ! %s (%s)", p.Path, p.Status)
		if p.Reason != "" {
			fmt.Fprintf(&b, ": %s", p.Reason)
		}
		b.WriteByte('\n')
	}
	if n := s.FilesPassthrough - len(s.Passthroughs); n > 0 {
		fmt.Fprintf(&b, "  ... and %d more\n", n)
	}
	b.WriteString(base)
	return b.String()
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
