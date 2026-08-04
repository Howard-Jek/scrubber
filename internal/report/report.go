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

	"github.com/howard/scrubber/internal/scrub"
)

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

	mu     sync.Mutex
	audit  AuditLevel
	redact bool
	salt   []byte
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

	// Summary accounting.
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
		}
	}
	for _, m := range matches {
		r.Summary.TotalMatches++
		r.Summary.MatchesByRule[m.RuleID]++
		r.Summary.MatchesByLabel[m.Replacement]++
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
