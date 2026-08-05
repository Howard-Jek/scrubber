package report

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/howard/scrubber/internal/scrub"
)

func manyMatches(n int) []scrub.Match {
	out := make([]scrub.Match, n)
	for i := range out {
		out[i] = scrub.Match{
			RuleID:      "preset:email",
			Line:        i + 1,
			Offset:      i * 40,
			Original:    fmt.Sprintf("user%06d@internal.acme.test", i),
			Replacement: "[EMAIL]",
		}
	}
	return out
}

// TestMatchTruncationKeepsCountsExact is the memory guard's correctness contract:
// the itemised list may be capped, but every count derived from it must still be
// the true total. A truncated list that also under-reports would misrepresent how
// much of a bundle was rewritten.
func TestMatchTruncationKeepsCountsExact(t *testing.T) {
	const total = maxMatchesPerFile * 3
	r := New("in.tar.gz", "out.tar.gz", AuditFull, false, "salt")
	r.Record("logs/app.log", StatusScrubbed, "", 1000, 900, manyMatches(total))

	if len(r.Files) != 1 {
		t.Fatalf("files = %d, want 1", len(r.Files))
	}
	f := r.Files[0]
	if len(f.Matches) != maxMatchesPerFile {
		t.Errorf("retained %d matches, want the cap of %d", len(f.Matches), maxMatchesPerFile)
	}
	if !f.MatchesTruncated {
		t.Error("truncation must be flagged; a short list that looks complete is misleading")
	}
	if f.MatchCount != total {
		t.Errorf("MatchCount = %d, want the true total %d", f.MatchCount, total)
	}
	if r.Summary.TotalMatches != total {
		t.Errorf("Summary.TotalMatches = %d, want %d", r.Summary.TotalMatches, total)
	}
	if got := r.Summary.MatchesByRule["preset:email"]; got != total {
		t.Errorf("MatchesByRule = %d, want %d", got, total)
	}
	if got := r.Summary.MatchesByLabel["[EMAIL]"]; got != total {
		t.Errorf("MatchesByLabel = %d, want %d", got, total)
	}
	if got := r.Digest().Matches; got != total {
		t.Errorf("Digest.Matches = %d, want %d", got, total)
	}
}

// TestMatchesUnderCapNotFlagged guards against every file being marked truncated.
func TestMatchesUnderCapNotFlagged(t *testing.T) {
	r := New("in.log", "out.log", AuditFull, false, "salt")
	r.Record("app.log", StatusScrubbed, "", 100, 90, manyMatches(5))

	f := r.Files[0]
	if f.MatchesTruncated {
		t.Error("a file under the cap must not be flagged as truncated")
	}
	if len(f.Matches) != 5 || f.MatchCount != 5 {
		t.Errorf("matches=%d count=%d, want 5/5", len(f.Matches), f.MatchCount)
	}
}

// TestAuditOffKeepsCountsWithoutList checks the summary-only mode still reports an
// exact count, and does not claim to have truncated a list it never built.
func TestAuditOffKeepsCountsWithoutList(t *testing.T) {
	const total = maxMatchesPerFile * 2
	r := New("in.log", "out.log", AuditOff, false, "salt")
	r.Record("app.log", StatusScrubbed, "", 100, 90, manyMatches(total))

	f := r.Files[0]
	if len(f.Matches) != 0 {
		t.Errorf("AuditOff retained %d matches, want none", len(f.Matches))
	}
	if f.MatchesTruncated {
		t.Error("AuditOff builds no list, so nothing was truncated")
	}
	if f.MatchCount != total || r.Summary.TotalMatches != total {
		t.Errorf("counts lost under AuditOff: entry=%d summary=%d, want %d",
			f.MatchCount, r.Summary.TotalMatches, total)
	}
}

// TestAuditCountsDropsCleartext is the disclosure contract for the service default:
// rule and location are kept, the matched text is not.
func TestAuditCountsDropsCleartext(t *testing.T) {
	r := New("in.log", "out.log", AuditCounts, false, "salt")
	r.Record("app.log", StatusScrubbed, "", 100, 90, manyMatches(3))

	for _, m := range r.Files[0].Matches {
		if m.Original != "" || m.Replacement != "" {
			t.Fatalf("AuditCounts leaked cleartext: %+v", m)
		}
		if m.RuleID == "" || m.Line == 0 {
			t.Fatalf("AuditCounts should keep rule and location: %+v", m)
		}
	}
}

// TestTruncationSurvivesJSON checks an operator reading the stored report can tell
// the list was capped.
func TestTruncationSurvivesJSON(t *testing.T) {
	r := New("in.log", "out.log", AuditFull, false, "salt")
	r.Record("app.log", StatusScrubbed, "", 100, 90, manyMatches(maxMatchesPerFile+1))

	raw, err := r.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Files []struct {
			MatchCount       int  `json:"match_count"`
			MatchesTruncated bool `json:"matches_truncated"`
		} `json:"files"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Files) != 1 {
		t.Fatalf("files = %d, want 1", len(decoded.Files))
	}
	if !decoded.Files[0].MatchesTruncated {
		t.Error("matches_truncated missing from the serialised report")
	}
	if decoded.Files[0].MatchCount != maxMatchesPerFile+1 {
		t.Errorf("match_count = %d, want %d", decoded.Files[0].MatchCount, maxMatchesPerFile+1)
	}
}

// TestRollbackUndoesTruncatedFile checks the accounting rollback still balances when
// the entry it is undoing had its match list capped. Rollback runs when an archive
// is scrubbed but cannot be repacked, and the replacements must be un-counted.
func TestRollbackUndoesTruncatedFile(t *testing.T) {
	r := New("in.tar", "out.tar", AuditFull, false, "salt")
	mark := r.Mark()
	r.Record("bundle.tar!a.log", StatusScrubbed, "", 100, 90, manyMatches(maxMatchesPerFile*2))
	r.Rollback(mark, "bundle.tar", StatusPassthrough, ReasonRepackFailed, "could not rebuild", 100, 100)

	if r.Summary.TotalMatches != 0 {
		t.Errorf("TotalMatches = %d after rollback, want 0", r.Summary.TotalMatches)
	}
	if r.Summary.FilesScrubbed != 0 {
		t.Errorf("FilesScrubbed = %d after rollback, want 0", r.Summary.FilesScrubbed)
	}
	if len(r.Summary.MatchesByRule) != 0 {
		t.Errorf("MatchesByRule not cleared: %v", r.Summary.MatchesByRule)
	}
}

// TestReportWideMatchCapAcrossManyFiles is the case the per-file cap misses entirely.
// An archive of many members, each individually well under maxMatchesPerFile, can
// still retain millions of matches in aggregate — which is what a real 18000-member
// bundle did, at roughly 440 MiB of report on a 2 GiB pod.
func TestReportWideMatchCapAcrossManyFiles(t *testing.T) {
	const (
		files       = 500
		perFile     = 200 // comfortably under maxMatchesPerFile
		totalRecord = files * perFile
	)
	r := New("bundle.tar.gz", "out.tar.gz", AuditFull, false, "salt")
	for i := 0; i < files; i++ {
		r.Record(fmt.Sprintf("bundle.tar.gz!logs/app-%04d.log", i),
			StatusScrubbed, "", 1000, 900, manyMatches(perFile))
	}

	retained := 0
	for _, f := range r.Files {
		retained += len(f.Matches)
	}
	if retained > maxMatchesPerReport {
		t.Errorf("retained %d matches across %d files, above the report cap of %d: a per-file cap "+
			"alone does not bound a bundle", retained, files, maxMatchesPerReport)
	}
	if r.Summary.TotalMatches != totalRecord {
		t.Errorf("Summary.TotalMatches = %d, want the true total %d", r.Summary.TotalMatches, totalRecord)
	}
	if got := r.Digest().Matches; got != totalRecord {
		t.Errorf("Digest.Matches = %d, want %d", got, totalRecord)
	}
	// Every file's own count must survive even where its list was dropped entirely.
	for i, f := range r.Files {
		if f.MatchCount != perFile {
			t.Fatalf("file %d MatchCount = %d, want %d", i, f.MatchCount, perFile)
		}
	}
	// Files past the budget must say so rather than looking clean.
	last := r.Files[len(r.Files)-1]
	if len(last.Matches) != 0 || !last.MatchesTruncated {
		t.Errorf("last file: matches=%d truncated=%v; want an empty, flagged list once the "+
			"report budget is spent", len(last.Matches), last.MatchesTruncated)
	}
}

// TestReportBudgetReturnedOnRollback checks an archive that is scrubbed and then
// cannot be repacked gives its retention budget back, rather than permanently
// spending it on a subtree that never reached the output.
func TestReportBudgetReturnedOnRollback(t *testing.T) {
	r := New("bundle.tar", "out.tar", AuditFull, false, "salt")
	mark := r.Mark()
	for i := 0; i < 20; i++ {
		r.Record(fmt.Sprintf("inner!f%02d.log", i), StatusScrubbed, "", 100, 90, manyMatches(500))
	}
	spent := r.retained
	if spent == 0 {
		t.Fatal("expected the retention budget to be consumed")
	}
	r.Rollback(mark, "bundle.tar", StatusPassthrough, ReasonRepackFailed, "could not rebuild", 100, 100)
	if r.retained != 0 {
		t.Errorf("retained = %d after rolling back every entry, want 0", r.retained)
	}
}

// Rollback undoes a subtree whose repack failed. The named binary skips must unwind
// with everything else, or a report lists a file as skipped inside a container that
// was ultimately emitted whole.
func TestRollbackUndoesNamedBinarySkips(t *testing.T) {
	r := New("in", "out", AuditFull, false, "salt")
	r.Record("bundle/app.log", StatusScrubbed, "utf-8", 10, 10, nil)

	mark := r.Mark()
	r.Record("bundle/inner.tar!logo.png", StatusBinarySkip, "detected binary content", 5, 5, nil)
	if len(r.Summary.BinarySkips) != 1 || r.Summary.FilesBinarySkip != 1 {
		t.Fatalf("skip was not recorded: %+v", r.Summary)
	}

	r.Rollback(mark, "bundle/inner.tar", StatusPassthrough, ReasonRepackFailed, "could not rebuild tar", 5, 5)

	if r.Summary.FilesBinarySkip != 0 {
		t.Errorf("FilesBinarySkip = %d after rollback, want 0", r.Summary.FilesBinarySkip)
	}
	if len(r.Summary.BinarySkips) != 0 {
		t.Errorf("BinarySkips still names %v after rollback", r.Summary.BinarySkips)
	}
}
