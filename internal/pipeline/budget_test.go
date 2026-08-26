package pipeline

import (
	"archive/tar"
	"bytes"
	"strings"
	"testing"

	"github.com/howard/scrubber/internal/report"
)

// Tests for what MAX_EXPAND_BYTES means.
//
// The engine used to charge a .tar.gz twice — once for the decompressed tar, once
// for the member bodies read out of it — so an operator who configured a 4 GiB
// budget got roughly 2 GiB of usable content and no way to tell from the setting.
// descend now refunds the container once the walk charges what is inside it. These
// tests pin both halves: that the refund happens, and that it cannot be turned into
// a way past the guard.

// minBudgetToScrub binary-searches the smallest MaxTotalBytes at which data is fully
// scrubbed. Below the answer the guard trips and the payload is passed through
// verbatim, so the predicate is monotone and the search is well defined.
func minBudgetToScrub(t *testing.T, data []byte, hi int64) int64 {
	t.Helper()
	scrubs := func(budget int64) bool {
		lim := DefaultLimits()
		lim.MaxTotalBytes = budget
		out, rep := run(t, data, lim)
		return !rep.HasUnscrubbed() && !bytes.Equal(out, data)
	}
	if !scrubs(hi) {
		t.Fatalf("not scrubbed even at the %d-byte ceiling; the search has no answer", hi)
	}
	lo := int64(1)
	for lo < hi {
		mid := lo + (hi-lo)/2
		if scrubs(mid) {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	return lo
}

// TestTarGzCostsItsContentOnce is the regression test for the double-draw. A .tar.gz
// must cost about what its content weighs, not twice that — otherwise the number an
// operator sets is not the number they get.
func TestTarGzCostsItsContentOnce(t *testing.T) {
	body := repetitiveLog(500)
	tarred := tarOf(t, "app.log", body)
	bundle := gz(t, tarred)

	need := minBudgetToScrub(t, bundle, 64<<20)
	content := int64(len(body))
	tarSize := int64(len(tarred))

	t.Logf("content %d, tar %d, min budget %d (%.2fx content)",
		content, tarSize, need, float64(need)/float64(content))

	// The old accounting needed tar + body, i.e. > 2x the content. Allow the tar's
	// own header and padding overhead on top of the content, but nothing like a
	// second copy.
	if limit := tarSize + content/4; need > limit {
		t.Errorf("a .tar.gz still costs %d for %d bytes of content (limit %d); "+
			"the container is being charged on top of its members", need, content, limit)
	}
	// And the budget must still be a real bound: one byte less than the tar itself
	// cannot possibly be enough to read it.
	if need < content {
		t.Errorf("min budget %d is below the content size %d — the budget stopped "+
			"accounting for the bytes actually read", need, content)
	}
}

// TestPlainContainersUnchangedByRefund: a plain .tar and a plain .zip never had a
// double-draw, because the container is the input and is never decompressed. The
// refund must not quietly give them budget back they never spent.
func TestPlainContainersUnchangedByRefund(t *testing.T) {
	body := repetitiveLog(500)
	content := int64(len(body))

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"tar", tarOf(t, "app.log", body)},
		{"zip", zipOf(t, map[string][]byte{"app.log": body})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			need := minBudgetToScrub(t, tc.data, 64<<20)
			t.Logf("content %d, min budget %d", content, need)
			if need > content+content/4 {
				t.Errorf("min budget %d for %d bytes of content: a plain container "+
					"should cost its members and nothing more", need, content)
			}
		})
	}
}

// TestRefundCannotBeUsedToBeatTheGuard is the safety half of the refund, and the
// reason it is capped at what the contents actually cost.
//
// The shape: an archive of many inner tars that are almost entirely header and
// padding, holding a byte or two of real content each. A naive "only charge leaves"
// rule refunds the whole bulk of every inner container and lets an arbitrarily large
// archive through on a tiny budget. The cap — refund no more than the contents were
// charged — is what keeps the bulk on the budget.
func TestRefundCannotBeUsedToBeatTheGuard(t *testing.T) {
	// Each inner tar is ~10 KiB of structure around 2 bytes of payload.
	var inner bytes.Buffer
	tw := tar.NewWriter(&inner)
	for i := 0; i < 10; i++ {
		body := []byte("x")
		if err := tw.WriteHeader(&tar.Header{
			Name: strings.Repeat("d", 60) + "/f", Mode: 0o644,
			Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("inner header: %v", err)
		}
		mustWrite(t, tw, body)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("inner close: %v", err)
	}

	var outer bytes.Buffer
	otw := tar.NewWriter(&outer)
	const nested = 20
	for i := 0; i < nested; i++ {
		b := inner.Bytes()
		if err := otw.WriteHeader(&tar.Header{
			Name: "nested" + strings.Repeat("0", i) + ".tar", Mode: 0o644,
			Size: int64(len(b)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("outer header: %v", err)
		}
		mustWrite(t, otw, b)
	}
	if err := otw.Close(); err != nil {
		t.Fatalf("outer close: %v", err)
	}
	bundle := outer.Bytes()

	// A budget far below the archive's own size must still trip. If the refund were
	// uncapped, the near-empty inner tars would be handed back in full and this
	// would sail through while staging the whole thing on disk.
	lim := DefaultLimits()
	lim.MaxTotalBytes = int64(len(bundle)) / 8

	out, rep := run(t, bundle, lim)
	if !bytes.Equal(out, bundle) {
		t.Errorf("archive %d bytes with a %d-byte budget was rewritten; the refund "+
			"is giving back more than the contents cost", len(bundle), lim.MaxTotalBytes)
	}
	if !rep.HasUnscrubbed() {
		t.Fatalf("over-budget nested archive was passed through WITHOUT being recorded")
	}
	t.Logf("bundle %d, budget %d, recorded: %s",
		len(bundle), lim.MaxTotalBytes, rep.Summary.Passthroughs[0].Detail)
}

// TestBudgetStillResetsPerObjectAfterRefund: the refund adds a second counter, and a
// counter that is not reset between objects leaks state from one scrub into the next.
func TestBudgetStillResetsPerObjectAfterRefund(t *testing.T) {
	body := repetitiveLog(200)
	bundle := gz(t, tarOf(t, "app.log", body))

	lim := DefaultLimits()
	lim.MaxTotalBytes = 8 << 20
	rep := report.New("in", "out", report.AuditFull, false, "test")
	eng := &Engine{Matcher: testMatcher(t), Report: rep, Limits: lim}

	for i := 0; i < 4; i++ {
		out := eng.Process("bundle", bundle, 0)
		if bytes.Equal(out, bundle) {
			t.Fatalf("object %d came back unscrubbed: budget or charge state leaked "+
				"across objects", i)
		}
	}
	if rep.HasUnscrubbed() {
		t.Errorf("repeated objects produced holes: %+v", rep.Summary.Passthroughs)
	}
}

// ---- the leaf cap ----

// TestLeafCapRefusesInsteadOfOOM covers the one payload the spill policy cannot
// bound. The matcher needs a contiguous string, so Blob.Bytes reads a spilled leaf
// back in full outside the resident accounting and Decode/Scrub/Encode each hold a
// copy. Left unbounded that is an OOM mid-object, which restarts the pod, re-queues
// the object and does it again. Refusing the file keeps the rest of the archive
// scrubbable and names the hole.
func TestLeafCapRefusesInsteadOfOOM(t *testing.T) {
	body := repetitiveLog(500)
	lim := DefaultLimits()
	lim.MaxLeafBytes = int64(len(body)) / 2

	out, rep := run(t, body, lim)
	if !bytes.Equal(out, body) {
		t.Errorf("an over-cap leaf must be passed through verbatim")
	}
	if !rep.HasUnscrubbed() {
		t.Fatalf("an over-cap leaf was passed through WITHOUT being recorded")
	}
	p := rep.Summary.Passthroughs[0]
	if p.Status != report.StatusGuardTripped {
		t.Errorf("status = %q, want %q", p.Status, report.StatusGuardTripped)
	}
	if p.Code != report.ReasonLeafCap {
		t.Errorf("reason = %q, want %q — an operator filters on this to tell "+
			"'this file is too big to scrub' from 'this bundle is too big to open'",
			p.Code, report.ReasonLeafCap)
	}
	t.Logf("recorded: %s", p.Detail)
}

// TestLeafCapZeroIsDisabled: zero must mean "no cap", which is what shipped and what
// the CLI relies on — a workstation scrubbing one large log has the memory for it.
func TestLeafCapZeroIsDisabled(t *testing.T) {
	body := repetitiveLog(500)
	lim := DefaultLimits()
	lim.MaxLeafBytes = 0

	out, rep := run(t, body, lim)
	if bytes.Equal(out, body) {
		t.Error("MaxLeafBytes=0 refused a leaf; zero must disable the check")
	}
	if rep.HasUnscrubbed() {
		t.Errorf("unexpected holes with the leaf cap disabled: %+v", rep.Summary.Passthroughs)
	}
}

// TestLeafCapSparesTheRestOfTheArchive: one oversized member must not cost the whole
// bundle. This is the difference between the leaf cap and the expansion budget —
// tripping the budget inside a container discards every member of it.
func TestLeafCapSparesTheRestOfTheArchive(t *testing.T) {
	big := repetitiveLog(400)
	small := repetitiveLog(5)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, m := range []struct {
		name string
		body []byte
	}{{"big.log", big}, {"small.log", small}} {
		if err := tw.WriteHeader(&tar.Header{
			Name: m.name, Mode: 0o644, Size: int64(len(m.body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("header: %v", err)
		}
		mustWrite(t, tw, m.body)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	bundle := buf.Bytes()

	lim := DefaultLimits()
	lim.MaxLeafBytes = int64(len(small)) * 2 // admits small.log, refuses big.log

	out, rep := run(t, bundle, lim)
	if bytes.Equal(out, bundle) {
		t.Fatal("the whole archive was passed through; one oversized member must " +
			"not stop the others being scrubbed")
	}
	if !rep.HasUnscrubbed() {
		t.Error("the oversized member was skipped without being recorded")
	}
	var sawLeafCap bool
	for _, p := range rep.Summary.Passthroughs {
		if p.Code == report.ReasonLeafCap {
			sawLeafCap = true
		}
	}
	if !sawLeafCap {
		t.Errorf("no leaf-cap hole recorded; got %+v", rep.Summary.Passthroughs)
	}
}
