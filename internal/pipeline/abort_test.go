package pipeline

import (
	"bytes"
	"testing"

	"github.com/howard/scrubber/internal/report"
)

// TestAbortedWalkNeverRepacks is the guard on the worst outcome this service can
// produce, so it is worth stating plainly what it is testing.
//
// The walk has no context and cannot be interrupted by cancelling one, so an
// in-flight cancel works by polling a predicate. The naive way to honour it — have
// each blob return "unchanged" once the predicate trips — is actively dangerous in
// a container: members before the abort have already been rewritten and members
// after it have not, so `changed` is still true and the container repacks into a
// well-formed archive of a few scrubbed members and many RAW ones. That bundle
// reaches the output bucket under the ordinary key, with a report that makes it
// look like a normal run.
//
// So the contract is stronger than "stop working": an aborted container must hand
// back its ORIGINAL INPUT, byte for byte, and report unchanged — at every level, so
// the collapse propagates all the way to the caller and there is nothing to ship.
func TestAbortedWalkNeverRepacks(t *testing.T) {
	// Many members, each holding content the policy matches, so a partial walk
	// would certainly have rewritten some of them before the abort.
	body := []byte("host AcmeCorp at 10.1.2.3 mail bob@acme.test\n")
	names := []string{"a.log", "b.log", "c.log", "d.log", "e.log", "f.log"}
	zipEntries := map[string][]byte{}
	tarEntries := make([][2]any, 0, len(names))
	for _, n := range names {
		zipEntries[n] = body
		tarEntries = append(tarEntries, [2]any{n, body})
	}

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"zip", zipOf(t, zipEntries)},
		{"tar", tarOfMany(t, tarEntries)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Abort after the first member has been recorded: mid-container is the
			// dangerous case, since some members are rewritten and some are not.
			rep := report.New("in", "out", report.AuditFull, false, "test")
			files := 0
			rep.OnFile(func(report.FileEntry, int) { files++ })

			eng := &Engine{
				Matcher: testMatcher(t),
				Report:  rep,
				Limits:  DefaultLimits(),
				Abort:   func() bool { return files >= 1 },
			}
			out := eng.Process("bundle", tc.data, 0)

			if !bytes.Equal(out, tc.data) {
				t.Fatalf("aborted %s walk returned %d bytes, want the original %d byte for byte; "+
					"a rebuilt container here is a bundle of part-scrubbed, part-RAW members",
					tc.name, len(out), len(tc.data))
			}
			if !eng.Aborted() {
				t.Error("engine did not latch the abort")
			}
		})
	}
}

// TestAbortLatches pins the latch. Polling the predicate afresh at each site would
// let one level of the walk see "not aborted" and the next see "aborted", which is
// exactly the interleaving that produces a half-rewritten container.
func TestAbortLatches(t *testing.T) {
	calls := 0
	eng := &Engine{
		Matcher: testMatcher(t),
		Report:  report.New("in", "out", report.AuditFull, false, "test"),
		Limits:  DefaultLimits(),
		// True once, then false forever after.
		Abort: func() bool { calls++; return calls == 1 },
	}
	if !eng.Aborted() {
		t.Fatal("first call should report aborted")
	}
	for i := 0; i < 5; i++ {
		if !eng.Aborted() {
			t.Fatal("abort did not latch; the walk can disagree with itself about whether it is stopping")
		}
	}
}

// TestNoAbortIsUnaffected is the other half: with no predicate set, nothing about
// the ordinary path changes. A cancel feature that quietly altered normal scrubs
// would be a far worse bug than the one it fixes.
func TestNoAbortIsUnaffected(t *testing.T) {
	data := zipOf(t, map[string][]byte{
		"app.log": []byte("host AcmeCorp at 10.1.2.3 mail bob@acme.test\n"),
	})
	rep := report.New("in", "out", report.AuditFull, false, "test")
	eng := &Engine{Matcher: testMatcher(t), Report: rep, Limits: DefaultLimits()}
	out := eng.Process("bundle", data, 0)

	if bytes.Equal(out, data) {
		t.Fatal("unaborted walk returned the input unchanged; it should have scrubbed")
	}
	if eng.Aborted() {
		t.Error("engine reports aborted with no Abort predicate set")
	}
}
