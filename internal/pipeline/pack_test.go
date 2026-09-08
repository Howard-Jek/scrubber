package pipeline

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/howard/scrubber/internal/report"
)

// packObj is one object to place in a synthetic packfile.
type packObj struct {
	typ     byte // 1 commit, 2 tree, 3 blob, 4 tag
	content string
}

// packOf builds a real, well-formed v2 packfile. Built by hand rather than by
// shelling out to git so the test does not depend on git being installed, and so the
// object IDs it asserts on are computed independently of the reader under test.
func packOf(t *testing.T, objs []packObj) []byte {
	t.Helper()
	var body bytes.Buffer
	body.WriteString("PACK")
	binary.Write(&body, binary.BigEndian, uint32(2))
	binary.Write(&body, binary.BigEndian, uint32(len(objs)))
	for _, o := range objs {
		size := len(o.content)
		b := byte(o.typ<<4) | byte(size&0x0f)
		size >>= 4
		for size > 0 {
			body.WriteByte(b | 0x80)
			b = byte(size & 0x7f)
			size >>= 7
		}
		body.WriteByte(b)

		zw := zlib.NewWriter(&body)
		if _, err := zw.Write([]byte(o.content)); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
	}
	sum := sha1.Sum(body.Bytes())
	body.Write(sum[:])
	return body.Bytes()
}

// gitID computes the object ID git would store this content under, independently of
// the implementation being tested.
func gitID(kind, content string) string {
	h := sha1.New()
	fmt.Fprintf(h, "%s %d\x00%s", kind, len(content), content)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// TestGitPackIsInspectedNamedAndNeverCalledClean is the whole contract for a
// packfile, and it is worth stating why each half matters.
//
// A pack is the richest source of secrets a bundle can carry -- every blob, tree and
// commit in the history, including the ones deleted from the working tree -- and it
// is invisible to every byte-level defence: each object is independently deflated,
// so the file is high-entropy throughout, sniffs as binary, and scans clean at every
// stride. It was skipped in silence.
//
// It also cannot be scrubbed. So the contract is: read it, say exactly what is in it
// and under which object ID, pass the bytes through untouched, and refuse to call
// the run clean.
func TestGitPackIsInspectedNamedAndNeverCalledClean(t *testing.T) {
	secret := "password = hunter2\ncontact bob@acme.test at AcmeCorp\n"
	innocuous := "package main\n\nfunc main() {}\n"

	data := packOf(t, []packObj{
		{typ: 3, content: innocuous},
		{typ: 3, content: secret},
		{typ: 1, content: "tree abc\nauthor Someone <bob@acme.test> 0 +0000\n\nremove the secrets\n"},
	})

	out, rep := run(t, data, DefaultLimits())

	// 1. The bytes are untouched. A "scrubbed" pack is a broken repository.
	if !bytes.Equal(out, data) {
		t.Fatal("the packfile was modified; any edit invalidates the object IDs, " +
			"the .idx and the trailer, leaving a repository git cannot open")
	}

	// 2. It is recorded as a hole, not as an inspected file.
	var hole *report.PassthroughNote
	for i := range rep.Summary.Passthroughs {
		if rep.Summary.Passthroughs[i].Code == report.ReasonGitPack {
			hole = &rep.Summary.Passthroughs[i]
		}
	}
	if hole == nil {
		t.Fatalf("no git-pack hole recorded; got %+v", rep.Summary.Passthroughs)
	}
	if hole.Status != report.StatusUnsupported {
		t.Errorf("status = %q, want %q", hole.Status, report.StatusUnsupported)
	}

	// 3. The secrets inside were actually found, and counted as NOT redacted.
	if rep.Summary.ResidualHits == 0 {
		t.Fatal("nothing was found inside the pack; the objects were not inspected")
	}

	// 4. The run must never read as clean.
	if v := rep.Summary.Verdict(); v != report.VerdictIncompleteRisky {
		t.Errorf("verdict = %q, want %q — a bundle carrying an unredacted credential "+
			"must divert for review, not pass as ordinary incomplete", v,
			report.VerdictIncompleteRisky)
	}
	if !rep.Summary.Verdict().NeedsReview() {
		t.Error("a pack carrying matches must be diverted to review/")
	}

	// 5. It LOCATES: the offending blob is named by its real git object ID, so the
	//    operator can run git cat-file -p <id> against it.
	wantID := gitID("blob", secret)
	found := false
	for _, s := range rep.Summary.ResidualSamples {
		if strings.Contains(s, wantID) {
			found = true
		}
	}
	for _, n := range rep.Summary.NotInspected {
		if strings.Contains(n.Path, wantID) {
			found = true
		}
	}
	if !found {
		t.Errorf("the offending blob was not named by its object ID %s\n"+
			"samples: %v\nnot-inspected: %+v",
			wantID, rep.Summary.ResidualSamples, rep.Summary.NotInspected)
	}
	t.Logf("detail: %s", hole.Detail)
}

// TestCleanGitPackIsNamedButNotRisky: a repository with nothing sensitive in it is
// still a hole worth naming -- it was not scrubbed -- but it must not trip the alarm
// that means "this bundle contains an unredacted credential", or that alarm stops
// meaning anything.
func TestCleanGitPackIsNamedButNotRisky(t *testing.T) {
	data := packOf(t, []packObj{
		{typ: 3, content: "package main\n\nfunc main() {}\n"},
		{typ: 3, content: "# README\n\nnothing to see here\n"},
	})

	out, rep := run(t, data, DefaultLimits())
	if !bytes.Equal(out, data) {
		t.Error("the packfile was modified")
	}
	if rep.Summary.ResidualHits != 0 {
		t.Errorf("clean pack reported %d residual hits", rep.Summary.ResidualHits)
	}
	if v := rep.Summary.Verdict(); v != report.VerdictIncomplete {
		t.Errorf("verdict = %q, want %q — named, but not an alarm", v, report.VerdictIncomplete)
	}
}

// TestGitPackInsideTarballIsFound is the shape this actually arrives in: nobody
// uploads a bare .pack, they upload a .tar.gz of a directory that happens to have a
// .git in it. The tar must still be scrubbed around the pack.
func TestGitPackInsideTarballIsFound(t *testing.T) {
	pack := packOf(t, []packObj{
		{typ: 3, content: "aws_secret = hunter2 for AcmeCorp\n"},
	})
	log := []byte("ordinary line mentioning AcmeCorp and bob@acme.test\n")

	data := tarOfMany(t, [][2]any{
		{"app/app.log", log},
		{"app/.git/objects/pack/pack-abc.pack", pack},
	})

	out, rep := run(t, data, DefaultLimits())

	if rep.Summary.ResidualHits == 0 {
		t.Error("the pack inside the tarball was not inspected")
	}
	if v := rep.Summary.Verdict(); v != report.VerdictIncompleteRisky {
		t.Errorf("verdict = %q, want %q", v, report.VerdictIncompleteRisky)
	}
	// The ordinary log beside it must still have been scrubbed.
	if !bytes.Contains(out, []byte("[EMAIL]")) {
		t.Error("the plain log next to the pack was not scrubbed")
	}
	// And the pack's own bytes survive inside the rebuilt tar.
	if !bytes.Contains(out, pack) {
		t.Error("the packfile did not survive the repack byte-for-byte")
	}
}

// TestPackGuardTripIsNotReportedAsCorruption: a pack refused by MAX_MEMBERS or by
// the expansion budget must be classified as the guard trip it is.
//
// Collapsing them into "could not be decoded" is what containerFailure exists to
// prevent — it sends an operator hunting a corrupt upload when the real answer is
// that a limit is too low, and it puts the wrong label on
// scrubber_files_not_inspected_total{reason}.
func TestPackGuardTripIsNotReportedAsCorruption(t *testing.T) {
	var objs []packObj
	for i := 0; i < 50; i++ {
		objs = append(objs, packObj{typ: 3, content: fmt.Sprintf("object number %d\n", i)})
	}
	data := packOf(t, objs)

	lim := DefaultLimits()
	lim.MaxMembers = 5

	_, rep := run(t, data, lim)

	var codes []report.Reason
	for _, p := range rep.Summary.Passthroughs {
		codes = append(codes, p.Code)
	}
	for _, c := range codes {
		if c == report.ReasonGitPack {
			t.Errorf("a member-cap trip was reported as %q; an operator would look for a "+
				"corrupt packfile instead of raising MAX_MEMBERS. got codes: %v",
				report.ReasonGitPack, codes)
		}
	}
	found := false
	for _, c := range codes {
		if c == report.ReasonMemberCap {
			found = true
		}
	}
	if !found {
		t.Errorf("no member-cap reason recorded; got %v", codes)
	}
}

// TestPackResidualLandsOnThePacksOwnEntry pins the report contract that the first
// version of this code broke.
//
// NoteResidual amends the MOST RECENT entry. Calling it once per object, before the
// pack's own Skip, wrote each object's hit count onto whatever unrelated file
// happened to have been recorded last — corrupting that entry's rollback ledger, so
// a failed repack would un-count hits from the wrong file and leave the total
// inflated. The annotation has to land on the pack.
func TestPackResidualLandsOnThePacksOwnEntry(t *testing.T) {
	pack := packOf(t, []packObj{
		{typ: 3, content: "aws_secret for AcmeCorp, mail bob@acme.test\n"},
	})
	// An ordinary file recorded BEFORE the pack: the entry a misdirected
	// NoteResidual would have landed on.
	data := tarOfMany(t, [][2]any{
		{"a-innocent.log", []byte("nothing interesting here\n")},
		{"b.pack", pack},
	})

	_, rep := run(t, data, DefaultLimits())

	var packNote, otherNote *report.Note
	for i := range rep.Summary.NotInspected {
		n := &rep.Summary.NotInspected[i]
		if strings.HasSuffix(n.Path, "b.pack") {
			packNote = n
		}
		if strings.Contains(n.Path, "a-innocent.log") {
			otherNote = n
		}
	}
	if packNote == nil {
		t.Fatalf("no entry for the pack; got %+v", rep.Summary.NotInspected)
	}
	if packNote.Residual == "" {
		t.Error("the pack's own entry carries no residual annotation, so a surface " +
			"reading the note list cannot see what was found inside it")
	}
	if otherNote != nil && otherNote.Residual != "" {
		t.Errorf("the residual annotation landed on %q instead of the pack", otherNote.Path)
	}
}

// --- delta helpers, mirroring the encoders git uses ---

func objHdr(typ byte, size int) []byte {
	var out []byte
	b := byte(typ<<4) | byte(size&0x0f)
	size >>= 4
	for size > 0 {
		out = append(out, b|0x80)
		b = byte(size & 0x7f)
		size >>= 7
	}
	return append(out, b)
}

func ofsEnc(v int) []byte {
	buf := make([]byte, 16)
	i := len(buf) - 1
	buf[i] = byte(v & 0x7f)
	for {
		v >>= 7
		if v == 0 {
			break
		}
		v--
		i--
		buf[i] = 0x80 | byte(v&0x7f)
	}
	return buf[i:]
}

func dv(v int) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v == 0 {
			return append(out, b)
		}
		out = append(out, b|0x80)
	}
}

func zdef(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// packCopyingDelta builds a pack whose second object is a delta that COPIES the
// whole of a secret-bearing base and appends an innocuous line. The secret appears
// nowhere in the delta's own instruction stream.
func packCopyingDelta(t *testing.T, secret, appended string) []byte {
	t.Helper()
	var b bytes.Buffer
	b.WriteString("PACK")
	binary.Write(&b, binary.BigEndian, uint32(2))
	binary.Write(&b, binary.BigEndian, uint32(2))

	baseOff := b.Len()
	b.Write(objHdr(3, len(secret)))
	b.Write(zdef(t, []byte(secret)))

	deltaOff := b.Len()
	var instr []byte
	instr = append(instr, dv(len(secret))...)
	instr = append(instr, dv(len(secret)+len(appended))...)
	op := byte(0x80)
	var sz []byte
	if len(secret)&0xff != 0 {
		op |= 0x10
		sz = append(sz, byte(len(secret)&0xff))
	}
	if (len(secret)>>8)&0xff != 0 {
		op |= 0x20
		sz = append(sz, byte((len(secret)>>8)&0xff))
	}
	instr = append(instr, op)
	instr = append(instr, sz...)
	instr = append(instr, byte(len(appended)))
	instr = append(instr, appended...)

	b.Write(objHdr(6, len(instr)))
	b.Write(ofsEnc(deltaOff - baseOff))
	b.Write(zdef(t, instr))

	sum := sha1.Sum(b.Bytes())
	b.Write(sum[:])
	return b.Bytes()
}

// TestPackDeltaCarryingCopiedSecretIsFound is the end-to-end version of the delta
// case, through the real pipeline.
//
// Both objects here hold the credential, but only the first holds it literally. The
// second is a delta that copies it, so before resolution the pipeline saw one hit and
// reported one object; the later revision of the file -- the one actually checked out
// at HEAD -- came back clean.
func TestPackDeltaCarryingCopiedSecretIsFound(t *testing.T) {
	const secret = "password = hunter2 for AcmeCorp contact bob@acme.test\n"
	data := packCopyingDelta(t, secret, "# a later, unrelated edit\n")

	_, rep := run(t, data, DefaultLimits())

	if v := rep.Summary.Verdict(); v != report.VerdictIncompleteRisky {
		t.Errorf("verdict = %q, want %q", v, report.VerdictIncompleteRisky)
	}

	// Both objects must be named: the one that introduced the secret and the one
	// that carries it forward.
	var hole *report.PassthroughNote
	for i := range rep.Summary.Passthroughs {
		if rep.Summary.Passthroughs[i].Code == report.ReasonGitPack {
			hole = &rep.Summary.Passthroughs[i]
		}
	}
	if hole == nil {
		t.Fatalf("no git-pack hole; got %+v", rep.Summary.Passthroughs)
	}
	if !strings.Contains(hole.Detail, "2 object(s) carry") {
		t.Errorf("expected BOTH the base and the delta to be reported as carrying the "+
			"secret; the delta copies it, so a scan of its raw instructions finds "+
			"nothing.\ndetail: %s", hole.Detail)
	}
	if strings.Contains(hole.Detail, "could not be resolved") {
		t.Errorf("a resolvable ofs-delta was reported as unresolved: %s", hole.Detail)
	}
	t.Logf("detail: %s", hole.Detail)
}

// TestSkipGitPacksStillReportsTheHole is the safety property of the kill switch.
//
// The switch exists for capacity: reading a pack charges the expansion budget several
// times the pack's size on disk, and an operator may need to stop that faster than an
// image rollback allows. What it must never become is a quiet way to make a bundle
// full of credentials look clean, so turning it on changes whether the pack is READ,
// never whether it is MENTIONED.
func TestSkipGitPacksStillReportsTheHole(t *testing.T) {
	secret := "password = hunter2\ncontact bob@acme.test at AcmeCorp\n"
	data := packOf(t, []packObj{{typ: 3, content: secret}})

	lim := DefaultLimits()
	lim.SkipGitPacks = true

	out, rep := run(t, data, lim)

	if !bytes.Equal(out, data) {
		t.Error("the packfile was modified")
	}
	var hole *report.PassthroughNote
	for i := range rep.Summary.Passthroughs {
		if rep.Summary.Passthroughs[i].Code == report.ReasonGitPack {
			hole = &rep.Summary.Passthroughs[i]
		}
	}
	if hole == nil {
		t.Fatalf("disabling pack scanning also hid the pack from the report; got %+v",
			rep.Summary.Passthroughs)
	}
	if !strings.Contains(hole.Detail, "disabled by configuration") {
		t.Errorf("the detail does not say nobody looked: %q", hole.Detail)
	}
	// Nobody looked, so the run cannot be cleared. An unread pack is an unscannable
	// hole, not an absence of findings.
	if v := rep.Summary.Verdict(); v != report.VerdictIncompleteRisky {
		t.Errorf("verdict = %q, want %q — a pack nobody examined must not pass as "+
			"ordinary incomplete, or disabling the scan becomes a way to launder a "+
			"bundle through the normal output bucket", v, report.VerdictIncompleteRisky)
	}
}
