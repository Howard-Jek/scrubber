package archive

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/howard/scrubber/internal/spill"
)

// --- helpers that build a real packfile containing a real ofs-delta ---

// objHeaderBytes encodes the type/size header (type in bits 4-6, size low nibble
// first, then 7 bits per continuation byte).
func objHeaderBytes(typ byte, size int) []byte {
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

// ofsBytes encodes an ofs-delta base offset: big-endian, with the implicit
// decrement per continuation byte that makes every value uniquely representable.
func ofsBytes(v int) []byte {
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

// dVarint encodes the delta header's size fields: little-endian, 7 bits per byte.
func dVarint(v int) []byte {
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

// deltaCopyThenInsert builds an instruction stream that COPIES the whole base and
// then INSERTS a literal. The copy is the half a raw scan cannot see.
func deltaCopyThenInsert(baseLen int, insert string) []byte {
	var d []byte
	d = append(d, dVarint(baseLen)...)
	d = append(d, dVarint(baseLen+len(insert))...)

	op := byte(0x80)
	var sizeBytes []byte
	if baseLen&0xff != 0 {
		op |= 0x10
		sizeBytes = append(sizeBytes, byte(baseLen&0xff))
	}
	if (baseLen>>8)&0xff != 0 {
		op |= 0x20
		sizeBytes = append(sizeBytes, byte((baseLen>>8)&0xff))
	}
	d = append(d, op)
	d = append(d, sizeBytes...) // offset 0 needs no bytes: absent means zero
	for len(insert) > 0 {
		n := len(insert)
		if n > 127 {
			n = 127
		}
		d = append(d, byte(n))
		d = append(d, insert[:n]...)
		insert = insert[n:]
	}
	return d
}

func deflate(t *testing.T, b []byte) []byte {
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

// packWithDelta builds a two-object pack: a blob, then an ofs-delta against it.
func packWithDelta(t *testing.T, base, insert string) []byte {
	t.Helper()
	var b bytes.Buffer
	b.WriteString("PACK")
	binary.Write(&b, binary.BigEndian, uint32(2))
	binary.Write(&b, binary.BigEndian, uint32(2))

	baseOff := b.Len()
	b.Write(objHeaderBytes(3, len(base))) // 3 = blob
	b.Write(deflate(t, []byte(base)))

	deltaOff := b.Len()
	instr := deltaCopyThenInsert(len(base), insert)
	b.Write(objHeaderBytes(6, len(instr))) // 6 = ofs-delta
	b.Write(ofsBytes(deltaOff - baseOff))
	b.Write(deflate(t, instr))

	sum := sha1.Sum(b.Bytes())
	b.Write(sum[:])
	return b.Bytes()
}

func gitBlobID(content string) string {
	h := sha1.New()
	fmt.Fprintf(h, "blob %d\x00%s", len(content), content)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// TestDeltaResolutionFindsCopiedText is the reason delta resolution exists.
//
// A delta stores edits, not content. Text it INSERTS appears literally in the
// instruction stream, so an unresolved scan finds it — that is the commit which
// introduced a secret. Text it COPIES from its base does not appear at all. So a
// credential added in one commit and merely carried forward in the next is found in
// the first object and invisible in every later one, and a file edited AROUND a
// secret produces an object that looks completely clean.
//
// Here the secret is only ever copied. Before resolution this object contained no
// trace of it.
func TestDeltaResolutionFindsCopiedText(t *testing.T) {
	const secret = "aws_secret_access_key = wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY\n"
	const added = "# unrelated edit appended later\n"

	data := packWithDelta(t, secret, added)

	objs, err := ReadPack(bytes.NewReader(data), 1<<20, 100, spill.DefaultPolicy, nil)
	defer ClosePack(objs)
	if err != nil {
		t.Fatalf("ReadPack: %v", err)
	}
	if len(objs) != 2 {
		t.Fatalf("decoded %d objects, want 2", len(objs))
	}

	d := objs[1]
	if !d.Delta {
		t.Fatal("second object should be stored as a delta")
	}
	if !d.Resolved {
		t.Fatal("the delta was not resolved, so the copied secret is still invisible")
	}
	if d.Type != "blob" {
		t.Errorf("resolved type = %q, want blob: a delta inherits its base's type, and "+
			"reporting it as \"ofs-delta\" tells nobody whether the hit is in a file or a commit", d.Type)
	}

	got, err := d.Body.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	want := secret + added
	if string(got) != want {
		t.Fatalf("resolved content = %q, want %q", got, want)
	}
	// The secret is present in the RESOLVED object and absent from the raw
	// instructions, which is the whole point.
	if !strings.Contains(string(got), "wJalrXUtnFEMIK7MDENG") {
		t.Error("the copied secret is missing from the resolved object")
	}
	// The negative half, which is the actual justification for this code: the
	// delta's own instruction stream does NOT contain the secret. Scanning it
	// unresolved -- what this reader did before -- would report this object clean.
	instr := deltaCopyThenInsert(len(secret), added)
	if bytes.Contains(instr, []byte("wJalrXUtnFEMIK7MDENG")) {
		t.Fatal("test is not exercising a COPY: the secret is literal in the delta " +
			"instructions, so an unresolved scan would have found it anyway")
	}
	t.Logf("delta instructions are %d bytes and contain no trace of the %d-byte secret; "+
		"only resolution finds it", len(instr), len(secret))
	// And the resolved object carries the object ID git would give it.
	if d.Name != gitBlobID(want) {
		t.Errorf("resolved object ID = %s, want %s", d.Name, gitBlobID(want))
	}
}

// TestDeltaChainResolves: a delta may be built against another delta, so resolution
// has to recurse rather than assume its base is a whole object.
func TestDeltaChainResolves(t *testing.T) {
	// Build blob -> delta -> delta by hand.
	const base = "line one\n"
	var b bytes.Buffer
	b.WriteString("PACK")
	binary.Write(&b, binary.BigEndian, uint32(2))
	binary.Write(&b, binary.BigEndian, uint32(3))

	off0 := b.Len()
	b.Write(objHeaderBytes(3, len(base)))
	b.Write(deflate(t, []byte(base)))

	mid := base + "line two\n"
	off1 := b.Len()
	i1 := deltaCopyThenInsert(len(base), "line two\n")
	b.Write(objHeaderBytes(6, len(i1)))
	b.Write(ofsBytes(off1 - off0))
	b.Write(deflate(t, i1))

	off2 := b.Len()
	i2 := deltaCopyThenInsert(len(mid), "line three\n")
	b.Write(objHeaderBytes(6, len(i2)))
	b.Write(ofsBytes(off2 - off1)) // base is the PREVIOUS DELTA
	b.Write(deflate(t, i2))

	sum := sha1.Sum(b.Bytes())
	b.Write(sum[:])

	objs, err := ReadPack(bytes.NewReader(b.Bytes()), 1<<20, 100, spill.DefaultPolicy, nil)
	defer ClosePack(objs)
	if err != nil {
		t.Fatalf("ReadPack: %v", err)
	}
	if len(objs) != 3 {
		t.Fatalf("decoded %d objects, want 3", len(objs))
	}
	if !objs[2].Resolved {
		t.Fatal("a delta against another delta was not resolved")
	}
	got, err := objs[2].Body.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if want := mid + "line three\n"; string(got) != want {
		t.Errorf("chain resolved to %q, want %q", got, want)
	}
}

// TestApplyDeltaRejectsHostileInstructions covers the delta interpreter directly.
//
// A copy instruction is a pair of numbers indexing into a buffer, read from a file an
// attacker supplies -- precisely the shape that reads out of bounds when a decoder
// trusts its input. Every one of these must be an error, never a panic and never a
// silent wrong answer, because a "successful" application of a corrupt delta yields
// plausible bytes that get scanned and reported as if they were an object's content.
func TestApplyDeltaRejectsHostileInstructions(t *testing.T) {
	base := []byte("0123456789")

	hdr := func(baseLen, resultLen int) []byte {
		return append(dVarint(baseLen), dVarint(resultLen)...)
	}

	for _, tc := range []struct {
		name  string
		delta []byte
	}{
		{"copy runs past the end of the base",
			append(hdr(10, 10), 0x90, 0xff)}, // op=copy size byte, size 255 from offset 0
		{"copy offset past the end of the base",
			append(hdr(10, 4), 0x91, 0xf0, 0x04)}, // offset 240, size 4
		{"reserved opcode zero",
			append(hdr(10, 1), 0x00)},
		{"declared base size does not match",
			append(hdr(99, 1), 0x91, 0x00, 0x01)},
		{"insert runs off the end of the stream",
			append(hdr(10, 20), 0x40, 'a', 'b')}, // says 64 bytes, supplies 2
		{"result longer than declared",
			append(hdr(10, 2), 0x90, 0x0a)}, // copies 10 into a declared 2
		{"header truncated", []byte{0x80}},
		{"empty", nil},
		{"result size absurd", append(dVarint(10), dVarint(1<<40)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on hostile delta: %v", r)
				}
			}()
			out, err := applyDelta(base, tc.delta)
			if err == nil {
				t.Fatalf("accepted a malformed delta, producing %q", out)
			}
		})
	}
}

// TestDeltaCycleIsRefused: nothing in the file stops an ofs-delta naming itself, or
// two deltas naming each other. Resolution recurses, so a cycle is a stack overflow
// unless it is detected -- and a stack overflow is not recoverable, it takes the
// whole process down with every other object in flight.
func TestDeltaCycleIsRefused(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("PACK")
	binary.Write(&b, binary.BigEndian, uint32(2))
	binary.Write(&b, binary.BigEndian, uint32(1))

	off := b.Len()
	instr := deltaCopyThenInsert(4, "x")
	b.Write(objHeaderBytes(6, len(instr)))
	b.Write(ofsBytes(0)) // base offset == its own offset: a self-reference
	_ = off
	b.Write(deflate(t, instr))
	sum := sha1.Sum(b.Bytes())
	b.Write(sum[:])

	done := make(chan struct{})
	go func() {
		defer close(done)
		objs, _ := ReadPack(bytes.NewReader(b.Bytes()), 1<<20, 100, spill.DefaultPolicy, nil)
		defer ClosePack(objs)
		for _, o := range objs {
			if o.Resolved {
				t.Error("a self-referential delta reported itself as resolved")
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("resolution did not terminate on a delta cycle")
	}
}

// chainPack builds n objects, each an ofs-delta against its predecessor, with the
// first one's base pointing at a place no object starts. Nothing resolves, and every
// resolution attempt has the whole prefix of the chain ahead of it.
func chainPack(t *testing.T, n int) []byte {
	t.Helper()
	var b bytes.Buffer
	b.WriteString("PACK")
	binary.Write(&b, binary.BigEndian, uint32(2))
	binary.Write(&b, binary.BigEndian, uint32(n))

	prev := -1
	for i := 0; i < n; i++ {
		off := b.Len()
		instr := deltaCopyThenInsert(4, "x")
		b.Write(objHeaderBytes(6, len(instr)))
		if prev < 0 {
			b.Write(ofsBytes(off - 3)) // lands mid-header: no object starts there
		} else {
			b.Write(ofsBytes(off - prev))
		}
		b.Write(deflate(t, instr))
		prev = off
	}
	sum := sha1.Sum(b.Bytes())
	b.Write(sum[:])
	return b.Bytes()
}

// TestFailedResolutionIsMemoised is the regression test for a CPU denial of service.
//
// An ofs-delta's base is always EARLIER in the file, so a pack of n objects each
// deltaing against its predecessor is one chain n long. Without memoising failure,
// object i walks i frames, fails, caches nothing, and object i+1 does it again:
// quadratic, and measured at 29 seconds for 25k objects in a 537 KB file. At the
// default MAX_MEMBERS of 100000 that is minutes of CPU from a couple of megabytes,
// and it is uninterruptible -- SCRUB_TIMEOUT is a cooperative latch, so a stretch
// that never polls it cannot be stopped and the whole queue stalls behind it.
//
// The assertion is on SHAPE, not on wall-clock: quadratic growth shows up as the
// larger case taking far more than proportionally longer, which is robust on a busy
// machine in a way an absolute timeout is not.
func TestFailedResolutionIsMemoised(t *testing.T) {
	small, large := 2000, 8000 // 4x the objects

	run := func(n int) time.Duration {
		data := chainPack(t, n)
		start := time.Now()
		objs, _ := ReadPack(bytes.NewReader(data), 1<<28, 0, spill.DefaultPolicy, nil)
		ClosePack(objs)
		return time.Since(start)
	}

	ts := run(small)
	tl := run(large)
	t.Logf("n=%d took %v; n=%d took %v", small, ts, large, tl)

	// Linear would be ~4x. Quadratic would be ~16x. Allow generous slack for a
	// loaded machine and a small fixed cost, and still catch the real thing.
	if ts > 0 && tl > 10*ts {
		t.Errorf("resolution grew %.1fx for 4x the objects, which is the quadratic "+
			"shape: failures are not being memoised", float64(tl)/float64(ts))
	}
	if tl > 30*time.Second {
		t.Errorf("resolving %d unresolvable objects took %v", large, tl)
	}
}

// TestDeepChainDoesNotOverflowTheStack: the visiting set refuses cycles, not depth.
// Each frame is several hundred bytes, and a stack overflow is a fatal runtime error
// that recover() cannot catch -- it takes down every object in flight, not just the
// bad one, which is exactly what the pipeline's panic handler exists to prevent.
func TestDeepChainDoesNotOverflowTheStack(t *testing.T) {
	data := chainPack(t, maxDeltaChainDepth*3)
	done := make(chan struct{})
	go func() {
		defer close(done)
		objs, _ := ReadPack(bytes.NewReader(data), 1<<28, 0, spill.DefaultPolicy, nil)
		ClosePack(objs)
	}()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("resolution did not terminate on a very deep chain")
	}
}

// TestReadPackHonoursAbort: SCRUB_TIMEOUT and an in-flight cancel are cooperative
// latches, so any stretch long enough to matter has to poll them. Before this,
// ReadPack was minutes of work that consulted nothing.
func TestReadPackHonoursAbort(t *testing.T) {
	data := chainPack(t, 20000)
	calls := 0
	abort := func() bool {
		calls++
		return calls > 5 // trip almost immediately
	}
	start := time.Now()
	objs, err := ReadPack(bytes.NewReader(data), 1<<28, 0, spill.DefaultPolicy, abort)
	ClosePack(objs)
	if err == nil {
		t.Fatal("ReadPack ran to completion despite the abort predicate tripping")
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("abort took %v to take effect", d)
	}
}

// TestOfsDeltaOffsetOverflowIsRefused: git's get_delta_base tests for overflow
// BEFORE shifting. Testing the sign bit afterwards misses values whose high bits
// shift cleanly past bit 63 and wrap to a small positive -- those were accepted and
// bound the delta to whatever happened to sit at the wrapped offset. With a base of
// the right size, applyDelta then succeeds and the object is reported under an ID
// that looks real and describes content that was never in the repository.
func TestOfsDeltaOffsetOverflowIsRefused(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("PACK")
	binary.Write(&b, binary.BigEndian, uint32(2))
	binary.Write(&b, binary.BigEndian, uint32(2))

	// A whole object first, so there is something plausible to land on.
	b.Write(objHeaderBytes(3, 4))
	b.Write(deflate(t, []byte("aaaa")))

	instr := deltaCopyThenInsert(4, "x")
	b.Write(objHeaderBytes(6, len(instr)))
	// Ten continuation bytes: the accumulated value shifts past bit 63.
	b.Write([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00})
	b.Write(deflate(t, instr))
	sum := sha1.Sum(b.Bytes())
	b.Write(sum[:])

	objs, err := ReadPack(bytes.NewReader(b.Bytes()), 1<<20, 100, spill.DefaultPolicy, nil)
	defer ClosePack(objs)
	if err == nil {
		t.Error("a base offset git rejects as overflow was accepted")
	}
	for _, o := range objs {
		if o.Delta && o.Resolved {
			t.Errorf("delta with an overflowing base offset resolved to %s; the report "+
				"would name an object that was never in the repository", o.Name)
		}
	}
}

// TestOfsDeltaPointingBeforeThePackIsRefused: a backward offset larger than the
// object's own position would make baseOff negative, which is the sentinel meaning
// "this is a ref-delta" -- so the object was diagnosed as a thin-pack base rather
// than as the malformed offset it is.
func TestOfsDeltaPointingBeforeThePackIsRefused(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("PACK")
	binary.Write(&b, binary.BigEndian, uint32(2))
	binary.Write(&b, binary.BigEndian, uint32(1))

	instr := deltaCopyThenInsert(4, "x")
	b.Write(objHeaderBytes(6, len(instr)))
	b.Write(ofsBytes(1 << 20)) // far beyond this object's own offset
	b.Write(deflate(t, instr))
	sum := sha1.Sum(b.Bytes())
	b.Write(sum[:])

	objs, err := ReadPack(bytes.NewReader(b.Bytes()), 1<<20, 100, spill.DefaultPolicy, nil)
	defer ClosePack(objs)
	if err == nil {
		t.Error("a base offset pointing before the start of the pack was accepted")
	} else if !strings.Contains(err.Error(), "before the pack") {
		t.Errorf("diagnosed as %q; it should name the malformed offset rather than "+
			"report a missing thin-pack base", err)
	}
}

// TestReverseOrderedRefDeltaChainResolves covers ordering the old two-pass loop
// could not handle.
//
// byID only learns an object once it has been resolved, so a ref-delta naming a base
// that appears LATER in the file misses on the pass it is first tried, and each pass
// advances such a chain by exactly one link. Two passes therefore resolved a chain of
// two and left everything deeper on the raw-instruction fallback -- which is the
// blind spot delta resolution exists to close, reached silently. Git's index-pack
// handles arbitrary ordering and its default pack.depth is 50.
func TestReverseOrderedRefDeltaChainResolves(t *testing.T) {
	const links = 6

	// Build the contents bottom-up so each link's base ID is known.
	contents := []string{"root object\n"}
	for i := 1; i < links; i++ {
		contents = append(contents, contents[i-1]+fmt.Sprintf("appended %d\n", i))
	}
	ids := make([]string, links)
	for i, c := range contents {
		ids[i] = gitBlobID(c)
	}

	// Emit deepest-first: object 0 is the deepest delta, the whole object is last.
	var b bytes.Buffer
	b.WriteString("PACK")
	binary.Write(&b, binary.BigEndian, uint32(2))
	binary.Write(&b, binary.BigEndian, uint32(links))

	for i := links - 1; i >= 1; i-- {
		instr := deltaCopyThenInsert(len(contents[i-1]), fmt.Sprintf("appended %d\n", i))
		b.Write(objHeaderBytes(7, len(instr))) // 7 = ref-delta
		raw, err := hex.DecodeString(ids[i-1])
		if err != nil {
			t.Fatal(err)
		}
		b.Write(raw)
		b.Write(deflate(t, instr))
	}
	b.Write(objHeaderBytes(3, len(contents[0])))
	b.Write(deflate(t, []byte(contents[0])))
	sum := sha1.Sum(b.Bytes())
	b.Write(sum[:])

	objs, err := ReadPack(bytes.NewReader(b.Bytes()), 1<<22, 100, spill.DefaultPolicy, nil)
	defer ClosePack(objs)
	if err != nil {
		t.Fatalf("ReadPack: %v", err)
	}

	resolved := 0
	for _, o := range objs {
		if !o.Delta || o.Resolved {
			resolved++
		}
	}
	if resolved != links {
		t.Errorf("resolved %d of %d objects; a reverse-ordered chain must resolve in "+
			"full, not one link per pass", resolved, links)
	}
	// And the deepest delta must carry the full accumulated content.
	deepest := objs[0]
	if !deepest.Resolved {
		t.Fatal("the deepest delta in the chain was not resolved")
	}
	got, err := deepest.Body.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if want := contents[links-1]; string(got) != want {
		t.Errorf("deepest object resolved to %q, want %q", got, want)
	}
	if deepest.Name != ids[links-1] {
		t.Errorf("deepest object ID = %s, want %s", deepest.Name, ids[links-1])
	}
}
