package archive

import (
	"bufio"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/howard/scrubber/internal/spill"
)

// A git packfile is the object database of a repository in one file, and it is the
// single richest source of secrets a bundle can carry: every blob, tree, commit and
// tag in the history, including the ones deleted from the working tree. A credential
// committed once and removed in the next commit is still in here, in full.
//
// None of it is visible from the outside. Each object is independently deflated, so
// the file is high-entropy end to end: a byte-level scan of the raw pack finds no
// text at any stride, `strings` returns compression noise, and grepping it for an
// address that git reads out of it in an instant returns nothing. That is what made
// this the worst case for a scrubber -- correctly sniffed as binary, correctly
// skipped, and silently the most sensitive file in the bundle.
//
// Read but never rewritten. Object IDs are the SHA-1 of the object's own content and
// the trailer is the SHA-1 of everything before it, so changing a single byte breaks
// the object, every tree and commit that references it, the .idx beside it and the
// trailer at once -- git stops being able to read the repository at all. CanWrite
// reports false for Pack, the pipeline never descends into a format it cannot write,
// and this reader exists to inspect and report rather than to scrub.
//
// The sibling .idx file needs none of this: it holds a fanout table, sorted object
// IDs, CRCs and offsets, with no filenames and no content, so skipping it as binary
// loses nothing.

// packObjectType maps the 3-bit type field of an object header.
var packObjectType = map[byte]string{
	1: "commit", 2: "tree", 3: "blob", 4: "tag", 6: "ofs-delta", 7: "ref-delta",
}

// PackObject is one object decoded out of a packfile.
type PackObject struct {
	// Name locates the object for whoever has to act on the report. For an object
	// whose content we hold it is the real git object ID, so `git cat-file -p <name>`
	// shows it and `git log --all --find-object=<name>` finds the commits carrying
	// it. For a delta that could not be resolved it is a positional label, because an
	// object ID cannot be computed without the content it names.
	Name string
	Type string
	Body *spill.Blob
	// Delta reports that this object was STORED as a difference against another.
	// It says how the object arrived, not what Body now holds.
	Delta bool
	// Resolved reports that a delta was applied, so Body is the object's real
	// content and Name is its real object ID. False on a delta means Body is still
	// the raw instruction stream: text the delta INSERTS is in there and will be
	// found, text it COPIES from its base is not.
	Resolved bool
}

// Ref returns how a person should look this object up.
func (o PackObject) Ref() string {
	switch {
	case !o.Delta:
		return o.Name + " (" + o.Type + ")"
	case o.Resolved:
		return o.Name + " (" + o.Type + ", stored as a delta)"
	default:
		return o.Name + " (" + o.Type + ", unresolved: only inserted text was scanned)"
	}
}

// countReader tracks how far into the pack we are, which ofs-delta needs: its base
// is named by a backwards byte offset from the delta's own start.
//
// It implements io.ByteReader as well as io.Reader on purpose. compress/flate reads
// byte-at-a-time when given a ByteReader and buffers ahead when not, and buffering
// ahead would both lose the offset and swallow the start of the next object.
type countReader struct {
	br *bufio.Reader
	n  int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.br.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *countReader) ReadByte() (byte, error) {
	b, err := c.br.ReadByte()
	if err == nil {
		c.n++
	}
	return b, err
}

// packEntry is one object as it came off the wire, before deltas are applied.
type packEntry struct {
	offset  int64
	typ     byte
	raw     *spill.Blob // content for a whole object, instructions for a delta
	baseOff int64       // ofs-delta: absolute offset of the base object
	baseID  string      // ref-delta: object ID of the base
}

// ReadPack decodes every object in a git packfile, resolving delta objects against
// their bases, and holds at most budget bytes of decoded content across the whole
// pack and at most maxObjects objects.
//
// A pack that stops making sense partway is not an error, for the same reason a
// truncated tar is not: the objects already decoded are real, and the secrets in
// them are real. What could be read is returned along with the error that stopped
// the walk, so the caller can report both the findings and the fact that the tail
// was not examined. A delta that cannot be resolved is likewise not an error -- it
// is returned unresolved, holding its instruction stream, which is what the reader
// did for every delta before resolution existed.
func ReadPack(r io.Reader, budget int64, maxObjects int, p spill.Policy, abort func() bool) ([]PackObject, error) {
	cr := &countReader{br: bufio.NewReader(r)}
	hdr := make([]byte, 12)
	if _, err := io.ReadFull(cr, hdr); err != nil {
		return nil, fmt.Errorf("pack header: %w", err)
	}
	if string(hdr[:4]) != "PACK" {
		return nil, fmt.Errorf("not a packfile")
	}
	count := binary.BigEndian.Uint32(hdr[8:12])

	var entries []packEntry
	remaining := budget
	fail := func(err error) ([]PackObject, error) {
		for _, e := range entries {
			if e.raw != nil {
				e.raw.Close()
			}
		}
		return nil, err
	}

	var readErr error
	for i := uint32(0); i < count; i++ {
		if maxObjects > 0 && len(entries) >= maxObjects {
			return fail(ErrTooManyMembers)
		}
		// Polled here as well as in resolution: SCRUB_TIMEOUT is a cooperative
		// latch, so a stretch that never asks cannot be stopped, and decoding a
		// pack of a hundred thousand objects is minutes of work before the first
		// delta is even reached.
		if abort != nil && abort() {
			return fail(errAborted)
		}
		at := cr.n
		typ, size, err := readPackObjHeader(cr)
		if err != nil {
			readErr = fmt.Errorf("object %d header: %w", i, err)
			break
		}
		e := packEntry{offset: at, typ: typ, baseOff: -1}
		switch typ {
		case 6: // ofs-delta: a varint offset BACKWARDS from this object's start
			back, err := readOffsetVarint(cr)
			if err != nil {
				readErr = fmt.Errorf("object %d base offset: %w", i, err)
				break
			}
			if back > at {
				// Would point before the start of the pack. Left unchecked it makes
				// baseOff negative, which is the sentinel meaning "this is a
				// ref-delta", so the object would be diagnosed as a thin-pack base
				// rather than as the malformed offset it is.
				readErr = fmt.Errorf("object %d: base offset %d points before the pack", i, back)
				break
			}
			e.baseOff = at - back
		case 7: // ref-delta: the base's object ID, raw
			var id [20]byte
			if _, err := io.ReadFull(cr, id[:]); err != nil {
				readErr = fmt.Errorf("object %d base ref: %w", i, err)
				break
			}
			e.baseID = hex.EncodeToString(id[:])
		}
		if readErr != nil {
			break
		}

		zr, err := zlib.NewReader(cr)
		if err != nil {
			readErr = fmt.Errorf("object %d: %w", i, err)
			break
		}
		body, err := spillCapped(zr, remaining, p)
		zr.Close()
		if err != nil {
			// A guard trip is terminal: the caller must not act on a partial view of
			// a pack it refused to finish reading.
			return fail(err)
		}
		remaining -= body.Size()
		// git checks this and so should we: a header that disagrees with its own
		// payload means the stream is not what it claims, and for a whole object the
		// declared size is what the object ID is computed over.
		if typ != 6 && typ != 7 && size != body.Size() {
			readErr = fmt.Errorf("object %d declares %d bytes but inflated to %d", i, size, body.Size())
			body.Close()
			break
		}
		e.raw = body
		entries = append(entries, e)
	}

	objects, err := resolvePack(entries, &remaining, p, abort)
	if err != nil {
		return fail(err)
	}
	return objects, readErr
}

// readOffsetVarint decodes the ofs-delta base offset, which uses a third encoding
// again -- big-endian with an implicit increment per continuation byte, so that
// every offset has exactly one representation.
func readOffsetVarint(cr *countReader) (int64, error) {
	b, err := cr.ReadByte()
	if err != nil {
		return 0, err
	}
	val := int64(b & 0x7f)
	for b&0x80 != 0 {
		val++
		// Checked BEFORE the shift, as git's get_delta_base does. Testing the sign
		// bit afterwards misses the values whose high bits shift cleanly past bit
		// 63 and wrap to a small positive: those were accepted here and bound the
		// delta to whatever happened to sit at the wrapped offset, leaving the
		// base-size check in applyDelta as the only thing between a crafted pack
		// and a fabricated object reported under a real-looking ID.
		if val <= 0 || val > math.MaxInt64>>7 {
			return 0, errors.New("base offset overflows")
		}
		if b, err = cr.ReadByte(); err != nil {
			return 0, err
		}
		val = (val << 7) | int64(b&0x7f)
	}
	return val, nil
}

// resolvePack turns raw entries into objects, applying deltas against their bases.
//
// Bases are reached by offset for ofs-delta and by object ID for ref-delta, and a
// base may itself be a delta, so resolution recurses. Chains are bounded by git's
// own pack depth, but nothing in the FILE guarantees that -- a hostile pack can name
// itself as its own base -- so the recursion carries a visiting set and refuses a
// cycle rather than exhausting the stack.
func resolvePack(entries []packEntry, remaining *int64, p spill.Policy, abort func() bool) ([]PackObject, error) {
	byOffset := make(map[int64]int, len(entries))
	for i, e := range entries {
		byOffset[e.offset] = i
	}

	out := make([]PackObject, len(entries))
	content := make([]*spill.Blob, len(entries)) // resolved content, nil until known
	state := make([]byte, len(entries))          // 0 unvisited, 1 visiting, 2 done
	byID := make(map[string]int, len(entries))

	// Blobs this function creates by applying deltas. They are not reachable from
	// `entries`, so the caller's cleanup cannot find them: if resolution gives up
	// partway, these are the temp files that would be left behind.
	var made []*spill.Blob
	abandon := func(err error) ([]PackObject, error) {
		for _, b := range made {
			b.Close()
		}
		return nil, err
	}

	// Whole objects are content already; index them by ID so a ref-delta can find
	// them.
	for i := range entries {
		if entries[i].typ == 6 || entries[i].typ == 7 {
			continue
		}
		kind := packObjectType[entries[i].typ]
		if kind == "" {
			kind = fmt.Sprintf("type-%d", entries[i].typ)
		}
		id, err := gitObjectID(kind, entries[i].raw)
		if err != nil {
			return abandon(err)
		}
		content[i] = entries[i].raw
		state[i] = stateDone
		byID[id] = i
		out[i] = PackObject{Name: id, Type: kind, Body: entries[i].raw}
	}

	var resolve func(i, depth int) (*spill.Blob, error)
	resolve = func(i, depth int) (*spill.Blob, error) {
		switch state[i] {
		case stateDone:
			return content[i], nil
		case stateVisiting:
			return nil, errCycle
		case stateFailed:
			// Memoised. Without this a failure is re-derived from scratch every
			// time anything reaches it, and since an ofs-delta's base is always
			// EARLIER in the file, a pack of N objects each deltaing against its
			// predecessor makes resolution quadratic: object i walks i frames,
			// fails, caches nothing, and object i+1 does it again. Measured at
			// 29s for 25k objects in a 537 KB file, which at the default member
			// cap is minutes of uninterruptible CPU from a couple of megabytes.
			return nil, errFailedEarlier
		}
		if depth > maxDeltaChainDepth {
			// The visiting set stops cycles, not depth. Each frame is ~675 bytes,
			// so an honest-looking chain long enough to exhaust the goroutine
			// stack is a fatal runtime error that recover() cannot catch -- it
			// takes down every other object in flight, not just this one.
			return nil, errChainTooDeep
		}
		if abort != nil && abort() {
			return nil, errAborted
		}
		state[i] = stateVisiting
		defer func() {
			if state[i] == stateVisiting {
				state[i] = stateFailed
			}
		}()

		e := entries[i]
		var baseIdx int
		var ok bool
		if e.baseOff >= 0 {
			baseIdx, ok = byOffset[e.baseOff]
		} else {
			baseIdx, ok = byID[e.baseID]
		}
		if !ok {
			// A thin pack: the base lives in the receiving repository, not in this
			// file. Nothing here can resolve it.
			return nil, errors.New("base object is not in this pack")
		}
		baseBlob, err := resolve(baseIdx, depth+1)
		if err != nil {
			return nil, err
		}
		if baseBlob.Size() > maxDeltaResolveBytes || e.raw.Size() > maxDeltaResolveBytes {
			return nil, errDeltaTooLarge
		}
		base, err := baseBlob.Bytes()
		if err != nil {
			return nil, err
		}
		instr, err := e.raw.Bytes()
		if err != nil {
			return nil, err
		}
		applied, err := applyDelta(base, instr)
		if err != nil {
			return nil, err
		}
		if int64(len(applied)) > *remaining {
			return nil, ErrTooLarge
		}
		blob, err := spill.FromBytes(applied, p)
		if err != nil {
			return nil, err
		}
		made = append(made, blob)
		*remaining -= int64(len(applied))

		// A delta inherits its base's type: the type field said "delta", not what
		// the object is. Without this every resolved object would be reported as a
		// delta and no report could say whether a secret sits in a blob or a commit.
		kind := out[baseIdx].Type
		id, err := gitObjectID(kind, blob)
		if err != nil {
			blob.Close()
			*remaining += int64(len(applied)) // debited above; the blob is gone
			return nil, err
		}
		content[i] = blob
		state[i] = stateDone
		byID[id] = i
		out[i] = PackObject{Name: id, Type: kind, Body: blob, Delta: true, Resolved: true}
		return blob, nil
	}

	// Run to a fixpoint rather than a fixed number of passes.
	//
	// byID only knows an object once it is resolved, so a ref-delta naming a base
	// that appears LATER in the file misses on the pass it is first tried. Each pass
	// therefore advances such a chain by exactly one link -- two passes resolve a
	// chain of two, and git's default pack.depth is 50. Looping until a pass resolves
	// nothing new is the shape that actually terminates on the input rather than on
	// an arithmetic guess.
	//
	// Bounded anyway. Failure memoisation makes one pass linear, so the ceiling caps
	// total work at maxResolvePasses x N rather than leaving it open to a pack whose
	// ordering is adversarial rather than merely awkward.
	for pass := 0; pass < maxResolvePasses; pass++ {
		progress := false
		for i := range entries {
			if entries[i].typ != 6 && entries[i].typ != 7 {
				continue
			}
			if state[i] == stateDone {
				continue
			}
			if state[i] == stateFailed {
				// Cleared between passes only: within a pass the memo is what keeps
				// resolution linear, across passes it must not outlive the knowledge
				// that produced it, since byID has grown since.
				state[i] = stateUnvisited
			}
			if _, err := resolve(i, 0); err != nil {
				if errors.Is(err, ErrTooLarge) || errors.Is(err, errAborted) {
					return abandon(err)
				}
				continue // left unresolved; filled in below
			}
			progress = true
		}
		if !progress {
			break
		}
	}

	// Whatever is still unresolved keeps the old behaviour: the raw instruction
	// stream, under a positional label, scanned for the text it inserts.
	for i := range entries {
		if state[i] == stateDone {
			continue
		}
		kind := packObjectType[entries[i].typ]
		if kind == "" {
			kind = fmt.Sprintf("type-%d", entries[i].typ)
		}
		out[i] = PackObject{
			Name:  fmt.Sprintf("object-%d@%d", i, entries[i].offset),
			Type:  kind,
			Body:  entries[i].raw,
			Delta: true,
		}
	}
	// A resolved delta's Body is the APPLIED content, so its instruction stream is
	// now orphaned -- ClosePack walks the returned objects and cannot reach it.
	// Without this a pack of mostly deltas leaves half its temp files behind.
	for i := range entries {
		if entries[i].raw != nil && out[i].Body != entries[i].raw {
			entries[i].raw.Close()
		}
	}
	return out, nil
}

// gitObjectID computes the SHA-1 git would store this object under.
func gitObjectID(kind string, body *spill.Blob) (string, error) {
	h := sha1.New()
	fmt.Fprintf(h, "%s %d\x00", kind, body.Size())
	rc, err := body.Reader()
	if err != nil {
		return "", err
	}
	defer rc.Close()
	if _, err := io.Copy(h, rc); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// readPackObjHeader decodes the variable-length type/size header that precedes each
// object: the first byte carries a continuation bit, a 3-bit type and the low four
// bits of the size, and each further byte carries seven more size bits.
func readPackObjHeader(br io.ByteReader) (typ byte, size int64, err error) {
	b, err := br.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	typ = (b >> 4) & 7
	size = int64(b & 0x0f)
	for shift := uint(4); b&0x80 != 0; shift += 7 {
		if b, err = br.ReadByte(); err != nil {
			return 0, 0, err
		}
		size |= int64(b&0x7f) << shift
	}
	return typ, size, nil
}

// ClosePack releases every decoded object body.
func ClosePack(objects []PackObject) error {
	var first error
	for _, o := range objects {
		if o.Body != nil {
			if err := o.Body.Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}
