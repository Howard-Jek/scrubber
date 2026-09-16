package archive

import (
	"errors"
	"fmt"
)

// Delta objects are how a packfile stays small: most objects are stored as a set of
// edits against another object rather than in full. In a real repository they are
// roughly half of everything -- the pack in this repo is 45% deltas -- so a scanner
// that cannot resolve them is reading half the history.
//
// Scanning the raw instruction stream is not nothing: text a delta INSERTS appears
// literally in it, which covers the common shape of a secret being added in a
// commit. What it misses is text the delta COPIES from its base. A credential added
// in one commit and still present in the next is inserted once and copied thereafter,
// so an unresolved scan finds it in the commit that introduced it and reports every
// later revision of that file as clean. Worse, the copy instruction is what survives
// when a file is edited AROUND a secret: the secret is copied, the edit is inserted,
// and the object carrying it looks empty.
//
// Resolving is therefore the difference between "we found where it was added" and
// "we found every object that contains it".

// errDeltaTooLarge marks a delta whose base or result is bigger than the resolver
// will hold in memory. It is not a failure of the pack; the caller falls back to
// scanning the raw instruction stream, which is what it did for every delta before.
var errDeltaTooLarge = errors.New("delta base or result exceeds the resolve ceiling")

// Resolution state. Named because the failure value is load-bearing rather than
// bookkeeping: see the comment on stateFailed in resolve.
const (
	stateUnvisited = iota
	stateVisiting
	stateDone
	stateFailed
)

// maxDeltaChainDepth bounds how far resolution will recurse.
//
// The visiting set refuses cycles; it says nothing about depth, and a chain does not
// have to be circular to be ruinous. Each frame costs roughly 675 bytes, so a pack of
// a million objects each deltaing against its predecessor -- about 25 MB on the wire
// -- exceeds Go's 1 GB goroutine stack limit, and that is a fatal runtime error
// recover() cannot catch: it takes the process down with every other object in
// flight, which is the one outcome the panic handler exists to prevent.
//
// Git's own default pack.depth is 50 and its ceiling is 4095. A chain deeper than
// this is not a repository git produced.
const maxDeltaChainDepth = 4096

// maxResolvePasses bounds the fixpoint loop over ref-deltas whose bases appear later
// in the file. Each pass advances such a chain by one link, so this is a depth limit
// wearing different clothes, and it is generous against git's pack.depth of 50.
const maxResolvePasses = 64

// errCycle, errChainTooDeep, errFailedEarlier and errAborted are internal: each
// leaves its object unresolved and falls back to the raw-instruction scan.
var (
	errCycle         = errors.New("delta chain contains a cycle")
	errChainTooDeep  = errors.New("delta chain is deeper than the resolver will follow")
	errFailedEarlier = errors.New("resolution already failed for this object")
	errAborted       = errors.New("resolution aborted")
)

// maxDeltaResolveBytes bounds the memory one delta resolution may take.
//
// Applying a delta needs its base contiguous in memory, and a chain needs each link
// in turn, so this is the one place the pack reader can allocate proportional to
// object size rather than to what it has already spilled.
//
// It bounds ONE BUFFER, not one resolution, and the difference matters when sizing a
// pod: base, instructions and result are all live at once and the result is
// pre-allocated at its declared size, so the peak is about three times this number.
// At 32 MiB that is ~96 MiB per delta, which sits under the leaf cap the pipeline
// derives for a 2 GiB pod rather than over it. A repository whose individual objects
// are larger than 32 MiB is one of binaries, where resolving buys little a raw scan
// would not also find.
const maxDeltaResolveBytes = 32 << 20

// readDeltaVarint decodes the little-endian, continuation-bit integer the delta
// header uses for its base and result sizes.
//
// NOT the same encoding as the object header's size field, which packs a type into
// its first byte and starts its shift at 4. Conflating them yields sizes that are
// wrong by a factor of sixteen and a resolver that appears to work on small objects.
func readDeltaVarint(b []byte) (val int64, n int, err error) {
	var shift uint
	for {
		if n >= len(b) {
			return 0, 0, errors.New("delta header truncated")
		}
		if shift > 56 {
			return 0, 0, errors.New("delta size varint too long")
		}
		c := b[n]
		n++
		val |= int64(c&0x7f) << shift
		if c&0x80 == 0 {
			return val, n, nil
		}
		shift += 7
	}
}

// applyDelta reconstructs an object from its base and a delta instruction stream.
//
// The format is two sizes followed by a run of instructions. An instruction with the
// top bit set COPIES a span of the base: the low four bits say which of the four
// offset bytes follow, the next three say which of the three size bytes follow, and
// absent bytes are zero -- so a copy of the first 64 KiB from offset 0 is a single
// byte on the wire. A size of zero means 0x10000, which is the one special case.
// With the top bit clear the instruction INSERTS: its low seven bits are the length
// of the literal that follows, and a length of zero is reserved rather than empty.
//
// Every bound here is checked. A packfile is attacker-controlled, and a copy
// instruction is a pair of numbers indexing into a buffer -- exactly the shape that
// reads out of bounds when a decoder trusts its input.
func applyDelta(base, delta []byte) ([]byte, error) {
	pos := 0
	baseSize, n, err := readDeltaVarint(delta[pos:])
	if err != nil {
		return nil, err
	}
	pos += n
	if baseSize != int64(len(base)) {
		// The delta names the size it was built against. A mismatch means the base
		// was resolved wrongly, and applying it would produce plausible garbage
		// rather than an error -- which in a scanner means silently scanning the
		// wrong bytes and reporting them clean.
		return nil, fmt.Errorf("delta expects a %d-byte base, got %d", baseSize, len(base))
	}
	resultSize, n, err := readDeltaVarint(delta[pos:])
	if err != nil {
		return nil, err
	}
	pos += n
	if resultSize > maxDeltaResolveBytes {
		return nil, errDeltaTooLarge
	}

	out := make([]byte, 0, resultSize)
	for pos < len(delta) {
		op := delta[pos]
		pos++
		switch {
		case op&0x80 != 0: // copy from base
			var off, size int64
			for i := uint(0); i < 4; i++ {
				if op&(1<<i) != 0 {
					if pos >= len(delta) {
						return nil, errors.New("delta copy offset truncated")
					}
					off |= int64(delta[pos]) << (8 * i)
					pos++
				}
			}
			for i := uint(0); i < 3; i++ {
				if op&(0x10<<i) != 0 {
					if pos >= len(delta) {
						return nil, errors.New("delta copy size truncated")
					}
					size |= int64(delta[pos]) << (8 * i)
					pos++
				}
			}
			if size == 0 {
				size = 0x10000
			}
			if off < 0 || size < 0 || off+size > int64(len(base)) {
				return nil, fmt.Errorf("delta copies [%d,%d) from a %d-byte base", off, off+size, len(base))
			}
			if int64(len(out))+size > resultSize {
				return nil, errors.New("delta produces more than its declared result size")
			}
			out = append(out, base[off:off+size]...)

		case op == 0:
			// Reserved. Git has never emitted it and a decoder that treats it as a
			// zero-length insert loops forever on a hostile pack.
			return nil, errors.New("reserved delta opcode 0")

		default: // insert literal
			size := int(op & 0x7f)
			if pos+size > len(delta) {
				return nil, errors.New("delta insert truncated")
			}
			if int64(len(out))+int64(size) > resultSize {
				return nil, errors.New("delta produces more than its declared result size")
			}
			out = append(out, delta[pos:pos+size]...)
			pos += size
		}
	}
	if int64(len(out)) != resultSize {
		return nil, fmt.Errorf("delta produced %d bytes, declared %d", len(out), resultSize)
	}
	return out, nil
}
