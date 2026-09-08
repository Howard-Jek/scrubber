package archive

import (
	"bufio"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

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
	// Name locates the object for whoever has to act on the report. For a whole
	// object it is the real git object ID, so `git cat-file -p <name>` shows the
	// content and `git log --all --find-object=<name>` finds the commits carrying
	// it. For a delta it is a positional label, because an object ID cannot be
	// computed without resolving the delta against its base.
	Name string
	Type string
	Body *spill.Blob
	// Delta marks an object stored as a difference against another. Its body is a
	// delta instruction stream rather than the object's content: new text appears
	// literally in the insert instructions and IS scannable, but text carried over
	// unchanged from the base lives in the base rather than here.
	Delta bool
}

// Ref returns how a person should look this object up.
func (o PackObject) Ref() string {
	if o.Delta {
		return o.Name + " (" + o.Type + ", not addressable without resolving the delta)"
	}
	return o.Name + " (" + o.Type + ")"
}

// ReadPack decodes every object in a git packfile, holding at most budget bytes of
// decoded content in total and at most maxObjects objects.
//
// A pack that stops making sense partway is not an error, for the same reason a
// truncated tar is not: the objects already decoded are real, and the secrets in
// them are real. What could be read is returned along with the error that stopped
// the walk, so the caller can report both the findings and the fact that the tail
// was not examined.
func ReadPack(r io.Reader, budget int64, maxObjects int, p spill.Policy) ([]PackObject, error) {
	br := bufio.NewReader(r)
	hdr := make([]byte, 12)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return nil, fmt.Errorf("pack header: %w", err)
	}
	if string(hdr[:4]) != "PACK" {
		return nil, fmt.Errorf("not a packfile")
	}
	count := binary.BigEndian.Uint32(hdr[8:12])

	var objects []PackObject
	remaining := budget
	fail := func(err error) ([]PackObject, error) {
		ClosePack(objects)
		return nil, err
	}

	for i := uint32(0); i < count; i++ {
		if maxObjects > 0 && len(objects) >= maxObjects {
			return fail(ErrTooManyMembers)
		}
		typ, size, err := readPackObjHeader(br)
		if err != nil {
			return objects, fmt.Errorf("object %d header: %w", i, err)
		}
		delta := typ == 6 || typ == 7
		switch typ {
		case 6: // ofs-delta: a varint offset back to the base
			if err := skipVarint(br); err != nil {
				return objects, fmt.Errorf("object %d base offset: %w", i, err)
			}
		case 7: // ref-delta: a raw object ID naming the base
			if _, err := io.CopyN(io.Discard, br, 20); err != nil {
				return objects, fmt.Errorf("object %d base ref: %w", i, err)
			}
		}

		zr, err := zlib.NewReader(br)
		if err != nil {
			return objects, fmt.Errorf("object %d: %w", i, err)
		}
		body, err := spillCapped(zr, remaining, p)
		zr.Close()
		if err != nil {
			// A guard trip is terminal: the caller must not act on a partial view of
			// a pack it refused to finish reading.
			return fail(err)
		}
		remaining -= body.Size()

		name := fmt.Sprintf("object-%d@%d", i, size)
		kind := packObjectType[typ]
		if kind == "" {
			kind = fmt.Sprintf("type-%d", typ)
		}
		if !delta {
			// The git object ID: SHA-1 over "<type> <size>\0<content>". Computing it
			// is what turns "there is a secret in this pack somewhere" into a name a
			// person can pass to git cat-file.
			id, idErr := gitObjectID(kind, body)
			if idErr != nil {
				// body is not in `objects` yet, so ClosePack inside fail cannot
				// reach it. Without this it is an orphaned temp file on a scratch
				// volume that is, by the nature of this failure, already unhealthy.
				body.Close()
				return fail(idErr)
			}
			name = id
		}
		objects = append(objects, PackObject{Name: name, Type: kind, Body: body, Delta: delta})
	}
	return objects, nil
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
func readPackObjHeader(br *bufio.Reader) (typ byte, size int64, err error) {
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

// skipVarint consumes a continuation-bit encoded integer without decoding it.
func skipVarint(br *bufio.Reader) error {
	for {
		b, err := br.ReadByte()
		if err != nil {
			return err
		}
		if b&0x80 == 0 {
			return nil
		}
	}
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
