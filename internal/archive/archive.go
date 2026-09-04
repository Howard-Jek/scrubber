// Package archive provides stateless unpack/repack helpers for each supported
// container and compression format. It contains no recursion and no scrubbing
// logic; the pipeline package drives it. Metadata (names, modes, times, methods,
// symlinks, ordering) is preserved so a repacked bundle matches its original form.
//
// Every read path takes an explicit byte budget and enforces it *while* reading,
// so a decompression bomb is stopped by a hard memory ceiling rather than by an
// expansion-ratio heuristic. Ratio heuristics cannot distinguish a bomb from an
// ordinary log file (real logs routinely exceed 200:1), so they are not used here.
//
// Member bodies are spill.Blobs rather than byte slices. A large archive used to
// hold every member on the heap at once, which made resident memory a multiple of
// the bundle size; now only the member being scrubbed is materialised.
//
// The unit of failure is the member, not the archive. A zip entry that cannot be
// decoded -- encrypted, an unsupported method, a bad checksum -- used to fail the
// whole archive, and the whole archive then went out unscrubbed: one password-
// protected file in a bundle of five hundred logs cost the other four hundred and
// ninety-nine their scrub. Such an entry is now carried across in its stored form,
// byte for byte, and everything around it is still scrubbed. A tar that ends early
// keeps every member that was readable and truncates its output where the input
// did; a compressed stream that ends early yields the prefix it did decode.
package archive

import (
	"archive/tar"
	"archive/zip"
	"compress/bzip2"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"

	"github.com/howard/scrubber/internal/detect"
	"github.com/howard/scrubber/internal/spill"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// spillCapped reads r into a blob under the same budget semantics every read path
// shares: at most max bytes, ErrTooLarge past that, the payload possibly on disk.
// spill.ErrTooLarge is translated to this package's ErrTooLarge so callers keep
// classifying guard trips the way they always have.
func spillCapped(r io.Reader, max int64, p spill.Policy) (*spill.Blob, error) {
	b, err := spill.FromReader(r, max, p)
	if errors.Is(err, spill.ErrTooLarge) {
		return nil, ErrTooLarge
	}
	return b, err
}

// truncReader turns a stream that ends early into one that merely ends.
//
// A decoder reports a truncated input as io.ErrUnexpectedEOF, and spill.FromReader
// rightly treats any error as "discard what was read". For a partial upload that
// discards the ninety-nine readable percent of a bundle on account of the one
// percent that is missing. Reporting EOF instead lets the reader keep the prefix,
// and the flag lets the caller say so.
type truncReader struct {
	r         io.Reader
	truncated bool
}

func (t *truncReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if errors.Is(err, io.ErrUnexpectedEOF) {
		t.truncated = true
		err = io.EOF
	}
	return n, err
}

// ---- tar ----

// TarMember is one entry of a tar archive. Body is nil for non-regular entries
// (directories, symlinks, hardlinks), which carry no payload.
type TarMember struct {
	Header *tar.Header
	Body   *spill.Blob
	// Truncated marks the final member of a tar whose input ended mid-body. Body
	// holds what was there; Header.Size still says how long it should have been,
	// and the writer honours that so the output ends where the input did.
	Truncated bool
}

// TarTail is what follows the last member a tar reader could parse: the bytes from
// the point the parse failed to the end of the input, carried across unread, and
// the error that stopped the parse. Nil when the archive read cleanly.
type TarTail struct {
	Raw *spill.Blob
	Err error
}

// ReadTar parses every entry of a tar stream, holding at most budget bytes of member
// bodies in total and at most maxMembers entries. Exceeding either returns
// ErrTooLarge / ErrTooManyMembers so the caller can pass the container through
// rather than exhausting memory.
//
// A malformed or truncated archive is not an error here. The members that could be
// read are returned, and what could not be is returned as the tail: a body cut short
// is kept as a Truncated member, a header that will not parse ends the walk with the
// remainder of the input in TarTail.Raw. The caller records the hole; nothing that
// was readable is thrown away on account of what was not.
//
// On a guard trip or a scratch failure every blob read so far is released, so a
// rejected archive leaves no temp files behind.
func ReadTar(r io.Reader, budget int64, maxMembers int, p spill.Policy) ([]TarMember, *TarTail, error) {
	tr := tar.NewReader(r)
	var members []TarMember
	remaining := budget
	fail := func(err error) ([]TarMember, *TarTail, error) {
		CloseTar(members)
		return nil, nil, err
	}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			// The reader has consumed the blocks it could not parse; what is left of
			// the input is carried across verbatim. Under the same budget: it lands
			// on scratch like any member body.
			raw, rerr := spillCapped(r, remaining, p)
			if rerr != nil {
				return fail(rerr)
			}
			return members, &TarTail{Raw: raw, Err: err}, nil
		}
		if maxMembers > 0 && len(members) >= maxMembers {
			return fail(ErrTooManyMembers)
		}
		var body *spill.Blob
		truncated := false
		if h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeRegA {
			t := &truncReader{r: tr}
			body, err = spillCapped(t, remaining, p)
			if err != nil {
				return fail(err)
			}
			remaining -= body.Size()
			truncated = t.truncated
		}
		hdr := *h // tar.Reader reuses its header struct
		members = append(members, TarMember{Header: &hdr, Body: body, Truncated: truncated})
		if truncated {
			// Nothing follows a body the input ran out in the middle of.
			return members, &TarTail{Err: io.ErrUnexpectedEOF}, nil
		}
	}
	return members, nil, nil
}

// CloseTar releases every member body. Callers defer it the moment ReadTar returns.
func CloseTar(members []TarMember) error {
	var first error
	for _, m := range members {
		if err := m.Body.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// WriteTarTo streams a tar archive to w, preserving headers and order.
//
// tar needs each entry's length in its header before the body, which is why Blob
// carries Size(): the member never has to be materialised to be repacked.
//
// A Truncated member is written with its ORIGINAL header size and whatever body it
// has, and nothing after it -- no padding, no end-of-archive blocks -- so the output
// stops exactly where the input did. A tail is appended after the last member's
// padding, again with no end-of-archive blocks, since the tail is whatever the input
// had there instead.
func WriteTarTo(w io.Writer, members []TarMember, tail *TarTail) error {
	tw := tar.NewWriter(w)
	for _, m := range members {
		h := *m.Header
		if m.Truncated {
			// Header says how long the body should have been; the bytes say how
			// long it is. Leave the writer unflushed: Close would either pad the
			// entry out to its declared size or complain that we did not.
			if err := tw.WriteHeader(&h); err != nil {
				return err
			}
			return copyBody(tw, m.Body)
		}
		if m.Header.Typeflag == tar.TypeReg || m.Header.Typeflag == tar.TypeRegA {
			h.Size = m.Body.Size()
		}
		if err := tw.WriteHeader(&h); err != nil {
			return err
		}
		if err := copyBody(tw, m.Body); err != nil {
			return err
		}
	}
	if tail != nil && tail.Raw != nil && tail.Raw.Size() > 0 {
		// Complete the last entry's padding, then hand the raw remainder through
		// untouched. No end-of-archive marker: the input did not have one here.
		if err := tw.Flush(); err != nil {
			return err
		}
		return copyBody(w, tail.Raw)
	}
	return tw.Close()
}

// copyBody streams one blob into w, scoped so a plain defer does not hold one open
// handle per member until the whole archive is written.
func copyBody(w io.Writer, b *spill.Blob) error {
	if b.Size() == 0 {
		return nil
	}
	rc, err := b.Reader()
	if err != nil {
		return err
	}
	defer rc.Close()
	_, err = io.Copy(w, rc)
	return err
}

// IsRegular reports whether a tar member is a regular file (eligible for scrub).
func (m TarMember) IsRegular() bool {
	return m.Header.Typeflag == tar.TypeReg || m.Header.Typeflag == tar.TypeRegA
}

// ---- zip ----

// ZipMember is one entry of a zip archive.
type ZipMember struct {
	Header *zip.FileHeader
	Body   *spill.Blob
	// Raw marks an entry whose body could not be decoded. Body then holds the entry
	// exactly as stored in the archive -- compressed, or encrypted -- so the repack
	// can carry it across byte for byte, and Err says what went wrong. Encrypted is
	// set from the general-purpose flag rather than from a failed inflate, because
	// the two call for different remedies.
	Raw       bool
	Encrypted bool
	Err       error
	// Changed is set by the caller when it has replaced Body with a rewritten
	// payload. WriteZipTo re-encodes only those; every other decodable member is
	// copied across in its stored form, which costs no deflate and reproduces the
	// original bytes exactly.
	Changed bool
	// index is the entry's position in the source archive, for the raw copy.
	index int
}

// ReadZip parses every entry of a zip archive, holding at most budget bytes of
// member bodies in total and at most maxMembers entries.
//
// The budget is what actually stops a zip bomb: each entry is deflate-compressed
// independently, so a few-KB archive can expand to many GB. Entries are read through
// a shrinking ceiling rather than with io.ReadAll.
//
// An entry that cannot be decoded is not an error. It is kept in its stored form,
// flagged Raw, and the rest of the archive is read normally; the caller records the
// hole and the repack carries the entry across unchanged. Only a guard trip or a
// scratch failure rejects the archive as a whole.
//
// zip needs random access because its central directory is at the end, hence
// io.ReaderAt rather than the io.Reader tar takes.
func ReadZip(ra io.ReaderAt, size, budget int64, maxMembers int, p spill.Policy) ([]ZipMember, error) {
	zr, err := zip.NewReader(ra, size)
	if err != nil {
		return nil, err
	}
	if maxMembers > 0 && len(zr.File) > maxMembers {
		return nil, ErrTooManyMembers
	}
	var members []ZipMember
	remaining := budget
	fail := func(err error) ([]ZipMember, error) {
		CloseZip(members)
		return nil, err
	}
	for i, f := range zr.File {
		hdr := f.FileHeader
		m := ZipMember{Header: &hdr, index: i}

		// The general-purpose flag's bit 0. Go's reader never checks it and would
		// inflate the ciphertext; ask for the stored bytes straight away.
		if f.Flags&0x1 != 0 {
			body, err := rawEntry(f, remaining, p)
			if err != nil {
				return fail(err)
			}
			m.Body, m.Raw, m.Encrypted, m.Err = body, true, true, ErrEncrypted
			remaining -= body.Size()
			members = append(members, m)
			continue
		}

		body, err := decodedEntry(f, remaining, p)
		if err != nil {
			if errors.Is(err, ErrTooLarge) || errors.Is(err, spill.ErrSpill) {
				return fail(err)
			}
			// Unsupported method, corrupt deflate, checksum mismatch: this entry is
			// carried across as stored. Everything else is still scrubbed.
			body, rerr := rawEntry(f, remaining, p)
			if rerr != nil {
				return fail(rerr)
			}
			m.Body, m.Raw, m.Err = body, true, err
			remaining -= body.Size()
			members = append(members, m)
			continue
		}
		m.Body = body
		remaining -= body.Size()
		members = append(members, m)
	}
	return members, nil
}

// decodedEntry inflates one entry under the budget.
func decodedEntry(f *zip.File, remaining int64, p spill.Policy) (*spill.Blob, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	body, err := spillCapped(rc, remaining, p)
	rc.Close()
	return body, err
}

// rawEntry captures one entry's stored bytes under the budget.
func rawEntry(f *zip.File, remaining int64, p spill.Policy) (*spill.Blob, error) {
	r, err := f.OpenRaw()
	if err != nil {
		return nil, err
	}
	return spillCapped(r, remaining, p)
}

// CloseZip releases every member body.
func CloseZip(members []ZipMember) error {
	var first error
	for _, m := range members {
		if err := m.Body.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// WriteZipTo streams a zip archive to w, preserving per-entry headers (name,
// compression method, modes, timestamps) and order.
//
// src is the archive the members came from. A member the caller did not change is
// copied from it in stored form -- no inflate, no deflate, and byte-identical to the
// original -- which is also how a Raw member travels. Only a Changed member is
// re-encoded, with the writer recomputing its size and CRC.
func WriteZipTo(w io.Writer, members []ZipMember, src io.ReaderAt, srcSize int64) error {
	zw := zip.NewWriter(w)
	var zr *zip.Reader // opened on first use; an archive of changed members never needs it
	for _, m := range members {
		h := *m.Header
		if m.Raw {
			// The header keeps the original CRC, sizes and flags -- including the
			// encryption bit, so a reader knows what it is looking at.
			fw, err := zw.CreateRaw(&h)
			if err != nil {
				return err
			}
			if err := copyBody(fw, m.Body); err != nil {
				return err
			}
			continue
		}
		if !m.Changed && src != nil {
			if zr == nil {
				var err error
				if zr, err = zip.NewReader(src, srcSize); err != nil {
					return err
				}
			}
			if m.index < len(zr.File) {
				r, err := zr.File[m.index].OpenRaw()
				if err != nil {
					return err
				}
				// h may carry a scrubbed name; the sizes and CRC are the entry's own.
				fw, err := zw.CreateRaw(&h)
				if err != nil {
					return err
				}
				if _, err := io.Copy(fw, r); err != nil {
					return err
				}
				continue
			}
		}
		// Let the writer recompute size/CRC for the (possibly changed) body.
		ew, err := zw.CreateHeader(&h)
		if err != nil {
			return err
		}
		if err := copyBody(ew, m.Body); err != nil {
			return err
		}
	}
	return zw.Close()
}

// IsDir reports whether a zip member is a directory entry.
func (m ZipMember) IsDir() bool { return m.Header.FileInfo().IsDir() }

// ---- single-stream compression wrappers ----

// Meta carries what must survive a decompress/recompress round-trip, and what the
// caller needs to know about how the decompression went.
//
// Gzip is the only format with header metadata: its original filename,
// modification time and comment would otherwise be lost on repack (a fidelity
// regression for a tool that promises to preserve form).
type Meta struct {
	Gzip *gzip.Header
	// Truncated reports that the stream ended before its encoder said it would.
	// The blob holds the prefix that did decode; the rest was not there to read.
	Truncated bool
}

// NewDecoder builds the decoding reader for f over r. The caller closes cl if
// non-nil. Exported for the residual scan, which looks inside content the pipeline
// declined to expand and needs the same decoders to do it; bzip2 is included
// because reading is all that scan does.
func NewDecoder(f detect.Format, r io.Reader) (dec io.Reader, cl io.Closer, err error) {
	dec, _, cl, err = decompressReader(f, r)
	return dec, cl, err
}

// decompressReader builds the decoding reader for f over r, plus any metadata that
// must survive the round-trip. The caller closes cl if non-nil.
func decompressReader(f detect.Format, r io.Reader) (dec io.Reader, meta *Meta, cl io.Closer, err error) {
	switch f {
	case detect.Gzip:
		zr, err := gzip.NewReader(r)
		if err != nil {
			return nil, nil, nil, err
		}
		// Capture the header before reading: for a multistream member the reader
		// advances to later members' headers as it consumes the body.
		hdr := zr.Header
		return zr, &Meta{Gzip: &hdr}, zr, nil
	case detect.Zlib:
		zr, err := zlib.NewReader(r)
		if err != nil {
			return nil, nil, nil, err
		}
		return zr, nil, zr, nil
	case detect.Bzip2:
		return bzip2.NewReader(r), nil, nil, nil
	case detect.Xz:
		xr, err := xz.NewReader(r)
		if err != nil {
			return nil, nil, nil, err
		}
		return xr, nil, nil, nil
	case detect.Zstd:
		zr, err := zstd.NewReader(r)
		if err != nil {
			return nil, nil, nil, err
		}
		rc := zr.IOReadCloser()
		return rc, nil, rc, nil
	default:
		return nil, nil, nil, errUnsupported
	}
}

// DecompressBlob expands a single-stream wrapper straight into a Blob, reading at
// most budget bytes and returning ErrTooLarge if the stream is larger. The
// decompressed container never has to be whole on the heap, which for a .tar.gz is
// one of the two copies that used to dominate resident memory.
//
// A stream that ends early is not an error: the prefix that decoded is returned and
// Meta.Truncated says so. A stream whose header will not parse still is.
func DecompressBlob(f detect.Format, in *spill.Blob, budget int64, p spill.Policy) (*spill.Blob, *Meta, error) {
	src, err := in.Reader()
	if err != nil {
		return nil, nil, err
	}
	defer src.Close()

	dec, meta, cl, err := decompressReader(f, src)
	if err != nil {
		return nil, nil, err
	}
	if cl != nil {
		defer cl.Close()
	}
	t := &truncReader{r: dec}
	out, err := spillCapped(t, budget, p)
	if err != nil {
		return nil, nil, err
	}
	if t.truncated {
		if meta == nil {
			meta = &Meta{}
		}
		meta.Truncated = true
	}
	return out, meta, nil
}

// CanWrite reports whether this build can re-encode f. Formats we can read but
// not write must not be descended into at all: the pipeline would decompress,
// scrub, then have to throw the result away, wasting the work and — worse —
// leaving the discarded matches counted as if they had been applied.
func CanWrite(f detect.Format) bool {
	switch f {
	case detect.Gzip, detect.Zlib, detect.Xz, detect.Zstd:
		return true
	default:
		return false
	}
}

// compressWriter builds the encoding writer for f over w, restoring metadata.
func compressWriter(f detect.Format, w io.Writer, meta *Meta) (io.WriteCloser, error) {
	switch f {
	case detect.Gzip:
		zw := gzip.NewWriter(w)
		if meta != nil && meta.Gzip != nil {
			// Preserve the original filename / mtime / comment. Extra is dropped:
			// it can encode reader-specific state that need not survive a rewrite.
			zw.Name = meta.Gzip.Name
			zw.Comment = meta.Gzip.Comment
			zw.ModTime = meta.Gzip.ModTime
			zw.OS = meta.Gzip.OS
		}
		return zw, nil
	case detect.Zlib:
		return zlib.NewWriter(w), nil
	case detect.Xz:
		return xz.NewWriter(w)
	case detect.Zstd:
		return zstd.NewWriter(w)
	default:
		// Gated by CanWrite in the pipeline; bzip2 lands here only if that gate
		// is bypassed.
		return nil, errUnsupported
	}
}

// CompressTo streams data from in, re-wrapped in f, to w.
func CompressTo(w io.Writer, f detect.Format, in *spill.Blob, meta *Meta) error {
	cw, err := compressWriter(f, w, meta)
	if err != nil {
		return err
	}
	rc, err := in.Reader()
	if err != nil {
		return err
	}
	defer rc.Close()
	if _, err := io.Copy(cw, rc); err != nil {
		cw.Close()
		return err
	}
	return cw.Close()
}
