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
// the bundle size; now only the member being scrubbed is materialised. The byte
// slice forms of the read/write helpers are kept as thin wrappers because the CLI
// works on whole files and has no reason to care.
package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
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

// readCapped copies from r into a fresh buffer, reading at most max bytes. It
// returns ErrTooLarge as soon as the stream exceeds max, having buffered no more
// than max+1 bytes — the memory bound holds regardless of the compression ratio.
func readCapped(r io.Reader, max int64) ([]byte, error) {
	if max <= 0 {
		return nil, ErrTooLarge
	}
	var buf bytes.Buffer
	n, err := io.CopyN(&buf, r, max+1)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if n > max {
		return nil, ErrTooLarge
	}
	return buf.Bytes(), nil
}

// spillCapped is readCapped's blob-backed twin: identical budget semantics, but the
// payload may land on disk. spill.ErrTooLarge is translated to this package's
// ErrTooLarge so callers keep classifying guard trips the way they always have.
func spillCapped(r io.Reader, max int64, p spill.Policy) (*spill.Blob, error) {
	b, err := spill.FromReader(r, max, p)
	if errors.Is(err, spill.ErrTooLarge) {
		return nil, ErrTooLarge
	}
	return b, err
}

// ---- tar ----

// TarMember is one entry of a tar archive. Body is nil for non-regular entries
// (directories, symlinks, hardlinks), which carry no payload.
type TarMember struct {
	Header *tar.Header
	Body   *spill.Blob
}

// ReadTar parses every entry of a tar stream, holding at most budget bytes of member
// bodies in total and at most maxMembers entries. Exceeding either returns
// ErrTooLarge / ErrTooManyMembers so the caller can pass the container through
// rather than exhausting memory.
//
// On any error every blob read so far is released, so a rejected archive leaves no
// temp files behind.
func ReadTar(r io.Reader, budget int64, maxMembers int, p spill.Policy) ([]TarMember, error) {
	tr := tar.NewReader(r)
	var members []TarMember
	remaining := budget
	fail := func(err error) ([]TarMember, error) {
		CloseTar(members)
		return nil, err
	}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fail(err)
		}
		if maxMembers > 0 && len(members) >= maxMembers {
			return fail(ErrTooManyMembers)
		}
		var body *spill.Blob
		if h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeRegA {
			body, err = spillCapped(tr, remaining, p)
			if err != nil {
				return fail(err)
			}
			remaining -= body.Size()
		}
		hdr := *h // tar.Reader reuses its header struct
		members = append(members, TarMember{Header: &hdr, Body: body})
	}
	return members, nil
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
func WriteTarTo(w io.Writer, members []TarMember) error {
	tw := tar.NewWriter(w)
	for _, m := range members {
		h := *m.Header
		if m.Header.Typeflag == tar.TypeReg || m.Header.Typeflag == tar.TypeRegA {
			h.Size = m.Body.Size()
		}
		if err := tw.WriteHeader(&h); err != nil {
			return err
		}
		if m.Body.Size() > 0 {
			rc, err := m.Body.Reader()
			if err != nil {
				return err
			}
			_, err = io.Copy(tw, rc)
			rc.Close()
			if err != nil {
				return err
			}
		}
	}
	return tw.Close()
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
}

// ReadZip parses every entry of a zip archive, holding at most budget bytes of
// member bodies in total and at most maxMembers entries.
//
// The budget is what actually stops a zip bomb: each entry is deflate-compressed
// independently, so a few-KB archive can expand to many GB. Entries are read through
// a shrinking ceiling rather than with io.ReadAll.
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
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			return fail(err)
		}
		body, err := spillCapped(rc, remaining, p)
		rc.Close()
		if err != nil {
			return fail(err)
		}
		remaining -= body.Size()
		hdr := f.FileHeader
		members = append(members, ZipMember{Header: &hdr, Body: body})
	}
	return members, nil
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
func WriteZipTo(w io.Writer, members []ZipMember) error {
	zw := zip.NewWriter(w)
	for _, m := range members {
		h := *m.Header
		// Let the writer recompute size/CRC for the (possibly changed) body.
		ew, err := zw.CreateHeader(&h)
		if err != nil {
			return err
		}
		if m.Body.Size() > 0 {
			rc, err := m.Body.Reader()
			if err != nil {
				return err
			}
			_, err = io.Copy(ew, rc)
			rc.Close()
			if err != nil {
				return err
			}
		}
	}
	return zw.Close()
}

// IsDir reports whether a zip member is a directory entry.
func (m ZipMember) IsDir() bool { return m.Header.FileInfo().IsDir() }

// ---- single-stream compression wrappers ----

// Meta carries format-specific metadata that must survive a decompress/recompress
// round-trip. Only gzip currently has any: its header records the original
// filename, modification time and comment, which would otherwise be lost on
// repack (a fidelity regression for a tool that promises to preserve form).
type Meta struct {
	Gzip *gzip.Header
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
	out, err := spillCapped(dec, budget, p)
	if err != nil {
		return nil, nil, err
	}
	return out, meta, nil
}

// Decompress is the byte-slice form, used by the CLI.
func Decompress(f detect.Format, data []byte, budget int64) ([]byte, *Meta, error) {
	dec, meta, cl, err := decompressReader(f, bytes.NewReader(data))
	if err != nil {
		return nil, nil, err
	}
	if cl != nil {
		defer cl.Close()
	}
	out, err := readCapped(dec, budget)
	if err != nil {
		return nil, nil, err
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
	case detect.Bzip2:
		return nil, ErrNoWriter
	default:
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

// Compress is the byte-slice form, used by the CLI. Returns ErrNoWriter for formats
// we can read but not write (bzip2 in this build).
func Compress(f detect.Format, data []byte, meta *Meta) ([]byte, error) {
	var buf bytes.Buffer
	cw, err := compressWriter(f, &buf, meta)
	if err != nil {
		return nil, err
	}
	if _, err := cw.Write(data); err != nil {
		cw.Close()
		return nil, err
	}
	if err := cw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
