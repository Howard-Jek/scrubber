// Package archive provides stateless unpack/repack helpers for each supported
// container and compression format. It contains no recursion and no scrubbing
// logic; the pipeline package drives it. Metadata (names, modes, times, methods,
// symlinks, ordering) is preserved so a repacked bundle matches its original form.
//
// Every read path takes an explicit byte budget and enforces it *while* reading,
// so a decompression bomb is stopped by a hard memory ceiling rather than by an
// expansion-ratio heuristic. Ratio heuristics cannot distinguish a bomb from an
// ordinary log file (real logs routinely exceed 200:1), so they are not used here.
package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"compress/zlib"
	"io"

	"github.com/howard/scrubber/internal/detect"
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

// ---- tar ----

// TarMember is one entry of a tar archive.
type TarMember struct {
	Header *tar.Header
	Body   []byte
}

// ReadTar parses every entry of a tar stream, holding at most budget bytes of
// member bodies in total and at most maxMembers entries. Exceeding either returns
// ErrTooLarge / ErrTooManyMembers so the caller can pass the container through
// rather than exhausting memory.
func ReadTar(data []byte, budget int64, maxMembers int) ([]TarMember, error) {
	tr := tar.NewReader(bytes.NewReader(data))
	var members []TarMember
	remaining := budget
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if maxMembers > 0 && len(members) >= maxMembers {
			return nil, ErrTooManyMembers
		}
		var body []byte
		if h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeRegA {
			body, err = readCapped(tr, remaining)
			if err != nil {
				return nil, err
			}
			remaining -= int64(len(body))
		}
		hdr := *h
		members = append(members, TarMember{Header: &hdr, Body: body})
	}
	return members, nil
}

// WriteTar rebuilds a tar stream from members, preserving headers and order.
func WriteTar(members []TarMember) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, m := range members {
		h := *m.Header
		if m.Header.Typeflag == tar.TypeReg || m.Header.Typeflag == tar.TypeRegA {
			h.Size = int64(len(m.Body))
		}
		if err := tw.WriteHeader(&h); err != nil {
			return nil, err
		}
		if len(m.Body) > 0 {
			if _, err := tw.Write(m.Body); err != nil {
				return nil, err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// IsRegular reports whether a tar member is a regular file (eligible for scrub).
func (m TarMember) IsRegular() bool {
	return m.Header.Typeflag == tar.TypeReg || m.Header.Typeflag == tar.TypeRegA
}

// ---- zip ----

// ZipMember is one entry of a zip archive.
type ZipMember struct {
	Header *zip.FileHeader
	Body   []byte
}

// ReadZip parses every entry of a zip archive, holding at most budget bytes of
// member bodies in total and at most maxMembers entries.
//
// The budget is what actually stops a zip bomb: each entry is deflate-compressed
// independently, so a few-KB archive can expand to many GB. Entries are read
// through a shrinking ceiling rather than with io.ReadAll.
func ReadZip(data []byte, budget int64, maxMembers int) ([]ZipMember, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	if maxMembers > 0 && len(zr.File) > maxMembers {
		return nil, ErrTooManyMembers
	}
	var members []ZipMember
	remaining := budget
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		body, err := readCapped(rc, remaining)
		rc.Close()
		if err != nil {
			return nil, err
		}
		remaining -= int64(len(body))
		hdr := f.FileHeader
		members = append(members, ZipMember{Header: &hdr, Body: body})
	}
	return members, nil
}

// WriteZip rebuilds a zip archive from members, preserving per-entry headers
// (name, compression method, modes, timestamps) and order.
func WriteZip(members []ZipMember) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, m := range members {
		h := *m.Header
		// Let the writer recompute size/CRC for the (possibly changed) body.
		w, err := zw.CreateHeader(&h)
		if err != nil {
			return nil, err
		}
		if len(m.Body) > 0 {
			if _, err := w.Write(m.Body); err != nil {
				return nil, err
			}
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
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

// Decompress expands a single-stream compression wrapper, reading at most budget
// bytes and returning ErrTooLarge if the stream is larger. It also returns any
// format metadata needed to rebuild an equivalent stream.
func Decompress(f detect.Format, data []byte, budget int64) ([]byte, *Meta, error) {
	switch f {
	case detect.Gzip:
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, nil, err
		}
		defer zr.Close()
		// Capture the header before reading: for a multistream member the reader
		// advances to later members' headers as it consumes the body.
		hdr := zr.Header
		out, err := readCapped(zr, budget)
		if err != nil {
			return nil, nil, err
		}
		return out, &Meta{Gzip: &hdr}, nil
	case detect.Zlib:
		zr, err := zlib.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, nil, err
		}
		defer zr.Close()
		out, err := readCapped(zr, budget)
		return out, nil, err
	case detect.Bzip2:
		out, err := readCapped(bzip2.NewReader(bytes.NewReader(data)), budget)
		return out, nil, err
	case detect.Xz:
		xr, err := xz.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, nil, err
		}
		out, err := readCapped(xr, budget)
		return out, nil, err
	case detect.Zstd:
		zr, err := zstd.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, nil, err
		}
		defer zr.Close()
		out, err := readCapped(zr.IOReadCloser(), budget)
		return out, nil, err
	default:
		return nil, nil, errUnsupported
	}
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

// Compress re-wraps data in the given single-stream format, restoring any
// metadata captured by Decompress. Returns ErrNoWriter for formats we can read
// but not write (bzip2 in this build).
func Compress(f detect.Format, data []byte, meta *Meta) ([]byte, error) {
	var buf bytes.Buffer
	switch f {
	case detect.Gzip:
		w := gzip.NewWriter(&buf)
		if meta != nil && meta.Gzip != nil {
			// Preserve the original filename / mtime / comment. Extra is dropped:
			// it can encode reader-specific state that need not survive a rewrite.
			w.Name = meta.Gzip.Name
			w.Comment = meta.Gzip.Comment
			w.ModTime = meta.Gzip.ModTime
			w.OS = meta.Gzip.OS
		}
		if _, err := w.Write(data); err != nil {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
	case detect.Zlib:
		w := zlib.NewWriter(&buf)
		if _, err := w.Write(data); err != nil {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
	case detect.Xz:
		w, err := xz.NewWriter(&buf)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(data); err != nil {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
	case detect.Zstd:
		w, err := zstd.NewWriter(&buf)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(data); err != nil {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
	case detect.Bzip2:
		return nil, ErrNoWriter
	default:
		return nil, errUnsupported
	}
	return buf.Bytes(), nil
}
