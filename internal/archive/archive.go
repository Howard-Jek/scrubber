// Package archive provides stateless unpack/repack helpers for each supported
// container and compression format. It contains no recursion and no scrubbing
// logic; the pipeline package drives it. Metadata (names, modes, times, methods,
// symlinks, ordering) is preserved so a repacked bundle matches its original form.
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

// ---- tar ----

// TarMember is one entry of a tar archive.
type TarMember struct {
	Header *tar.Header
	Body   []byte
}

// ReadTar parses every entry of a tar stream.
func ReadTar(data []byte) ([]TarMember, error) {
	tr := tar.NewReader(bytes.NewReader(data))
	var members []TarMember
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		var body []byte
		if h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeRegA {
			body, err = io.ReadAll(tr)
			if err != nil {
				return nil, err
			}
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

// ReadZip parses every entry of a zip archive.
func ReadZip(data []byte) ([]ZipMember, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	var members []ZipMember
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, err
		}
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

// Decompress expands a single-stream compression wrapper.
func Decompress(f detect.Format, data []byte) ([]byte, error) {
	switch f {
	case detect.Gzip:
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		return io.ReadAll(zr)
	case detect.Zlib:
		zr, err := zlib.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		return io.ReadAll(zr)
	case detect.Bzip2:
		return io.ReadAll(bzip2.NewReader(bytes.NewReader(data)))
	case detect.Xz:
		xr, err := xz.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		return io.ReadAll(xr)
	case detect.Zstd:
		zr, err := zstd.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		return io.ReadAll(zr)
	default:
		return nil, errUnsupported
	}
}

// Compress re-wraps data in the given single-stream format. Returns
// ErrNoWriter for formats we can read but not write (bzip2 in this build).
func Compress(f detect.Format, data []byte) ([]byte, error) {
	var buf bytes.Buffer
	switch f {
	case detect.Gzip:
		w := gzip.NewWriter(&buf)
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
