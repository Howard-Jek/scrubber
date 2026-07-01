// Package detect identifies archive/compression formats by content (magic bytes)
// rather than by file extension, and distinguishes text from binary leaf files.
package detect

import (
	"bytes"
	"encoding/binary"
	"unicode/utf8"
)

// Format enumerates the container/compression formats the scrubber recognizes.
type Format int

const (
	Unknown Format = iota
	Zip
	Tar
	Gzip
	Bzip2
	Xz
	Zstd
	Zlib
	SevenZip
	Rar
)

func (f Format) String() string {
	switch f {
	case Zip:
		return "zip"
	case Tar:
		return "tar"
	case Gzip:
		return "gzip"
	case Bzip2:
		return "bzip2"
	case Xz:
		return "xz"
	case Zstd:
		return "zstd"
	case Zlib:
		return "zlib"
	case SevenZip:
		return "7z"
	case Rar:
		return "rar"
	default:
		return "unknown"
	}
}

// magic byte signatures for the formats whose header is a fixed prefix.
var (
	sigZip      = []byte{'P', 'K', 0x03, 0x04}
	sigZipEmpty = []byte{'P', 'K', 0x05, 0x06} // empty archive
	sigGzip     = []byte{0x1f, 0x8b}
	sigBzip2    = []byte{'B', 'Z', 'h'}
	sigXz       = []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}
	sigZstd     = []byte{0x28, 0xb5, 0x2f, 0xfd}
	sig7z       = []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}
	sigRar4     = []byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x00}
	sigRar5     = []byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x01, 0x00}
)

// DetectFormat inspects a leading slice of a stream and returns the recognized
// container/compression format, or Unknown for a plain (leaf) file.
//
// header should contain at least the first 512 bytes when available so that the
// tar checksum heuristic can run; fewer bytes are tolerated.
func DetectFormat(header []byte) Format {
	switch {
	case bytes.HasPrefix(header, sigZip), bytes.HasPrefix(header, sigZipEmpty):
		return Zip
	case bytes.HasPrefix(header, sigGzip):
		return Gzip
	case bytes.HasPrefix(header, sigBzip2):
		return Bzip2
	case bytes.HasPrefix(header, sigXz):
		return Xz
	case bytes.HasPrefix(header, sigZstd):
		return Zstd
	case bytes.HasPrefix(header, sig7z):
		return SevenZip
	case bytes.HasPrefix(header, sigRar5), bytes.HasPrefix(header, sigRar4):
		return Rar
	case isZlib(header):
		return Zlib
	case isTar(header):
		return Tar
	default:
		return Unknown
	}
}

// isZlib recognizes a raw zlib stream by its 2-byte header (CMF/FLG): the low
// nibble of the first byte is 8 (deflate) and (CMF*256+FLG) is a multiple of 31.
func isZlib(header []byte) bool {
	if len(header) < 2 {
		return false
	}
	cmf := header[0]
	if cmf&0x0f != 0x08 { // compression method must be deflate
		return false
	}
	return binary.BigEndian.Uint16(header[:2])%31 == 0
}

// isTar checks the POSIX tar magic and validates the header checksum, which is a
// reliable way to recognize tar (which has no leading magic bytes).
func isTar(header []byte) bool {
	if len(header) < 512 {
		return false
	}
	// "ustar" magic lives at offset 257.
	magic := header[257:262]
	if !bytes.Equal(magic, []byte("ustar")) {
		return false
	}
	return validTarChecksum(header[:512])
}

func validTarChecksum(block []byte) bool {
	// Stored checksum is an octal string in bytes 148..156.
	stored := parseOctal(block[148:156])
	if stored < 0 {
		return false
	}
	// Compute checksum treating the checksum field itself as spaces.
	var unsigned int64
	for i, b := range block {
		if i >= 148 && i < 156 {
			b = ' '
		}
		unsigned += int64(b)
	}
	return unsigned == stored
}

func parseOctal(b []byte) int64 {
	var n int64
	seen := false
	for _, c := range b {
		if c == 0 || c == ' ' {
			if seen {
				break
			}
			continue
		}
		if c < '0' || c > '7' {
			return -1
		}
		seen = true
		n = n*8 + int64(c-'0')
	}
	if !seen {
		return -1
	}
	return n
}

// IsBinary reports whether a sample of file content looks like binary data and
// should therefore be passed through untouched rather than scrubbed as text.
//
// Heuristic: a NUL byte is a strong binary signal; otherwise the sample must be
// decodable as valid UTF-8 (after stripping a leading BOM) to be treated as text.
// Empty content is treated as text (nothing to scrub, safe to pass through scrub).
func IsBinary(sample []byte) bool {
	if len(sample) == 0 {
		return false
	}
	sample = stripBOM(sample)
	if bytes.IndexByte(sample, 0x00) >= 0 {
		return true
	}
	// Trim a possibly truncated final rune before validating UTF-8.
	trimmed := sample
	for len(trimmed) > 0 && !utf8.Valid(trimmed) {
		if utf8.Valid(trimmed[:len(trimmed)-1]) || len(trimmed) == 1 {
			break
		}
		trimmed = trimmed[:len(trimmed)-1]
	}
	if utf8.Valid(trimmed) {
		return false
	}
	// Not valid UTF-8: count control bytes; many => binary.
	var ctrl int
	for _, b := range sample {
		if b < 0x09 || (b > 0x0d && b < 0x20) {
			ctrl++
		}
	}
	return ctrl*100/len(sample) > 10
}

var (
	bomUTF8    = []byte{0xef, 0xbb, 0xbf}
	bomUTF16BE = []byte{0xfe, 0xff}
	bomUTF16LE = []byte{0xff, 0xfe}
)

func stripBOM(b []byte) []byte {
	switch {
	case bytes.HasPrefix(b, bomUTF8):
		return b[3:]
	case bytes.HasPrefix(b, bomUTF16BE), bytes.HasPrefix(b, bomUTF16LE):
		return b[2:]
	}
	return b
}
