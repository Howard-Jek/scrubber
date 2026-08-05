// Package textenc decides whether a payload is text, in which encoding, and converts
// it to and from Go's UTF-8 strings.
//
// It exists because the scrubber used to call anything containing a NUL byte binary
// and pass it through unscrubbed. UTF-16 text is more than half NUL bytes — ASCII 'A'
// is the two bytes 41 00 — so every UTF-16 file tripped that on byte two. On Windows
// that is not an exotic case: PowerShell's `>` and Out-File, and Notepad's "Save as
// Unicode", all write UTF-16LE by default, so an ordinary .txt log was silently
// emitted with every address and hostname still in it.
//
// The contract that makes rewriting safe: for any payload Decode accepts,
// Encode(Decode(payload)) reproduces it byte for byte. A rewritten file therefore
// differs from its input only where a match was replaced. Anything that would break
// that — an odd length, an unpaired surrogate, a decode that turns out to be control
// characters rather than text — is refused, and the caller passes it through as
// before. Refusing is always available; corrupting is not.
package textenc

import (
	"bytes"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Encoding is how a text payload is laid out in bytes.
type Encoding int

const (
	// Binary is not text and must be passed through untouched.
	Binary Encoding = iota
	// UTF8 covers ASCII and UTF-8, with or without a BOM. It is the identity case:
	// Decode and Encode do not alter the bytes at all.
	UTF8
	UTF16LE
	UTF16BE
)

func (e Encoding) String() string {
	switch e {
	case UTF8:
		return "utf-8"
	case UTF16LE:
		return "utf-16le"
	case UTF16BE:
		return "utf-16be"
	default:
		return "binary"
	}
}

var (
	bomUTF8    = []byte{0xef, 0xbb, 0xbf}
	bomUTF16BE = []byte{0xfe, 0xff}
	bomUTF16LE = []byte{0xff, 0xfe}
	bomUTF32LE = []byte{0xff, 0xfe, 0x00, 0x00}
	bomUTF32BE = []byte{0x00, 0x00, 0xfe, 0xff}
)

const (
	// minUTF16Sniff is the smallest sample the BOM-less heuristic will judge. Below
	// it the NUL distribution is noise, and a wrong guess there costs a scrub.
	minUTF16Sniff = 16
	// utf16NULShare is the share of code units whose high byte must be NUL before a
	// BOM-less payload is called UTF-16, as a percentage. Latin-script text sits
	// near 100; the threshold is low enough to tolerate accented and symbol
	// characters mixed in.
	utf16NULShare = 30
	// utf16NULSkew is how many times more NULs the candidate byte position must
	// carry than the other one. Real UTF-16LE text has them almost exclusively in
	// the high byte; a payload where both positions are NUL-heavy is not text.
	utf16NULSkew = 8
	// ctrlSharePercent is the share of control characters above which content is
	// judged binary rather than text.
	ctrlSharePercent = 10
)

// Sniff classifies a leading sample of a payload.
//
// It only ever proposes: a UTF-16 answer is confirmed by Decode over the whole
// payload, so a sample that looks like UTF-16 for 8KiB and turns malformed later
// costs nothing. Anything not confidently UTF-16 that today reads as text still
// returns UTF8, which keeps the working path exactly as it was.
func Sniff(sample []byte) Encoding {
	if len(sample) == 0 {
		return UTF8 // nothing to scrub; scrubbing it is a no-op, not a risk
	}
	// UTF-32LE begins FF FE 00 00, which is also a UTF-16LE BOM. Check the longer
	// signature first so a UTF-32 file is reported as unsupported rather than
	// quietly mislabelled as UTF-16 we then fail to find anything in.
	if bytes.HasPrefix(sample, bomUTF32LE) || bytes.HasPrefix(sample, bomUTF32BE) {
		return Binary
	}
	if bytes.HasPrefix(sample, bomUTF16LE) {
		return UTF16LE
	}
	if bytes.HasPrefix(sample, bomUTF16BE) {
		return UTF16BE
	}
	if enc, ok := sniffUTF16NoBOM(sample); ok {
		return enc
	}
	if looksBinary(sample) {
		return Binary
	}
	return UTF8
}

// sniffUTF16NoBOM recognises UTF-16 without a byte-order mark, which is what most
// non-Windows tooling writes.
//
// Latin-script text in UTF-16 puts a NUL in the high byte of nearly every code unit
// and almost never in the low byte, so the NUL distribution across even and odd byte
// positions gives the encoding and the byte order together.
func sniffUTF16NoBOM(sample []byte) (Encoding, bool) {
	n := len(sample) &^ 1 // a truncated trailing byte tells us nothing
	if n < minUTF16Sniff {
		return Binary, false
	}
	var evenNUL, oddNUL int
	for i := 0; i < n; i += 2 {
		if sample[i] == 0 {
			evenNUL++
		}
		if sample[i+1] == 0 {
			oddNUL++
		}
	}
	units := n / 2
	switch {
	case oddNUL*100 >= units*utf16NULShare && oddNUL >= evenNUL*utf16NULSkew:
		return UTF16LE, true
	case evenNUL*100 >= units*utf16NULShare && evenNUL >= oddNUL*utf16NULSkew:
		return UTF16BE, true
	}
	return Binary, false
}

// Refusal says why Decode would not hand back text. The distinction matters
// downstream: "well-formed but not text" is an ordinary binary file and should be
// reported as one, while "not well-formed in this encoding" is a genuine encoding
// problem an operator may want to chase. Collapsing them would put PNGs in the same
// bucket as truncated UTF-16 and make the reason codes useless for triage.
type Refusal int

const (
	RefusalNone      Refusal = iota // the payload decoded and is text
	RefusalMalformed                // not well-formed in this encoding
	RefusalNotText                  // decoded cleanly, but the result is control characters
)

// Decode converts a payload to a Go string, reporting whether it really is enc.
//
// UTF8 is the identity case and is never re-examined: Sniff already judged the
// sample, and inspecting the whole payload here would newly skip files that are text
// at the front and binary further in — a behaviour change to the path that works.
//
// UTF-16 is checked twice over, because accepting it means rewriting it. The byte
// sequence must be well formed, and the text it decodes to must actually read as
// text: a binary payload with NULs on alternating bytes can decode cleanly into
// control-character soup, and scrubbing a match out of that would corrupt a file the
// tool was supposed to leave alone.
func Decode(data []byte, enc Encoding) (string, Refusal) {
	switch enc {
	case UTF8:
		return string(data), RefusalNone
	case UTF16LE, UTF16BE:
		s, ok := decodeUTF16(data, enc == UTF16BE)
		if !ok {
			return "", RefusalMalformed
		}
		if looksBinaryText(s) {
			// Binary with NULs on alternating bytes decodes as well-formed UTF-16 and
			// then turns out to be control characters. It is a binary file that
			// happened to fit the shape, not text we failed to handle.
			return "", RefusalNotText
		}
		return s, RefusalNone
	default:
		return "", RefusalNotText
	}
}

// Encode renders text back in enc.
//
// A byte-order mark needs no special handling: it decodes to U+FEFF like any other
// character and encodes back to the same two bytes, so it survives a round trip
// without being tracked separately.
func Encode(text string, enc Encoding) []byte {
	switch enc {
	case UTF16LE, UTF16BE:
		units := utf16.Encode([]rune(text))
		out := make([]byte, 2*len(units))
		be := enc == UTF16BE
		for i, u := range units {
			putUnit(out[2*i:], u, be)
		}
		return out
	default:
		return []byte(text)
	}
}

func unit(b []byte, i int, be bool) uint16 {
	if be {
		return uint16(b[i])<<8 | uint16(b[i+1])
	}
	return uint16(b[i+1])<<8 | uint16(b[i])
}

func putUnit(b []byte, u uint16, be bool) {
	if be {
		b[0], b[1] = byte(u>>8), byte(u)
		return
	}
	b[0], b[1] = byte(u), byte(u>>8)
}

// decodeUTF16 refuses malformed input rather than repairing it.
//
// utf16.Decode substitutes U+FFFD for an unpaired surrogate, which would silently
// rewrite bytes we were only meant to read past. Returning false instead means the
// caller passes the payload through untouched, and everything we do accept re-encodes
// to exactly the bytes it came from.
func decodeUTF16(data []byte, be bool) (string, bool) {
	if len(data)%2 != 0 {
		return "", false
	}
	var b strings.Builder
	b.Grow(len(data)/2 + utf8.UTFMax)
	for i := 0; i < len(data); i += 2 {
		u := unit(data, i, be)
		switch {
		case u < 0xd800 || u > 0xdfff:
			b.WriteRune(rune(u))
		case u >= 0xdc00:
			return "", false // a low surrogate with no high surrogate before it
		case i+3 >= len(data):
			return "", false // a high surrogate at the very end
		default:
			lo := unit(data, i+2, be)
			if lo < 0xdc00 || lo > 0xdfff {
				return "", false // a high surrogate not followed by a low one
			}
			b.WriteRune(utf16.DecodeRune(rune(u), rune(lo)))
			i += 2
		}
	}
	return b.String(), true
}

// looksBinary judges raw bytes. A NUL is a strong binary signal; otherwise the sample
// must be decodable as UTF-8 (after a BOM) to be treated as text.
//
// This is reached only once the UTF-16 possibilities are exhausted, so a NUL here
// really does mean binary.
func looksBinary(sample []byte) bool {
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
	// Not valid UTF-8: many control bytes means binary. Latin-1 and other single-byte
	// encodings land here and are treated as text, which is intended — they scrub
	// correctly because the bytes pass through the matcher unchanged.
	var ctrl int
	for _, b := range sample {
		if b < 0x09 || (b > 0x0d && b < 0x20) {
			ctrl++
		}
	}
	return ctrl*100/len(sample) > ctrlSharePercent
}

// looksBinaryText judges already-decoded text, which is valid UTF-8 by construction
// and so cannot be judged by the byte heuristic above. It is the guard that stops a
// binary payload which happens to decode as well-formed UTF-16 from being rewritten.
func looksBinaryText(s string) bool {
	if s == "" {
		return false
	}
	var ctrl, total int
	for _, r := range s {
		total++
		if r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			ctrl++
		}
	}
	return ctrl*100/total > ctrlSharePercent
}

func stripBOM(b []byte) []byte {
	switch {
	case bytes.HasPrefix(b, bomUTF8):
		return b[3:]
	case bytes.HasPrefix(b, bomUTF16BE), bytes.HasPrefix(b, bomUTF16LE):
		return b[2:]
	}
	return b
}
