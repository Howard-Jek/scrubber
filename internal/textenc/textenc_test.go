package textenc

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf16"
)

// utf16Bytes encodes s the way a real tool would, so the fixtures below are the
// files people actually produce rather than hand-built byte strings.
func utf16Bytes(t testing.TB, s string, be, bom bool) []byte {
	t.Helper()
	if bom {
		s = "\ufeff" + s
	}
	units := utf16.Encode([]rune(s))
	out := make([]byte, 2*len(units))
	for i, u := range units {
		putUnit(out[2*i:], u, be)
	}
	return out
}

const logLine = "2026-06-12T09:00:00Z INFO user bob@acme.test from 10.1.2.3 org=AcmeCorp\n"

func TestSniff(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want Encoding
	}{
		{"empty", nil, UTF8},
		{"ascii", []byte(logLine), UTF8},
		{"utf-8 with BOM", append([]byte("\xef\xbb\xbf"), logLine...), UTF8},
		{"utf-8 accented", []byte("café résumé naïve\n"), UTF8},
		{"latin-1", []byte("caf\xe9 r\xe9sum\xe9\n"), UTF8},

		// The reported bug: what PowerShell's `>` and Notepad's "Unicode" write.
		{"utf-16le with BOM", utf16Bytes(t, strings.Repeat(logLine, 4), false, true), UTF16LE},
		{"utf-16le no BOM", utf16Bytes(t, strings.Repeat(logLine, 4), false, false), UTF16LE},
		{"utf-16be with BOM", utf16Bytes(t, strings.Repeat(logLine, 4), true, true), UTF16BE},
		{"utf-16be no BOM", utf16Bytes(t, strings.Repeat(logLine, 4), true, false), UTF16BE},

		// UTF-32LE opens with FF FE 00 00, which is also a UTF-16LE BOM. Reporting it
		// as binary is honest; calling it UTF-16 would mean scrubbing nothing and
		// claiming the file was inspected.
		{"utf-32le", append([]byte{0xff, 0xfe, 0x00, 0x00}, 'a', 0, 0, 0), Binary},
		{"utf-32be", append([]byte{0x00, 0x00, 0xfe, 0xff}, 0, 0, 0, 'a'), Binary},

		{"png header", []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x01\x00"), Binary},

		// Below minUTF16Sniff there is not enough evidence to call a NUL distribution
		// UTF-16, so the NUL wins and the payload is binary — the same answer as
		// before this package existed. A file this small has nothing worth redacting,
		// and guessing an encoding from four bytes is how you corrupt one.
		{"utf-16 too short to judge, no BOM", []byte{'h', 0, 'i', 0}, Binary},
		{"utf-16 too short but BOM is decisive", []byte{0xff, 0xfe, 'h', 0, 'i', 0}, UTF16LE},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Sniff(tc.data); got != tc.want {
				t.Errorf("Sniff = %v, want %v", got, tc.want)
			}
		})
	}
}

// The whole point of the change: the same text in three encodings must reach the
// matcher as the same string.
func TestDecodeYieldsIdenticalText(t *testing.T) {
	want := strings.Repeat(logLine, 4)
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"utf-8", []byte(want)},
		{"utf-16le+bom", utf16Bytes(t, want, false, true)},
		{"utf-16be+bom", utf16Bytes(t, want, true, true)},
		{"utf-16le", utf16Bytes(t, want, false, false)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Decode(tc.data, Sniff(tc.data))
			if !ok {
				t.Fatal("Decode refused a well-formed payload")
			}
			// A BOM decodes to U+FEFF and is preserved; strip it for the comparison.
			if got = strings.TrimPrefix(got, "\ufeff"); got != want {
				t.Errorf("decoded text differs\n got %q\nwant %q", got[:60], want[:60])
			}
		})
	}
}

// The invariant the rewrite rests on. If this ever fails, a scrubbed UTF-16 file
// differs from its input somewhere no match was applied — that is corruption.
func TestRoundTripIsByteIdentical(t *testing.T) {
	texts := []string{
		logLine,
		strings.Repeat(logLine, 50),
		"",
		"\ufeffleading BOM\n",
		"astral: \U0001F600 \U0001F4A9 and CJK: 日本語テキスト\n",
		"mixed \u00e9\u00fc\u00df and control \t\r\n",
	}
	for _, enc := range []Encoding{UTF8, UTF16LE, UTF16BE} {
		for _, s := range texts {
			data := Encode(s, enc)
			got, ok := Decode(data, enc)
			if !ok {
				t.Fatalf("%v: Decode refused what Encode produced for %q", enc, s)
			}
			if got != s {
				t.Errorf("%v: text round trip differs\n got %q\nwant %q", enc, got, s)
			}
			if again := Encode(got, enc); !bytes.Equal(again, data) {
				t.Errorf("%v: byte round trip differs for %q", enc, s)
			}
		}
	}
}

func TestDecodeRefusesMalformed(t *testing.T) {
	hi := []byte{0x00, 0xd8} // a high surrogate, little endian
	lo := []byte{0x00, 0xdc} // a low surrogate
	cases := []struct {
		name string
		data []byte
	}{
		{"odd length", []byte{'a', 0, 'b'}},
		{"lone high surrogate", append(append([]byte{'a', 0}, hi...), 'b', 0)},
		{"lone low surrogate", append(append([]byte{'a', 0}, lo...), 'b', 0)},
		{"high surrogate at end", append([]byte{'a', 0}, hi...)},
		{"reversed pair", append(append([]byte{}, lo...), hi...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := Decode(tc.data, UTF16LE); ok {
				t.Error("Decode accepted malformed UTF-16; it must refuse rather than repair")
			}
		})
	}
}

// A binary payload with NULs on alternating bytes can decode as well-formed UTF-16.
// Accepting it would mean rewriting a file the tool is supposed to leave alone, so
// the decoded text is checked for being text at all.
func TestDecodeRefusesBinaryThatHappensToDecode(t *testing.T) {
	var buf bytes.Buffer
	for i := 0; i < 256; i++ {
		buf.WriteByte(byte(i % 0x20)) // control characters only
		buf.WriteByte(0x00)
	}
	if _, ok := Decode(buf.Bytes(), UTF16LE); ok {
		t.Error("Decode accepted control-character soup as text")
	}
}

func TestEncodingString(t *testing.T) {
	for enc, want := range map[Encoding]string{
		UTF8: "utf-8", UTF16LE: "utf-16le", UTF16BE: "utf-16be", Binary: "binary",
	} {
		if got := enc.String(); got != want {
			t.Errorf("String() = %q, want %q", got, want)
		}
	}
}

// FuzzRoundTrip asserts the safety contract over arbitrary input: whatever Decode
// accepts must re-encode to exactly the bytes it was given. A counterexample is a
// payload the scrubber would silently alter.
func FuzzRoundTrip(f *testing.F) {
	f.Add([]byte(logLine))
	f.Add(utf16Bytes(f, logLine, false, true))
	f.Add([]byte{0xff, 0xfe, 0x00, 0xd8, 0x00, 0xdc})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	f.Add([]byte("\x89PNG\r\n\x1a\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		enc := Sniff(data)
		if enc == Binary {
			return
		}
		text, ok := Decode(data, enc)
		if !ok {
			return
		}
		if got := Encode(text, enc); !bytes.Equal(got, data) {
			t.Fatalf("round trip altered the payload for %v:\n in  %x\n out %x", enc, data, got)
		}
	})
}
