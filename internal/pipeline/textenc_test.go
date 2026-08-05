package pipeline

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/howard/scrubber/internal/report"
)

// The reported defect: two .txt files, same content, same policy. The UTF-8 one was
// scrubbed and the UTF-16 one came back untouched, reported as binary — because
// UTF-16 spends a NUL on the high byte of every ASCII character and the binary check
// stopped at the first NUL it saw. On Windows this is not an edge case: PowerShell's
// `>` and Out-File, and Notepad's "Save as Unicode", all write UTF-16LE.

const sensitiveLine = "2026-06-12T09:00:00Z INFO user bob@acme.test from 10.1.2.3 org=AcmeCorp\n"

func utf16le(t *testing.T, s string, bom bool) []byte { return encUTF16(t, s, false, bom) }
func utf16be(t *testing.T, s string, bom bool) []byte { return encUTF16(t, s, true, bom) }

func encUTF16(t *testing.T, s string, be, bom bool) []byte {
	t.Helper()
	if bom {
		s = "\ufeff" + s
	}
	units := utf16.Encode([]rune(s))
	out := make([]byte, 2*len(units))
	for i, u := range units {
		if be {
			out[2*i], out[2*i+1] = byte(u>>8), byte(u)
		} else {
			out[2*i], out[2*i+1] = byte(u), byte(u>>8)
		}
	}
	return out
}

func decUTF16(t *testing.T, b []byte, be bool) string {
	t.Helper()
	if len(b)%2 != 0 {
		t.Fatalf("output is not an even number of bytes (%d); it is not valid UTF-16", len(b))
	}
	units := make([]uint16, len(b)/2)
	for i := range units {
		if be {
			units[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
		} else {
			units[i] = uint16(b[2*i+1])<<8 | uint16(b[2*i])
		}
	}
	return string(utf16.Decode(units))
}

func TestUTF16LeavesAreScrubbed(t *testing.T) {
	body := strings.Repeat(sensitiveLine, 20)
	lim := Limits{MaxDepth: 16, MaxTotalBytes: 8 << 20, MaxMembers: 100}

	cases := []struct {
		name string
		data []byte
		be   bool
		bom  bool
	}{
		{"utf-16le with BOM", utf16le(t, body, true), false, true},
		{"utf-16le no BOM", utf16le(t, body, false), false, false},
		{"utf-16be with BOM", utf16be(t, body, true), true, true},
		{"utf-16be no BOM", utf16be(t, body, false), true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, rep := run(t, tc.data, lim)

			if rep.Summary.FilesScrubbed != 1 {
				t.Fatalf("file was not scrubbed: %+v", rep.Summary)
			}
			if rep.Summary.FilesBinarySkip != 0 {
				t.Errorf("UTF-16 text was still counted as binary: %+v", rep.Summary)
			}
			// The same content in UTF-8 finds 60 matches (20 lines x email, ip,
			// company). Encoding must not change what the matcher sees.
			if got, want := rep.Summary.TotalMatches, 60; got != want {
				t.Errorf("matches = %d, want %d — the same as the UTF-8 form", got, want)
			}

			text := decUTF16(t, out, tc.be)
			for _, secret := range []string{"bob@acme.test", "10.1.2.3", "AcmeCorp"} {
				if strings.Contains(text, secret) {
					t.Errorf("%q survived the scrub", secret)
				}
			}
			for _, want := range []string{"[EMAIL]", "[IPV4]", "[COMPANY]"} {
				if !strings.Contains(text, want) {
					t.Errorf("replacement %q missing from the output", want)
				}
			}

			// The output must still be the encoding it arrived in, or whatever reads
			// these files next breaks on a file the scrubber "fixed".
			if tc.bom {
				wantBOM := []byte{0xff, 0xfe}
				if tc.be {
					wantBOM = []byte{0xfe, 0xff}
				}
				if !bytes.HasPrefix(out, wantBOM) {
					t.Errorf("byte-order mark lost: output starts %x, want %x", out[:2], wantBOM)
				}
			} else if out[0] == 0xff || out[0] == 0xfe {
				t.Error("a byte-order mark was added to a file that had none")
			}

			if entry := rep.Files[0]; !strings.Contains(entry.Detail, "utf-16") {
				t.Errorf("report should name the encoding it found, got detail %q", entry.Detail)
			}
		})
	}
}

// A UTF-16 file with nothing to redact must come back exactly as it went in. This is
// the invariant that makes rewriting safe: if a no-match file changes, then a
// with-match file changed somewhere beyond its matches too.
func TestUTF16WithNoMatchesIsByteIdentical(t *testing.T) {
	data := utf16le(t, strings.Repeat("nothing sensitive on this line at all\n", 50), true)
	out, rep := run(t, data, Limits{MaxDepth: 16, MaxTotalBytes: 8 << 20, MaxMembers: 100})

	if !bytes.Equal(out, data) {
		t.Error("an unchanged UTF-16 file was not returned byte for byte")
	}
	if rep.Summary.FilesUnchanged != 1 {
		t.Errorf("expected one unchanged file, got %+v", rep.Summary)
	}
}

func TestUTF16InsideArchiveIsScrubbed(t *testing.T) {
	var raw bytes.Buffer
	zw := gzip.NewWriter(&raw)
	tw := tar.NewWriter(zw)
	members := map[string][]byte{
		"logs/windows.txt": utf16le(t, strings.Repeat(sensitiveLine, 5), true),
		"logs/linux.log":   []byte(strings.Repeat(sensitiveLine, 5)),
	}
	for _, name := range []string{"logs/windows.txt", "logs/linux.log"} {
		body := members[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Size: int64(len(body)), Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	zw.Close()

	_, rep := run(t, raw.Bytes(), Limits{MaxDepth: 16, MaxTotalBytes: 8 << 20, MaxMembers: 100})
	if rep.Summary.FilesScrubbed != 2 {
		t.Fatalf("both members should scrub regardless of encoding: %+v", rep.Summary)
	}
	if got, want := rep.Summary.TotalMatches, 30; got != want {
		t.Errorf("matches = %d, want %d (15 per member)", got, want)
	}
}

// Genuinely binary content must still be skipped — the fix widens what counts as
// text, it does not stop the tool refusing to rewrite a PNG.
func TestBinaryIsStillSkipped(t *testing.T) {
	blob := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0x00, 0x01, 0x02, 0x03}, 500)...)
	out, rep := run(t, blob, Limits{MaxDepth: 16, MaxTotalBytes: 8 << 20, MaxMembers: 100})

	if rep.Summary.FilesBinarySkip != 1 {
		t.Errorf("binary content should still be skipped: %+v", rep.Summary)
	}
	if !bytes.Equal(out, blob) {
		t.Error("a skipped binary file was modified")
	}
}

// Malformed UTF-16 must be refused rather than repaired: utf16.Decode would replace a
// lone surrogate with U+FFFD, which rewrites bytes nobody asked us to touch.
func TestMalformedUTF16IsSkippedNotRepaired(t *testing.T) {
	data := append(utf16le(t, strings.Repeat(sensitiveLine, 10), true),
		0x00, 0xd8) // a high surrogate with nothing after it
	out, rep := run(t, data, Limits{MaxDepth: 16, MaxTotalBytes: 8 << 20, MaxMembers: 100})

	if !bytes.Equal(out, data) {
		t.Error("a malformed UTF-16 file was altered; it must be passed through verbatim")
	}
	if rep.Summary.FilesBinarySkip != 1 {
		t.Errorf("expected the malformed file to be skipped, got %+v", rep.Summary)
	}
	if d := rep.Files[0].Detail; !strings.Contains(d, "utf-16") {
		t.Errorf("the reason should say what it looked like, got %q", d)
	}
}

// zlib is detected from two header bytes with no magic number, and plain text
// satisfies the test — "x " and "H," among others (see internal/detect). Such a file
// used to be handed to the decompressor, fail, and be emitted unscrubbed. Failing to
// inflate is proof the guess was wrong, so it is retried as the text it is.
func TestZlibFalsePositiveIsStillScrubbed(t *testing.T) {
	for _, prefix := range []string{"x ", "H,", "h$"} {
		t.Run(prefix, func(t *testing.T) {
			data := []byte(prefix + "started\n" + strings.Repeat(sensitiveLine, 10))
			out, rep := run(t, data, Limits{MaxDepth: 16, MaxTotalBytes: 8 << 20, MaxMembers: 100})

			if rep.Summary.FilesPassthrough != 0 {
				t.Errorf("text mistaken for zlib was passed through unscrubbed: %+v", rep.Summary)
			}
			if rep.Summary.FilesScrubbed != 1 {
				t.Fatalf("expected the file to be scrubbed, got %+v", rep.Summary)
			}
			if bytes.Contains(out, []byte("bob@acme.test")) {
				t.Error("the address survived")
			}
			if !bytes.HasPrefix(out, []byte(prefix)) {
				t.Error("the leading bytes were not preserved")
			}
		})
	}
}

// Binary skips must be named, not just counted. They were invisible: the summary
// carried a bare number, the digest had no field for them at all, and the UI showed a
// green check — so a UTF-16 log leaked with nothing to notice.
func TestBinarySkipsAreNamed(t *testing.T) {
	var raw bytes.Buffer
	zw := gzip.NewWriter(&raw)
	tw := tar.NewWriter(zw)
	blob := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0x00, 0x01}, 500)...)
	for name, body := range map[string][]byte{
		"assets/logo.png": blob,
		"logs/app.log":    []byte(strings.Repeat(sensitiveLine, 5)),
	} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Size: int64(len(body)), Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	zw.Close()

	_, rep := run(t, raw.Bytes(), Limits{MaxDepth: 16, MaxTotalBytes: 8 << 20, MaxMembers: 100})

	if len(rep.Summary.BinarySkips) != 1 {
		t.Fatalf("expected the skipped file to be named, got %+v", rep.Summary.BinarySkips)
	}
	note := rep.Summary.BinarySkips[0]
	if !strings.Contains(note.Path, "logo.png") {
		t.Errorf("wrong path recorded: %q", note.Path)
	}
	if note.Status != report.StatusBinarySkip {
		t.Errorf("status = %q, want %q", note.Status, report.StatusBinarySkip)
	}
	if note.Detail == "" {
		t.Error("a named skip with no reason is barely better than a bare count")
	}
	if note.Code != report.ReasonBinary {
		t.Errorf("skip code = %q, want %q — the code is what metrics label and the UI groups by",
			note.Code, report.ReasonBinary)
	}
}
