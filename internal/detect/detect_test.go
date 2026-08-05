package detect

import (
	"archive/tar"
	"bytes"
	"fmt"
	"testing"
)

func tarHeader(t *testing.T, name string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: name, Size: 0, Mode: 0o644, Format: tar.FormatGNU}); err != nil {
		t.Fatalf("tar header: %v", err)
	}
	tw.Close()
	return buf.Bytes()
}

func TestDetectFormat(t *testing.T) {
	cases := []struct {
		name   string
		header []byte
		want   Format
	}{
		{"zip", []byte("PK\x03\x04rest of the archive"), Zip},
		{"empty zip", []byte("PK\x05\x06"), Zip},
		{"gzip", []byte{0x1f, 0x8b, 0x08, 0x00}, Gzip},
		{"bzip2", []byte("BZh9payload"), Bzip2},
		{"xz", []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}, Xz},
		{"zstd", []byte{0x28, 0xb5, 0x2f, 0xfd}, Zstd},
		{"7z", []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}, SevenZip},
		{"rar5", []byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x01, 0x00}, Rar},
		{"zlib", []byte{0x78, 0x9c, 0x01, 0x02}, Zlib},
		{"tar", tarHeader(t, "logs/app.log"), Tar},

		{"plain text", []byte("2026-06-12 INFO something happened\n"), Unknown},
		{"empty", nil, Unknown},
		{"short", []byte("hi"), Unknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DetectFormat(tc.header); got != tc.want {
				t.Errorf("DetectFormat = %v, want %v", got, tc.want)
			}
		})
	}
}

// "BZh" is three bytes of perfectly ordinary text. Without the block-size digit the
// format mandates after it, a log line starting with those letters is sent off to be
// decompressed, fails, and is emitted unscrubbed.
func TestBzip2NeedsItsLevelDigit(t *testing.T) {
	for _, tc := range []struct {
		header string
		want   Format
	}{
		{"BZh9\x31AY&SY", Bzip2},
		{"BZh1data", Bzip2},
		{"BZh0invalid level", Unknown},
		{"BZhang, Wei <wei@example.test> logged in\n", Unknown},
		{"BZh", Unknown},
	} {
		t.Run(tc.header[:min(len(tc.header), 12)], func(t *testing.T) {
			if got := DetectFormat([]byte(tc.header)); got != tc.want {
				t.Errorf("DetectFormat(%q) = %v, want %v", tc.header, got, tc.want)
			}
		})
	}
}

// zlib is recognised from two bytes with no magic number, and plain text satisfies
// the test: the first byte needs a low nibble of 8 ('H', 'X', 'h', 'x') and the pair
// must be a multiple of 31. These are real English words that a log file could
// plausibly open with, and every one of them used to be routed to the decompressor.
//
// Nothing here can be fixed in the header alone, so this test documents the exposure
// rather than asserting it away. The pipeline closes it by retrying a failed inflate
// as a text leaf — see TestZlibFalsePositiveIsStillScrubbed in internal/pipeline.
func TestZlibFalsePositivesOnPlainText(t *testing.T) {
	var got []string
	for _, prefix := range []string{"H", "X", "h", "x"} {
		for b := 0x20; b < 0x7f; b++ { // printable second bytes only
			header := []byte{prefix[0], byte(b)}
			if DetectFormat(header) == Zlib {
				got = append(got, fmt.Sprintf("%q", string(header)))
			}
		}
	}
	if len(got) == 0 {
		t.Fatal("expected the 2-byte zlib heuristic to match some plain text; " +
			"if it no longer does, the pipeline's inflate-failure fallback may be dead code")
	}
	t.Logf("%d printable 2-byte prefixes are indistinguishable from zlib: %v", len(got), got)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
