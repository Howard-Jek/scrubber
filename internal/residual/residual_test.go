package residual

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/howard/scrubber/internal/config"
	"github.com/howard/scrubber/internal/scrub"
	"github.com/howard/scrubber/internal/spill"
)

const secretLine = "2026-06-12T09:00:00Z INFO user bob@acme.test from 10.1.2.3 org=AcmeCorp\n"

func testMatcher(t *testing.T) *scrub.Matcher {
	t.Helper()
	cfg := config.Config{
		DefaultReplacement: "[REDACTED]",
		Literals:           []config.Term{{Value: "AcmeCorp", Replacement: "[COMPANY]"}},
		Presets:            []string{"email", "ipv4"},
	}
	m, err := cfg.Compile()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return m
}

func blob(t *testing.T, b []byte) *spill.Blob {
	t.Helper()
	bl, err := spill.FromBytes(b, spill.Policy{Threshold: 1 << 20, ResidentMax: 8 << 20})
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	t.Cleanup(func() { bl.Close() })
	return bl
}

func wide(s string, be bool) []byte {
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

// The point of the package: it finds the policy inside content whose format and
// encoding the pipeline got wrong, because it never asks what the format is.
func TestScanFindsSecretsWhateverTheEncoding(t *testing.T) {
	m := testMatcher(t)
	body := strings.Repeat(secretLine, 10)

	cases := []struct {
		name string
		data []byte
	}{
		{"plain utf-8", []byte(body)},
		{"utf-16le — the shape read as binary for a whole release", wide(body, false)},
		{"utf-16be", wide(body, true)},
		{"utf-16le with a BOM", append([]byte{0xff, 0xfe}, wide(body, false)...)},
		{"buried in binary noise", append(append(
			bytes.Repeat([]byte{0x00, 0x01, 0x02}, 500), []byte(body)...),
			bytes.Repeat([]byte{0xfe, 0xff}, 500)...)},
		{"utf-16 buried in binary noise", append(append(
			bytes.Repeat([]byte{0x7f, 0x03, 0x11}, 500), wide(body, false)...),
			bytes.Repeat([]byte{0x99, 0x88}, 500)...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Scan(blob(t, tc.data), m, 0)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if res.Hits == 0 {
				t.Fatal("found nothing; this is the check that catches a wrong classification")
			}
			for _, want := range []string{"[EMAIL]", "[IPV4]", "[COMPANY]"} {
				if res.Labels[want] == 0 {
					t.Errorf("no %s hits in %v", want, res.Labels)
				}
			}
			// Labels only. This summary goes into a report that may travel further
			// than the bundle; quoting the matched value back would be its own leak.
			if s := res.Summary(); strings.Contains(s, "bob@acme.test") || strings.Contains(s, "10.1.2.3") {
				t.Errorf("summary discloses the matched value: %q", s)
			}
		})
	}
}

// Genuine binary must stay quiet, or every bundle containing an image is escalated
// and the signal is worth nothing.
func TestScanIsQuietOnRealBinary(t *testing.T) {
	m := testMatcher(t)
	var png bytes.Buffer
	png.WriteString("\x89PNG\r\n\x1a\n")
	for i := 0; i < 8192; i++ {
		png.WriteByte(byte(i*7 + i/3))
	}
	res, err := Scan(blob(t, png.Bytes()), m, 0)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.Hits != 0 {
		t.Errorf("false positives on binary: %d hits %v", res.Hits, res.Labels)
	}
}

func TestScanRespectsBudget(t *testing.T) {
	m := testMatcher(t)
	// Secrets only after the first 4KiB, with a budget that stops before them.
	data := append(bytes.Repeat([]byte("harmless padding line\n"), 200), []byte(secretLine)...)
	res, err := Scan(blob(t, data), m, 1024)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.Hits != 0 {
		t.Errorf("scanned past the budget: %d hits", res.Hits)
	}
	if !res.Truncated {
		t.Error("a budget-limited scan must say so, or a zero result reads as 'nothing here'")
	}
}

// A run split across the chunk boundary must still be found, and a wide run must not
// be shifted out of alignment by an odd-length chunk.
func TestScanFindsMatchesAcrossChunkBoundaries(t *testing.T) {
	m := testMatcher(t)
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"narrow", append(bytes.Repeat([]byte("x"), chunkSize-20), []byte(secretLine)...)},
		{"wide", append(bytes.Repeat([]byte{'x', 0}, (chunkSize-20)/2), wide(secretLine, false)...)},
		{"wide, odd leading byte", append(append([]byte{0x41},
			bytes.Repeat([]byte{'x', 0}, (chunkSize-20)/2)...), wide(secretLine, false)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Scan(blob(t, tc.data), m, 0)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if res.Hits == 0 {
				t.Error("a match spanning the chunk boundary was missed")
			}
		})
	}
}

func TestScanHandlesNothing(t *testing.T) {
	m := testMatcher(t)
	for _, tc := range []struct {
		name string
		b    *spill.Blob
	}{
		{"nil blob", nil},
		{"empty blob", blob(t, nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Scan(tc.b, m, 0)
			if err != nil || res.Hits != 0 {
				t.Errorf("Scan(%s) = %+v, %v; want an empty result and no error", tc.name, res, err)
			}
		})
	}
	if res, err := Scan(blob(t, []byte(secretLine)), nil, 0); err != nil || res.Hits != 0 {
		t.Errorf("Scan with no matcher = %+v, %v; want an empty result", res, err)
	}
}

func TestSummaryIsStable(t *testing.T) {
	r := Result{Hits: 4, Labels: map[string]int{"[IPV4]": 1, "[EMAIL]": 3}}
	if got, want := r.Summary(), "[EMAIL]×3, [IPV4]×1"; got != want {
		t.Errorf("Summary() = %q, want %q (sorted, so reports diff cleanly)", got, want)
	}
	r.Truncated = true
	if !strings.Contains(r.Summary(), "partial") {
		t.Error("a truncated scan must say so in its summary")
	}
	if (Result{}).Summary() != "" {
		t.Error("an empty result should render as nothing at all")
	}
}
