// Package residual looks inside the content the scrubber decided not to inspect.
//
// Every other guard in this codebase trusts a classification: this is a tar, that is
// binary, this is UTF-16. When a classification is wrong the file leaves unscrubbed
// and everything downstream agrees it was fine, because everything downstream is
// derived from the same wrong answer. UTF-16 logs read as binary went out that way,
// and nothing in the pipeline was in a position to notice.
//
// So this package does not classify. It pulls printable runs straight out of the raw
// bytes at every code-unit width Latin text uses — one byte, UTF-16's two, UTF-32's
// four, either byte order — and applies the policy to whatever falls out. It
// does not need to know the format or the encoding, which is exactly why it survives
// getting those wrong. A UTF-16 log misfiled as binary still contains a recognisable
// address; this finds it.
//
// It does, however, decompress. A refused .tar.gz used to be scanned as gzip bytes,
// which contain no text at any stride, so the one shape the pipeline most needed a
// second opinion on -- a compressed bundle it had declined to open -- was the one
// shape the net could not see into. The scan now unwraps gzip, zlib, bzip2, xz and
// zstd, and walks zip entries, before extracting text; a payload that is a
// recognised container and yields nothing decodable is reported as opaque, which is
// the verdict's cue that "nothing found" here means "could not look".
//
// The result is a signal, not a verdict: "the tool skipped this and it demonstrably
// contains the sort of thing the tool exists to remove — look at it". False positives
// on genuine binary are possible and acceptable at that strength.
package residual

import (
	"archive/zip"
	"bufio"
	"io"
	"sort"
	"strings"

	"github.com/howard/scrubber/internal/archive"
	"github.com/howard/scrubber/internal/detect"
	"github.com/howard/scrubber/internal/scrub"
	"github.com/howard/scrubber/internal/spill"
)

const (
	// DefaultBudget bounds the bytes read from any one payload. Uninspected content
	// is normally a small share of a bundle, and a match in the first few MiB is
	// enough to say "look at this" — reading a 500MiB binary in full to say it twice
	// as loudly would just slow the queue down.
	DefaultBudget = 8 << 20
	// chunkSize is the read granularity. A multiple of 4, because extraction reads
	// fixed-width code units up to 4 bytes wide and a chunk boundary must not fall
	// inside one.
	chunkSize = 64 << 10
	// alignment is the widest code unit extraction handles (UTF-32).
	alignment = 4
	// maxNesting bounds how many compression layers the scan will unwrap. Two is a
	// .tar.gz inside a zip; anything deeper is not a shape real bundles take.
	maxNesting = 3
)

// Result is what a scan found.
type Result struct {
	// Hits is the number of policy matches found in content that was not inspected.
	Hits int
	// Labels counts them by replacement label ("[EMAIL]": 3). Labels only, never the
	// matched values: this goes into a report that may be shared more widely than the
	// bundle, and quoting the secret back into it would be its own leak.
	Labels map[string]int
	// Truncated marks a payload larger than the budget, so a zero result reads as
	// "nothing found in the first N bytes" rather than "nothing here".
	Truncated bool
	// Decoded is how many bytes the matcher actually saw, after any decompression.
	Decoded int64
	// Opaque reports that the payload is a recognised compressed or archive format
	// from which nothing could be decoded -- encrypted, an unsupported method, a
	// header without a body. A clean result is then no reassurance at all, and the
	// verdict treats it accordingly.
	Opaque bool
}

// Summary renders the labels as a stable, sorted, disclosure-safe string.
func (r Result) Summary() string {
	if r.Hits == 0 {
		return ""
	}
	keys := make([]string, 0, len(r.Labels))
	for k := range r.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"×"+itoa(r.Labels[k]))
	}
	out := strings.Join(parts, ", ")
	if r.Truncated {
		out += " (partial scan)"
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// Scan reads up to budget bytes of b and applies m to every text run it can find,
// unwrapping any compression it recognises on the way.
//
// budget <= 0 uses DefaultBudget. A nil blob or nil matcher scans nothing.
func Scan(b *spill.Blob, m *scrub.Matcher, budget int64) (Result, error) {
	var res Result
	if b == nil || m == nil || b.Size() == 0 {
		return res, nil
	}
	if budget <= 0 {
		budget = DefaultBudget
	}
	if b.Size() > budget {
		res.Truncated = true
	}

	s := &scanner{m: m, budget: budget, labels: map[string]int{}}

	// Zip needs random access; everything else streams.
	head, err := b.Head(512)
	if err != nil {
		return res, err
	}
	if detect.DetectFormat(head) == detect.Zip {
		ra, closer, err := b.ReaderAt()
		if err != nil {
			return res, err
		}
		defer closer.Close()
		s.scanZip(ra, b.Size(), 0)
	} else {
		rc, err := b.Reader()
		if err != nil {
			return res, err
		}
		defer rc.Close()
		s.scanStream(rc, 0)
	}

	res.Hits, res.Labels, res.Decoded = s.hits, s.labels, s.read
	res.Opaque = s.recognised && s.read == 0
	return res, nil
}

// scanner carries one scan's budget and tallies across nested streams.
type scanner struct {
	m      *scrub.Matcher
	budget int64
	read   int64 // bytes handed to the extractor, across every layer
	hits   int
	labels map[string]int
	// recognised is set once any layer identified a container or compressed
	// format. Together with read == 0 it means "there was something to look into
	// and looking failed", which is what Opaque reports.
	recognised bool
}

func (s *scanner) exhausted() bool { return s.read >= s.budget }

// scanZip walks a zip's entries, decoding each that will decode and scanning the
// result. An entry that will not open -- encrypted, an unsupported method -- is
// skipped; the others still get looked at, which is the whole point.
func (s *scanner) scanZip(ra io.ReaderAt, size int64, depth int) {
	s.recognised = true
	zr, err := zip.NewReader(ra, size)
	if err != nil {
		return
	}
	for _, f := range zr.File {
		if s.exhausted() {
			return
		}
		if f.Flags&0x1 != 0 || strings.HasSuffix(f.Name, "/") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		s.scanStream(rc, depth+1)
		rc.Close()
	}
}

// scanStream sniffs the stream's first bytes and either unwraps a compression
// layer it recognises or extracts text from the bytes as they are. Errors from a
// decoder end that layer: whatever had decoded by then has been scanned.
func (s *scanner) scanStream(r io.Reader, depth int) {
	br := bufio.NewReaderSize(r, chunkSize)
	head, _ := br.Peek(512)
	f := detect.DetectFormat(head)
	switch f {
	case detect.Gzip, detect.Zlib, detect.Bzip2, detect.Xz, detect.Zstd:
		if depth >= maxNesting {
			break
		}
		s.recognised = true
		dec, cl, err := archive.NewDecoder(f, br)
		if err != nil {
			// A header the decoder refuses: the bytes are all there is to look at.
			s.extract(br)
			return
		}
		s.scanStream(dec, depth+1)
		if cl != nil {
			cl.Close()
		}
		return
	case detect.SevenZip, detect.Rar:
		// Recognised, unreadable. The raw bytes are scanned anyway on the off
		// chance -- some 7z members are stored uncompressed -- but a clean result
		// is not evidence of anything, and recognised says so.
		s.recognised = true
	}
	s.extract(br)
}

// extract applies the matcher to every reading of the stream's bytes, in chunks,
// until the budget is spent or the stream ends.
func (s *scanner) extract(r io.Reader) {
	buf := make([]byte, chunkSize)
	var carry []byte // a partial trailing code unit, held back to keep units aligned
	for !s.exhausted() {
		want := int64(len(buf))
		if left := s.budget - s.read; left < want {
			want = left
		}
		n, rerr := io.ReadFull(r, buf[:want])
		if n > 0 {
			s.read += int64(n)
			chunk := buf[:n]
			if len(carry) > 0 {
				chunk = append(append([]byte{}, carry...), chunk...)
				carry = nil
			}
			// Hold back a partial trailing code unit: extraction reads fixed-width
			// units, and splitting one across chunks would shift every subsequent
			// unit and turn real text into noise.
			if rem := len(chunk) % alignment; rem != 0 && rerr == nil {
				carry = append([]byte{}, chunk[len(chunk)-rem:]...)
				chunk = chunk[:len(chunk)-rem]
			}
			for _, text := range readingsOf(chunk) {
				if _, ms := s.m.Scrub(text); len(ms) > 0 {
					s.hits += len(ms)
					for _, mm := range ms {
						s.labels[mm.Replacement]++
					}
				}
			}
		}
		if rerr != nil {
			return // EOF, a short final read, or a decoder giving up: the layer is exhausted
		}
	}
}

// readings enumerates how Latin-script text can be laid out in fixed-width code
// units: one byte per character, two (UTF-16, either byte order), or four (UTF-32,
// either byte order). The offset is where the significant byte sits within the unit.
//
// This is the whole trick. The package does not decide which of these a payload *is*
// — deciding is what went wrong — it reads all of them and lets the policy say which
// one produced something worth worrying about.
var readings = []struct{ stride, offset int }{
	{1, 0}, // ASCII, UTF-8, Latin-1
	{2, 0}, // UTF-16LE
	{2, 1}, // UTF-16BE
	{4, 0}, // UTF-32LE
	{4, 3}, // UTF-32BE
}

// readingsOf returns the candidate texts hidden in a chunk of arbitrary bytes.
//
// Each reading keeps the printable bytes and replaces everything else with a newline,
// so unrelated runs cannot be glued into a match that spans them. A multi-byte
// reading additionally requires every padding byte in the unit to be NUL, which is
// what makes it precise: real UTF-16 Latin text has a NUL in every high byte and
// arbitrary binary does not, so binary decimates into separators rather than into
// plausible text.
func readingsOf(chunk []byte) []string {
	if len(chunk) < 2 {
		return nil
	}
	out := make([]string, 0, len(readings))
	for _, r := range readings {
		buf := make([]byte, 0, len(chunk)/r.stride)
		for i := 0; i+r.stride <= len(chunk); i += r.stride {
			unit := chunk[i : i+r.stride]
			padded := true
			for j, c := range unit {
				if j != r.offset && c != 0x00 {
					padded = false
					break
				}
			}
			if padded {
				buf = append(buf, keepOrBreak(unit[r.offset]))
			} else {
				buf = append(buf, '\n')
			}
		}
		out = append(out, string(buf))
	}
	return out
}

// keepOrBreak passes printable bytes through and turns anything else into a run
// separator. Bytes above 0x7f are kept: they carry accented Latin text in both UTF-8
// and the single-byte encodings, and dropping them would break matches inside it.
func keepOrBreak(c byte) byte {
	switch {
	case c == '\t' || c == '\n' || c == '\r':
		return '\n'
	case c < 0x20 || c == 0x7f:
		return '\n'
	default:
		return c
	}
}
