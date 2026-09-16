package scrub

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Encoded content is the dangerous quadrant of the coverage contract.
//
// Every other hole in this tool is NAMED. An unopenable 7z is reported
// `unsupported-format`; a binary is reported `binary-skipped`; a container over
// the expansion budget is reported `guard-tripped`. The reader of a report can
// see exactly what was not looked at.
//
// Encoded text is different, and worse. A base64 blob is plain ASCII, so the
// file is not flagged binary. It is inspected. It is scrubbed. It is reported
// CLEAN -- and the credential inside it travels to whoever receives the bundle.
// There is no status, no reason code, and no exit code that betrays it. That is
// `todo.md` S9, and it is the one place the contract fails silently rather than
// loudly.
//
// This file closes the base64 case. The neighbours S9 lists -- percent-encoding,
// HTML entities, JSON \uXXXX, quoted-printable -- share the shape and are left
// for a follow-up; `Encoding` on each finding exists so they can be added without
// changing the call site.
//
// Two deliberate conservatisms, because a false positive here corrupts a
// customer's file:
//
//  1. A candidate must be a syntactically complete base64 string that decodes
//     cleanly. A run whose length is not a multiple of four is skipped rather
//     than trimmed to fit -- trimming would decode a prefix of something we have
//     not understood.
//  2. A region is only REWRITTEN when its decoded form is valid UTF-8 text. Hex
//     digests share base64's alphabet and decode to binary noise; re-encoding
//     one would replace a checksum with garbage. Those are scanned and reported
//     but never rewritten.

// minWrapWidth is the shortest line length accepted as a wrapped base64 block.
// PEM wraps at 64 and MIME at 76; nothing legitimate wraps encoded data much
// narrower, and a low bar would start joining unrelated short lines.
const minWrapWidth = 32

// MaxEncodedDepth bounds recursion into content that is itself encoded. Secrets
// wrapped twice are real -- a base64 kubeconfig containing a base64 token -- but
// each level costs another decode of the whole payload, and nothing legitimate
// nests deeply.
const MaxEncodedDepth = 3

// minB64Run is the shortest candidate considered, in encoded characters. 24
// characters decode to 18 bytes, comfortably below the shortest credential worth
// finding and comfortably above the longest ordinary word.
const minB64Run = 24

// b64Run matches a syntactically plausible standard-base64 token. base64url
// (-_) is deliberately excluded: JWTs use it and already have their own preset,
// and admitting it here would double-report them.
var b64Run = regexp.MustCompile(`[A-Za-z0-9+/]{` + itoa(minB64Run) + `,}={0,2}`)

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

// EncodedFinding is a policy match found inside an encoded region of a file that
// was otherwise inspected and would otherwise have been reported clean.
type EncodedFinding struct {
	Encoding  string  `json:"encoding"`  // "base64"
	Offset    int     `json:"offset"`    // byte offset of the region in the containing text
	Length    int     `json:"length"`    // length of the region, in encoded bytes
	Depth     int     `json:"depth"`     // 0 for a region in the file itself, 1 inside one of those, ...
	Matches   []Match `json:"matches"`   // what the policy found in the decoded content
	Rewritten bool    `json:"rewritten"` // false means the secret survives into the output and must be reported
	// Unexamined marks a region the depth limit stopped us from decoding. It
	// carries no Matches, and that is the point: nobody looked inside it, so
	// nothing here says whether it holds a credential.
	//
	// Without this, MaxEncodedDepth was a silent hole -- exactly the shape this
	// file exists to close, moved up one level. A secret wrapped six times was
	// neither found nor mentioned, and the run reported complete.
	Unexamined bool `json:"unexamined,omitempty"`
}

// ScrubEncoded finds encoded regions in text, runs the policy over their decoded
// content, and rewrites the region where it can do so safely.
//
// It returns the possibly-rewritten text and one finding per encoded region that
// carried a policy match. A region with no matches produces no finding: the point
// is coverage, not an inventory of every blob in the file.
//
// A finding with Rewritten false means the secret is still in the output. The
// caller must not report that file clean.
func (m *Matcher) ScrubEncoded(text string) (string, []EncodedFinding) {
	return m.scrubEncoded(text, 0)
}

// wrappedBlock describes a run of consecutive lines that together form one
// base64 payload, as PEM and MIME emit it.
type wrappedBlock struct {
	start, end int // byte offsets into the containing text
	width      int // the wrap width, so a rewrite can keep the file's shape
	joined     string
}

// findWrappedBlocks locates runs of two or more consecutive lines that are
// base64 all the way across and uniformly wrapped.
//
// Decoding such lines one at a time -- which is what happens without this -- is
// worse than not decoding them at all. A secret straddling a line boundary is
// never seen whole, while the lines that do decode produce matches, so the run
// reports a match and a clean verdict over a live credential.
//
// The uniformity requirement is the safety rail. Every line but the last must be
// the same width, that width must be a multiple of four, and the joined result
// must itself decode. Ragged lines that merely happen to use the base64 alphabet
// are left to the single-region pass, because joining them would decode
// something nobody ever encoded.
func findWrappedBlocks(text string) []wrappedBlock {
	type line struct{ start, end int }
	var lines []line
	for i := 0; i <= len(text); {
		j := strings.IndexByte(text[i:], '\n')
		if j < 0 {
			if i < len(text) {
				lines = append(lines, line{i, len(text)})
			}
			break
		}
		lines = append(lines, line{i, i + j})
		i += j + 1
	}

	isB64Line := func(l line) bool {
		if l.end-l.start == 0 {
			return false
		}
		for k := l.start; k < l.end; k++ {
			c := text[k]
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
				c == '+' || c == '/' || c == '=') {
				return false
			}
		}
		return true
	}

	var out []wrappedBlock
	for i := 0; i < len(lines); i++ {
		if !isB64Line(lines[i]) {
			continue
		}
		width := lines[i].end - lines[i].start
		if width < minWrapWidth || width%4 != 0 {
			continue
		}
		j := i + 1
		for j < len(lines) && isB64Line(lines[j]) {
			w := lines[j].end - lines[j].start
			if w == width {
				j++
				continue
			}
			if w < width { // a shorter line can only be the last one
				j++
			}
			break
		}
		if j-i < 2 {
			continue
		}
		var b strings.Builder
		for k := i; k < j; k++ {
			b.WriteString(text[lines[k].start:lines[k].end])
		}
		joined := b.String()
		if len(joined)%4 == 0 {
			if _, ok := decodeBase64(joined); ok {
				out = append(out, wrappedBlock{lines[i].start, lines[j-1].end, width, joined})
			}
		}
		i = j - 1
	}
	return out
}

// rewrap re-emits an encoded payload at the width the file was using, so a
// rewritten block keeps the shape its reader expects.
func rewrap(enc string, width int) string {
	if width <= 0 || len(enc) <= width {
		return enc
	}
	var b strings.Builder
	for i := 0; i < len(enc); i += width {
		if i > 0 {
			b.WriteByte('\n')
		}
		end := i + width
		if end > len(enc) {
			end = len(enc)
		}
		b.WriteString(enc[i:end])
	}
	return b.String()
}

func (m *Matcher) scrubWrapped(text string, depth int) (string, []EncodedFinding) {
	blocks := findWrappedBlocks(text)
	if len(blocks) == 0 {
		return text, nil
	}
	var (
		out      []byte
		findings []EncodedFinding
		last     int
	)
	for _, blk := range blocks {
		decoded, ok := decodeBase64(blk.joined)
		if !ok {
			continue
		}
		inner, innerFindings := m.scrubEncoded(string(decoded), depth+1)
		scrubbed, matches := m.Scrub(inner)
		if len(matches) == 0 && len(innerFindings) == 0 {
			continue
		}
		f := EncodedFinding{
			Encoding: "base64",
			Offset:   blk.start,
			Length:   blk.end - blk.start,
			Depth:    depth,
			Matches:  matches,
		}
		if isText(decoded) {
			if out == nil {
				out = make([]byte, 0, len(text))
			}
			out = append(out, text[last:blk.start]...)
			out = append(out, rewrap(base64.StdEncoding.EncodeToString([]byte(scrubbed)), blk.width)...)
			last = blk.end
			f.Rewritten = true
		}
		findings = append(findings, f)
		findings = append(findings, innerFindings...)
	}
	if out == nil {
		return text, findings
	}
	out = append(out, text[last:]...)
	return string(out), findings
}

func (m *Matcher) scrubEncoded(text string, depth int) (string, []EncodedFinding) {
	if m == nil {
		return text, nil
	}
	var wrappedFindings []EncodedFinding
	if depth < MaxEncodedDepth {
		text, wrappedFindings = m.scrubWrapped(text, depth)
	}

	locs := b64Run.FindAllStringIndex(text, -1)
	if locs == nil {
		return text, wrappedFindings
	}
	if depth >= MaxEncodedDepth {
		// Out of budget. Say so rather than returning quietly: a clean scan of
		// something nobody could open is the absence of a scan, and this codebase
		// treats that as a hole everywhere else it occurs.
		//
		// Only regions that actually decode are reported. A hex digest shares the
		// base64 alphabet and would otherwise turn every checksum at the bottom of
		// the recursion into a spurious hole.
		var holes []EncodedFinding
		for _, loc := range locs {
			if _, ok := decodeBase64(text[loc[0]:loc[1]]); !ok {
				continue
			}
			holes = append(holes, EncodedFinding{
				Encoding:   "base64",
				Offset:     loc[0],
				Length:     loc[1] - loc[0],
				Depth:      depth,
				Unexamined: true,
			})
		}
		return text, append(wrappedFindings, holes...)
	}

	var (
		out      []byte
		findings []EncodedFinding
		last     int
	)
	for _, loc := range locs {
		start, end := loc[0], loc[1]
		region := text[start:end]

		decoded, ok := decodeBase64(region)
		if !ok {
			continue
		}

		// Recurse before matching: a secret encoded twice is invisible to the
		// policy at this level but visible one level down.
		inner, innerFindings := m.scrubEncoded(string(decoded), depth+1)
		scrubbed, matches := m.Scrub(inner)

		if len(matches) == 0 && len(innerFindings) == 0 {
			continue
		}
		// A region whose only news is "we ran out of depth inside it" is a hole,
		// not a match. Propagate it without claiming we found something.

		f := EncodedFinding{
			Encoding: "base64",
			Offset:   start,
			Length:   end - start,
			Depth:    depth,
			Matches:  matches,
		}
		// Only rewrite what we understood. Binary payloads are reported and left
		// alone; replacing them would corrupt the file to hide a string.
		if isText(decoded) {
			if out == nil {
				out = make([]byte, 0, len(text))
			}
			out = append(out, text[last:start]...)
			out = append(out, base64.StdEncoding.EncodeToString([]byte(scrubbed))...)
			last = end
			f.Rewritten = true
		}
		findings = append(findings, f)
		findings = append(findings, innerFindings...)
	}

	findings = append(wrappedFindings, findings...)
	if out == nil {
		return text, findings
	}
	out = append(out, text[last:]...)
	return string(out), findings
}

// decodeBase64 accepts only a syntactically complete token. Anything else is not
// something we have understood well enough to act on.
func decodeBase64(s string) ([]byte, bool) {
	if len(s) < minB64Run || len(s)%4 != 0 {
		return nil, false
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) == 0 {
		return nil, false
	}
	return b, true
}

// isText reports whether a decoded payload is text we can safely re-encode.
//
// The bar is deliberately high. A hex digest is valid base64 input and decodes
// to noise; so does a compressed or encrypted blob. Rewriting one of those would
// substitute garbage for a value some consumer depends on, which is a worse
// outcome than the leak we are trying to close.
func isText(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	printable := 0
	for _, r := range string(b) {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			printable++
		case r < 0x20 || r == 0x7f:
			return false // any other control byte means this is not text
		default:
			printable++
		}
	}
	return printable*5 >= len(b)*4 // at least 80% printable runes per byte
}
