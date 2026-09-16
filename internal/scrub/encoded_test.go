package scrub

import (
	"encoding/base64"
	"strings"
	"testing"
)

// The dangerous quadrant, from todo.md S9: base64 (and its neighbours) are plain
// ASCII, so a file carrying an encoded secret is not flagged binary, is inspected,
// is scrubbed, and is reported CLEAN. An unopenable 7z at least gets named. These
// tests are the contract for closing that.

func encMatcher(t *testing.T) *Matcher {
	t.Helper()
	m, err := NewMatcher("[REDACTED]", []Rule{
		{ID: "preset:aws_key", Replacement: "[AWS_KEY]", Pattern: `(?:AKIA|ASIA)[0-9A-Z]{16}`},
		{ID: "preset:email", Replacement: "[EMAIL]", Pattern: `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`},
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestEncodedFindsSecretInsideBase64(t *testing.T) {
	m := encMatcher(t)
	payload := "contact hidden.admin@acme.test key AKIAIOSFODNN7EXAMPLE"
	text := "# exported blob\n" + b64(payload) + "\n"

	_, findings := m.ScrubEncoded(text)
	if len(findings) == 0 {
		t.Fatal("no findings: a base64-wrapped secret was reported clean, which is the bug")
	}
	var rules []string
	for _, f := range findings {
		if f.Encoding != "base64" {
			t.Errorf("encoding = %q, want base64", f.Encoding)
		}
		for _, mm := range f.Matches {
			rules = append(rules, mm.RuleID)
		}
	}
	joined := strings.Join(rules, ",")
	for _, want := range []string{"preset:aws_key", "preset:email"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %s in findings; got %v", want, rules)
		}
	}
}

func TestEncodedRewriteRemovesTheSecret(t *testing.T) {
	m := encMatcher(t)
	payload := "key AKIAIOSFODNN7EXAMPLE"
	text := "blob=" + b64(payload) + "\n"

	out, findings := m.ScrubEncoded(text)
	if len(findings) != 1 || !findings[0].Rewritten {
		t.Fatalf("want one rewritten finding, got %+v", findings)
	}
	if strings.Contains(out, b64(payload)) {
		t.Error("the original base64 survived into the output")
	}
	// and the rewritten region must still decode to something sane
	for _, tok := range strings.Fields(strings.ReplaceAll(out, "blob=", "")) {
		dec, err := base64.StdEncoding.DecodeString(tok)
		if err != nil {
			t.Fatalf("output no longer valid base64: %q (%v)", tok, err)
		}
		if strings.Contains(string(dec), "AKIAIOSFODNN7EXAMPLE") {
			t.Error("secret still present after decoding the rewritten region")
		}
		if !strings.Contains(string(dec), "[AWS_KEY]") {
			t.Errorf("decoded region lost its replacement token: %q", dec)
		}
	}
}

func TestEncodedLeavesOrdinaryTextAlone(t *testing.T) {
	m := encMatcher(t)
	for _, in := range []string{
		"a perfectly ordinary log line with no encoding at all\n",
		"deadbeefdeadbeefdeadbeefdeadbeef\n",                      // hex: valid base64 alphabet, garbage when decoded
		"2026-03-02T08:14:02Z INFO boot: starting build 4.18.2\n", // short tokens
	} {
		out, findings := m.ScrubEncoded(in)
		if out != in {
			t.Errorf("rewrote text it should not have:\n in: %q\nout: %q", in, out)
		}
		for _, f := range findings {
			if len(f.Matches) > 0 {
				t.Errorf("false positive finding in %q: %+v", in, f)
			}
		}
	}
}

func TestEncodedCleanBase64IsNotAFinding(t *testing.T) {
	m := encMatcher(t)
	text := "blob=" + b64("nothing sensitive in here at all, just prose") + "\n"
	out, findings := m.ScrubEncoded(text)
	if out != text {
		t.Errorf("rewrote a clean encoded region: %q", out)
	}
	for _, f := range findings {
		if len(f.Matches) > 0 {
			t.Errorf("clean payload reported as a finding: %+v", f)
		}
	}
}

func TestEncodedNestedBase64(t *testing.T) {
	m := encMatcher(t)
	inner := b64("key AKIAIOSFODNN7EXAMPLE")
	text := "outer=" + b64("wrapped "+inner) + "\n"

	_, findings := m.ScrubEncoded(text)
	found := false
	for _, f := range findings {
		for _, mm := range f.Matches {
			if mm.RuleID == "preset:aws_key" {
				found = true
			}
		}
	}
	if !found {
		t.Error("a secret base64-encoded twice was not found; depth must be > 1")
	}
}

// The depth limit is a limit on what we LOOKED AT, not a licence to call the rest
// clean. A secret nested deeper than MaxEncodedDepth was, before this, invisible
// AND unreported -- the same silent-hole shape the whole file exists to close,
// moved up one level.

func TestEncodedDepthLimitIsReportedNotIgnored(t *testing.T) {
	m := encMatcher(t)
	s := "key AKIAIOSFODNN7EXAMPLE"
	for i := 0; i < 5; i++ {
		s = b64(s)
	}
	text := "blob=" + s + "\n"

	_, findings := m.ScrubEncoded(text)
	for _, f := range findings {
		if f.Unexamined {
			if len(f.Matches) != 0 {
				t.Errorf("an unexamined region must carry no matches; we did not look: %+v", f)
			}
			return
		}
	}
	t.Fatal("nesting past the depth limit produced no Unexamined finding: " +
		"the file would be reported clean when nobody looked inside it")
}

func TestEncodedShallowNestingIsNotAHole(t *testing.T) {
	m := encMatcher(t)
	// one level of wrapping, well inside the limit: found, cleaned, and NOT a hole
	text := "blob=" + b64("key AKIAIOSFODNN7EXAMPLE") + "\n"
	_, findings := m.ScrubEncoded(text)
	for _, f := range findings {
		if f.Unexamined {
			t.Errorf("reported a hole for content it decoded fine: %+v", f)
		}
	}
}

func TestEncodedPlainTextIsNotAHole(t *testing.T) {
	m := encMatcher(t)
	// a hex digest is valid base64 alphabet; it must not be reported as an
	// unexamined hole just because it sits at the bottom of the recursion
	_, findings := m.ScrubEncoded("sha=deadbeefdeadbeefdeadbeefdeadbeef\n")
	for _, f := range findings {
		if f.Unexamined {
			t.Errorf("hex digest reported as an unexamined encoded hole: %+v", f)
		}
	}
}

// Line-wrapped base64 is the commonest real shape -- PEM wraps at 64 columns,
// MIME at 76 -- and decoding each line alone is worse than not decoding at all.
// A secret straddling a line boundary is never seen whole, while the lines that
// DO decode produce matches, so the report shows a match and the verdict reads
// complete over a live credential. Partial coverage that reads as total.

func wrap(s string, n int) string {
	var out []string
	for i := 0; i < len(s); i += n {
		end := i + n
		if end > len(s) {
			end = len(s)
		}
		out = append(out, s[i:end])
	}
	return strings.Join(out, "\n")
}

// long enough that the encoded form spans more than one wrapped line, and
// positioned so the secret straddles the first boundary
const wrappedPayload = "key AKIAIOSFODNN7EXAMPLE plus padding to force the encoded form past a single line of output"

func TestEncodedWrappedPEMIsFound(t *testing.T) {
	m := encMatcher(t)
	text := "-----BEGIN BLOB-----\n" + wrap(b64(wrappedPayload), 64) + "\n-----END BLOB-----\n"

	out, findings := m.ScrubEncoded(text)
	if len(findings) == 0 {
		t.Fatal("no findings: a secret wrapped at 64 columns was reported clean")
	}
	if strings.Contains(strings.ReplaceAll(out, "\n", ""), b64(wrappedPayload)) {
		t.Error("the original encoded payload survived into the output")
	}
	joined := strings.ReplaceAll(strings.ReplaceAll(out, "-----BEGIN BLOB-----", ""), "-----END BLOB-----", "")
	joined = strings.ReplaceAll(joined, "\n", "")
	dec, err := base64.StdEncoding.DecodeString(joined)
	if err != nil {
		t.Fatalf("rewritten block is no longer valid base64 when joined: %v", err)
	}
	if strings.Contains(string(dec), "AKIAIOSFODNN7EXAMPLE") {
		t.Error("secret still recoverable by joining the rewritten lines")
	}
	if !strings.Contains(string(dec), "[AWS_KEY]") {
		t.Errorf("decoded block lost its replacement token: %q", dec)
	}
}

func TestEncodedWrappedMIMEIsFound(t *testing.T) {
	m := encMatcher(t)
	text := "Content-Transfer-Encoding: base64\n\n" + wrap(b64(wrappedPayload), 76) + "\n"
	_, findings := m.ScrubEncoded(text)
	if len(findings) == 0 {
		t.Fatal("a secret wrapped at 76 columns was reported clean")
	}
}

func TestEncodedWrappedPreservesLineShape(t *testing.T) {
	m := encMatcher(t)
	text := wrap(b64(wrappedPayload), 64) + "\n"
	out, _ := m.ScrubEncoded(text)
	for _, ln := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if len(ln) > 64 {
			t.Errorf("rewritten line exceeds the original wrap width: %d chars", len(ln))
		}
	}
}

func TestEncodedRaggedLinesAreNotJoined(t *testing.T) {
	m := encMatcher(t)
	// consecutive base64-alphabet lines of DIFFERENT lengths are not a wrapped
	// block; joining them would decode something nobody encoded
	text := "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\nYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXphYmNkZWY=\n"
	out, findings := m.ScrubEncoded(text)
	for _, f := range findings {
		if f.Length > len(text)/2 && f.Rewritten {
			t.Errorf("joined two ragged lines into one region: %+v", f)
		}
	}
	_ = out
}

func TestEncodedProseIsNotAWrappedBlock(t *testing.T) {
	m := encMatcher(t)
	text := "the quick brown fox jumps over the lazy dog and keeps going for a while\n" +
		"another perfectly ordinary line of log output with nothing encoded in it\n"
	out, findings := m.ScrubEncoded(text)
	if out != text {
		t.Errorf("rewrote prose: %q", out)
	}
	if len(findings) != 0 {
		t.Errorf("prose produced findings: %+v", findings)
	}
}
