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
