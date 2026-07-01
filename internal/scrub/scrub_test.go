package scrub

import (
	"strings"
	"testing"
)

func newTestMatcher(t *testing.T) *Matcher {
	t.Helper()
	m, err := NewMatcher("[REDACTED]", []Rule{
		{ID: "literal:secret", Pattern: `secret`},
		{ID: "regex:tok", Replacement: "[TOK]", Pattern: `tok-\d+`},
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestScrubBasic(t *testing.T) {
	m := newTestMatcher(t)
	out, matches := m.Scrub("a secret and tok-42 here")
	if strings.Contains(out, "secret") || strings.Contains(out, "tok-42") {
		t.Errorf("not fully scrubbed: %q", out)
	}
	if out != "a [REDACTED] and [TOK] here" {
		t.Errorf("unexpected output: %q", out)
	}
	if len(matches) != 2 {
		t.Fatalf("want 2 matches, got %d", len(matches))
	}
	if matches[0].RuleID != "literal:secret" || matches[1].Replacement != "[TOK]" {
		t.Errorf("match attribution wrong: %+v", matches)
	}
}

func TestScrubNoMatch(t *testing.T) {
	m := newTestMatcher(t)
	out, matches := m.Scrub("nothing to see")
	if out != "nothing to see" || matches != nil {
		t.Errorf("expected passthrough, got %q / %v", out, matches)
	}
}

func TestScrubLineNumbers(t *testing.T) {
	m := newTestMatcher(t)
	_, matches := m.Scrub("line1\nline2 secret\nline3")
	if len(matches) != 1 || matches[0].Line != 2 {
		t.Errorf("want match on line 2, got %+v", matches)
	}
}

func TestValidatorRejects(t *testing.T) {
	m, err := NewMatcher("[X]", []Rule{{ID: "even", Pattern: `\d+`}})
	if err != nil {
		t.Fatal(err)
	}
	// reject odd numbers
	m.rules[0].SetValidator(func(s string) bool { return len(s)%2 == 0 })
	out, matches := m.Scrub("12 vs 123")
	if !strings.Contains(out, "123") {
		t.Errorf("odd-length number should be left intact: %q", out)
	}
	if len(matches) != 1 || matches[0].Original != "12" {
		t.Errorf("expected only even-length match: %+v", matches)
	}
}
