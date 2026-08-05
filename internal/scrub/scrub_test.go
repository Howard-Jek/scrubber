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

// A policy must converge: scrubbing its own output must find nothing. Otherwise every
// file it touches comes out still containing the term, reported as scrubbed — the
// half-scrubbed document, caught here at load rather than per file at runtime.
func TestNewMatcherRejectsNonConvergentPolicies(t *testing.T) {
	cases := []struct {
		name  string
		rules []Rule
		def   string
		ok    bool
	}{
		{
			name:  "replacement contains the term",
			rules: []Rule{{ID: "literal:secret", Pattern: `secret`, Replacement: "secret-[REDACTED]"}},
		},
		{
			name: "replacement matched by a different rule",
			rules: []Rule{
				{ID: "literal:acme", Pattern: `AcmeCorp`, Replacement: "[COMPANY]"},
				{ID: "literal:company", Pattern: `\[COMPANY\]`, Replacement: "[X]"},
			},
		},
		{
			name:  "default replacement is matched",
			rules: []Rule{{ID: "literal:redacted", Pattern: `REDACTED`}},
			def:   "[REDACTED]",
		},
		{
			name: "ordinary policy converges",
			rules: []Rule{
				{ID: "literal:acme", Pattern: `AcmeCorp`, Replacement: "[COMPANY]"},
				{ID: "preset:email", Pattern: `[a-z]+@[a-z.]+`, Replacement: "[EMAIL]"},
			},
			ok: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			def := tc.def
			if def == "" {
				def = "[REDACTED]"
			}
			_, err := NewMatcher(def, tc.rules)
			if tc.ok && err != nil {
				t.Fatalf("a convergent policy was rejected: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("a policy that cannot converge was accepted")
			}
		})
	}
}

// The check runs the real Scrub, so a rule with a candidate validator is judged
// exactly as it will be in production: a replacement that matches the pattern but
// fails the validator is not a match and must not be rejected.
func TestConvergenceCheckHonoursValidators(t *testing.T) {
	// Pattern matches any 16 digits; the validator accepts none of them, so nothing
	// is ever really replaced and the policy converges trivially.
	r := Rule{ID: "preset:card", Pattern: `\d{16}`, Replacement: "4111111111111111"}
	r.valid = func(string) bool { return false }
	if _, err := NewMatcher("[REDACTED]", []Rule{r}); err != nil {
		t.Errorf("validator-gated rule wrongly reported as non-convergent: %v", err)
	}
}
