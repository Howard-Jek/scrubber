// Package scrub holds the matching/replacement engine. Rules (compiled from the
// terms config) are applied to text in a single combined pass so that every
// replacement is attributable to exactly one rule and reported with its location.
package scrub

import (
	"fmt"
	"regexp"
	"strings"
)

// Rule is one compiled replacement rule.
type Rule struct {
	ID          string // human-readable identifier, e.g. "literal:AcmeCorp" or "preset:email"
	Replacement string // text written in place of a match ("" => matcher default)
	Pattern     string // effective regexp source (with flags/boundaries already applied)

	re    *regexp.Regexp
	valid func(string) bool // optional candidate validator (e.g. Luhn); nil => always valid
}

// SetValidator attaches a candidate validator used to reject false positives
// (a matched span for which validator returns false is left untouched).
func (r *Rule) SetValidator(fn func(string) bool) { r.valid = fn }

// Match records a single replacement for the transparency report.
type Match struct {
	RuleID      string `json:"rule"`
	Line        int    `json:"line"`
	Offset      int    `json:"offset"`
	Original    string `json:"original"`
	Replacement string `json:"replacement"`
}

// Matcher applies an ordered set of rules. Rule order defines precedence when
// two rules could match the same span (earlier rules win).
type Matcher struct {
	rules              []Rule
	combined           *regexp.Regexp
	defaultReplacement string
}

// NewMatcher compiles the combined scanner from already-compiled rules.
func NewMatcher(defaultReplacement string, rules []Rule) (*Matcher, error) {
	if defaultReplacement == "" {
		defaultReplacement = "[REDACTED]"
	}
	parts := make([]string, len(rules))
	for i := range rules {
		re, err := regexp.Compile(rules[i].Pattern)
		if err != nil {
			return nil, err
		}
		rules[i].re = re
		parts[i] = "(?:" + rules[i].Pattern + ")"
	}
	combined, err := regexp.Compile(strings.Join(parts, "|"))
	if err != nil {
		return nil, err
	}
	m := &Matcher{
		rules:              rules,
		combined:           combined,
		defaultReplacement: defaultReplacement,
	}
	if err := m.checkConverges(); err != nil {
		return nil, err
	}
	return m, nil
}

// checkConverges rejects a policy whose own output still matches it.
//
// If a rule replaces "secret" with "secret-[REDACTED]", scrubbing never finishes the
// job: the result still contains the term, and every downstream surface reports the
// file as scrubbed anyway. That is a half-scrubbed document, and it is a property of
// the *policy*, not of any particular file — so it is caught here, once, when the
// policy loads, rather than by re-scanning every leaf at runtime. Measured, that
// runtime check cost ~70% of the drain rate on a one-CPU pod; this costs one pass over
// a handful of short strings and fails before any data is touched.
//
// The check runs the real Scrub rather than matching the combined pattern directly,
// so rules with candidate validators (a card number that fails its Luhn check is not
// a match) are judged exactly as they will be in production, with no second
// implementation to drift.
func (m *Matcher) checkConverges() error {
	seen := map[string]bool{}
	for i := range m.rules {
		rep := m.rules[i].Replacement
		if rep == "" {
			rep = m.defaultReplacement
		}
		if seen[rep] {
			continue
		}
		seen[rep] = true
		if _, matches := m.Scrub(rep); len(matches) > 0 {
			return fmt.Errorf("policy does not converge: the replacement %q for rule %q is itself "+
				"matched by rule %q, so scrubbing its own output would find the term again and the "+
				"file would be emitted only partly redacted. Choose a replacement no rule matches",
				rep, m.rules[i].ID, matches[0].RuleID)
		}
	}
	return nil
}

// RuleCount returns the number of compiled rules.
func (m *Matcher) RuleCount() int { return len(m.rules) }

// RuleInfo describes a rule for the operator's policy panel: the kind, the actual
// term being matched (literal value, regex pattern, or preset name), and the
// replacement label. Operators are inside the trust boundary and need to see the
// literal terms to verify what will be scrubbed.
type RuleInfo struct {
	Kind  string `json:"kind"`  // "literal" | "regex" | "preset"
	Text  string `json:"text"`  // literal value, regex pattern, or preset name
	Label string `json:"label"` // replacement, e.g. "[EMAIL]"
}

// Rules returns the rule summary for the policy.
func (m *Matcher) Rules() []RuleInfo {
	out := make([]RuleInfo, 0, len(m.rules))
	for _, r := range m.rules {
		kind, rest := "rule", r.ID
		if i := strings.IndexByte(r.ID, ':'); i >= 0 {
			kind, rest = r.ID[:i], r.ID[i+1:]
		}
		label := r.Replacement
		if label == "" {
			label = m.defaultReplacement
		}
		out = append(out, RuleInfo{Kind: kind, Text: rest, Label: label})
	}
	return out
}

// Scrub replaces all matches in text and returns the scrubbed text plus a record
// of every replacement made (in document order).
func (m *Matcher) Scrub(text string) (string, []Match) {
	locs := m.combined.FindAllStringIndex(text, -1)
	if len(locs) == 0 {
		return text, nil
	}
	var (
		b        strings.Builder
		matches  []Match
		last     int
		lineBase = 1 // line number of byte 0
		lastNL   = 0 // byte index from which we've already counted newlines
	)
	b.Grow(len(text))
	for _, loc := range locs {
		s, e := loc[0], loc[1]
		orig := text[s:e]
		rule := m.attribute(orig)
		if rule == nil || (rule.valid != nil && !rule.valid(orig)) {
			// Not a real hit (validator rejected): leave the text as-is.
			continue
		}
		repl := rule.Replacement
		if repl == "" {
			repl = m.defaultReplacement
		}
		b.WriteString(text[last:s])
		b.WriteString(repl)

		lineBase += strings.Count(text[lastNL:s], "\n")
		lastNL = s
		matches = append(matches, Match{
			RuleID:      rule.ID,
			Line:        lineBase,
			Offset:      s,
			Original:    orig,
			Replacement: repl,
		})
		last = e
	}
	b.WriteString(text[last:])
	return b.String(), matches
}

// ScrubName applies the matcher to a file path, one segment at a time so the
// directory structure is preserved. A replacement can never introduce a path
// separator (any "/" or "\" it produces is neutralized to "_"), so scrubbing a
// name can't create path traversal or escape a directory.
func (m *Matcher) ScrubName(name string) (string, []Match) {
	parts := strings.Split(name, "/")
	var all []Match
	changed := false
	for i, p := range parts {
		if p == "" || p == "." || p == ".." {
			continue
		}
		s, ms := m.Scrub(p)
		if len(ms) == 0 {
			continue
		}
		s = strings.ReplaceAll(s, "/", "_")
		s = strings.ReplaceAll(s, `\`, "_")
		parts[i] = s
		all = append(all, ms...)
		changed = true
	}
	if !changed {
		return name, nil
	}
	return strings.Join(parts, "/"), all
}

// attribute returns the first rule whose own pattern matches the full span,
// which is the rule that produced this combined match (precedence = order).
func (m *Matcher) attribute(span string) *Rule {
	for i := range m.rules {
		loc := m.rules[i].re.FindStringIndex(span)
		if loc != nil && loc[0] == 0 && loc[1] == len(span) {
			return &m.rules[i]
		}
	}
	// Fallback: any rule that matches anywhere in the span.
	for i := range m.rules {
		if m.rules[i].re.MatchString(span) {
			return &m.rules[i]
		}
	}
	return nil
}
