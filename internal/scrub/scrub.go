// Package scrub holds the matching/replacement engine. Rules (compiled from the
// terms config) are applied to text in a single combined pass so that every
// replacement is attributable to exactly one rule and reported with its location.
package scrub

import (
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
	return &Matcher{
		rules:              rules,
		combined:           combined,
		defaultReplacement: defaultReplacement,
	}, nil
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
