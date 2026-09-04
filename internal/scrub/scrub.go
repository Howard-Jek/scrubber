// Package scrub holds the matching/replacement engine. Rules (compiled from the
// terms config) are applied to text in a single combined pass so that every
// replacement is attributable to exactly one rule and reported with its location.
package scrub

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Rule is one compiled replacement rule.
type Rule struct {
	ID          string // human-readable identifier, e.g. "literal:AcmeCorp" or "preset:email"
	Replacement string // text written in place of a match ("" => matcher default)
	Pattern     string // effective regexp source (with flags/boundaries already applied)

	re    *regexp.Regexp
	valid func(string) bool // optional candidate validator (e.g. Luhn); nil => always valid
	// group is the index of this rule's capture group in the combined pattern.
	// Reading it off the submatch is how a match is attributed to its rule at no
	// extra matching cost; it used to be re-derived by running every rule's own
	// regexp against the span, which was the largest per-match term in the profile.
	group int
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
	group := 1
	for i := range rules {
		re, err := regexp.Compile(rules[i].Pattern)
		if err != nil {
			return nil, err
		}
		rules[i].re = re
		rules[i].group = group
		// One capturing group per rule, wrapping the rule's own groups, so the
		// first group that participated names the rule.
		parts[i] = "(" + rules[i].Pattern + ")"
		group += 1 + re.NumSubexp()
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
				"file would be emitted only partly redacted. Choose a replacement no rule matches; "+
				"for a preset, set it under \"preset_replacements\" in the policy. A label with an "+
				"underscore in it, such as [IP_V4], cannot be read as a word by the shape-matching "+
				"presets (hostname, fqdn), which is the usual way this arises",
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
//
// The combined pattern is leftmost-first: at any position the earliest rule in
// precedence order that matches wins, and the scan resumes after its span. A
// candidate a validator rejects does NOT consume its span. It used to, and that
// is how an SSN inside a card-shaped run of digits went out unredacted: the card
// rule claimed thirteen digits, Luhn said no, and the scan moved on past the SSN
// that was sitting in the middle of them. Now the other rules get their turn at
// the same position, and failing that the scan advances one character into the
// rejected span.
func (m *Matcher) Scrub(text string) (string, []Match) {
	var (
		b        strings.Builder
		matches  []Match
		last     int
		pos      int
		lineBase = 1 // line number of byte 0
		lastNL   = 0 // byte index from which we've already counted newlines
		grown    bool
	)
	for pos <= len(text) {
		loc := m.combined.FindStringSubmatchIndex(text[pos:])
		if loc == nil {
			break
		}
		s, e := pos+loc[0], pos+loc[1]
		if e == s {
			// An empty match is a property of a pathological pattern, not of the
			// text; replacing nothing with something at every position is never
			// what a policy meant.
			pos = s + runeWidth(text, s)
			continue
		}
		rule := m.ruleFor(loc)
		if rule.valid != nil && !rule.valid(text[s:e]) {
			// Another rule may legitimately match right here -- later in precedence,
			// so the combined scan never got to it. Try them in order before giving
			// the position up.
			if alt, ae := m.retryAt(rule, text, s); alt != nil {
				rule, e = alt, ae
			} else {
				pos = s + runeWidth(text, s)
				continue
			}
		}
		repl := rule.Replacement
		if repl == "" {
			repl = m.defaultReplacement
		}
		if !grown {
			b.Grow(len(text))
			grown = true
		}
		b.WriteString(text[last:s])
		b.WriteString(repl)

		lineBase += strings.Count(text[lastNL:s], "\n")
		lastNL = s
		matches = append(matches, Match{
			RuleID:      rule.ID,
			Line:        lineBase,
			Offset:      s,
			Original:    text[s:e],
			Replacement: repl,
		})
		last = e
		pos = e
	}
	if len(matches) == 0 {
		return text, nil
	}
	b.WriteString(text[last:])
	return b.String(), matches
}

// ruleFor names the rule whose group participated in a combined match. Exactly one
// top-level group does under leftmost-first alternation, and it is the earliest in
// precedence order that could match at that position.
func (m *Matcher) ruleFor(loc []int) *Rule {
	for i := range m.rules {
		g := 2 * m.rules[i].group
		if g < len(loc) && loc[g] >= 0 {
			return &m.rules[i]
		}
	}
	// Unreachable for a well-formed combined pattern; the first rule is the
	// conservative answer, as it was under the old attribution fallback.
	return &m.rules[0]
}

// retryAt offers the position a rejected candidate started at to every rule after
// the rejected one, in precedence order, and returns the first that matches there
// and passes its own validator.
//
// Rules before the rejected one need no retry: had any of them matched at this
// position, the leftmost-first alternation would have chosen it instead.
func (m *Matcher) retryAt(rejected *Rule, text string, s int) (*Rule, int) {
	after := false
	for i := range m.rules {
		r := &m.rules[i]
		if r == rejected {
			after = true
			continue
		}
		if !after {
			continue
		}
		loc := r.re.FindStringIndex(text[s:])
		if loc == nil || loc[0] != 0 || loc[1] == 0 {
			continue
		}
		e := s + loc[1]
		if r.valid != nil && !r.valid(text[s:e]) {
			continue
		}
		return r, e
	}
	return nil, 0
}

// runeWidth is the byte length of the character at i, never less than one.
func runeWidth(text string, i int) int {
	if i >= len(text) {
		return 1
	}
	_, w := utf8.DecodeRuneInString(text[i:])
	if w < 1 {
		return 1
	}
	return w
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
