// Package config loads, validates and compiles the terms JSON into a ready-to-use
// scrub.Matcher. Validation is strict and happens up front: if anything is wrong
// (bad JSON, empty term, uncompilable regex, unknown preset) Load returns an error
// and the caller must abort BEFORE touching any input data.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/howard/scrubber/internal/scrub"
)

// Term is one literal or regex entry in the terms file.
type Term struct {
	Value           string `json:"value"`
	Pattern         string `json:"pattern"`
	Replacement     string `json:"replacement"`
	CaseInsensitive bool   `json:"case_insensitive"`
	WholeWord       bool   `json:"whole_word"`
}

// Config is the on-disk schema of the terms file.
type Config struct {
	DefaultReplacement string   `json:"default_replacement"`
	Literals           []Term   `json:"literals"`
	Regex              []Term   `json:"regex"`
	Presets            []string `json:"presets"`
}

// Load reads, validates and compiles the terms file at path.
func Load(path string) (*scrub.Matcher, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading terms file: %w", err)
	}
	return CompileBytes(raw)
}

// CompileBytes parses, validates and compiles a terms document held in memory.
// The service path (which loads policies from ConfigMaps/objects rather than a
// file) uses this so validation stays identical to the CLI.
func CompileBytes(raw []byte) (*scrub.Matcher, error) {
	var cfg Config
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("terms file is not valid JSON: %w", err)
	}
	return cfg.Compile()
}

// Compile turns a parsed Config into a Matcher, validating every rule.
func (cfg *Config) Compile() (*scrub.Matcher, error) {
	var rules []scrub.Rule

	for i, l := range cfg.Literals {
		if l.Value == "" {
			return nil, fmt.Errorf("literals[%d]: empty value", i)
		}
		pat := regexp.QuoteMeta(l.Value)
		if l.WholeWord {
			pat = `\b` + pat + `\b`
		}
		if l.CaseInsensitive {
			pat = `(?i:` + pat + `)`
		}
		if _, err := regexp.Compile(pat); err != nil {
			return nil, fmt.Errorf("literals[%d] (%q): %w", i, l.Value, err)
		}
		rules = append(rules, scrub.Rule{
			ID:          "literal:" + l.Value,
			Replacement: l.Replacement,
			Pattern:     pat,
		})
	}

	for i, r := range cfg.Regex {
		if r.Pattern == "" {
			return nil, fmt.Errorf("regex[%d]: empty pattern", i)
		}
		pat := r.Pattern
		if r.WholeWord {
			pat = `\b(?:` + pat + `)\b`
		}
		if r.CaseInsensitive {
			pat = `(?i:` + pat + `)`
		}
		if _, err := regexp.Compile(pat); err != nil {
			return nil, fmt.Errorf("regex[%d] (%q) does not compile: %w", i, r.Pattern, err)
		}
		rules = append(rules, scrub.Rule{
			ID:          "regex:" + r.Pattern,
			Replacement: r.Replacement,
			Pattern:     pat,
		})
	}

	for _, name := range cfg.Presets {
		p, ok := presets[name]
		if !ok {
			return nil, fmt.Errorf("unknown preset %q (available: %s)", name, availablePresets())
		}
		rule := scrub.Rule{
			ID:          "preset:" + name,
			Replacement: p.replacement,
			Pattern:     p.pattern,
		}
		if p.valid != nil {
			rule.SetValidator(p.valid)
		}
		rules = append(rules, rule)
	}

	if len(rules) == 0 {
		return nil, fmt.Errorf("terms file defines no literals, regex, or presets")
	}
	return scrub.NewMatcher(cfg.DefaultReplacement, rules)
}

func availablePresets() string {
	names := make([]string, 0, len(presets))
	for n := range presets {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
