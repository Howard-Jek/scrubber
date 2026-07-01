// Package policy loads named scrub policies (JSON files using the same schema as
// the CLI terms file) and resolves which policy applies to a given object key.
// Resolution precedence: per-object override > prefix default > global default.
package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/howard/scrubber/internal/config"
	"github.com/howard/scrubber/internal/scrub"
)

// Registry holds compiled named policies loaded from a directory of *.json files.
// It is safe for concurrent use; Reload swaps the compiled set atomically.
type Registry struct {
	dir           string
	defaultPolicy string
	prefixRules   []prefixRule // sorted longest-prefix-first

	mu       sync.RWMutex
	compiled map[string]*scrub.Matcher
}

type prefixRule struct {
	prefix string
	policy string
}

// New loads and compiles every policy in dir. Policy name = file base name
// without the .json extension. It fails fast if any policy is invalid or if the
// configured default/prefix policies are missing.
func New(dir, defaultPolicy string, prefixMap map[string]string) (*Registry, error) {
	r := &Registry{dir: dir, defaultPolicy: defaultPolicy}
	for prefix, pol := range prefixMap {
		r.prefixRules = append(r.prefixRules, prefixRule{prefix: prefix, policy: pol})
	}
	sort.Slice(r.prefixRules, func(i, j int) bool {
		return len(r.prefixRules[i].prefix) > len(r.prefixRules[j].prefix)
	})
	if err := r.Reload(); err != nil {
		return nil, err
	}
	if defaultPolicy != "" {
		if _, ok := r.Get(defaultPolicy); !ok {
			return nil, fmt.Errorf("default policy %q not found in %s", defaultPolicy, dir)
		}
	}
	for _, pr := range r.prefixRules {
		if _, ok := r.Get(pr.policy); !ok {
			return nil, fmt.Errorf("prefix policy %q (for prefix %q) not found in %s", pr.policy, pr.prefix, dir)
		}
	}
	return r, nil
}

// Reload recompiles all policies from the directory and swaps them in atomically.
func (r *Registry) Reload() error {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return fmt.Errorf("reading policy dir: %w", err)
	}
	next := make(map[string]*scrub.Matcher)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(r.dir, e.Name()))
		if err != nil {
			return fmt.Errorf("reading policy %s: %w", e.Name(), err)
		}
		m, err := config.CompileBytes(raw)
		if err != nil {
			return fmt.Errorf("policy %s: %w", e.Name(), err)
		}
		name := strings.TrimSuffix(e.Name(), ".json")
		next[name] = m
	}
	if len(next) == 0 {
		return fmt.Errorf("no policies found in %s", r.dir)
	}
	r.mu.Lock()
	r.compiled = next
	r.mu.Unlock()
	return nil
}

// Get returns the compiled matcher for a named policy.
func (r *Registry) Get(name string) (*scrub.Matcher, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.compiled[name]
	return m, ok
}

// Names returns the sorted list of loaded policy names.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.compiled))
	for n := range r.compiled {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Resolution is the outcome of resolving a policy for an object.
type Resolution struct {
	Matcher *scrub.Matcher
	Name    string // policy name, or "override:<key>" for an inline override
}

// Resolve picks the policy for an object key.
//   - overrideTerms (per-object *.terms.json contents) wins if non-nil.
//   - else overrideName (e.g. from an object tag) is used if non-empty.
//   - else the longest matching prefix rule.
//   - else the global default policy.
func (r *Registry) Resolve(key string, overrideTerms []byte, overrideName string) (Resolution, error) {
	if len(overrideTerms) > 0 {
		m, err := config.CompileBytes(overrideTerms)
		if err != nil {
			return Resolution{}, fmt.Errorf("per-object terms invalid: %w", err)
		}
		return Resolution{Matcher: m, Name: "override:" + key}, nil
	}
	if overrideName != "" {
		m, ok := r.Get(overrideName)
		if !ok {
			return Resolution{}, fmt.Errorf("object requested unknown policy %q", overrideName)
		}
		return Resolution{Matcher: m, Name: overrideName}, nil
	}
	for _, pr := range r.prefixRules {
		if strings.HasPrefix(key, pr.prefix) {
			if m, ok := r.Get(pr.policy); ok {
				return Resolution{Matcher: m, Name: pr.policy}, nil
			}
		}
	}
	if r.defaultPolicy != "" {
		if m, ok := r.Get(r.defaultPolicy); ok {
			return Resolution{Matcher: m, Name: r.defaultPolicy}, nil
		}
	}
	return Resolution{}, fmt.Errorf("no policy resolved for %q and no default set", key)
}
