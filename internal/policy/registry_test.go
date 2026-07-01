package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func setupDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("default.json", `{"literals":[{"value":"AcmeCorp"}]}`)
	write("strict.json", `{"presets":["email","ipv4"]}`)
	return dir
}

func TestNewAndResolvePrecedence(t *testing.T) {
	dir := setupDir(t)
	reg, err := New(dir, "default", map[string]string{"secure/": "strict"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := reg.Names(); len(got) != 2 {
		t.Fatalf("want 2 policies, got %v", got)
	}

	// prefix rule wins over default
	r, err := reg.Resolve("secure/app.log", nil, "")
	if err != nil || r.Name != "strict" {
		t.Errorf("prefix resolution: got %q err %v", r.Name, err)
	}
	// default otherwise
	r, _ = reg.Resolve("logs/app.log", nil, "")
	if r.Name != "default" {
		t.Errorf("default resolution: got %q", r.Name)
	}
	// explicit name override wins over prefix/default
	r, _ = reg.Resolve("secure/app.log", nil, "default")
	if r.Name != "default" {
		t.Errorf("name override: got %q", r.Name)
	}
	// per-object terms wins over everything
	r, err = reg.Resolve("secure/app.log", []byte(`{"literals":[{"value":"x"}]}`), "strict")
	if err != nil || r.Name != "override:secure/app.log" {
		t.Errorf("override terms: got %q err %v", r.Name, err)
	}
}

func TestResolveErrors(t *testing.T) {
	reg, _ := New(setupDir(t), "default", nil)
	if _, err := reg.Resolve("k", []byte("{bad json"), ""); err == nil {
		t.Error("expected error for bad override terms")
	}
	if _, err := reg.Resolve("k", nil, "nope"); err == nil {
		t.Error("expected error for unknown named policy")
	}
}

func TestNewMissingDefault(t *testing.T) {
	if _, err := New(setupDir(t), "ghost", nil); err == nil {
		t.Error("expected error when default policy missing")
	}
}

func TestNewMissingPrefixPolicy(t *testing.T) {
	if _, err := New(setupDir(t), "default", map[string]string{"a/": "ghost"}); err == nil {
		t.Error("expected error when prefix policy missing")
	}
}
