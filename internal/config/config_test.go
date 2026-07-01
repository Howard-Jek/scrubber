package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "terms.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadValid(t *testing.T) {
	p := writeTemp(t, `{
		"default_replacement": "[X]",
		"literals": [{"value": "AcmeCorp", "replacement": "[CO]"}],
		"regex": [{"pattern": "id-\\d+"}],
		"presets": ["email", "ipv4", "credit_card"]
	}`)
	m, err := Load(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.RuleCount() != 5 {
		t.Errorf("want 5 rules, got %d", m.RuleCount())
	}
}

func TestLoadMalformedJSON(t *testing.T) {
	p := writeTemp(t, `{"literals": [`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestLoadBadRegex(t *testing.T) {
	p := writeTemp(t, `{"regex": [{"pattern": "("}]}`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for uncompilable regex")
	}
}

func TestLoadUnknownPreset(t *testing.T) {
	p := writeTemp(t, `{"presets": ["not_a_preset"]}`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for unknown preset")
	}
}

func TestLoadEmptyRules(t *testing.T) {
	p := writeTemp(t, `{"default_replacement": "[X]"}`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error when no rules defined")
	}
}

func TestLuhn(t *testing.T) {
	if !luhn("4111 1111 1111 1111") {
		t.Error("valid Visa test number rejected")
	}
	if luhn("1234 5678 9012 3456") {
		t.Error("invalid number accepted")
	}
}
