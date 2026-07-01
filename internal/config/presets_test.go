package config

import (
	"strings"
	"testing"
)

// scrubWith compiles a presets-only config and returns the scrubbed text.
func scrubWith(t *testing.T, preset, text string) string {
	t.Helper()
	m, err := (&Config{Presets: []string{preset}}).Compile()
	if err != nil {
		t.Fatalf("compile %s: %v", preset, err)
	}
	out, _ := m.Scrub(text)
	return out
}

func TestPresetWindowsAccount(t *testing.T) {
	out := scrubWith(t, "windows_account", `login ACME\jsmith and CORP\svc_backup$ ok`)
	if strings.Contains(out, `ACME\jsmith`) || strings.Contains(out, `CORP\svc_backup$`) {
		t.Errorf("accounts not scrubbed: %q", out)
	}
	if !strings.Contains(out, "[ACCOUNT]") {
		t.Errorf("missing replacement: %q", out)
	}
}

func TestPresetUPN(t *testing.T) {
	out := scrubWith(t, "upn", "user jsmith@acme.com signed in")
	if strings.Contains(out, "jsmith@acme.com") || !strings.Contains(out, "[UPN]") {
		t.Errorf("upn not scrubbed: %q", out)
	}
}

func TestPresetFQDN(t *testing.T) {
	out := scrubWith(t, "fqdn", "host db-prod-01.internal.acme.com served file archive.tar.gz")
	if strings.Contains(out, "db-prod-01.internal.acme.com") {
		t.Errorf("fqdn not scrubbed: %q", out)
	}
	if !strings.Contains(out, "[FQDN]") {
		t.Errorf("missing replacement: %q", out)
	}
	// filename must NOT be treated as a domain
	if !strings.Contains(out, "archive.tar.gz") {
		t.Errorf("filename wrongly scrubbed as fqdn: %q", out)
	}
}

func TestPresetHostname(t *testing.T) {
	out := scrubWith(t, "hostname", "server db-prod-01 had an error during login")
	if strings.Contains(out, "db-prod-01") {
		t.Errorf("hostname not scrubbed: %q", out)
	}
	// plain words (no digit/hyphen) must be left alone
	if !strings.Contains(out, "error") || !strings.Contains(out, "login") {
		t.Errorf("plain words wrongly scrubbed as hostname: %q", out)
	}
}
