package config

import "strings"

// presetRule defines a built-in PII pattern. valid is an optional second-stage
// check applied to a candidate span to suppress false positives.
type presetRule struct {
	pattern     string
	replacement string
	valid       func(string) bool
}

// presets is the catalog of built-in PII patterns selectable by name in the
// terms file. Patterns are intentionally conservative to limit false positives.
var presets = map[string]presetRule{
	"email": {
		pattern:     `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
		replacement: "[EMAIL]",
	},
	"ipv4": {
		pattern:     `\b(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\b`,
		replacement: "[IPV4]",
	},
	"ipv6": {
		pattern:     `\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b`,
		replacement: "[IPV6]",
	},
	"credit_card": {
		pattern:     `\b\d(?:[ -]?\d){12,18}\b`,
		replacement: "[CARD]",
		valid:       luhn,
	},
	"ssn": {
		pattern:     `\b\d{3}-\d{2}-\d{4}\b`,
		replacement: "[SSN]",
	},
	"aws_key": {
		pattern:     `\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b`,
		replacement: "[AWS_KEY]",
	},
	"jwt": {
		pattern:     `\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+`,
		replacement: "[JWT]",
	},
	"phone_us": {
		pattern:     `\b(?:\+?1[ .\-]?)?\(?\d{3}\)?[ .\-]?\d{3}[ .\-]?\d{4}\b`,
		replacement: "[PHONE]",
	},
	// Windows/NetBIOS account: DOMAIN\user. Anchored on the backslash, so very low
	// false-positive rate.
	"windows_account": {
		pattern:     `\b[A-Za-z][A-Za-z0-9.\-]{0,61}\\[A-Za-z0-9._$\-]+`,
		replacement: "[ACCOUNT]",
	},
	// User principal name / login: user@domain.tld (same shape as an email address).
	"upn": {
		pattern:     `\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`,
		replacement: "[UPN]",
	},
	// Fully-qualified domain / host name, e.g. db-prod-01.internal.acme.com. The
	// validator rejects things that are really filenames (archive.tar.gz).
	"fqdn": {
		pattern:     `\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b`,
		replacement: "[FQDN]",
		valid:       notFileName,
	},
	// Short (single-label) host name, e.g. db-prod-01. Noisiest preset: the
	// validator requires a digit or hyphen so plain dictionary words are ignored,
	// but you should still anchor to your own naming convention where possible.
	"hostname": {
		pattern:     `\b[A-Za-z][A-Za-z0-9\-]{1,62}\b`,
		replacement: "[HOST]",
		valid:       looksLikeHostname,
	},
}

// commonFileExts are extensions we do NOT want the fqdn preset to treat as a domain.
var commonFileExts = map[string]bool{
	"go": true, "json": true, "log": true, "txt": true, "md": true, "yaml": true,
	"yml": true, "conf": true, "cfg": true, "ini": true, "xml": true, "csv": true,
	"png": true, "jpg": true, "jpeg": true, "gif": true, "svg": true, "pdf": true,
	"zip": true, "tar": true, "gz": true, "tgz": true, "bz2": true, "xz": true,
	"7z": true, "rar": true, "exe": true, "dll": true, "so": true, "sh": true,
	"ps1": true, "bat": true, "py": true, "js": true, "ts": true, "html": true,
	"htm": true, "css": true, "sql": true, "bak": true, "tmp": true, "old": true,
}

// notFileName rejects an fqdn candidate whose final label is a common file
// extension (so "archive.tar.gz" or "app.log" is not mistaken for a domain).
func notFileName(s string) bool {
	dot := strings.LastIndexByte(s, '.')
	if dot < 0 {
		return true
	}
	return !commonFileExts[strings.ToLower(s[dot+1:])]
}

// looksLikeHostname requires a digit or hyphen in the label so ordinary words
// (e.g. "login", "error") are not scrubbed as host names.
func looksLikeHostname(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '-' || (s[i] >= '0' && s[i] <= '9') {
			return true
		}
	}
	return false
}

// luhn validates a candidate card-number span (ignoring spaces/dashes) using the
// Luhn checksum, rejecting random digit runs that merely match the shape.
func luhn(s string) bool {
	var digits []int
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}
