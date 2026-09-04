package config

import (
	"net/netip"
	"strings"
)

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
	// The shape is deliberately loose -- any run of hex groups and colons, with an
	// optional dotted IPv4 tail for the mapped form -- and the validator does the
	// real work by parsing the candidate as an address. The previous pattern
	// required every group to be present, so it could not see "fe80::1" or
	// "2001:db8::1" (the forms addresses are actually written in) while it matched
	// "12:30:45", which is every syslog timestamp, and every MAC address.
	"ipv6": {
		pattern:     `[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:\.[0-9]{1,3}){0,3}`,
		replacement: "[IPV6]",
		valid:       isIPv6,
	},
	"credit_card": {
		pattern:     `\b\d(?:[ -]?\d){12,18}\b`,
		replacement: "[CARD]",
		valid:       cardNumber,
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
	// A bare ten-digit run is not a phone number: it is an epoch timestamp, a
	// process id, an order number. Separators are required unless the number
	// carries a country code or area-code parentheses, and the parentheses have to
	// balance -- "555) 123-4567" used to match.
	"phone_us": {
		pattern: `\+1[ .\-]?(?:\(\d{3}\)|\d{3})[ .\-]?\d{3}[ .\-]?\d{4}\b` +
			`|\b1[ .\-](?:\(\d{3}\)|\d{3})[ .\-]?\d{3}[ .\-]?\d{4}\b` +
			`|\(\d{3}\)[ .\-]?\d{3}[ .\-]?\d{4}\b` +
			`|\b\d{3}[ .\-]\d{3}[ .\-]\d{4}\b`,
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

// isIPv6 accepts a candidate only if it parses as an IPv6 address AND has enough
// substance to be one in a log: at least two hex groups, or one after a leading
// "::". The parse is what rejects timestamps and MAC addresses (neither has eight
// groups or a "::"); the group rule is what rejects "d::" out of "std::vector" and
// the bare "::" of every C++ scope, both of which parse as valid addresses.
func isIPv6(s string) bool {
	addr, err := netip.ParseAddr(s)
	if err != nil || !addr.Is6() {
		return false
	}
	groups := 0
	for _, g := range strings.Split(s, ":") {
		if g != "" {
			groups++
		}
	}
	return groups >= 2 || (groups == 1 && strings.HasPrefix(s, "::"))
}

// cardNumber validates a candidate card-number span: it must carry an issuer
// prefix a payment network actually uses, and pass Luhn. The prefix check is what
// keeps millisecond epoch timestamps out -- thirteen digits starting with 1, which
// Luhn alone accepted one time in ten.
func cardNumber(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			return s[i] >= '3' && s[i] <= '6' && luhn(s)
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
