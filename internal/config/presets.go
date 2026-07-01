package config

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
