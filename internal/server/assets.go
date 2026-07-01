package server

import (
	"crypto/rand"
	"encoding/hex"
	_ "embed"
	"path"
	"regexp"
	"strings"
)

//go:embed static/index.html
var indexHTML []byte

var unsafeKeyChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// newKey builds a collision-resistant, path-safe object key from a filename:
// "<8hex>-<sanitized base name>". No slash, so it routes to the default policy
// (prefix rules require a slash) and can't traverse buckets.
func newKey(name string) string {
	base := path.Base(strings.ReplaceAll(name, `\`, "/"))
	base = unsafeKeyChars.ReplaceAllString(base, "_")
	if base == "" || base == "." {
		base = "upload"
	}
	var b [4]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:]) + "-" + base
}
