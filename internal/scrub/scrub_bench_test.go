package scrub

import (
	"fmt"
	"strings"
	"testing"
)

// benchMatcher approximates a real deployed policy: a handful of literals plus the
// kind of regexes the shipped presets use. Rule count matters because every rule
// becomes a branch of one combined alternation.
func benchMatcher(b *testing.B) *Matcher {
	b.Helper()
	m, err := NewMatcher("[REDACTED]", []Rule{
		{ID: "literal:acme", Pattern: `AcmeCorp`},
		{ID: "literal:internal", Pattern: `internal\.acme\.test`},
		{ID: "regex:email", Replacement: "[EMAIL]", Pattern: `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`},
		{ID: "regex:ipv4", Replacement: "[IP]", Pattern: `\b(?:\d{1,3}\.){3}\d{1,3}\b`},
		{ID: "regex:token", Replacement: "[TOK]", Pattern: `tok-[0-9a-f]{16}`},
		{ID: "regex:uuid", Replacement: "[UUID]", Pattern: `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`},
	})
	if err != nil {
		b.Fatal(err)
	}
	return m
}

// benchLog builds roughly n bytes of log lines. hitEvery controls match density:
// every nth line carries something the policy replaces, which is what drives the
// rebuild cost, since a file with no matches is returned without being rewritten.
func benchLog(n, hitEvery int) string {
	var sb strings.Builder
	sb.Grow(n + 256)
	for i := 0; sb.Len() < n; i++ {
		if hitEvery > 0 && i%hitEvery == 0 {
			fmt.Fprintf(&sb, "2024-01-01T12:00:%02dZ INFO  user bob%d@internal.acme.test from 10.1.2.%d hit AcmeCorp with tok-00112233445566%02x\n",
				i%60, i, i%256, i%256)
			continue
		}
		fmt.Fprintf(&sb, "2024-01-01T12:00:%02dZ DEBUG worker=%d handled request id=%d in %dms with no notable content\n",
			i%60, i%8, i, i%400)
	}
	return sb.String()
}

// BenchmarkMatcherScrub is the throughput baseline for the hottest function in the
// service: one combined alternation over the whole file, with every match position
// materialised at once. MB/s here is the ceiling on how fast anything upstream can
// drain a queue, so it is the number to watch when a scheduling change is supposed
// to have made things faster.
func BenchmarkMatcherScrub(b *testing.B) {
	m := benchMatcher(b)
	for _, tc := range []struct {
		name     string
		size     int
		hitEvery int
	}{
		{"1MiB/dense", 1 << 20, 2},
		{"1MiB/sparse", 1 << 20, 50},
		{"1MiB/clean", 1 << 20, 0},
		{"8MiB/sparse", 8 << 20, 50},
	} {
		b.Run(tc.name, func(b *testing.B) {
			text := benchLog(tc.size, tc.hitEvery)
			b.SetBytes(int64(len(text)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				m.Scrub(text)
			}
		})
	}
}

// BenchmarkMatcherScrubName covers the per-archive-member path. It runs once per
// file inside a bundle rather than once per bundle, so its cost is multiplied by
// member count.
func BenchmarkMatcherScrubName(b *testing.B) {
	m := benchMatcher(b)
	name := "logs/AcmeCorp/bob@internal.acme.test/app-2024-01-01.log"
	b.SetBytes(int64(len(name)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.ScrubName(name)
	}
}
