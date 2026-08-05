package pipeline

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"strings"
	"testing"

	"github.com/howard/scrubber/internal/config"
	"github.com/howard/scrubber/internal/report"
	"github.com/howard/scrubber/internal/scrub"
)

func benchMatcher(b *testing.B) *scrub.Matcher {
	b.Helper()
	cfg := config.Config{
		DefaultReplacement: "[REDACTED]",
		Literals:           []config.Term{{Value: "AcmeCorp", Replacement: "[COMPANY]"}},
		Presets:            []string{"email", "ipv4"},
	}
	m, err := cfg.Compile()
	if err != nil {
		b.Fatalf("compile config: %v", err)
	}
	return m
}

// benchLog builds roughly n bytes of log lines, one in every hitEvery carrying
// something the policy replaces.
func benchLog(n, hitEvery int) []byte {
	var sb strings.Builder
	sb.Grow(n + 256)
	for i := 0; sb.Len() < n; i++ {
		if hitEvery > 0 && i%hitEvery == 0 {
			fmt.Fprintf(&sb, "2024-01-01T12:00:%02dZ INFO  bob%d@acme.test at 10.1.2.%d contacted AcmeCorp\n",
				i%60, i, i%256)
			continue
		}
		fmt.Fprintf(&sb, "2024-01-01T12:00:%02dZ DEBUG worker=%d handled request id=%d in %dms\n",
			i%60, i%8, i, i%400)
	}
	return []byte(sb.String())
}

// benchTarGz packs members files of about each bytes into a gzipped tar. This is
// the shape that draws on the expansion budget twice — once for the decompressed
// tar, once for the member bodies copied out of it.
func benchTarGz(b *testing.B, members, each int) []byte {
	b.Helper()
	var tbuf bytes.Buffer
	tw := tar.NewWriter(&tbuf)
	for i := 0; i < members; i++ {
		body := benchLog(each, 20)
		hdr := &tar.Header{Name: fmt.Sprintf("logs/app-%03d.log", i), Mode: 0o644, Size: int64(len(body))}
		if err := tw.WriteHeader(hdr); err != nil {
			b.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			b.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		b.Fatal(err)
	}
	var gbuf bytes.Buffer
	gw := gzip.NewWriter(&gbuf)
	if _, err := gw.Write(tbuf.Bytes()); err != nil {
		b.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		b.Fatal(err)
	}
	return gbuf.Bytes()
}

// runEngine processes data once with a fresh Engine, the way the worker does. The
// Engine is single-use per top-level object — its expansion budget is engine state —
// so it must be rebuilt per iteration rather than hoisted out of the loop.
func runEngine(m *scrub.Matcher, key string, data []byte) []byte {
	rep := report.New(key, key, report.AuditFull, false, "bench")
	eng := &Engine{Matcher: m, Report: rep, Limits: DefaultLimits(), ScrubNames: true}
	return eng.Process(key, data, 0)
}

// BenchmarkProcessPlainLog measures the whole per-object path for the simplest
// input: detect, scrub, return. MB/s is against the input size.
func BenchmarkProcessPlainLog(b *testing.B) {
	m := benchMatcher(b)
	for _, size := range []int{256 << 10, 1 << 20} {
		b.Run(fmt.Sprintf("%dKiB", size>>10), func(b *testing.B) {
			data := benchLog(size, 20)
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				runEngine(m, "app.log", data)
			}
		})
	}
}

// BenchmarkProcessTarGz measures the bundle path: gunzip, untar, scrub every
// member, repack, recompress. MB/s is against the *compressed* input, which is what
// MAX_OBJECT_BYTES caps, so the figure is not comparable with the plain-log case —
// it is the one that matters for sizing, because it is what an upload actually is.
func BenchmarkProcessTarGz(b *testing.B) {
	m := benchMatcher(b)
	for _, tc := range []struct{ members, each int }{
		{10, 64 << 10},
		{100, 64 << 10},
	} {
		b.Run(fmt.Sprintf("%dx%dKiB", tc.members, tc.each>>10), func(b *testing.B) {
			data := benchTarGz(b, tc.members, tc.each)
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				runEngine(m, "bundle.tar.gz", data)
			}
		})
	}
}
