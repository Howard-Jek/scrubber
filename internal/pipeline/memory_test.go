package pipeline

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"math/rand"
	"runtime"
	"runtime/metrics"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/howard/scrubber/internal/config"
	"github.com/howard/scrubber/internal/report"
	"github.com/howard/scrubber/internal/scrub"
)

// The pod this service runs in is capped at 2 GiB and cannot be raised, so the
// question this file answers is not "how fast" but "how much memory does one object
// cost, and which shape of object costs the most".
//
// The expansion budget (MAX_EXPAND_BYTES) bounds bytes *read*. Resident memory is a
// multiple of that: the compressed input, the decompressed container, every member
// body, each member's scrubbed output, and the repacked container can all be live at
// once. The ratio is not constant across inputs — it depends on container format,
// member count, match density and compressibility — so a cap set from a single
// fixture is a cap set from an anecdote.
//
// These tests measure peak heap per shape in seconds, with no MinIO and no
// containers, so the whole matrix is cheap enough to keep in CI as a regression
// guard. The absolute numbers here are heap, not RSS: use them to compare shapes and
// to catch regressions, and confirm the worst shape end to end with
// scripts/memory-matrix.sh before setting a production cap.

// heapMetric is the live-heap reading used below. runtime/metrics is deliberate:
// runtime.ReadMemStats stops the world on every call, so sampling it in a loop both
// slows the work being measured to a crawl and perturbs the thing being measured.
const heapMetric = "/memory/classes/heap/objects:bytes"

func readHeap(sample []metrics.Sample) uint64 {
	metrics.Read(sample)
	return sample[0].Value.Uint64()
}

// peakHeap runs fn while sampling live heap, and returns the high-water mark above
// the pre-run baseline.
//
// It is a sampling estimate: an allocation spike between two samples can be missed,
// so treat the result as a floor on true peak rather than an exact figure. It is
// good enough for what it is for — ranking shapes against each other and catching a
// regression — but production caps should be confirmed against RSS end to end
// (scripts/memory-matrix.sh), not set from this number alone.
func peakHeap(fn func()) uint64 {
	runtime.GC()
	sample := []metrics.Sample{{Name: heapMetric}}
	base := readHeap(sample)

	var (
		mu   sync.Mutex
		peak uint64
		stop = make(chan struct{})
		done = make(chan struct{})
	)
	go func() {
		defer close(done)
		s := []metrics.Sample{{Name: heapMetric}}
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				v := readHeap(s)
				mu.Lock()
				if v > peak {
					peak = v
				}
				mu.Unlock()
			}
		}
	}()

	fn()
	close(stop)
	<-done

	mu.Lock()
	defer mu.Unlock()
	if peak < base {
		return 0
	}
	return peak - base
}

func memMatcher(t *testing.T) *scrub.Matcher {
	t.Helper()
	cfg := config.Config{
		DefaultReplacement: "[REDACTED]",
		Literals:           []config.Term{{Value: "AcmeCorp", Replacement: "[COMPANY]"}},
		Presets:            []string{"email", "ipv4"},
	}
	m, err := cfg.Compile()
	if err != nil {
		t.Fatalf("compile config: %v", err)
	}
	return m
}

// --- body generators, one per compressibility class ---

// repetitiveBody is the best case for compression and the worst for match count:
// every hitEvery-th line carries three replacements.
func repetitiveBody(n, hitEvery int) []byte {
	var sb strings.Builder
	sb.Grow(n + 256)
	for i := 0; sb.Len() < n; i++ {
		if hitEvery > 0 && i%hitEvery == 0 {
			fmt.Fprintf(&sb, "2024-01-01T12:00:%02dZ INFO  bob%d@acme.test at 10.1.2.%d hit AcmeCorp\n",
				i%60, i, i%256)
			continue
		}
		fmt.Fprintf(&sb, "2024-01-01T12:00:%02dZ DEBUG worker=%d request=%d ok\n", i%60, i%8, i)
	}
	return []byte(sb.String())
}

// incompressibleBody models the reported real-world case: bundles whose uploaded and
// expanded sizes are roughly equal. Still text, so it goes down the scrub path.
func incompressibleBody(n int, seed int64) []byte {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -_.:"
	rng := rand.New(rand.NewSource(seed))
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rng.Intn(len(alphabet))]
		if i%120 == 119 {
			b[i] = '\n'
		}
	}
	return b
}

// binaryBody trips the binary detector, so members are passed through without being
// scrubbed or rebuilt — the cheapest path, and worth measuring as the floor.
func binaryBody(n int, seed int64) []byte {
	rng := rand.New(rand.NewSource(seed))
	b := make([]byte, n)
	_, _ = rng.Read(b)
	for i := 0; i < n; i += 64 {
		b[i] = 0 // NUL bytes are what the detector keys on
	}
	return b
}

// --- container builders ---

func buildTar(t *testing.T, bodies [][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i, body := range bodies {
		h := &tar.Header{Name: fmt.Sprintf("logs/app-%05d.log", i), Mode: 0o644, Size: int64(len(body))}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildZip(t *testing.T, bodies [][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i, body := range bodies {
		w, err := zw.Create(fmt.Sprintf("logs/app-%05d.log", i))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// zipWrapping puts an inner container inside a zip, exercising the nested path where
// the inner archive's members are live at the same time as the outer's.
func zipWrapping(t *testing.T, name string, inner []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(inner); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func bodies(count int, gen func(i int) []byte) [][]byte {
	out := make([][]byte, count)
	for i := range out {
		out[i] = gen(i)
	}
	return out
}

type memCase struct {
	name    string
	build   func(t *testing.T) []byte
	content int // total member bytes before packing
}

// TestMemoryMatrix records peak heap per input shape and fails if any shape exceeds
// heapCeilingRatio. The ratio is against *content* bytes (what the members hold),
// because that is what MAX_EXPAND_BYTES is denominated in.
func TestMemoryMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates hundreds of MiB; skipped under -short")
	}
	m := memMatcher(t)

	// Kept modest so the matrix runs in seconds and fits comfortably in a CI box.
	// Ratios are what transfer to production sizing, not absolute bytes.
	const (
		unit           = 4 << 20 // 4 MiB per "large" member
		fewMembers     = 8
		manySmall      = 1000
		manyTiny       = 20000
		totalContent   = fewMembers * unit
		heapCeiling    = 14.0 // ratio of peak heap to content bytes
		binaryFloorMax = 8.0
	)

	cases := []memCase{
		{
			name:    "targz/8x4MiB/dense/repetitive",
			content: totalContent,
			build: func(t *testing.T) []byte {
				return gzipBytes(t, buildTar(t, bodies(fewMembers, func(int) []byte {
					return repetitiveBody(unit, 3)
				})))
			},
		},
		{
			name:    "targz/8x4MiB/sparse/repetitive",
			content: totalContent,
			build: func(t *testing.T) []byte {
				return gzipBytes(t, buildTar(t, bodies(fewMembers, func(int) []byte {
					return repetitiveBody(unit, 200)
				})))
			},
		},
		{
			name:    "targz/8x4MiB/nomatch/repetitive",
			content: totalContent,
			build: func(t *testing.T) []byte {
				return gzipBytes(t, buildTar(t, bodies(fewMembers, func(int) []byte {
					return repetitiveBody(unit, 0)
				})))
			},
		},
		{
			// The reported real-world shape: uploaded size ~= expanded size.
			name:    "targz/8x4MiB/sparse/incompressible",
			content: totalContent,
			build: func(t *testing.T) []byte {
				return gzipBytes(t, buildTar(t, bodies(fewMembers, func(i int) []byte {
					return incompressibleBody(unit, int64(i))
				})))
			},
		},
		{
			name:    "targz/8x4MiB/binary",
			content: totalContent,
			build: func(t *testing.T) []byte {
				return gzipBytes(t, buildTar(t, bodies(fewMembers, func(i int) []byte {
					return binaryBody(unit, int64(i))
				})))
			},
		},
		{
			name:    "tar/8x4MiB/dense/repetitive",
			content: totalContent,
			build: func(t *testing.T) []byte {
				return buildTar(t, bodies(fewMembers, func(int) []byte {
					return repetitiveBody(unit, 3)
				}))
			},
		},
		{
			name:    "zip/8x4MiB/dense/repetitive",
			content: totalContent,
			build: func(t *testing.T) []byte {
				return buildZip(t, bodies(fewMembers, func(int) []byte {
					return repetitiveBody(unit, 3)
				}))
			},
		},
		{
			// Per-member overhead rather than per-byte: same content, 1000 members.
			name:    "targz/1000xsmall/dense/repetitive",
			content: totalContent,
			build: func(t *testing.T) []byte {
				return gzipBytes(t, buildTar(t, bodies(manySmall, func(int) []byte {
					return repetitiveBody(totalContent/manySmall, 3)
				})))
			},
		},
		{
			name:    "targz/20000xtiny/dense/repetitive",
			content: totalContent,
			build: func(t *testing.T) []byte {
				return gzipBytes(t, buildTar(t, bodies(manyTiny, func(int) []byte {
					return repetitiveBody(totalContent/manyTiny, 1)
				})))
			},
		},
		{
			name:    "zip>targz/8x4MiB/dense/repetitive",
			content: totalContent,
			build: func(t *testing.T) []byte {
				inner := gzipBytes(t, buildTar(t, bodies(fewMembers, func(int) []byte {
					return repetitiveBody(unit, 3)
				})))
				return zipWrapping(t, "inner.tar.gz", inner)
			},
		},
	}

	type result struct {
		name  string
		in    int
		peak  uint64
		ratio float64
	}
	results := make([]result, 0, len(cases))

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			data := tc.build(t)
			var out []byte
			peak := peakHeap(func() {
				rep := report.New("in", "out", report.AuditCounts, false, "salt")
				eng := &Engine{
					Matcher: m, Report: rep,
					Limits:     Limits{MaxDepth: 16, MaxTotalBytes: 4 << 30, MaxMembers: 100000},
					ScrubNames: true,
				}
				out = eng.Process("bundle", data, 0)
			})
			if len(out) == 0 {
				t.Fatal("engine returned nothing")
			}
			ratio := float64(peak) / float64(tc.content)
			results = append(results, result{tc.name, len(data), peak, ratio})

			ceiling := heapCeiling
			if strings.Contains(tc.name, "binary") {
				ceiling = binaryFloorMax
			}
			if ratio > ceiling {
				t.Errorf("peak heap %.1fx content (%d MiB peak for %d MiB content) exceeds the %.1fx ceiling; "+
					"a change has made one object markedly more expensive, which on a fixed 2Gi pod means "+
					"lowering MAX_EXPAND_BYTES to compensate",
					ratio, peak>>20, tc.content>>20, ceiling)
			}
		})
	}

	sort.Slice(results, func(i, j int) bool { return results[i].ratio > results[j].ratio })
	t.Log("peak heap per shape, worst first (ratio is peak heap / content bytes):")
	for _, r := range results {
		t.Logf("  %-40s in=%5dKiB peak=%5dMiB ratio=%5.1fx", r.name, r.in>>10, r.peak>>20, r.ratio)
	}
	if len(results) > 0 {
		t.Logf("WORST SHAPE: %s at %.1fx — size MAX_EXPAND_BYTES from this, not from an average",
			results[0].name, results[0].ratio)
	}
}

// TestReportDetailDoesNotScaleWithMatches is the regression guard for the unbounded
// growth path that report.maxMatchesPerFile closes.
//
// It compares AuditFull against AuditCounts on the *same* dense input, which isolates
// the report from everything else: both levels do identical decompression, scrubbing
// and repacking, so any difference between them is purely the per-match detail being
// retained. AuditFull holds each match's original text and replacement where
// AuditCounts does not — before the cap, a file with millions of matches made that
// difference unbounded and MAX_EXPAND_BYTES did nothing to check it. With the cap
// both levels retain at most maxMatchesPerFile entries, so they should land close.
//
// Comparing dense against sparse instead would mostly measure rebuild cost, which
// legitimately differs, and would be flaky.
func TestReportDetailDoesNotScaleWithMatches(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates hundreds of MiB; skipped under -short")
	}
	m := memMatcher(t)
	const size = 16 << 20

	run := func(level report.AuditLevel) uint64 {
		data := repetitiveBody(size, 1) // every line matches: ~250k matches
		return peakHeap(func() {
			rep := report.New("in", "out", level, false, "salt")
			eng := &Engine{Matcher: m, Report: rep,
				Limits: Limits{MaxDepth: 16, MaxTotalBytes: 4 << 30, MaxMembers: 100000}}
			_ = eng.Process("app.log", data, 0)
		})
	}

	full := run(report.AuditFull)
	counts := run(report.AuditCounts)
	t.Logf("peak heap on identical dense input: AuditFull=%dMiB AuditCounts=%dMiB", full>>20, counts>>20)

	// Allow generous slack: this is a guard against unbounded growth, not a tight
	// budget. Uncapped, the gap scaled with match count and would blow well past it.
	if full > counts+(counts/2)+(64<<20) {
		t.Errorf("AuditFull used %dMiB against AuditCounts %dMiB on identical input: per-match detail "+
			"is scaling with match count again, so a small repetitive log can exhaust the pod no matter "+
			"how low MAX_EXPAND_BYTES is set (see report.maxMatchesPerFile)",
			full>>20, counts>>20)
	}
}
