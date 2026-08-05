package worker

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/howard/scrubber/internal/metrics"
	"github.com/howard/scrubber/internal/pipeline"
	"github.com/howard/scrubber/internal/policy"
	"github.com/prometheus/client_golang/prometheus"
)

// benchLog builds roughly n bytes of log lines, one in five carrying something the
// test policy replaces.
func benchLog(n int) []byte {
	var sb strings.Builder
	sb.Grow(n + 128)
	for i := 0; sb.Len() < n; i++ {
		if i%5 == 0 {
			fmt.Fprintf(&sb, "2024-01-01T12:00:%02dZ INFO  bob%d@acme.test hit AcmeCorp\n", i%60, i)
			continue
		}
		fmt.Fprintf(&sb, "2024-01-01T12:00:%02dZ DEBUG worker=%d request=%d ok\n", i%60, i%8, i)
	}
	return []byte(sb.String())
}

func benchWorker(b *testing.B, ms *memStore) *Worker {
	b.Helper()
	m := metrics.New(prometheus.NewRegistry())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(ms, benchRegistry(b), m, metrics.NewJobLog(1000), Config{
		InputBucket: "input", OutputBucket: "output", ReportsBucket: "reports",
		Action: ActionMove, PollInterval: time.Hour, Workers: 1,
		Limits: pipeline.DefaultLimits(),
	}, log)
}

func seedInput(b *testing.B, objects, size int) (*memStore, int64) {
	b.Helper()
	ms := newMemStore("input", "output", "reports")
	body := benchLog(size)
	for i := 0; i < objects; i++ {
		ms.putAt("input", fmt.Sprintf("obj-%03d.log", i), body,
			memStoreEpoch.Add(time.Duration(i)*time.Second))
	}
	return ms, int64(objects * len(body))
}

// BenchmarkDrainSerialVsFanOut is the in-process version of the deployment
// question: on a single CPU, does scrubbing one object at a time cost throughput
// compared with the old fan-out?
//
// It must be run with GOMAXPROCS=1, because that is what the pod has
// (limits.cpu: "1"):
//
//	go test ./internal/worker -bench=DrainSerialVsFanOut -cpu=1
//
// The check below is not pedantry. Measured on a 4-core box the fan-out looks
// roughly twice as fast, which is true and irrelevant — it answers a question about
// hardware the service does not have. Rather than let that number be produced by
// accident, skip.
//
// Pinned, the honest result on this workload is that the fan-out still wins on raw
// throughput by roughly 8% (about 9.0 MB/s against 8.4 MB/s). Serialising is not
// free, and this benchmark exists so nobody has to take that on faith. Two caveats
// cut the other way in production: the store here is in-memory, so the fan-out never
// gets the overlap it would from real MinIO round-trips, and it holds two objects
// resident where the queue holds one — which on a 2Gi pod is the difference between
// budgeting 1152Mi and 576Mi.
//
// So the trade is a few percent of throughput for halved memory and arrival-ordered
// completion. The latter is the point and does not show up here at all: this
// measures total drain time, whereas a user cares when *their* object finishes.
// scripts/bench-queue.sh measures that, plus RSS.
func BenchmarkDrainSerialVsFanOut(b *testing.B) {
	if n := runtime.GOMAXPROCS(0); n != 1 {
		b.Skipf("run with -cpu=1 to model the single-CPU pod (GOMAXPROCS=%d)", n)
	}

	const objects, size = 8, 128 << 10

	b.Run("serial", func(b *testing.B) {
		ms, total := seedInput(b, objects, size)
		w := benchWorker(b, ms)
		b.SetBytes(total)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			restoreInput(ms, objects)
			b.StartTimer()
			w.runOnce(context.Background())
		}
	})

	// fanout reproduces the shape this change removed: every eligible object
	// dispatched at once behind a semaphore, with no ordering.
	b.Run("fanout-2", func(b *testing.B) {
		ms, total := seedInput(b, objects, size)
		w := benchWorker(b, ms)
		b.SetBytes(total)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			restoreInput(ms, objects)
			objs, err := ms.List(context.Background(), "input", "")
			if err != nil {
				b.Fatal(err)
			}
			b.StartTimer()

			sem := make(chan struct{}, 2)
			var wg sync.WaitGroup
			for _, o := range objs {
				if !w.eligible(o, time.Now()) {
					continue
				}
				obj := o
				sem <- struct{}{}
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer func() { <-sem }()
					w.processObject(context.Background(), obj)
				}()
			}
			wg.Wait()
		}
	})
}

// restoreInput puts the objects back where a completed run moved them from, so each
// iteration starts with the same backlog.
func restoreInput(ms *memStore, objects int) {
	body := benchLog(128 << 10)
	for i := 0; i < objects; i++ {
		key := fmt.Sprintf("obj-%03d.log", i)
		ms.mu.Lock()
		delete(ms.buckets["input"], "processed/"+key)
		ms.mu.Unlock()
		ms.putAt("input", key, body, memStoreEpoch.Add(time.Duration(i)*time.Second))
	}
}

// BenchmarkDiscoverOnce measures the producer's per-poll cost against a bucket that
// has accumulated processed/ objects, which is the term that grows over time: the
// listing covers the whole bucket and the prefix filter runs afterwards.
func BenchmarkDiscoverOnce(b *testing.B) {
	for _, processed := range []int{0, 1000, 10000} {
		b.Run(fmt.Sprintf("processed=%d", processed), func(b *testing.B) {
			ms := newMemStore("input", "output", "reports")
			for i := 0; i < 25; i++ {
				ms.putAt("input", fmt.Sprintf("live-%03d.log", i), []byte("AcmeCorp\n"),
					memStoreEpoch.Add(time.Duration(i)*time.Second))
			}
			for i := 0; i < processed; i++ {
				ms.putAt("input", fmt.Sprintf("processed/old-%06d.log", i), []byte("x"), memStoreEpoch)
			}
			w := benchWorker(b, ms)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				w.discoverOnce(context.Background(), "bench")
			}
		})
	}
}

// benchRegistry mirrors testRegistry for benchmarks (testing.B is not testing.T).
func benchRegistry(b *testing.B) *policy.Registry {
	b.Helper()
	dir := b.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "default.json"),
		[]byte(`{"literals":[{"value":"AcmeCorp","replacement":"[CO]"}],"presets":["email"]}`), 0o600); err != nil {
		b.Fatal(err)
	}
	reg, err := policy.New(dir, "default", nil)
	if err != nil {
		b.Fatal(err)
	}
	return reg
}
