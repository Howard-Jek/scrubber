package worker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/howard/scrubber/internal/metrics"
	"github.com/howard/scrubber/internal/pipeline"
	"github.com/prometheus/client_golang/prometheus"
)

// TestConcurrentConsumersScrubEveryObject drives the REAL consumer loop with
// several workers against a bucket of objects.
//
// Every other test in this package calls runOnce, which drains the queue on one
// goroutine — so the race detector never saw two scrubs in flight and the shared
// state between them was never exercised. That shared state is the whole risk of
// raising WORKERS: the in-flight registry, the process-wide spill reservation,
// the job ring, the queue, and one scrub.Matcher used by every consumer at once.
//
// Run this under -race or it proves much less than it looks like it does.
func TestConcurrentConsumersScrubEveryObject(t *testing.T) {
	const objects = 16
	ms := newMemStore("input", "output", "reports")
	for i := 0; i < objects; i++ {
		ms.Put(context.Background(), "input", fmt.Sprintf("obj-%02d.log", i),
			[]byte("host AcmeCorp mailed bob@acme.test about it\n"), "")
	}

	w := New(ms, testRegistry(t), metrics.New(prometheus.NewRegistry()),
		metrics.NewJobLog(64),
		Config{
			InputBucket: "input", OutputBucket: "output", ReportsBucket: "reports",
			Action: ActionMove, PollInterval: 10 * time.Millisecond,
			Workers: 4, RedactReports: true, Limits: pipeline.DefaultLimits(),
		},
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	if w.cfg.Workers != 4 {
		t.Fatalf("Workers = %d, want 4; the rest of this test proves nothing", w.cfg.Workers)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); w.Run(ctx) }()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if countOutputs(ms, objects) == objects {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after its context was cancelled; a consumer is wedged")
	}

	if got := countOutputs(ms, objects); got != objects {
		t.Fatalf("scrubbed %d of %d objects with 4 consumers", got, objects)
	}
	// Every one actually scrubbed, and the input disposed of exactly once.
	for i := 0; i < objects; i++ {
		key := fmt.Sprintf("obj-%02d.log", i)
		out, err := ms.Get(context.Background(), "output", key)
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		if bytes.Contains(out, []byte("AcmeCorp")) || bytes.Contains(out, []byte("bob@acme.test")) {
			t.Errorf("%s went out unscrubbed under concurrency: %q", key, out)
		}
		if ms.has("input", key) {
			t.Errorf("%s was left in the input bucket; it would be scrubbed again", key)
		}
		if !ms.has("input", "processed/"+key) {
			t.Errorf("%s was not moved aside", key)
		}
	}
}

func countOutputs(ms *memStore, n int) int {
	got := 0
	for i := 0; i < n; i++ {
		if ms.has("output", fmt.Sprintf("obj-%02d.log", i)) {
			got++
		}
	}
	return got
}
