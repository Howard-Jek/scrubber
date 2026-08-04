package queue

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// benchItems builds n items whose keys are anti-correlated with their arrival times,
// so Sync's sort has real work to do rather than confirming an already-sorted slice.
func benchItems(n int) []Item {
	items := make([]Item, n)
	for i := 0; i < n; i++ {
		items[i] = Item{
			Key:  fmt.Sprintf("%08d-upload.tar.gz", n-i),
			Size: 1 << 20,
			At:   base.Add(time.Duration(i) * time.Millisecond),
		}
	}
	return items
}

// BenchmarkSync measures the per-poll rebuild. This runs once per POLL_INTERVAL on
// the producer goroutine, so it needs to be a rounding error against the object it
// is about to hand to the consumer — seconds of scrubbing versus this.
func BenchmarkSync(b *testing.B) {
	for _, n := range []int{100, 1000, DefaultMax} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			items := benchItems(n)
			q := New(0)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				q.Sync(items)
			}
		})
	}
}

// BenchmarkPosition measures the cost of one /api/status answer. With 25 files
// queued and the browser polling every 1.2s this is called ~20x/sec, and it takes
// the same mutex the consumer needs, so it has to be cheap.
func BenchmarkPosition(b *testing.B) {
	for _, n := range []int{100, 1000, DefaultMax} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			items := benchItems(n)
			q := New(0)
			q.Sync(items)
			// Worst case: the key sits at the tail, so the scan runs the full list.
			tail := q.pending[len(q.pending)-1].Key
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				q.Position(tail)
			}
		})
	}
}

// BenchmarkPositionUnderSync is the contention case that matters: many browsers
// polling status while the producer re-syncs. If Position collapses here, a busy UI
// can starve the consumer on q.mu.
func BenchmarkPositionUnderSync(b *testing.B) {
	items := benchItems(1000)
	q := New(0)
	q.Sync(items)

	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				q.Sync(items)
			}
		}
	}()
	defer close(stop)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			q.Position("00000500-upload.tar.gz")
		}
	})
}

// BenchmarkNextThroughput measures the pop path, including the in-flight bookkeeping
// the consumer pays per object.
func BenchmarkNextThroughput(b *testing.B) {
	items := benchItems(1000)
	q := New(0)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if i%len(items) == 0 {
			b.StopTimer()
			q.Sync(items)
			b.StartTimer()
		}
		it, ok := q.Next(ctx)
		if !ok {
			b.Fatal("Next reported not-ok on a primed queue")
		}
		q.Done(it.Key)
	}
}
