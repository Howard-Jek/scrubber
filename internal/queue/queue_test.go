package queue

import (
	"context"
	"testing"
	"time"
)

var base = time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

func at(sec int) time.Time { return base.Add(time.Duration(sec) * time.Second) }

func item(key string, sec int) Item { return Item{Key: key, Size: 1, At: at(sec)} }

// drain pops everything currently pending, marking each done immediately, and
// returns the order.
func drain(q *Queue) []string {
	var got []string
	for {
		it, ok := q.TryNext()
		if !ok {
			return got
		}
		got = append(got, it.Key)
		q.Done(it.Key)
	}
}

func eq(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func TestQueueOrdersByArrivalNotKey(t *testing.T) {
	q := New(0)
	// Keys are deliberately anti-lexicographic against their arrival times, so a
	// stray sort by key (which is what MinIO's listing gives us) fails loudly.
	q.Sync([]Item{item("zzz", 0), item("aaa", 2), item("mmm", 1)})
	eq(t, drain(q), []string{"zzz", "mmm", "aaa"})
}

func TestQueueTieBreaksByKey(t *testing.T) {
	q := New(0)
	q.Sync([]Item{item("c", 5), item("a", 5), item("b", 5)})
	eq(t, drain(q), []string{"a", "b", "c"})

	// Stability: the same set presented in a different order must sort identically,
	// or a client's position would jitter between polls.
	q2 := New(0)
	q2.Sync([]Item{item("b", 5), item("c", 5), item("a", 5)})
	eq(t, drain(q2), []string{"a", "b", "c"})
}

func TestQueueSyncDropsVanishedKeys(t *testing.T) {
	q := New(0)
	q.Sync([]Item{item("a", 0), item("b", 1), item("c", 2)})
	q.Sync([]Item{item("a", 0), item("c", 2)}) // b deleted out from under us

	if _, _, st := q.Position("b"); st != StateAbsent {
		t.Errorf("Position(b) state = %v, want StateAbsent", st)
	}
	if got := q.Depth(); got != 2 {
		t.Errorf("Depth = %d, want 2", got)
	}
	eq(t, drain(q), []string{"a", "c"})
}

func TestQueueSyncKeepsInFlightOut(t *testing.T) {
	q := New(0)
	q.Sync([]Item{item("a", 0), item("b", 1), item("c", 2)})

	got, ok := q.TryNext()
	if !ok || got.Key != "a" {
		t.Fatalf("TryNext = %q, %v; want a, true", got.Key, ok)
	}
	// "a" is still listed because finish() has not run yet. It must not be handed
	// out a second time.
	q.Sync([]Item{item("a", 0), item("b", 1), item("c", 2)})
	if d := q.Depth(); d != 3 {
		t.Errorf("Depth = %d, want 3 (2 pending + 1 in flight)", d)
	}
	eq(t, drain(q), []string{"b", "c"})
}

func TestQueueDoneReleasesInFlight(t *testing.T) {
	q := New(0)
	q.Sync([]Item{item("a", 0)})
	it, _ := q.TryNext()
	q.Done(it.Key)

	// After Done, a listing that still contains the key re-admits it. This is the
	// path an object takes when its finalize failed and it must be retried.
	q.Sync([]Item{item("a", 0)})
	eq(t, drain(q), []string{"a"})
}

func TestQueuePositionCountsInFlight(t *testing.T) {
	q := New(0)
	q.Sync([]Item{item("a", 0), item("b", 1), item("c", 2)})
	q.TryNext() // a is now running

	if pos, depth, st := q.Position("a"); pos != 1 || depth != 3 || st != StateRunning {
		t.Errorf("Position(a) = %d, %d, %v; want 1, 3, StateRunning", pos, depth, st)
	}
	if pos, depth, st := q.Position("b"); pos != 2 || depth != 3 || st != StateQueued {
		t.Errorf("Position(b) = %d, %d, %v; want 2, 3, StateQueued", pos, depth, st)
	}
	if pos, depth, st := q.Position("c"); pos != 3 || depth != 3 || st != StateQueued {
		t.Errorf("Position(c) = %d, %d, %v; want 3, 3, StateQueued", pos, depth, st)
	}
	if pos, _, st := q.Position("nope"); pos != 0 || st != StateAbsent {
		t.Errorf("Position(nope) = %d, %v; want 0, StateAbsent", pos, st)
	}
}

// TestQueuePositionNeverIncreases pins the invariant the UI depends on. A position
// that goes up reads to a user as the service losing their upload.
func TestQueuePositionNeverIncreases(t *testing.T) {
	q := New(0)
	watched := "watch-me"
	items := []Item{item("a", 0), item("b", 1), item(watched, 2), item("d", 3)}
	q.Sync(items)

	prev, _, _ := q.Position(watched)

	for round := 0; round < 4; round++ {
		it, ok := q.TryNext()
		if !ok {
			break
		}
		if it.Key == watched {
			break
		}
		q.Done(it.Key)

		// Remove the finished key and add a brand-new later arrival, exactly as a
		// fresh listing would.
		var next []Item
		for _, cand := range items {
			if cand.Key != it.Key {
				next = append(next, cand)
			}
		}
		next = append(next, item("late-"+it.Key, 100+round))
		items = next
		q.Sync(items)

		pos, _, st := q.Position(watched)
		if st != StateQueued {
			t.Fatalf("round %d: watched key state = %v, want StateQueued", round, st)
		}
		if pos > prev {
			t.Fatalf("round %d: position rose from %d to %d", round, prev, pos)
		}
		prev = pos
	}
}

func TestQueueNextBlocksUntilWorkArrives(t *testing.T) {
	q := New(0)
	ch := make(chan string, 1)
	go func() {
		it, ok := q.Next(context.Background())
		if ok {
			ch <- it.Key
		}
	}()

	select {
	case k := <-ch:
		t.Fatalf("Next returned %q on an empty queue", k)
	case <-time.After(50 * time.Millisecond):
	}

	q.Sync([]Item{item("a", 0)})
	select {
	case k := <-ch:
		if k != "a" {
			t.Errorf("Next = %q, want a", k)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Next did not wake after Sync")
	}
}

func TestQueueNextUnblocksOnContextCancel(t *testing.T) {
	q := New(0)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool, 1)
	go func() {
		_, ok := q.Next(ctx)
		done <- ok
	}()

	cancel()
	select {
	case ok := <-done:
		if ok {
			t.Error("Next reported ok=true after cancellation")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Next did not return after context cancellation")
	}
}

func TestQueueMaxKeepsEarliest(t *testing.T) {
	q := New(3)
	dropped := q.Sync([]Item{item("e", 4), item("a", 0), item("d", 3), item("b", 1), item("c", 2)})
	if dropped != 2 {
		t.Errorf("dropped = %d, want 2", dropped)
	}
	eq(t, drain(q), []string{"a", "b", "c"})
}

func TestQueueSnapshot(t *testing.T) {
	q := New(0)
	q.Sync([]Item{item("a", 0), item("b", 1), item("c", 2)})
	q.TryNext()

	inflight, pending := q.Snapshot(1)
	if len(inflight) != 1 || inflight[0] != "a" {
		t.Errorf("inflight = %v, want [a]", inflight)
	}
	if len(pending) != 1 || pending[0] != "b" {
		t.Errorf("pending = %v, want [b]", pending)
	}
}

// TestQueueConcurrentSyncAndNext is the -race canary: producers and a consumer hit
// the same mutex from different goroutines on every poll in production.
func TestQueueConcurrentSyncAndNext(t *testing.T) {
	q := New(0)
	const total = 200

	all := make([]Item, 0, total)
	for i := 0; i < total; i++ {
		all = append(all, Item{Key: string(rune('a'+i%26)) + "-" + time.Duration(i).String(), At: at(i)})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stop := make(chan struct{})
	for w := 0; w < 4; w++ {
		go func() {
			for {
				select {
				case <-stop:
					return
				default:
					q.Sync(all)
				}
			}
		}()
	}

	seen := map[string]int{}
	for i := 0; i < 100; i++ {
		it, ok := q.Next(ctx)
		if !ok {
			t.Fatal("Next reported not-ok while producers were active")
		}
		seen[it.Key]++
		q.Done(it.Key)
	}
	close(stop)

	// A key may legitimately repeat: Done releases it and a concurrent Sync
	// re-admits it, which is the retry path. What must not happen is a panic or a
	// data race, which -race asserts for us.
	if len(seen) == 0 {
		t.Fatal("no items delivered")
	}
}
