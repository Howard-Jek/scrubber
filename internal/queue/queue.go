// Package queue is the strict first-come-first-serve pending set that sits between
// the worker's discovery pass and its single consumer.
//
// It deliberately imports nothing from internal/: it holds no object bytes, knows
// nothing about MinIO or policies, and can be exercised on its own in milliseconds.
// Filtering (sidecars, already-processed keys, finalize backoff) belongs to the
// caller, which passes an already-filtered listing to Sync.
//
// The queue is a *derived* view of the input bucket, not durable state. The bucket
// is the real queue: on restart, the first Sync rebuilds the pending order from the
// listing and nothing is lost.
package queue

import (
	"context"
	"sort"
	"sync"
	"time"
)

// DefaultMax is the pending-set cap. It exists to bound memory if a bucket is
// pathologically large, not to shed work: anything truncated is still sitting in the
// bucket and returns on a later Sync.
const DefaultMax = 10000

// Item is one unit of pending work.
//
// At is the ordering key. For a first attempt it is the object's LastModified —
// the moment its upload completed, taken from the object store's clock so there is
// no client skew to reconcile. For a key being retried after a failed finalize it
// is the moment the key became eligible again, which is what keeps a stuck object
// at the back of the queue instead of at the head: its LastModified is by
// definition the oldest in the bucket, so ordering retries by it would let one
// unmovable object re-run ahead of everyone else on every backoff expiry.
type Item struct {
	Key  string
	Size int64
	At   time.Time
}

// State reports where a key sits relative to the queue.
type State int

const (
	StateAbsent  State = iota // neither pending nor running here
	StateQueued               // waiting; Position and depth are meaningful
	StateRunning              // popped, being processed right now
)

// Queue is an arrival-ordered pending set with an in-flight registry.
//
// Safe for concurrent use: the producer calls Sync, the consumer calls Next/Done,
// and the HTTP handlers call Position/Depth on every client poll.
type Queue struct {
	max int

	mu       sync.Mutex
	pending  []Item
	inflight map[string]time.Time // key -> when it was popped

	// notify wakes a blocked Next when Sync adds work. Buffered so Sync never
	// blocks on a consumer that is busy scrubbing.
	notify chan struct{}

	// truncated is the size of the last listing that overflowed max, or 0. The
	// caller reads it to log the drop; a silently capped queue reads as
	// "everything is queued" when it is not.
	truncated int
}

// New builds an empty queue holding at most max pending items (<=0 uses DefaultMax).
func New(max int) *Queue {
	if max <= 0 {
		max = DefaultMax
	}
	return &Queue{
		max:      max,
		inflight: map[string]time.Time{},
		notify:   make(chan struct{}, 1),
	}
}

// Sync replaces the pending set with items, ordered by (At, Key), dropping anything
// currently in flight.
//
// It rebuilds rather than appends on purpose. Rebuilding is what makes a key deleted
// out from under us disappear, what restores the correct order after a restart, and
// what lets a retry take its new place once the caller has recomputed its At.
//
// It returns the number of pending items that were dropped because they exceeded the
// cap, so the caller can log it.
func (q *Queue) Sync(items []Item) (dropped int) {
	next := make([]Item, 0, len(items))

	q.mu.Lock()
	for _, it := range items {
		if _, running := q.inflight[it.Key]; running {
			continue
		}
		next = append(next, it)
	}
	// (At, Key) is a total order. The key tiebreak is load-bearing, not cosmetic:
	// some S3 backends report LastModified only to the second, and without a total
	// order the same listing could sort differently on consecutive polls and a
	// client's queue position would jitter backwards.
	sort.Slice(next, func(i, j int) bool {
		if !next[i].At.Equal(next[j].At) {
			return next[i].At.Before(next[j].At)
		}
		return next[i].Key < next[j].Key
	})
	if len(next) > q.max {
		dropped = len(next) - q.max
		next = next[:q.max] // keep the earliest arrivals
	}
	q.truncated = dropped
	q.pending = next
	hasWork := len(next) > 0
	q.mu.Unlock()

	if hasWork {
		select {
		case q.notify <- struct{}{}:
		default: // a wake-up is already pending; one is enough
		}
	}
	return dropped
}

// TryNext pops the head without blocking and marks it in flight. The caller must
// call Done for every item it receives.
func (q *Queue) TryNext() (Item, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.pending) == 0 {
		return Item{}, false
	}
	it := q.pending[0]
	q.pending = q.pending[1:]
	q.inflight[it.Key] = time.Now()
	return it, true
}

// Next blocks until an item is pending or ctx is done, then pops it and marks it in
// flight. The caller must call Done for every item it receives.
//
// Cancellation is checked before each pop, not only while waiting: a cancelled
// consumer with a full backlog must stop taking work rather than drain it. Starting
// a fresh object during shutdown means scrubbing it twice, since the process is
// killed before it can finish.
func (q *Queue) Next(ctx context.Context) (Item, bool) {
	for {
		if ctx.Err() != nil {
			return Item{}, false
		}
		if it, ok := q.TryNext(); ok {
			return it, true
		}
		// A cancellable wait is why this is a channel and not a sync.Cond: a Cond
		// cannot be woken by context cancellation, so shutdown would hang here.
		select {
		case <-ctx.Done():
			return Item{}, false
		case <-q.notify:
		}
	}
}

// Done clears the in-flight mark for key, making it eligible for a later Sync again
// (which is how an object whose finalize failed comes back around).
func (q *Queue) Done(key string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.inflight, key)
}

// Position reports where key sits.
//
// pos is 1-based and counts the in-flight object as position 1, so while something
// is being scrubbed the head of the pending list correctly reads "2 of N". depth is
// pending plus in-flight. For an absent key pos is 0.
//
// The pending scan is linear. That is deliberate: this is called once per client
// status poll, where realistic depths are tens of objects (~350ns, no allocations —
// see BenchmarkPosition), and keeping a position index in sync would cost every
// Sync more than it saves here.
func (q *Queue) Position(key string) (pos, depth int, state State) {
	q.mu.Lock()
	defer q.mu.Unlock()
	depth = len(q.pending) + len(q.inflight)
	if _, running := q.inflight[key]; running {
		return 1, depth, StateRunning
	}
	for i, it := range q.pending {
		if it.Key == key {
			return i + 1 + len(q.inflight), depth, StateQueued
		}
	}
	return 0, depth, StateAbsent
}

// Depth is pending plus in-flight.
func (q *Queue) Depth() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.pending) + len(q.inflight)
}

// Inflight is the number of objects being processed right now (0 or 1 for the
// single-consumer worker).
func (q *Queue) Inflight() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.inflight)
}

// Snapshot returns the in-flight keys and up to limit pending keys, in queue order.
// Used by the operator-facing /api/queue endpoint.
func (q *Queue) Snapshot(limit int) (inflight, pending []string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for k := range q.inflight {
		inflight = append(inflight, k)
	}
	sort.Strings(inflight)
	if limit <= 0 || limit > len(q.pending) {
		limit = len(q.pending)
	}
	pending = make([]string, 0, limit)
	for _, it := range q.pending[:limit] {
		pending = append(pending, it.Key)
	}
	return inflight, pending
}
