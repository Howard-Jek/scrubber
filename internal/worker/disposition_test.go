package worker

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/howard/scrubber/internal/policy"
	"github.com/howard/scrubber/internal/store"
)

// failingStore fails the output write with an ordinary error -- the shape of a
// denied PutStream, which is the commonest way to reach the generic failure branch.
type failingStore struct {
	*memStore
	failOn string
	calls  int
}

func (f *failingStore) PutStream(ctx context.Context, bucket, key string, r io.Reader, size int64, ct string) error {
	if bucket == f.failOn {
		f.calls++
		return errors.New("access denied")
	}
	return f.memStore.PutStream(ctx, bucket, key, r, size, ct)
}

// clearBackoff expires the deferral without touching the attempt count, so a test
// can drive several attempts without sleeping through the real backoff.
func clearBackoff(w *Worker) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for k := range w.deferUntil {
		w.deferUntil[k] = time.Now().Add(-time.Second)
	}
}

// TestGenericFailureStepsAsideInsteadOfRetakingTheHead is the regression test for
// the queue trap.
//
// An ordinary error used to record and log and do nothing else. Because nothing
// called deferRetry, attempts stayed 0, and orderKey falls back to the object's
// LastModified for an object with no attempts -- which is by definition the oldest
// key still in the input bucket. So the failing object sorted to position 1 on the
// very next poll, ahead of every upload that had arrived while it was failing, and
// re-downloaded and re-walked the same bytes forever.
func TestGenericFailureStepsAsideInsteadOfRetakingTheHead(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	ms.Put(context.Background(), "input", "denied.log", []byte("hi from AcmeCorp\n"), "")

	fs := &failingStore{memStore: ms, failOn: "output"}
	w := newTestWorker(t, ms)
	w.store = fs
	w.runOnce(context.Background())

	if attemptsFor(w, "denied.log") == 0 {
		t.Fatal("no attempt recorded: attempts stays 0, so orderKey returns the object's " +
			"LastModified and it retakes the head of the queue on the next poll")
	}
	if w.eligible(store.Object{Key: "denied.log"}, time.Now()) {
		t.Error("failed object is immediately eligible again; it will retake the head of " +
			"the queue every cycle and hold everything behind it")
	}
	if !ms.has("input", "denied.log") {
		t.Error("a retryable failure must leave the input in place")
	}

	j, ok := w.jobs.Get("denied.log")
	if !ok {
		t.Fatal("no job recorded")
	}
	if j.Status != "retrying" {
		t.Errorf("status = %q, want retrying while attempts remain", j.Status)
	}
	if j.RetryInSeconds <= 0 {
		t.Errorf("RetryInSeconds = %d, want > 0 so the page can say when", j.RetryInSeconds)
	}
	if !strings.Contains(j.Error, "retried in") {
		t.Errorf("error text does not say what happens next: %q", j.Error)
	}
}

// TestSystemicFailureNeverEmptiesTheInputBucket guards the hazard that an attempt
// ceiling would have introduced while fixing the queue trap.
//
// A denied output write is not a property of the object -- it fails every object in
// the bucket at once, and it usually clears. If repeated failure retired inputs, a
// three-minute outage would move the entire backlog into processed/ UNSCRUBBED,
// where a consumer looking for finished work would pick it up. That is a far worse
// outcome than the stuck queue being fixed here, so ordinary errors back off
// forever and never step aside.
func TestSystemicFailureNeverEmptiesTheInputBucket(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	for _, k := range []string{"a.log", "b.log", "c.log"} {
		ms.Put(context.Background(), "input", k, []byte("hi from AcmeCorp\n"), "")
	}

	fs := &failingStore{memStore: ms, failOn: "output"}
	w := newTestWorker(t, ms)
	w.store = fs

	// Far more attempts than any ceiling would allow.
	for i := 0; i < maxAttempts*3; i++ {
		clearBackoff(w)
		w.runOnce(context.Background())
	}

	for _, k := range []string{"a.log", "b.log", "c.log"} {
		if !ms.has("input", k) {
			t.Errorf("%s left the input bucket during an outage that would have cleared", k)
		}
		if ms.has("input", "processed/"+k) {
			t.Errorf("%s was moved to processed/ unscrubbed; a consumer would treat it as finished", k)
		}
	}
}

// TestMissingDefaultPolicyDefersRatherThanRetires covers the other deployment-wide
// fault. A registry that cannot resolve anything fails every object, and it heals on
// its own -- watchPolicies hot-reloads the policy directory -- so these objects must
// still be in the bucket when it does.
func TestMissingDefaultPolicyDefersRatherThanRetires(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	ms.Put(context.Background(), "input", "app.log", []byte("hi from AcmeCorp\n"), "")

	w := newTestWorker(t, ms)
	// A registry that loaded fine but has no default policy and no prefix rule that
	// matches: Resolve walks to its final return and fails every object in the bucket.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "other.json"),
		[]byte(`{"literals":[{"value":"AcmeCorp","replacement":"[CO]"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := policy.New(dir, "", nil)
	if err != nil {
		t.Fatalf("registry with no default should still load: %v", err)
	}
	w.policies = reg
	w.runOnce(context.Background())

	if !ms.has("input", "app.log") {
		t.Error("input was retired for a deployment-wide policy fault that hot-reload can fix")
	}
	if ms.has("input", "processed/app.log") {
		t.Error("input was moved aside unscrubbed for a fault that is not the object's")
	}
	if attemptsFor(w, "app.log") == 0 {
		t.Error("no attempt recorded, so the object retakes the head of the queue")
	}
}

// TestUnresolvablePolicyRetiresImmediately covers the errors that no retry can fix.
// A malformed per-object sidecar is malformed on every attempt, so spending five
// attempts on it just delays the same outcome while holding a queue slot.
func TestUnresolvablePolicyRetiresImmediately(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	ms.Put(context.Background(), "input", "app.log", []byte("hi from AcmeCorp\n"), "")
	ms.Put(context.Background(), "input", "app.log"+termsSuffix, []byte("{not valid json"), "")

	w := newTestWorker(t, ms)
	w.runOnce(context.Background())

	if ms.has("input", "app.log") {
		t.Error("an unresolvable object was left in the input bucket; it will be retried forever")
	}
	if !ms.has("input", "processed/app.log") {
		t.Error("an unresolvable object was not moved aside")
	}
	if n := attemptsFor(w, "app.log"); n != 0 {
		t.Errorf("attempts = %d, want 0: this error is retired rather than retried", n)
	}
	j, ok := w.jobs.Get("app.log")
	if !ok {
		t.Fatal("no job recorded")
	}
	if j.Status != "error" {
		t.Errorf("status = %q, want error", j.Status)
	}
	if !strings.Contains(j.Error, "re-upload it once the cause is fixed") {
		t.Errorf("error text does not tell the operator what to do: %q", j.Error)
	}
}

// TestPanicStepsAsideInsteadOfLooping is the sharper half of the same trap. A panic
// is deterministic in the bytes that caused it, so an object that panics once panics
// on every poll -- a guaranteed loop writing a fresh stack trace each cycle.
func TestPanicStepsAsideInsteadOfLooping(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	ms.Put(context.Background(), "input", "boom.log", []byte("AcmeCorp\n"), "")

	ps := &panicStore{memStore: ms, panicOn: "output"}
	w := newTestWorker(t, ms)
	w.store = ps
	w.runOnce(context.Background())

	if attemptsFor(w, "boom.log") == 0 {
		t.Fatal("a panic recorded no attempt; the object retakes the head of the queue " +
			"and panics again on every poll, forever")
	}
	if w.eligible(store.Object{Key: "boom.log"}, time.Now()) {
		t.Error("panicking object is immediately eligible again")
	}

	// And it is eventually given up on rather than retried forever.
	for i := attemptsFor(w, "boom.log"); i < maxAttempts; i++ {
		clearBackoff(w)
		w.runOnce(context.Background())
	}
	if ms.has("input", "boom.log") {
		t.Errorf("input still present after %d panics; it will loop forever", maxAttempts)
	}
	if !ms.has("input", "processed/boom.log") {
		t.Error("a repeatedly panicking input was not moved aside")
	}
}
