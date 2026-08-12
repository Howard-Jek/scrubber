package store

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

// hangingReader never returns from Read. It models the failure this guard
// exists for: a connection that is established and then goes quiet, which
// produces no error and no EOF for a reader to notice.
type hangingReader struct{ release chan struct{} }

func (h *hangingReader) Read([]byte) (int, error) {
	<-h.release
	return 0, io.EOF
}

// TestStallGuardTripsOnSilence is the core contract: a transfer that moves no
// bytes is abandoned rather than waited on, and the context it was given is
// cancelled so the blocked read actually unwinds.
func TestStallGuardTripsOnSilence(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g := newStallGuard(20*time.Millisecond, cancel)
	defer g.stop()

	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("guard never tripped; a stalled transfer would wait forever")
	}
	if !g.stop() {
		t.Error("stop() must report that the guard tripped, so the caller can " +
			"distinguish a stall from an ordinary cancellation")
	}
}

// TestStallGuardHeldOffByProgress pins the other half: a slow transfer that is
// still moving must not be killed. A guard that cannot tell slow from stalled
// would abort exactly the large bundles this service exists to handle.
func TestStallGuardHeldOffByProgress(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g := newStallGuard(60*time.Millisecond, cancel)
	defer g.stop()

	// Dribble bytes for well past the timeout, never pausing long enough to trip.
	w := &stallWriter{w: io.Discard, g: g}
	for i := 0; i < 12; i++ {
		if _, err := w.Write([]byte("x")); err != nil {
			t.Fatalf("write: %v", err)
		}
		time.Sleep(15 * time.Millisecond)
	}
	if ctx.Err() != nil {
		t.Fatal("guard tripped on a transfer that was still moving bytes")
	}
	if g.stop() {
		t.Error("guard reported a stall for a transfer that never stalled")
	}
}

// TestStallGuardDisabled covers the escape hatch. A non-positive timeout must
// leave the transfer unguarded rather than trip immediately — the setting exists
// to prove a hang is happening, and a guard that fired at once would mask it.
func TestStallGuardDisabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g := newStallGuard(0, cancel)
	defer g.stop()

	time.Sleep(50 * time.Millisecond)
	if ctx.Err() != nil {
		t.Error("a disabled guard must never cancel the transfer")
	}
	if g.stop() {
		t.Error("a disabled guard must never report a stall")
	}
}

// TestStalledOrClassifies checks the mapping a caller depends on. Both a stall
// and a shutdown surface as context.Canceled from the copy, and reporting one as
// the other sends whoever reads the log to the wrong system.
func TestStalledOrClassifies(t *testing.T) {
	t.Run("stall becomes ErrStalled", func(t *testing.T) {
		_, cancel := context.WithCancel(context.Background())
		defer cancel()
		g := newStallGuard(5*time.Millisecond, cancel)
		time.Sleep(200 * time.Millisecond)
		err := stalledOr(g, context.Canceled)
		if !errors.Is(err, ErrStalled) {
			t.Fatalf("err = %v, want ErrStalled", err)
		}
		if !errors.Is(err, context.Canceled) {
			t.Error("the underlying cause must stay wrapped for debugging")
		}
	})

	t.Run("ordinary cancellation is left alone", func(t *testing.T) {
		_, cancel := context.WithCancel(context.Background())
		defer cancel()
		g := newStallGuard(time.Hour, cancel) // will not trip
		err := stalledOr(g, context.Canceled)
		if errors.Is(err, ErrStalled) {
			t.Fatal("a shutdown was misreported as a backend stall")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled unchanged", err)
		}
	})
}

// TestGuardedReadUnwinds is the end-to-end shape: a read that hangs forever is
// unblocked by the guard instead of blocking its caller indefinitely.
func TestGuardedReadUnwinds(t *testing.T) {
	h := &hangingReader{release: make(chan struct{})}
	defer close(h.release)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g := newStallGuard(30*time.Millisecond, cancel)
	defer g.stop()

	done := make(chan error, 1)
	go func() {
		// Mirrors the copy inside GetLimitedTo: a read that never returns, with
		// only the guard's cancellation available to end it.
		<-ctx.Done()
		done <- ctx.Err()
	}()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a hung transfer was not unwound")
	}
	_ = h
}
