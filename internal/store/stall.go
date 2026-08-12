package store

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// ErrStalled reports that a transfer stopped moving bytes for longer than the
// configured stall timeout, and was abandoned rather than waited on.
//
// It exists because the alternative is an unbounded wait. A read from object
// storage runs on the worker's long-lived context, so a connection that accepts
// the request and then goes quiet — a dropped path with no RST, a backend that
// stops writing mid-body, a load balancer that silently blackholes an
// established flow — blocks the single consumer forever. Nothing upstream
// notices: /healthz is a pure liveness signal, /readyz reports a *new*
// connection succeeding, and every per-file progress counter is pinned at zero
// because no file has been read yet. One such object wedges the whole queue.
var ErrStalled = errors.New("transfer stalled")

// defaultStallTimeout is how long a transfer may move no bytes at all before it
// is treated as wedged.
//
// This is deliberately not a deadline on the whole transfer. A large object over
// a congested link legitimately takes minutes, and any fixed deadline generous
// enough not to kill that is too generous to catch a hang worth catching. What
// separates the two cases is not elapsed time but whether *anything* is still
// arriving, so that is what is measured.
const defaultStallTimeout = 60 * time.Second

// defaultListTimeout bounds one bucket listing.
//
// Sized against the listing rather than against the network: paginating a large
// input bucket (which includes processed/) is legitimately slower than any point
// operation, but not minutes-slower. The previous derivation of 10x the stall
// timeout put this at ten minutes by default, during which a dead backend looked
// idle rather than broken.
const defaultListTimeout = 90 * time.Second

// stallGuard cancels a transfer's context when nothing has moved for timeout.
//
// The timer starts on construction, not on the first byte, so a request that
// never produces a response header is caught by the same mechanism as one that
// dies halfway through the body.
type stallGuard struct {
	timeout time.Duration
	cancel  context.CancelFunc

	// moved counts bytes transferred, purely so the error can say how far the
	// transfer got. "Stalled after 0 bytes" and "stalled after 900 MB" send an
	// operator to different places — the first is a connection that never
	// delivered, the second one that died partway.
	moved atomic.Int64

	mu      sync.Mutex
	timer   *time.Timer
	fired   bool
	stopped bool
}

func newStallGuard(timeout time.Duration, cancel context.CancelFunc) *stallGuard {
	g := &stallGuard{timeout: timeout, cancel: cancel}
	if timeout <= 0 {
		return g // disabled
	}
	g.timer = time.AfterFunc(timeout, g.trip)
	return g
}

// trip records the stall and cancels the transfer. Cancelling is what actually
// unblocks the reader: the HTTP body read returns context.Canceled, which
// unwinds the copy.
func (g *stallGuard) trip() {
	g.mu.Lock()
	if g.stopped {
		g.mu.Unlock()
		return
	}
	g.fired = true
	g.mu.Unlock()
	g.cancel()
}

// progress restarts the clock. Called for every non-empty chunk transferred.
func (g *stallGuard) progress(n int) {
	g.moved.Add(int64(n))
	if g.timer == nil {
		return
	}
	g.mu.Lock()
	if !g.fired && !g.stopped {
		g.timer.Reset(g.timeout)
	}
	g.mu.Unlock()
}

// bytesMoved reports how far the transfer got before it stopped.
func (g *stallGuard) bytesMoved() int64 { return g.moved.Load() }

// stop ends the watch and reports whether the guard had already tripped. It is
// idempotent so it can be deferred and also consulted on the error path.
//
// The return value is what lets a caller tell a stall from an ordinary
// cancellation: both surface as context.Canceled from the copy, and reporting a
// shutdown as a backend stall — or a backend stall as a shutdown — sends
// whoever reads the log to the wrong place.
func (g *stallGuard) stop() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.stopped = true
	if g.timer != nil {
		g.timer.Stop()
	}
	return g.fired
}

// stallWriter is the destination side of a guarded transfer: bytes arriving from
// object storage reset the clock as they are written out.
type stallWriter struct {
	w io.Writer
	g *stallGuard
}

func (s *stallWriter) Write(p []byte) (int, error) {
	n, err := s.w.Write(p)
	if n > 0 {
		s.g.progress(n)
	}
	return n, err
}

// stallReader is the source side. On an upload the bytes are already in hand, so
// what stalls is the client draining them; a Read that is never called again is
// the same signal as a Write that never arrives.
type stallReader struct {
	r io.Reader
	g *stallGuard
}

func (s *stallReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if n > 0 {
		s.g.progress(n)
	}
	return n, err
}
