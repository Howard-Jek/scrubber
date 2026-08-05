// Package spill keeps large payloads out of the heap.
//
// The scrubber handles one object at a time, but a single object is an archive: its
// members, their scrubbed replacements, and the repacked container were all live at
// once, which made resident memory a multiple of the bundle size and put a ~500MiB
// upload out of reach on a 2GiB pod. A Blob is the unit that fixes that — small
// payloads stay on the heap where they are cheap, large ones go to a temp file, and
// the pipeline materialises only the one it is scrubbing right now.
//
// A spilled Blob holds a *path*, not an open file. That matters: an archive may
// legitimately carry 100000 members (MAX_MEMBERS), and holding a descriptor per
// member would trade an out-of-memory failure for an out-of-descriptors one.
//
// Temp files are created with os.CreateTemp(""), which honours TMPDIR. The container
// sets TMPDIR=/work (an emptyDir), so spilled data lands on the pod's ephemeral
// volume with no extra plumbing — but that volume then needs a sizeLimit, because
// the expansion budget now bounds mostly disk rather than memory, and an
// ephemeral-storage eviction kills a pod just as dead as an OOM.
package spill

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

// ErrTooLarge is returned when a stream exceeds the budget it was read under. It
// mirrors archive.ErrTooLarge so a caller can treat a spill overrun exactly like a
// decompression overrun: pass the container through, flagged, rather than fail.
var ErrTooLarge = errors.New("payload exceeds size limit")

// ErrSpill wraps any filesystem failure while spilling — no space, read-only mount,
// too many open files. It is deliberately distinct from ErrTooLarge and from a
// malformed-container error: the pipeline must be able to tell "this bundle is
// hostile" from "this pod is out of disk", because they are different operational
// problems and only one of them is the uploader's fault.
var ErrSpill = errors.New("could not spill to disk")

// DefaultPolicy is the sizing used when a caller supplies none.
var DefaultPolicy = Policy{Threshold: 4 << 20, ResidentMax: 64 << 20}

// Policy decides which payloads stay in memory.
//
// Two limits, because one is not enough. Threshold alone gets the many-small-members
// shape wrong: twenty thousand 4KiB members never trip a per-payload size limit
// individually while still holding the whole bundle on the heap — and that is
// measured as the *worst* shape in the pipeline's memory matrix, not a hypothetical.
// ResidentMax bounds the aggregate: once in-memory blobs exceed it, everything
// subsequent spills however small it is.
type Policy struct {
	// Threshold is the largest payload kept in memory. <=0 spills everything.
	Threshold int64
	// ResidentMax is the total in-memory budget across live blobs. <=0 disables the
	// aggregate check.
	ResidentMax int64
}

func (p Policy) normalise() Policy {
	if p.Threshold <= 0 && p.ResidentMax <= 0 {
		return DefaultPolicy
	}
	return p
}

// resident tracks aggregate in-memory bytes held by live blobs. Process-wide on
// purpose: the worker scrubs one object at a time, so a single counter is exactly
// the budget that matters, and threading an allocator through every archive call
// site would buy nothing.
var resident struct {
	mu    sync.Mutex
	bytes int64
}

func reserve(n int64, p Policy) bool {
	if p.ResidentMax <= 0 {
		return true
	}
	resident.mu.Lock()
	defer resident.mu.Unlock()
	if resident.bytes+n > p.ResidentMax {
		return false
	}
	resident.bytes += n
	return true
}

func release(n int64) {
	resident.mu.Lock()
	defer resident.mu.Unlock()
	if resident.bytes -= n; resident.bytes < 0 {
		resident.bytes = 0
	}
}

// Resident reports in-memory bytes currently held by live blobs.
func Resident() int64 {
	resident.mu.Lock()
	defer resident.mu.Unlock()
	return resident.bytes
}

// Blob is a payload held in memory or in a temp file. The zero value is a valid
// empty payload. Not safe for concurrent use; the pipeline is single-threaded per
// object by design.
type Blob struct {
	mem    []byte
	path   string
	size   int64
	closed bool
}

// Empty returns a zero-length blob.
func Empty() *Blob { return &Blob{} }

// FromBytes wraps b, spilling if the policy calls for it. Ownership of b transfers
// to the Blob: do not mutate it afterwards.
func FromBytes(b []byte, p Policy) (*Blob, error) {
	p = p.normalise()
	n := int64(len(b))
	if n <= p.Threshold && reserve(n, p) {
		return &Blob{mem: b, size: n}, nil
	}
	f, err := os.CreateTemp("", "scrubber-*")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSpill, err)
	}
	name := f.Name()
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(name)
		return nil, fmt.Errorf("%w: %v", ErrSpill, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(name)
		return nil, fmt.Errorf("%w: %v", ErrSpill, err)
	}
	return &Blob{path: name, size: n}, nil
}

// FromReader consumes r, reading at most max bytes, returning ErrTooLarge if the
// stream is longer.
//
// The cap is enforced while reading, never after, so a decompression bomb is stopped
// by the ceiling rather than discovered once it has already been buffered. That is
// the same contract archive.readCapped has, extended to disk. Note max<=0 is
// ErrTooLarge, matching readCapped exactly — a shrinking budget that reaches zero
// rejects the next member even if it is empty, and the guard tests pin that.
func FromReader(r io.Reader, max int64, p Policy) (*Blob, error) {
	p = p.normalise()
	if max <= 0 {
		return nil, ErrTooLarge
	}

	// Buffer up to the in-memory threshold first: most payloads are small and never
	// touch the filesystem, which is what keeps a 20000-member archive from creating
	// 20000 files.
	head := p.Threshold
	if head > max {
		head = max
	}
	var buf bytes.Buffer
	n, err := io.CopyN(&buf, r, head)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if err == io.EOF {
		return FromBytes(buf.Bytes(), p)
	}

	// More to come. Spill, still under the cap.
	f, ferr := os.CreateTemp("", "scrubber-*")
	if ferr != nil {
		return nil, fmt.Errorf("%w: %v", ErrSpill, ferr)
	}
	name := f.Name()
	if _, werr := f.Write(buf.Bytes()); werr != nil {
		f.Close()
		os.Remove(name)
		return nil, fmt.Errorf("%w: %v", ErrSpill, werr)
	}
	// max-n+1 so exceeding the budget is detected rather than silently truncated.
	copied, cerr := io.CopyN(f, r, max-n+1)
	if closeErr := f.Close(); cerr == nil && closeErr != nil {
		cerr = closeErr
	}
	if cerr != nil && cerr != io.EOF {
		os.Remove(name)
		// A short write here is a disk problem, not a hostile bundle.
		return nil, fmt.Errorf("%w: %v", ErrSpill, cerr)
	}
	total := n + copied
	if total > max {
		os.Remove(name)
		return nil, ErrTooLarge
	}
	return &Blob{path: name, size: total}, nil
}

// Create returns a blob backed by a fresh temp file plus the writer to fill it. The
// caller must close the writer, then call Done to publish the size. Used by the
// repack path, which streams an archive out without ever holding it whole.
func Create() (*Blob, *os.File, error) {
	f, err := os.CreateTemp("", "scrubber-*")
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrSpill, err)
	}
	return &Blob{path: f.Name()}, f, nil
}

// Done records the final size of a blob created with Create.
func (b *Blob) Done(size int64) { b.size = size }

// Size is the payload length in bytes.
func (b *Blob) Size() int64 {
	if b == nil {
		return 0
	}
	return b.size
}

// Spilled reports whether this blob is file-backed rather than heap-backed.
func (b *Blob) Spilled() bool { return b != nil && b.path != "" }

// Bytes materialises the payload.
//
// This is the one operation that puts a whole payload back on the heap, so the
// pipeline calls it for exactly one member at a time: the leaf scrubber needs a
// contiguous string and nothing else does.
func (b *Blob) Bytes() ([]byte, error) {
	if b == nil {
		return nil, nil
	}
	if b.path == "" {
		return b.mem, nil
	}
	return os.ReadFile(b.path)
}

// Head returns up to n leading bytes without materialising the whole payload —
// enough for format sniffing (512B) and binary detection (8KiB).
func (b *Blob) Head(n int) ([]byte, error) {
	if b == nil {
		return nil, nil
	}
	if b.path == "" {
		if int64(n) > b.size {
			n = int(b.size)
		}
		return b.mem[:n], nil
	}
	f, err := os.Open(b.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	head := make([]byte, n)
	read, err := io.ReadFull(f, head)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	return head[:read], nil
}

// Reader returns a reader over the payload. The caller must Close it.
func (b *Blob) Reader() (io.ReadCloser, error) {
	if b == nil {
		return io.NopCloser(bytes.NewReader(nil)), nil
	}
	if b.path == "" {
		return io.NopCloser(bytes.NewReader(b.mem)), nil
	}
	return os.Open(b.path)
}

// ReaderAt returns random access over the payload, which zip needs because its
// central directory lives at the end. The caller must Close it.
func (b *Blob) ReaderAt() (io.ReaderAt, io.Closer, error) {
	if b == nil {
		return bytes.NewReader(nil), io.NopCloser(nil), nil
	}
	if b.path == "" {
		return bytes.NewReader(b.mem), io.NopCloser(nil), nil
	}
	f, err := os.Open(b.path)
	if err != nil {
		return nil, nil, err
	}
	return f, f, nil
}

// Close releases the blob: unlinks the temp file, or returns its heap budget.
//
// Safe to call repeatedly and safe on nil, because the pipeline's error paths and
// the worker's panic recovery both unwind through defers that overlap.
func (b *Blob) Close() error {
	if b == nil || b.closed {
		return nil
	}
	b.closed = true
	if b.path != "" {
		path := b.path
		b.path = ""
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	release(int64(len(b.mem)))
	b.mem = nil
	return nil
}
