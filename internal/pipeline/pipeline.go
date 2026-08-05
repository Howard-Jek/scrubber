// Package pipeline performs the recursive walk over a bundle: detect format,
// unpack containers, scrub text leaves, repack, and at every node fall back to a
// verbatim passthrough of the original bytes if anything goes wrong. This is where
// the "never produce a corrupted or half-scrubbed bundle" guarantee lives.
//
// Payloads move through the walk as spill.Blobs, not byte slices. Only the leaf
// currently being scrubbed is materialised on the heap; every other member, the
// decompressed container and the repacked result live on disk when large. That is
// what makes a several-hundred-MiB bundle fit a 2GiB pod: resident memory tracks the
// biggest single member rather than the whole archive.
package pipeline

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/howard/scrubber/internal/archive"
	"github.com/howard/scrubber/internal/detect"
	"github.com/howard/scrubber/internal/report"
	"github.com/howard/scrubber/internal/scrub"
	"github.com/howard/scrubber/internal/spill"
)

// Limits bounds resource use to defuse decompression bombs and quines.
//
// There is deliberately no expansion-ratio limit. Ratio cannot separate a bomb
// from an ordinary log: real-world log files compress at 200:1 to 1000:1, so any
// ratio threshold low enough to catch a bomb also rejects the tool's primary
// input — and rejection means the file is emitted UNSCRUBBED. Memory is bounded
// instead by MaxTotalBytes, enforced while reading, which is a true bound.
type Limits struct {
	MaxDepth int // maximum container nesting depth
	// MaxTotalBytes is the cumulative expansion budget for one top-level object:
	// the total decompressed bytes the engine will read across every nested stream
	// and archive member.
	//
	// Note this bounds bytes *read*, and since members now spill it bounds mostly
	// DISK rather than resident memory. Size the pod's scratch volume against it,
	// not just the memory limit — an ephemeral-storage eviction kills a pod as dead
	// as an OOM.
	MaxTotalBytes int64
	MaxMembers    int // maximum entries in a single archive
	// Spill decides which payloads stay on the heap. The zero value uses
	// spill.DefaultPolicy.
	Spill spill.Policy
}

// DefaultLimits returns conservative defaults.
func DefaultLimits() Limits {
	return Limits{MaxDepth: 16, MaxTotalBytes: 2 << 30, MaxMembers: 100000}
}

// Engine carries the compiled rules, the report sink, and the limits.
//
// An Engine is single-use per top-level object and is not safe for concurrent
// Process calls; the expansion budget is engine state. The worker builds one per
// object, and the CLI reuses one sequentially (the budget resets at depth 0).
type Engine struct {
	Matcher    *scrub.Matcher
	Report     *report.Report
	Limits     Limits
	ScrubNames bool // also scrub archive member names / paths, not just contents

	// budget is the remaining cumulative expansion allowance, reset on each
	// depth-0 Process call.
	budget int64
	// staged holds every blob this walk created, so that a panic cannot orphan a
	// temp file. Each normal path closes its own blobs the moment they are dead;
	// this is the backstop for the abnormal one, and Blob.Close is idempotent so
	// the two never conflict. The service recovers from panics rather than dying,
	// which is exactly what turns "one orphaned file" into "a full scratch volume
	// a week later".
	staged []*spill.Blob
}

// stageNew stages a blob from a constructor that may have failed.
func (e *Engine) stageNew(b *spill.Blob, err error) (*spill.Blob, error) {
	if err != nil {
		return nil, err
	}
	return e.stage(b), nil
}

// stageCreated stages a blob from spill.Create, which also yields its writer.
func (e *Engine) stageCreated(b *spill.Blob, w *os.File, err error) (*spill.Blob, *os.File, error) {
	if err != nil {
		return nil, nil, err
	}
	return e.stage(b), w, nil
}

// stage records a blob this engine created and returns it unchanged.
func (e *Engine) stage(b *spill.Blob) *spill.Blob {
	e.staged = append(e.staged, b)
	return b
}

// Release closes every blob the engine staged during its walk.
//
// Callers of ProcessBlob must defer this; Process does it for you. It is safe to
// call more than once and safe to call while still holding the result of a walk
// only if that result has already been consumed — Release closes it too.
func (e *Engine) Release() {
	for _, b := range e.staged {
		b.Close()
	}
	e.staged = nil
}

// take draws n bytes from the expansion budget.
func (e *Engine) take(n int64) { e.budget -= n }

// scrubMemberName scrubs an archive entry's name (when enabled), records any hits,
// and reports whether the name changed. origPath is the report label.
func (e *Engine) scrubMemberName(origPath, name string, inBytes int64) (string, bool) {
	if !e.ScrubNames {
		return name, false
	}
	newName, matches := e.Matcher.ScrubName(name)
	if len(matches) == 0 {
		return name, false
	}
	e.Report.Record(origPath+" [name]", report.StatusScrubbed, "filename scrubbed", int(inBytes), len(newName), matches)
	return newName, true
}

// Process transforms one stream (file or archive) and returns the result. It never
// returns an error: on any failure it records the event and returns the original
// bytes unchanged.
//
// This is the byte-slice entry point, kept for the CLI (which works on whole files
// anyway) and for the tests. It wraps the payload, delegates to the blob path, and
// materialises the answer. When nothing changed it returns the caller's original
// slice untouched, so byte-for-byte fidelity is exact rather than reconstructed.
func (e *Engine) Process(path string, data []byte, depth int) []byte {
	in, err := spill.FromBytes(data, e.Limits.Spill)
	if err != nil {
		// Cannot even stage the input: emit it verbatim rather than fail.
		e.Report.Record(path, report.StatusPassthrough,
			fmt.Sprintf("could not stage payload: %v", err), len(data), len(data), nil)
		return data
	}
	defer in.Close()
	defer e.Release()

	out, changed := e.ProcessBlob(path, in, depth)
	if !changed {
		return data
	}
	defer out.Close()
	b, err := out.Bytes()
	if err != nil {
		// The scrubbed result exists but cannot be read back. Returning the original
		// is the safe answer, but the matches recorded for it never reached an
		// output, so they must not stay counted.
		e.Report.Record(path, report.StatusPassthrough,
			fmt.Sprintf("could not read back scrubbed payload: %v", err), len(data), len(data), nil)
		return data
	}
	return b
}

// ProcessBlob is the memory-bounded walk.
//
// It returns the result and whether anything changed. When changed is false the
// returned blob IS the input blob — callers must not close the result separately in
// that case, and an unchanged container is passed through byte-for-byte rather than
// rebuilt. When changed is true the caller owns the returned blob and must close it.
//
// Like Process it never returns an error: every failure records a status and yields
// the original payload.
func (e *Engine) ProcessBlob(path string, in *spill.Blob, depth int) (*spill.Blob, bool) {
	if depth == 0 {
		// A reused engine (the CLI walks files sequentially) starts clean: anything
		// left staged belongs to a walk that has already finished.
		e.Release()
		e.budget = e.Limits.MaxTotalBytes
		if e.budget <= 0 {
			e.budget = DefaultLimits().MaxTotalBytes
		}
	}
	if depth > e.Limits.MaxDepth {
		e.recordSize(path, report.StatusGuardTripped,
			fmt.Sprintf("nesting depth exceeded %d", e.Limits.MaxDepth), in)
		return in, false
	}

	head, err := in.Head(512)
	if err != nil {
		e.recordSize(path, report.StatusPassthrough,
			fmt.Sprintf("could not read payload: %v", err), in)
		return in, false
	}
	switch f := detect.DetectFormat(head); f {
	case detect.Zip:
		return e.handleZip(path, in, depth)
	case detect.Tar:
		return e.handleTar(path, in, depth)
	case detect.Gzip, detect.Zlib, detect.Bzip2, detect.Xz, detect.Zstd:
		return e.handleCompressed(f, path, in, depth)
	case detect.SevenZip, detect.Rar:
		e.recordSize(path, report.StatusUnsupported,
			"read-only archive format in this build; passed through unchanged", in)
		return in, false
	default:
		return e.handleLeaf(path, in)
	}
}

// recordSize records an outcome whose byte counts are just the payload size, which
// is every passthrough case.
func (e *Engine) recordSize(path string, status report.Status, detail string, b *spill.Blob) {
	n := int(b.Size())
	e.Report.Record(path, status, detail, n, n, nil)
}

// containerFailure classifies a container read error and records it.
//
// The three outcomes are deliberately distinct. A guard trip means the bundle is
// hostile or oversized; a spill failure means this pod is out of disk and the bundle
// may be perfectly fine; anything else means the container is malformed. Collapsing
// them would send an operator hunting a corrupt upload when the real problem is a
// full /work volume.
func (e *Engine) containerFailure(path, kind string, in *spill.Blob, err error) {
	switch {
	case errors.Is(err, archive.ErrTooLarge):
		e.recordSize(path, report.StatusGuardTripped,
			fmt.Sprintf("%s members would exceed the remaining %d-byte expansion budget", kind, e.budget), in)
	case errors.Is(err, archive.ErrTooManyMembers):
		e.recordSize(path, report.StatusGuardTripped,
			fmt.Sprintf("%s member count exceeds %d", kind, e.Limits.MaxMembers), in)
	case errors.Is(err, spill.ErrSpill):
		e.recordSize(path, report.StatusPassthrough,
			fmt.Sprintf("could not stage %s members to scratch storage (%v); passed through unchanged and NOT scrubbed", kind, err), in)
	default:
		e.recordSize(path, report.StatusPassthrough,
			fmt.Sprintf("could not read %s: %v", kind, err), in)
	}
}

func (e *Engine) handleLeaf(path string, in *spill.Blob) (*spill.Blob, bool) {
	sample, err := in.Head(8192)
	if err != nil {
		e.recordSize(path, report.StatusPassthrough,
			fmt.Sprintf("could not read payload: %v", err), in)
		return in, false
	}
	if detect.IsBinary(sample) {
		e.recordSize(path, report.StatusBinarySkip, "detected binary content", in)
		return in, false
	}

	// The one place a payload must be contiguous: the matcher works on a string.
	// This is why the spill threshold matters — a leaf briefly costs a few times its
	// own size, and that cost is bounded by the largest single member, not by the
	// archive.
	data, err := in.Bytes()
	if err != nil {
		e.recordSize(path, report.StatusPassthrough,
			fmt.Sprintf("could not read payload: %v", err), in)
		return in, false
	}
	scrubbed, matches := e.Matcher.Scrub(string(data))
	if len(matches) == 0 {
		e.recordSize(path, report.StatusUnchanged, "", in)
		return in, false
	}
	out, err := e.stageNew(spill.FromBytes([]byte(scrubbed), e.Limits.Spill))
	if err != nil {
		e.recordSize(path, report.StatusPassthrough,
			fmt.Sprintf("could not stage scrubbed payload: %v", err), in)
		return in, false
	}
	e.Report.Record(path, report.StatusScrubbed, "", len(data), int(out.Size()), matches)
	return out, true
}

func (e *Engine) handleCompressed(f detect.Format, path string, in *spill.Blob, depth int) (*spill.Blob, bool) {
	// Do not descend into a format we cannot re-encode. Scrubbing it would mean
	// discarding the result at repack time, wasting the work and leaving those
	// matches counted as redacted when they were never applied.
	if !archive.CanWrite(f) {
		e.recordSize(path, report.StatusUnsupported,
			fmt.Sprintf("%s can be read but not rewritten in this build; passed through unchanged and NOT scrubbed", f), in)
		return in, false
	}

	mark := e.Report.Mark()
	inner, meta, err := archive.DecompressBlob(f, in, e.budget, e.Limits.Spill)
	if err != nil {
		switch {
		case errors.Is(err, archive.ErrTooLarge):
			e.recordSize(path, report.StatusGuardTripped,
				fmt.Sprintf("decompressing %s would exceed the remaining %d-byte expansion budget", f, e.budget), in)
		case errors.Is(err, spill.ErrSpill):
			e.recordSize(path, report.StatusPassthrough,
				fmt.Sprintf("could not stage decompressed %s to scratch storage (%v); passed through unchanged and NOT scrubbed", f, err), in)
		default:
			e.recordSize(path, report.StatusPassthrough,
				fmt.Sprintf("could not decompress %s: %v", f, err), in)
		}
		return in, false
	}
	e.stage(inner)
	defer inner.Close()
	e.take(inner.Size())

	processed, changed := e.ProcessBlob(path, inner, depth+1)
	if !changed {
		// Nothing changed inside; keep the original bytes for exact fidelity.
		return in, false
	}
	defer processed.Close()

	out, w, err := e.stageCreated(spill.Create())
	if err != nil {
		e.Report.Rollback(mark, path, report.StatusPassthrough,
			fmt.Sprintf("could not stage recompressed %s (%v); passed through unchanged and NOT scrubbed", f, err),
			int(in.Size()), int(in.Size()))
		return in, false
	}
	cerr := archive.CompressTo(w, f, processed, meta)
	size, serr := w.Seek(0, io.SeekCurrent)
	if closeErr := w.Close(); cerr == nil {
		cerr = closeErr
	}
	if cerr != nil || serr != nil {
		out.Close()
		// The scrubbed bytes cannot be repacked, so the original goes out instead.
		// Roll the subtree's accounting back: those replacements never landed.
		e.Report.Rollback(mark, path, report.StatusUnsupported,
			fmt.Sprintf("cannot re-write %s (%v); passed through unchanged and NOT scrubbed", f, firstErr(cerr, serr)),
			int(in.Size()), int(in.Size()))
		return in, false
	}
	out.Done(size)
	return out, true
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) handleTar(path string, in *spill.Blob, depth int) (*spill.Blob, bool) {
	mark := e.Report.Mark()
	rc, err := in.Reader()
	if err != nil {
		e.recordSize(path, report.StatusPassthrough, fmt.Sprintf("could not read tar: %v", err), in)
		return in, false
	}
	members, err := archive.ReadTar(rc, e.budget, e.Limits.MaxMembers, e.Limits.Spill)
	rc.Close()
	if err != nil {
		e.containerFailure(path, "tar", in, err)
		return in, false
	}
	defer archive.CloseTar(members)

	for i := range members {
		e.stage(members[i].Body)
		e.take(members[i].Body.Size())
	}

	changed := false
	for i := range members {
		origName := members[i].Header.Name
		memberPath := path + "!" + origName
		if newName, ok := e.scrubMemberName(memberPath, origName, members[i].Body.Size()); ok {
			members[i].Header.Name = newName
			changed = true
		}
		if !members[i].IsRegular() {
			continue
		}
		out, memberChanged := e.ProcessBlob(memberPath, members[i].Body, depth+1)
		if memberChanged {
			// Release the original now rather than at the deferred sweep: with many
			// large members the difference is the whole archive's worth of scratch.
			members[i].Body.Close()
			members[i].Body = out
			changed = true
		}
	}
	if !changed {
		return in, false
	}
	return e.repack(mark, path, "tar", in, func(w io.Writer) error {
		return archive.WriteTarTo(w, members)
	})
}

func (e *Engine) handleZip(path string, in *spill.Blob, depth int) (*spill.Blob, bool) {
	mark := e.Report.Mark()
	ra, closer, err := in.ReaderAt()
	if err != nil {
		e.recordSize(path, report.StatusPassthrough, fmt.Sprintf("could not read zip: %v", err), in)
		return in, false
	}
	members, err := archive.ReadZip(ra, in.Size(), e.budget, e.Limits.MaxMembers, e.Limits.Spill)
	closer.Close()
	if err != nil {
		e.containerFailure(path, "zip", in, err)
		return in, false
	}
	defer archive.CloseZip(members)

	for i := range members {
		e.stage(members[i].Body)
		e.take(members[i].Body.Size())
	}

	changed := false
	for i := range members {
		origName := members[i].Header.Name
		memberPath := path + "!" + origName
		if newName, ok := e.scrubMemberName(memberPath, origName, members[i].Body.Size()); ok {
			members[i].Header.Name = newName
			changed = true
		}
		if members[i].IsDir() {
			continue
		}
		out, memberChanged := e.ProcessBlob(memberPath, members[i].Body, depth+1)
		if memberChanged {
			members[i].Body.Close()
			members[i].Body = out
			changed = true
		}
	}
	if !changed {
		return in, false
	}
	return e.repack(mark, path, "zip", in, func(w io.Writer) error {
		return archive.WriteZipTo(w, members)
	})
}

// repack streams a rebuilt container to scratch storage.
//
// A failure here lands *after* members have been scrubbed and recorded, so it must
// roll the subtree back rather than merely record: otherwise the report would claim
// replacements that never reached an output, which is the one direction a
// transparency report must never be wrong in.
func (e *Engine) repack(mark int, path, kind string, in *spill.Blob, write func(io.Writer) error) (*spill.Blob, bool) {
	fail := func(err error) (*spill.Blob, bool) {
		e.Report.Rollback(mark, path, report.StatusPassthrough,
			fmt.Sprintf("could not rebuild %s (%v); passed through unchanged and NOT scrubbed", kind, err),
			int(in.Size()), int(in.Size()))
		return in, false
	}
	out, w, err := e.stageCreated(spill.Create())
	if err != nil {
		return fail(err)
	}
	werr := write(w)
	size, serr := w.Seek(0, io.SeekCurrent)
	if closeErr := w.Close(); werr == nil {
		werr = closeErr
	}
	if werr != nil || serr != nil {
		out.Close()
		return fail(firstErr(werr, serr))
	}
	out.Done(size)
	return out, true
}
