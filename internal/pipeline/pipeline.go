// Package pipeline performs the recursive walk over a bundle: detect format,
// unpack containers, scrub text leaves, repack, and at every node fall back to a
// verbatim passthrough of the original bytes if anything goes wrong. This is where
// the "never produce a corrupted or half-scrubbed bundle" guarantee lives.
package pipeline

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/howard/scrubber/internal/archive"
	"github.com/howard/scrubber/internal/detect"
	"github.com/howard/scrubber/internal/report"
	"github.com/howard/scrubber/internal/scrub"
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
	// the total decompressed bytes the engine will hold across every nested
	// stream and archive member. Size it below the process memory limit.
	MaxTotalBytes int64
	MaxMembers    int // maximum entries in a single archive
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
}

// take draws n bytes from the expansion budget.
func (e *Engine) take(n int) { e.budget -= int64(n) }

// scrubMemberName scrubs an archive entry's name (when enabled), records any hits,
// and reports whether the name changed. origPath is the report label.
func (e *Engine) scrubMemberName(origPath, name string, inBytes int) (string, bool) {
	if !e.ScrubNames {
		return name, false
	}
	newName, matches := e.Matcher.ScrubName(name)
	if len(matches) == 0 {
		return name, false
	}
	e.Report.Record(origPath+" [name]", report.StatusScrubbed, "filename scrubbed", inBytes, len(newName), matches)
	return newName, true
}

// Process transforms one stream (file or archive) and returns the result. It never
// returns an error: on any failure it records the event and returns the original
// bytes unchanged.
func (e *Engine) Process(path string, data []byte, depth int) []byte {
	if depth == 0 {
		e.budget = e.Limits.MaxTotalBytes
		if e.budget <= 0 {
			e.budget = DefaultLimits().MaxTotalBytes
		}
	}
	if depth > e.Limits.MaxDepth {
		e.Report.Record(path, report.StatusGuardTripped,
			fmt.Sprintf("nesting depth exceeded %d", e.Limits.MaxDepth), len(data), len(data), nil)
		return data
	}

	head := data
	if len(head) > 512 {
		head = head[:512]
	}
	switch detect.DetectFormat(head) {
	case detect.Zip:
		return e.handleZip(path, data, depth)
	case detect.Tar:
		return e.handleTar(path, data, depth)
	case detect.Gzip, detect.Zlib, detect.Bzip2, detect.Xz, detect.Zstd:
		return e.handleCompressed(detect.DetectFormat(head), path, data, depth)
	case detect.SevenZip, detect.Rar:
		e.Report.Record(path, report.StatusUnsupported,
			"read-only archive format in this build; passed through unchanged", len(data), len(data), nil)
		return data
	default:
		return e.handleLeaf(path, data)
	}
}

func (e *Engine) handleLeaf(path string, data []byte) []byte {
	sample := data
	if len(sample) > 8192 {
		sample = sample[:8192]
	}
	if detect.IsBinary(sample) {
		e.Report.Record(path, report.StatusBinarySkip, "detected binary content", len(data), len(data), nil)
		return data
	}
	scrubbed, matches := e.Matcher.Scrub(string(data))
	if len(matches) == 0 {
		e.Report.Record(path, report.StatusUnchanged, "", len(data), len(data), nil)
		return data
	}
	out := []byte(scrubbed)
	e.Report.Record(path, report.StatusScrubbed, "", len(data), len(out), matches)
	return out
}

func (e *Engine) handleCompressed(f detect.Format, path string, data []byte, depth int) []byte {
	inner, meta, err := archive.Decompress(f, data, e.budget)
	if err != nil {
		if errors.Is(err, archive.ErrTooLarge) {
			e.Report.Record(path, report.StatusGuardTripped,
				fmt.Sprintf("decompressing %s would exceed the remaining %d-byte expansion budget", f, e.budget),
				len(data), len(data), nil)
			return data
		}
		e.Report.Record(path, report.StatusPassthrough,
			fmt.Sprintf("could not decompress %s: %v", f, err), len(data), len(data), nil)
		return data
	}
	e.take(len(inner))

	processed := e.Process(path, inner, depth+1)
	if bytes.Equal(processed, inner) {
		// Nothing changed inside; keep the original bytes for exact fidelity.
		return data
	}
	recompressed, err := archive.Compress(f, processed, meta)
	if err != nil {
		// Read-only format (e.g. bzip2) or compressor error: pass original through.
		e.Report.Record(path, report.StatusUnsupported,
			fmt.Sprintf("cannot re-write %s (%v); passed through unchanged", f, err), len(data), len(data), nil)
		return data
	}
	return recompressed
}

func (e *Engine) handleTar(path string, data []byte, depth int) []byte {
	members, err := archive.ReadTar(data, e.budget, e.Limits.MaxMembers)
	if err != nil {
		if tripped, why := containerGuard(err, "tar", e.budget, e.Limits.MaxMembers); tripped {
			e.Report.Record(path, report.StatusGuardTripped, why, len(data), len(data), nil)
			return data
		}
		e.Report.Record(path, report.StatusPassthrough,
			fmt.Sprintf("could not read tar: %v", err), len(data), len(data), nil)
		return data
	}
	for i := range members {
		e.take(len(members[i].Body))
	}
	changed := false
	for i := range members {
		origName := members[i].Header.Name
		memberPath := path + "!" + origName
		if newName, ok := e.scrubMemberName(memberPath, origName, len(members[i].Body)); ok {
			members[i].Header.Name = newName
			changed = true
		}
		if !members[i].IsRegular() {
			continue
		}
		out := e.Process(memberPath, members[i].Body, depth+1)
		if !bytes.Equal(out, members[i].Body) {
			members[i].Body = out
			changed = true
		}
	}
	if !changed {
		return data
	}
	rebuilt, err := archive.WriteTar(members)
	if err != nil {
		e.Report.Record(path, report.StatusPassthrough,
			fmt.Sprintf("could not rebuild tar: %v", err), len(data), len(data), nil)
		return data
	}
	return rebuilt
}

func (e *Engine) handleZip(path string, data []byte, depth int) []byte {
	members, err := archive.ReadZip(data, e.budget, e.Limits.MaxMembers)
	if err != nil {
		if tripped, why := containerGuard(err, "zip", e.budget, e.Limits.MaxMembers); tripped {
			e.Report.Record(path, report.StatusGuardTripped, why, len(data), len(data), nil)
			return data
		}
		e.Report.Record(path, report.StatusPassthrough,
			fmt.Sprintf("could not read zip: %v", err), len(data), len(data), nil)
		return data
	}
	for i := range members {
		e.take(len(members[i].Body))
	}
	changed := false
	for i := range members {
		origName := members[i].Header.Name
		memberPath := path + "!" + origName
		if newName, ok := e.scrubMemberName(memberPath, origName, len(members[i].Body)); ok {
			members[i].Header.Name = newName
			changed = true
		}
		if members[i].IsDir() {
			continue
		}
		out := e.Process(memberPath, members[i].Body, depth+1)
		if !bytes.Equal(out, members[i].Body) {
			members[i].Body = out
			changed = true
		}
	}
	if !changed {
		return data
	}
	rebuilt, err := archive.WriteZip(members)
	if err != nil {
		e.Report.Record(path, report.StatusPassthrough,
			fmt.Sprintf("could not rebuild zip: %v", err), len(data), len(data), nil)
		return data
	}
	return rebuilt
}

// containerGuard translates an archive read failure into a guard-tripped reason
// when it was a resource limit rather than a malformed container, so the two are
// never conflated in the report.
func containerGuard(err error, kind string, budget int64, maxMembers int) (bool, string) {
	switch {
	case errors.Is(err, archive.ErrTooLarge):
		return true, fmt.Sprintf("%s members would exceed the remaining %d-byte expansion budget", kind, budget)
	case errors.Is(err, archive.ErrTooManyMembers):
		return true, fmt.Sprintf("%s member count exceeds %d", kind, maxMembers)
	}
	return false, ""
}
