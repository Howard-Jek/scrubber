// Package pipeline performs the recursive walk over a bundle: detect format,
// unpack containers, scrub text leaves, repack, and at every node fall back to a
// verbatim passthrough of the original bytes if anything goes wrong. This is where
// the "never produce a corrupted or half-scrubbed bundle" guarantee lives.
package pipeline

import (
	"bytes"
	"fmt"

	"github.com/howard/scrubber/internal/archive"
	"github.com/howard/scrubber/internal/detect"
	"github.com/howard/scrubber/internal/report"
	"github.com/howard/scrubber/internal/scrub"
)

// Limits bounds resource use to defuse decompression bombs and quines.
type Limits struct {
	MaxDepth      int   // maximum container nesting depth
	MaxRatio      int   // maximum decompressed/compressed size ratio per stream
	MaxTotalBytes int64 // absolute cap on a single decompressed stream
	MaxMembers    int   // maximum entries in a single archive
}

// DefaultLimits returns conservative defaults.
func DefaultLimits() Limits {
	return Limits{MaxDepth: 16, MaxRatio: 200, MaxTotalBytes: 2 << 30, MaxMembers: 100000}
}

// Engine carries the compiled rules, the report sink, and the limits.
type Engine struct {
	Matcher *scrub.Matcher
	Report  *report.Report
	Limits  Limits
}

// Process transforms one stream (file or archive) and returns the result. It never
// returns an error: on any failure it records the event and returns the original
// bytes unchanged.
func (e *Engine) Process(path string, data []byte, depth int) []byte {
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
	inner, err := archive.Decompress(f, data)
	if err != nil {
		e.Report.Record(path, report.StatusPassthrough,
			fmt.Sprintf("could not decompress %s: %v", f, err), len(data), len(data), nil)
		return data
	}
	if tripped, why := e.guard(len(data), inner); tripped {
		e.Report.Record(path, report.StatusGuardTripped, why, len(data), len(data), nil)
		return data
	}

	processed := e.Process(path, inner, depth+1)
	if bytes.Equal(processed, inner) {
		// Nothing changed inside; keep the original bytes for exact fidelity.
		return data
	}
	recompressed, err := archive.Compress(f, processed)
	if err != nil {
		// Read-only format (e.g. bzip2) or compressor error: pass original through.
		e.Report.Record(path, report.StatusUnsupported,
			fmt.Sprintf("cannot re-write %s (%v); passed through unchanged", f, err), len(data), len(data), nil)
		return data
	}
	return recompressed
}

func (e *Engine) handleTar(path string, data []byte, depth int) []byte {
	members, err := archive.ReadTar(data)
	if err != nil {
		e.Report.Record(path, report.StatusPassthrough,
			fmt.Sprintf("could not read tar: %v", err), len(data), len(data), nil)
		return data
	}
	if len(members) > e.Limits.MaxMembers {
		e.Report.Record(path, report.StatusGuardTripped,
			fmt.Sprintf("member count %d exceeds %d", len(members), e.Limits.MaxMembers), len(data), len(data), nil)
		return data
	}
	changed := false
	for i := range members {
		if !members[i].IsRegular() {
			continue
		}
		memberPath := path + "!" + members[i].Header.Name
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
	members, err := archive.ReadZip(data)
	if err != nil {
		e.Report.Record(path, report.StatusPassthrough,
			fmt.Sprintf("could not read zip: %v", err), len(data), len(data), nil)
		return data
	}
	if len(members) > e.Limits.MaxMembers {
		e.Report.Record(path, report.StatusGuardTripped,
			fmt.Sprintf("member count %d exceeds %d", len(members), e.Limits.MaxMembers), len(data), len(data), nil)
		return data
	}
	changed := false
	for i := range members {
		if members[i].IsDir() {
			continue
		}
		memberPath := path + "!" + members[i].Header.Name
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

// guard applies the decompression-bomb checks to a freshly decompressed stream.
func (e *Engine) guard(compressed int, inner []byte) (bool, string) {
	if int64(len(inner)) > e.Limits.MaxTotalBytes {
		return true, fmt.Sprintf("decompressed size %d exceeds cap %d", len(inner), e.Limits.MaxTotalBytes)
	}
	if compressed > 0 && len(inner)/compressed > e.Limits.MaxRatio {
		return true, fmt.Sprintf("expansion ratio %d exceeds %d", len(inner)/compressed, e.Limits.MaxRatio)
	}
	return false, ""
}
