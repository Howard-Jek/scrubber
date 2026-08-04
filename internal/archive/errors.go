package archive

import "errors"

// ErrNoWriter is returned by Compress for a format we can read but not write in
// this build (e.g. bzip2). The pipeline treats it as "pass the container through
// unmodified" rather than producing a broken bundle.
var ErrNoWriter = errors.New("format is read-only in this build")

// ErrTooLarge is returned when a stream exceeds the caller's byte ceiling. It is
// reported *while* decompressing, so the oversized data is never fully buffered:
// this is the actual memory bound, not a ratio heuristic applied after the fact.
var ErrTooLarge = errors.New("decompressed stream exceeds the byte limit")

// ErrTooManyMembers is returned when an archive declares more entries than the
// caller's limit allows.
var ErrTooManyMembers = errors.New("archive has too many members")

var errUnsupported = errors.New("unsupported format for this operation")
