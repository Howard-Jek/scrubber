package archive

import "errors"

// ErrTooLarge is returned when a stream exceeds the caller's byte ceiling. It is
// reported *while* decompressing, so the oversized data is never fully buffered:
// this is the actual memory bound, not a ratio heuristic applied after the fact.
var ErrTooLarge = errors.New("decompressed stream exceeds the byte limit")

// ErrTooManyMembers is returned when an archive declares more entries than the
// caller's limit allows.
var ErrTooManyMembers = errors.New("archive has too many members")

// ErrEncrypted marks a zip entry whose general-purpose flag says it is encrypted.
// Go's reader does not check that bit: it inflates the ciphertext as if it were
// deflate, fails somewhere inside, and the failure reads as corruption. Naming it
// matters because the operator's next step is different -- ask for the password,
// rather than ask for a re-upload.
var ErrEncrypted = errors.New("zip entry is encrypted")

var errUnsupported = errors.New("unsupported format for this operation")
