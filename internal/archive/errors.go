package archive

import "errors"

// ErrNoWriter is returned by Compress for a format we can read but not write in
// this build (e.g. bzip2). The pipeline treats it as "pass the container through
// unmodified" rather than producing a broken bundle.
var ErrNoWriter = errors.New("format is read-only in this build")

var errUnsupported = errors.New("unsupported format for this operation")
