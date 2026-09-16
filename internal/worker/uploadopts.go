package worker

import (
	"encoding/json"
	"fmt"
	"time"
)

// optsSuffix marks a per-object settings file: "<key>.opts.json".
//
// A sibling of termsSuffix and deliberately separate from it. That one carries a
// POLICY -- what to look for -- and is compiled into a matcher; this carries budgets
// for one bundle. Merging them would mean a settings typo failing policy compilation,
// and a policy edit needing to round-trip fields it does not care about.
const optsSuffix = ".opts.json"

// UploadOptions is what the person who uploaded a bundle may say about it.
//
// The set is small on purpose, and the rule that keeps it small is that nothing here
// may WEAKEN a scrub. The API this arrives through has no authentication of any kind
// (see internal/server/cancel.go), so every field is one an anonymous caller can set,
// and a field that could turn detection down would be a way to launder a bundle
// through the normal output bucket rather than a convenience.
//
// Budgets pass that test in a way policy, audit level and the residual scan do not.
// A longer budget only means more of the bundle is inspected. A shorter one abandons
// the caller's OWN object, is reported as a timeout rather than as a clean run, and
// costs nobody else anything. So: time, and nothing else.
type UploadOptions struct {
	// ScrubSeconds overrides SCRUB_TIMEOUT for this object alone.
	ScrubSeconds int `json:"scrub_seconds,omitempty"`
	// FileSeconds overrides FILE_SCRUB_TIMEOUT for this object alone.
	FileSeconds int `json:"file_seconds,omitempty"`
}

// OptionLimits are the operator's ceilings on what an uploader may ask for.
//
// A ceiling is required rather than optional, because the queue is shared and single
// -- one consumer, strict FCFS, no per-tenant fairness. Without a bound, "give my
// bundle more time" is also "hold everybody else's up for as long as I like", which
// is a denial of service written in a form field.
type OptionLimits struct {
	// Enabled gates the whole mechanism. Off means a sidecar is ignored, and said
	// to be ignored, rather than silently obeyed.
	Enabled bool
	// MaxScrub and MaxFile bound what may be requested. Zero means the
	// corresponding field cannot be raised at all.
	MaxScrub time.Duration
	MaxFile  time.Duration
}

// clamp applies the operator's ceilings and reports, in words meant for the job
// record, anything it had to refuse. A refusal is never silent: a caller who asked
// for two hours and received twenty minutes has to be told, or the timeout that
// follows looks like the service ignoring its own configuration.
func (o UploadOptions) clamp(lim OptionLimits) (scrub, file time.Duration, notes []string) {
	if !lim.Enabled {
		if o.ScrubSeconds > 0 || o.FileSeconds > 0 {
			notes = append(notes, "per-upload settings accompanied this object but are "+
				"disabled on this deployment (ALLOW_UPLOAD_OPTIONS=false); the server "+
				"defaults were used")
		}
		return 0, 0, notes
	}
	if o.ScrubSeconds < 0 || o.FileSeconds < 0 {
		notes = append(notes, "negative durations in the per-upload settings were ignored")
	}
	if o.ScrubSeconds > 0 {
		scrub = time.Duration(o.ScrubSeconds) * time.Second
		if lim.MaxScrub <= 0 {
			notes = append(notes, "a scrub budget was requested but this deployment does "+
				"not allow raising it (MAX_UPLOAD_SCRUB_TIMEOUT is unset)")
			scrub = 0
		} else if scrub > lim.MaxScrub {
			notes = append(notes, fmt.Sprintf("the requested scrub budget of %s exceeds the "+
				"%s this deployment allows and was reduced to it",
				roundDur(scrub), roundDur(lim.MaxScrub)))
			scrub = lim.MaxScrub
		}
	}
	if o.FileSeconds > 0 {
		file = time.Duration(o.FileSeconds) * time.Second
		if lim.MaxFile <= 0 {
			notes = append(notes, "a per-file budget was requested but this deployment does "+
				"not allow raising it (MAX_UPLOAD_FILE_TIMEOUT is unset)")
			file = 0
		} else if file > lim.MaxFile {
			notes = append(notes, fmt.Sprintf("the requested per-file budget of %s exceeds "+
				"the %s this deployment allows and was reduced to it",
				roundDur(file), roundDur(lim.MaxFile)))
			file = lim.MaxFile
		}
	}
	return scrub, file, notes
}

// parseUploadOptions reads a sidecar's bytes.
//
// A malformed sidecar is NOT an error that stops the object. It arrived from a form
// field, the bundle it accompanies is fine, and refusing to scrub a perfectly good
// upload because its settings file has a stray comma would be a worse outcome than
// scrubbing it with the defaults. The fault is reported on the job record instead.
func parseUploadOptions(b []byte) (UploadOptions, string) {
	var o UploadOptions
	if len(b) == 0 {
		return o, ""
	}
	if err := json.Unmarshal(b, &o); err != nil {
		return UploadOptions{}, "the per-upload settings file could not be read (" +
			err.Error() + "); the server defaults were used instead"
	}
	return o, ""
}
