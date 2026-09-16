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
	"strings"
	"syscall"
	"time"

	"github.com/howard/scrubber/internal/archive"
	"github.com/howard/scrubber/internal/detect"
	"github.com/howard/scrubber/internal/report"
	"github.com/howard/scrubber/internal/residual"
	"github.com/howard/scrubber/internal/scrub"
	"github.com/howard/scrubber/internal/spill"
	"github.com/howard/scrubber/internal/textenc"
)

// Limits bounds resource use to defuse decompression bombs and quines.
//
// There is deliberately no expansion-ratio limit. Ratio cannot separate a bomb
// from an ordinary log: real-world log files compress at 200:1 to 1000:1, so any
// ratio threshold low enough to catch a bomb also rejects the tool's primary
// input — and rejection means the file is emitted UNSCRUBBED. Expansion is bounded
// instead by MaxTotalBytes, enforced while reading, which is a true bound.
//
// The three size limits here answer to three different resources, and mixing them up
// is how a pod dies rather than how a bundle is refused:
//
//	MaxTotalBytes bounds SCRATCH  — expanded payloads spill to TMPDIR.
//	MaxLeafBytes  bounds HEAP     — one file must be contiguous for the matcher.
//	MaxMembers    bounds HEAP too — per-member bookkeeping does not spill.
//
// In the service each is derived from the pod resource that actually governs it, so
// MaxTotalBytes follows the ephemeral-storage declaration and MaxLeafBytes follows
// limits.memory. Swapping them reads plausibly and fails in production.
type Limits struct {
	MaxDepth int // maximum container nesting depth
	// MaxTotalBytes is the expansion budget for one top-level object: the total
	// decompressed CONTENT the engine will accept across every nested stream and
	// archive member.
	//
	// Content, not bytes materialised. An intermediate container is charged when it is
	// decompressed, and that charge is lent back for the duration of the walk into it
	// (see descend), so a .tar.gz costs its content once rather than twice and this
	// number means to an operator what its name says. Before the lend existed, a 4 GiB
	// setting admitted only ~2 GiB of tar.gz content.
	//
	// Because members spill, it bounds mostly DISK rather than resident memory — and
	// the disk actually touched is a MULTIPLE of it: the decompressed container, the
	// member bodies and the repacked result are live at once, so one object can occupy
	// roughly 3x this plus the compressed object.
	//
	// In the service this is DERIVED from the scratch volume rather than chosen: the
	// declaration is the input and this is that ceiling divided by the multiple above
	// (see cmd/scrubberd deriveCaps). Do not read the relationship the other way and
	// size a volume from this number — an ephemeral-storage eviction kills a pod as
	// dead as an OOM, and it happens without a report.
	MaxTotalBytes int64
	MaxMembers    int // maximum entries in a single archive
	// MaxLeafBytes is the largest single text file the matcher will materialise.
	// Zero disables the check, which is the behaviour that shipped and what the CLI
	// wants — a workstation scrubbing one large log has the memory for it and no
	// kubelet to answer to.
	//
	// It exists because this is the only payload the spill policy cannot bound (see
	// handleLeaf), so it is the one limit that must be sized from the pod's MEMORY
	// rather than from its scratch volume. Above it the file is passed through and
	// flagged ReasonLeafCap instead of being scrubbed.
	MaxLeafBytes int64
	// MaxFileTime is the longest the matcher will spend on a single file before
	// abandoning that file and moving to the next. Zero disables the check, which is
	// the behaviour that shipped.
	//
	// It is the time analogue of MaxLeafBytes, and it closes the same class of gap.
	// Every other time budget here is scoped to the whole object: SCRUB_TIMEOUT is a
	// total, and STALL_ABORT_AFTER fires only when nothing at all is moving. Neither
	// can say "this one member is pathological, skip it and keep going" -- so a
	// single dense file took a bundle of otherwise ordinary logs down with it, and
	// published nothing, on a budget the other members would never have touched.
	//
	// Sized in time rather than in bytes because the cost of a file is not its size:
	// a 10 MiB log where every line matches is far more expensive than a 200 MiB one
	// where nothing does, and MaxLeafBytes cannot tell them apart.
	//
	// Above it the file is passed through unscrubbed and flagged ReasonFileTimeout,
	// and the rest of the archive is scrubbed normally.
	MaxFileTime time.Duration
	// SkipGitPacks turns off reading git packfiles, restoring the behaviour that
	// shipped before they were recognised: the pack is sniffed as binary and passed
	// through. Off by default -- packs are read.
	//
	// It exists because reading one is not free. A pack is a compressed object
	// database, and resolving its deltas reconstructs every historical version of
	// every file, so it charges the expansion budget roughly five to eight times its
	// own size on disk and spills the same to scratch. Where a pack cost nothing
	// before, a bundle carrying a large repository can now exhaust MAX_EXPAND_BYTES
	// and leave later members of the same archive guard-tripped. That is safe --
	// they are flagged, not silently skipped -- but it is a capacity change an
	// operator may need to undo faster than an image rollback allows.
	//
	// Turning it on does NOT make the pack invisible again. Every affected report
	// still records the pack as a hole and says the scan was disabled by
	// configuration, because the one thing this must never become is a quiet way to
	// make a bundle full of credentials look clean.
	SkipGitPacks bool
	// Spill decides which payloads stay on the heap. The zero value uses
	// spill.DefaultPolicy.
	Spill spill.Policy
	// VerifyOutput re-runs the matcher over every scrubbed leaf and reports any file
	// whose result still matches the policy.
	//
	// Off by default, and the reason is measured rather than assumed: it doubles the
	// matcher's work and cost ~70% of the drain rate on the 500MiB shape in
	// scripts/memory-matrix.sh (139s to 237s). The failure it guards against — a
	// policy whose replacement matches its own rule — is a property of the policy,
	// and scrub.NewMatcher now rejects that when the policy loads, before any data is
	// touched. What remains is defence against a bug inside the matcher itself, which
	// is worth having available for a paranoid deployment and is not worth paying for
	// on every object of every run.
	VerifyOutput bool
	// ResidualBudget bounds the bytes the residual scan reads across one object.
	// Zero uses DefaultResidualBudget; negative disables the scan entirely, which
	// is a supported choice but removes the only check that does not depend on the
	// pipeline's own classification being right.
	ResidualBudget int64
}

// DefaultResidualBudget is the per-object allowance for scanning uninspected
// content. Generous enough that a real skipped log is read in full, small enough
// that a bundle of large binaries does not double the drain time.
const DefaultResidualBudget = 64 << 20

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

	// Abort, when set, is polled during the walk. Returning true stops it.
	//
	// The walk is otherwise uninterruptible: no function on this path takes a
	// context, so a cancelled request reaches only the store calls that bracket
	// it, and the multi-minute middle — expanding and scrubbing a large container
	// — runs to completion regardless. This is the seam that makes an in-flight
	// cancel mean anything.
	//
	// It must NOT be wired to a context's Done channel. Shutdown cancels that
	// context, and an abort predicate that shutdown can trip would silently turn
	// every SIGTERM into a discarded scrub.
	Abort func() bool

	// Progress, when set, is called while the walk is doing long work that files
	// no report entry, with a description of the stage and the bytes written so far.
	//
	// Rebuilding a container and recompressing it happen AFTER the last member has
	// been recorded, and nothing on that path touches the report: no callback
	// fires, the progress stamp is never refreshed, and the member that finished
	// last stays on the record as though the walk were still working on it. On a
	// large bundle that is minutes of honest work published as no progress at all
	// — which is what makes the stall warner announce that an object "may be
	// stalled rather than slow" while naming a file it had already finished.
	Progress func(stage string, bytes int64)

	// budget is the remaining cumulative expansion allowance, reset on each
	// depth-0 Process call.
	budget int64
	// charged is the gross total ever drawn by take, never reduced by a lend. Only
	// descend reads it, and only as a difference across a subtree: "did walking into
	// this container charge the budget for what was inside it?"
	charged int64
	// staged holds every blob this walk created, so that a panic cannot orphan a
	// temp file. Each normal path closes its own blobs the moment they are dead;
	// this is the backstop for the abnormal one, and Blob.Close is idempotent so
	// the two never conflict. The service recovers from panics rather than dying,
	// which is exactly what turns "one orphaned file" into "a full scratch volume
	// a week later".
	staged []*spill.Blob

	// residualLeft is the remaining allowance for scanning uninspected content,
	// reset per object alongside the expansion budget.
	residualLeft int64
	// residualHits and residualLabels accumulate what the scan found across the
	// whole object. Non-zero is what turns a merely incomplete run into a risky one.
	residualHits   int
	residualLabels map[string]int

	// aborted latches once Abort first returns true, so the whole walk agrees on
	// one answer. Polling the predicate directly at each site would let a walk see
	// "not aborted" at one level and "aborted" at the next, which is precisely how
	// a container ends up half-rewritten.
	aborted bool

	// asMember records that the payload about to be walked was itself already
	// counted as a member of the archive that contains it. See noteMembers.
	asMember bool
}

// noteMembers tells the report how many entries an opened container adds to the
// count a progress display divides by, which is NOT the same as how many entries
// the container has.
//
// Two corrections, and without them the denominator is permanently larger than the
// numerator, so a bar drawn as files_done/files_total can never reach the end. Every
// entry counted here must eventually produce exactly one report entry, because that
// is what the numerator counts.
//
//	n is the members that will actually be WALKED. A directory entry or a tar
//	symlink is a member of the archive and is never scrubbed, so it files no
//	report entry and must not be in the total.
//
//	Minus one when this container is itself a member. A nested .zip is counted
//	once by its parent, then opened here and replaced by its own members — it
//	files no entry of its own, only its children do. Leaving both in place is
//	what pinned a bundle of five nested zips at 92% forever: 50 leaves against a
//	total of 55, which never closes however long the scrub runs.
//
// The delta may be zero (a nested container holding one file) or negative (an empty
// one); both are correct and NoteMembers applies them.
func (e *Engine) noteMembers(n int) {
	if e.asMember {
		// Consumed here: a .tar.gz member reaches handleTar through
		// handleCompressed, which passes the flag along untouched, and only the
		// container that actually opens is the one that replaces the member.
		e.asMember = false
		n--
	}
	e.Report.NoteMembers(n)
}

// Aborted reports whether the walk has been told to stop, latching the first true
// answer.
//
// Latching is what makes the guarantee below hold: once any level of the walk has
// seen the abort, every enclosing container returns unchanged, so `changed`
// collapses to false all the way up and the caller is handed back its original
// input rather than a partial rebuild.
func (e *Engine) Aborted() bool {
	if e.aborted {
		return true
	}
	if e.Abort != nil && e.Abort() {
		e.aborted = true
	}
	return e.aborted
}

// WasAborted reports whether the walk actually observed the abort and stopped
// early. Unlike Aborted it does not poll the predicate.
//
// The difference decides whether finished work is delivered or destroyed. A
// deadline that expires in the gap between the walk returning and the caller
// asking must not condemn a scrub that is already complete: polling there failed
// an object for overrunning a budget it had in fact met, threw the output away,
// and moved the input aside so it was never retried. An hour of work, discarded
// at the moment it succeeded.
func (e *Engine) WasAborted() bool { return e.aborted }

// errAborted stops a long write when the walk is told to stop. It never reaches a
// report: repack recognises it and returns the input unchanged, exactly as every
// other aborted path does.
var errAborted = errors.New("walk aborted")

// progressEveryBytes is how often a rebuild publishes a heartbeat. The abort is
// polled on every write instead: the predicate is a pair of atomic loads, while
// publishing copies a job record and takes a lock, and a rebuild that could only
// be stopped every few megabytes would not be interruptible at all on a small
// archive.
const progressEveryBytes = 4 << 20

// abortWriter makes rebuilding a container interruptible.
//
// Repacking a multi-gigabyte bundle is minutes of work that reports no progress
// and, before this, could not be stopped: the abort was polled before the repack
// and never again, so a deadline that expired during the rebuild was noticed only
// once the rebuild had finished.
type abortWriter struct {
	w     io.Writer
	e     *Engine
	stage string
	n     int64
	next  int64
}

func (a *abortWriter) Write(p []byte) (int, error) {
	if a.e.Aborted() {
		return 0, errAborted
	}
	a.n += int64(len(p))
	// The first bytes out fire a heartbeat, so the record says "rebuilding" from
	// the moment the rebuild starts rather than once four megabytes have gone by.
	if a.n > 0 && a.n >= a.next {
		a.next = a.n + progressEveryBytes
		if a.e.Progress != nil {
			a.e.Progress(a.stage, a.n)
		}
	}
	return a.w.Write(p)
}

// ResidualFindings reports what the safety net found in content this walk did not
// inspect: the match count and a disclosure-safe label breakdown.
func (e *Engine) ResidualFindings() (int, map[string]int) { return e.residualHits, e.residualLabels }

// residualScan looks inside a payload the walk declined to inspect and records what
// it finds on the report.
//
// It runs at the moment of the skip, where the blob is already open and the path is
// already known, so it costs no second walk. ReasonBinary is the case it exists for:
// "we decided this is not text" is precisely the judgement that was wrong before, and
// this is the one check that does not take that judgement's word for it.
func (e *Engine) residualScan(path string, reason report.Reason, b *spill.Blob) {
	if e.Limits.ResidualBudget < 0 || e.Matcher == nil || b == nil {
		return
	}
	if e.residualLeft <= 0 {
		return
	}
	res, err := residual.Scan(b, e.Matcher, e.residualLeft)
	if err != nil {
		return // the payload is already being passed through; a failed peek changes nothing
	}
	if n := b.Size(); n < e.residualLeft {
		e.residualLeft -= n
	} else {
		e.residualLeft = 0
	}
	if res.Opaque {
		// A recognised container that yielded nothing readable: encrypted, an
		// unsupported method, a stream cut off before its first byte of content.
		// A clean scan of something nobody could open is the ABSENCE of a scan,
		// not a reassurance, and the verdict has to treat it that way — this is
		// what stops a password-protected bundle leaving as merely "incomplete".
		e.Report.NoteOpaque()
	}
	if res.Hits == 0 {
		return
	}
	e.residualHits += res.Hits
	if e.residualLabels == nil {
		e.residualLabels = map[string]int{}
	}
	for k, v := range res.Labels {
		e.residualLabels[k] += v
	}
	e.Report.NoteResidual(path, reason, res.Hits, res.Summary())
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
//
// charged accumulates the same amount and is never given back, which is what lets
// descend below tell "the walk charged this container's contents" apart from "the
// walk charged nothing, so the container's own bytes are all there is".
func (e *Engine) take(n int64) {
	e.budget -= n
	e.charged += n
}

// descend walks into a payload that has ALREADY been charged to the budget, lending
// that charge back for the duration so the payload's own contents can be read
// against it, then settling up.
//
// This is what makes MAX_EXPAND_BYTES mean "expanded content" rather than "bytes
// materialised on the way to it". A .tar.gz used to draw on the budget twice — once
// for the decompressed tar, once for the member bodies read out of that tar — so a
// 4 GiB setting admitted only ~2 GiB of real content and the configured number meant
// nothing an operator could reason about.
//
// The lend has to happen BEFORE the descent, not as a refund after it. The budget is
// not only an accounting total: the remaining balance is passed down as the read
// ceiling (ReadTar, ReadZip and DecompressBlob all take e.budget), so a container
// that stays charged while its own members are being read has already shrunk the
// ceiling those members must fit under. Refunding afterwards fixes the books and
// changes nothing about what was admitted — measured at 2.03x content before this
// was moved earlier.
//
// Settling is where the safety lives. If the contents charged less than the container
// itself cost, the difference goes back on the budget: the container's bulk is real
// bytes on real disk and something must answer for it. That is what stops the obvious
// abuse — an archive of large, near-empty inner containers, which under a naive
// "only charge leaves" rule would refund almost its entire size and let sixteen
// levels of nesting through for free.
//
// Net effect per shape: a .tar.gz costs its decompressed tar once (~content plus tar
// padding); a plain .tar or .zip is untouched, since the container is the input and
// was never charged; and a container full of padding still costs its padding.
func (e *Engine) descend(path string, b *spill.Blob, depth int, charged int64) (*spill.Blob, bool) {
	e.budget += charged
	mark := e.charged
	out, changed := e.ProcessBlob(path, b, depth)
	if contents := e.charged - mark; contents < charged {
		e.budget -= charged - contents
	}
	return out, changed
}

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
	e.Report.Record(origPath+" [name]", report.StatusScrubbed, report.DetailFilenameScrubbed, int(inBytes), len(newName), matches)
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
	// The caller's bytes are already whole in memory -- that is what this entry
	// point means -- so wrap them rather than copy them out to scratch and read
	// them back. FromBytes spilled every input above the threshold, and Head and
	// Bytes then read it off disk again, for nothing.
	mark := e.Report.Mark()
	in := spill.Wrap(data)
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
		// output, so they must not stay counted -- and this is a hole, so it needs
		// the reason code every other hole carries. Recording it through Record gave
		// it ReasonUnclassified, which is the tripwire the corpus asserts nobody
		// trips; the corpus never caught it because it drives ProcessBlob directly.
		e.Report.Rollback(mark, path, report.StatusPassthrough, report.ReasonScratch,
			fmt.Sprintf("could not read the scrubbed payload back from scratch storage (%v); "+
				"passed through unchanged and NOT scrubbed", err), len(data), len(data))
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
		e.charged = 0
		e.residualLeft = e.Limits.ResidualBudget
		if e.residualLeft == 0 {
			e.residualLeft = DefaultResidualBudget
		}
		e.residualHits, e.residualLabels = 0, nil
		// The top-level object is nobody's member: it was never counted, so its own
		// members are added in full.
		e.asMember = false
	}
	// Nothing below this point runs once the walk is aborted, and every level
	// returns its input unchanged. Deliberately no e.skip() call: skip records a
	// coverage hole and runs a residual scan over the payload, which on an abort
	// would spend the budget scanning content nobody will ship and could flip the
	// verdict to incomplete-risky, diverting a cancelled object into the review
	// queue. A cancelled object produces no output and no verdict at all.
	if e.Aborted() {
		return in, false
	}
	if depth > e.Limits.MaxDepth {
		e.skip(path, report.StatusGuardTripped, report.ReasonDepthCap,
			fmt.Sprintf("nesting depth exceeded %d", e.Limits.MaxDepth), in)
		return in, false
	}

	head, err := in.Head(512)
	if err != nil {
		e.skip(path, report.StatusPassthrough, report.ReasonMalformed,
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
	case detect.Pack:
		if e.Limits.SkipGitPacks {
			// Recorded, not ignored. Same status and reason code as a pack that was
			// read, so an operator filtering on git-pack sees both, and the detail
			// is explicit that nobody looked rather than that nothing was found.
			e.Report.Skip(path, report.StatusUnsupported, report.ReasonGitPack,
				"git packfile: scanning is disabled by configuration (SCRUB_GIT_PACKS=false), "+
					"so this file was NOT examined and nothing here says whether it contains "+
					"credentials. It holds the repository's whole history, including content "+
					"deleted from the working tree. Re-enable pack scanning, or strip the .git "+
					"directory before uploading.", int(in.Size()), int(in.Size()))
			// Nobody could look, which is not the same as looking and finding
			// nothing: the verdict has to treat it as a hole that cannot be cleared.
			e.Report.NoteOpaque()
			return in, false
		}
		return e.handlePack(path, in)
	case detect.SevenZip, detect.Rar:
		e.skip(path, report.StatusUnsupported, report.ReasonUnsupported,
			"read-only archive format in this build; passed through unchanged", in)
		return in, false
	default:
		return e.handleLeaf(path, in)
	}
}

// skip records a file whose content is not covered by the scrub. Byte counts are
// just the payload size, which is true of every such case: nothing was rewritten.
//
// The reason code is a required argument, not an optional extra. Three shipped bugs
// came from a site picking a status, writing a sentence, and moving on — after which
// whether anyone ever saw it depended on which summary bucket that status happened to
// land in. A code cannot be omitted, is what metrics label, and is what the residual
// scan below decides to run on.
func (e *Engine) skip(path string, status report.Status, reason report.Reason, detail string, b *spill.Blob) {
	n := int(b.Size())
	e.Report.Skip(path, status, reason, detail, n, n)
	e.residualScan(path, reason, b)
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
		e.skip(path, report.StatusGuardTripped, report.ReasonExpandBudget,
			fmt.Sprintf("%s members would exceed the remaining %d-byte expansion budget", kind, e.budget), in)
	case errors.Is(err, archive.ErrTooManyMembers):
		e.skip(path, report.StatusGuardTripped, report.ReasonMemberCap,
			fmt.Sprintf("%s member count exceeds %d", kind, e.Limits.MaxMembers), in)
	case errors.Is(err, spill.ErrSpill):
		e.skip(path, report.StatusPassthrough, report.ReasonScratch,
			fmt.Sprintf("could not stage %s members to scratch storage (%v); passed through unchanged and NOT scrubbed", kind, err), in)
	default:
		e.skip(path, report.StatusPassthrough, report.ReasonMalformed,
			fmt.Sprintf("could not read %s: %v", kind, err), in)
	}
}

// fileBudget builds the predicate the matcher polls while scrubbing one file.
//
// It folds two questions that must stay distinguishable into the single boolean
// ScrubAbortable understands: "has the caller given up on this object?" and "has
// this one file spent its allowance?". The matcher only needs to know that it
// should stop; the caller re-asks e.Abort afterwards to find out which it was,
// because the two answers cost very different things -- one collapses the walk and
// publishes nothing, the other costs a single member.
//
// The clock starts when this is called, which is the moment the payload is handed
// to the matcher, so the budget covers the scrub itself and not the decode and
// spill-read that precede it. Those are bounded by size rather than by time.
func (e *Engine) fileBudget() func() bool {
	if e.Limits.MaxFileTime <= 0 {
		return e.Abort
	}
	deadline := time.Now().Add(e.Limits.MaxFileTime)
	return func() bool {
		if e.Abort != nil && e.Abort() {
			return true
		}
		return time.Now().After(deadline)
	}
}

func (e *Engine) handleLeaf(path string, in *spill.Blob) (*spill.Blob, bool) {
	mark := e.Report.Mark()
	sample, err := in.Head(8192)
	if err != nil {
		e.skip(path, report.StatusPassthrough, report.ReasonMalformed,
			fmt.Sprintf("could not read payload: %v", err), in)
		return in, false
	}
	enc := textenc.Sniff(sample)
	if enc == textenc.Binary {
		e.skip(path, report.StatusBinarySkip, report.ReasonBinary, "detected binary content", in)
		return in, false
	}

	// The one place a payload must be contiguous: the matcher works on a string.
	// This is why the spill threshold matters — a leaf briefly costs a few times its
	// own size, and that cost is bounded by the largest single member, not by the
	// archive.
	//
	// It is also the one payload the spill policy does NOT bound. Bytes() reads the
	// whole file back off scratch without going through the resident reservation, and
	// Decode, Scrub and Encode each hold their own copy, so one text file costs three
	// to four times its size in heap however small SPILL_RESIDENT_MAX is set. That was
	// survivable only because the expansion budget was small enough to bound it by
	// accident; once the budget follows the pod's declared scratch it no longer does,
	// and the failure it produces is an OOM mid-object — the pod dies, restarts, picks
	// the same object up and dies again. Refusing the file is strictly better: the rest
	// of the archive is still scrubbed and the hole is named in the report.
	if e.Limits.MaxLeafBytes > 0 && in.Size() > e.Limits.MaxLeafBytes {
		e.skip(path, report.StatusGuardTripped, report.ReasonLeafCap,
			fmt.Sprintf("file is %d bytes, above the %d-byte single-file scrub limit; "+
				"the matcher needs it contiguous in memory and this pod cannot hold it",
				in.Size(), e.Limits.MaxLeafBytes), in)
		return in, false
	}
	data, err := in.Bytes()
	if err != nil {
		e.skip(path, report.StatusPassthrough, report.ReasonMalformed,
			fmt.Sprintf("could not read payload: %v", err), in)
		return in, false
	}
	// Sniff judged 8KiB; Decode judges the whole payload and can still refuse. It
	// does so for anything that would not re-encode to exactly these bytes, which
	// keeps "we only changed what we redacted" true for UTF-16 as it already was for
	// UTF-8. A refusal is the old behaviour: pass it through as binary.
	text, refusal := textenc.Decode(data, enc)
	switch refusal {
	case textenc.RefusalMalformed:
		e.skip(path, report.StatusBinarySkip, report.ReasonEncoding,
			fmt.Sprintf("looked like %s but is not well-formed; passed through unchanged", enc), in)
		return in, false
	case textenc.RefusalNotText:
		e.skip(path, report.StatusBinarySkip, report.ReasonBinary,
			"detected binary content", in)
		return in, false
	}
	// The abort is polled inside the matcher, not only between members. A single
	// file can be large enough to outlast the whole scrub budget on a throttled
	// pod, and an uninterruptible member is how a walk came to run past its
	// deadline and then have every byte of that work discarded for missing it.
	scrubbed, matches, stopped := e.Matcher.ScrubAbortable(text, e.fileBudget())
	if stopped {
		// Which predicate tripped decides whether this costs one file or the whole
		// object, so the order here is the whole point. A cancel or a scrub deadline
		// is checked FIRST and collapses the walk: those mean the caller is no longer
		// waiting for this bundle, and a container must then hand back its original
		// bytes rather than repack a half-scrubbed archive.
		//
		// Only if neither of those is what stopped it was it this file's own budget,
		// and that is deliberately NOT an abort: e.aborted stays false, the walk
		// continues to the next member, and the hole is named in the report.
		if e.Aborted() {
			return in, false
		}
		// Report.Skip rather than e.skip, which is the one place this deviates from
		// every other hole, and deliberately. e.skip runs the residual scan, and the
		// residual scan runs THIS SAME MATCHER over THIS SAME payload with no abort
		// predicate -- it is bounded in bytes only. But this file is here precisely
		// because the matcher was too slow on it, and MaxFileTime exists because
		// cost tracks match density rather than size, so a byte bound does not bound
		// the time. Re-scanning here would hand the file that just outran its budget
		// straight back to an uninterruptible pass that neither MaxFileTime nor
		// SCRUB_TIMEOUT can stop, which is the deadline-cannot-reach-the-work bug
		// this codebase already fixed once.
		//
		// So the safety net is skipped for this one reason code, and the detail says
		// so rather than letting a reader assume the usual scan happened.
		e.Report.Skip(path, report.StatusGuardTripped, report.ReasonFileTimeout,
			fmt.Sprintf("file was still being scrubbed after %s, the single-file time "+
				"limit; abandoned unscrubbed so the rest of the archive could be "+
				"processed. The residual scan was NOT run over it: that scan uses the "+
				"same matcher and is bounded in bytes rather than time, so on the one "+
				"file already proven too slow it could outrun the budget again with "+
				"nothing able to interrupt it.", e.Limits.MaxFileTime),
			int(in.Size()), int(in.Size()))
		// And because the safety net did not run, nobody looked at this file at all.
		// That is the definition of an unscannable hole, and this codebase's rule for
		// one is not negotiable: a clean scan of something that could not be read is
		// the ABSENCE of a scan, not a reassurance. Without this the run comes out
		// merely "incomplete" and publishes to the NORMAL output bucket carrying a
		// member that was abandoned mid-scrub and never examined -- which is exactly
		// the shape the review/ diversion exists to catch.
		e.Report.NoteOpaque()
		return in, false
	}
	// Encoded regions, todo.md S9: the one hole in the coverage contract that is
	// silent rather than named. A base64 blob is plain ASCII, so this file was not
	// flagged binary, was inspected, and -- until this pass existed -- fell through
	// the len(matches) == 0 branch below as StatusUnchanged with a live credential
	// inside it. No status, no reason code and no exit code betrayed it.
	//
	// This runs on the already-scrubbed text so the two passes compose: plaintext
	// first, then whatever the plaintext pass could not see.
	if encoded, findings := e.Matcher.ScrubEncoded(scrubbed); len(findings) > 0 {
		for i := range findings {
			if findings[i].Rewritten {
				continue
			}
			// Found, and cannot be removed without corrupting the file. The rule for
			// content this tool cannot clean is the same as everywhere else: emit the
			// original, name it, and do not let the run be mistaken for a clean one.
			e.Report.Skip(path, report.StatusPassthrough, report.ReasonEncoded,
				fmt.Sprintf("a %s region at offset %d carries %d policy match(es) and its "+
					"decoded content is not text, so rewriting it would replace a value "+
					"some consumer depends on with garbage. Emitted unchanged and NOT "+
					"scrubbed: the match is real and still present in this file.",
					findings[i].Encoding, findings[i].Offset, len(findings[i].Matches)),
				int(in.Size()), int(in.Size()))
			e.Report.NoteOpaque()
			return in, false
		}
		for i := range findings {
			matches = append(matches, findings[i].Matches...)
		}
		scrubbed = encoded
	}

	if len(matches) == 0 {
		e.Report.Record(path, report.StatusUnchanged, enc.String(), int(in.Size()), int(in.Size()), nil)
		return in, false
	}

	// Post-condition, when asked for: the scrub is only done if the policy no longer
	// matches its own output. This verifies the bytes rather than the decision, which
	// is what makes it the one check that can catch a half-scrubbed file.
	//
	// The realistic trigger — a policy whose replacement matches its own rule — is
	// caught at policy load by scrub.NewMatcher, so this is off unless VerifyOutput
	// is set. See the field's comment for the measurement behind that default.
	if e.Limits.VerifyOutput {
		if _, residualMatches := e.Matcher.Scrub(scrubbed); len(residualMatches) > 0 {
			e.Report.Rollback(mark, path, report.StatusResidualMatch, report.ReasonResidualScrub,
				fmt.Sprintf("scrubbed, but %d match(es) of rule %q survive in the result; "+
					"emitted unchanged and NOT scrubbed",
					len(residualMatches), residualMatches[0].RuleID),
				int(in.Size()), int(in.Size()))
			return in, false
		}
	}

	out, err := e.stageNew(spill.FromBytes(textenc.Encode(scrubbed, enc), e.Limits.Spill))
	if err != nil {
		e.skip(path, report.StatusPassthrough, report.ReasonScratch,
			fmt.Sprintf("could not stage scrubbed payload: %v", err), in)
		return in, false
	}
	// The encoding goes in the detail so a report answers "what actually is this
	// file?" without anyone having to hex-dump it.
	e.Report.Record(path, report.StatusScrubbed, enc.String(), len(data), int(out.Size()), matches)
	return out, true
}

func (e *Engine) handleCompressed(f detect.Format, path string, in *spill.Blob, depth int) (*spill.Blob, bool) {
	// Do not descend into a format we cannot re-encode. Scrubbing it would mean
	// discarding the result at repack time, wasting the work and leaving those
	// matches counted as redacted when they were never applied.
	if !archive.CanWrite(f) {
		e.skip(path, report.StatusUnsupported, report.ReasonUnsupported,
			fmt.Sprintf("%s can be read but not rewritten in this build; passed through unchanged and NOT scrubbed", f), in)
		return in, false
	}

	mark := e.Report.Mark()
	inner, meta, err := archive.DecompressBlob(f, in, e.budget, e.Limits.Spill)
	if err != nil {
		switch {
		case errors.Is(err, archive.ErrTooLarge):
			e.skip(path, report.StatusGuardTripped, report.ReasonExpandBudget,
				fmt.Sprintf("decompressing %s would exceed the remaining %d-byte expansion budget", f, e.budget), in)
		case errors.Is(err, spill.ErrSpill):
			e.skip(path, report.StatusPassthrough, report.ReasonScratch,
				fmt.Sprintf("could not stage decompressed %s to scratch storage (%v); passed through unchanged and NOT scrubbed", f, err), in)
		case f == detect.Zlib:
			// zlib has no magic number: it is recognised from two header bytes that
			// ordinary text can satisfy, so a plain log beginning "H," or "xK" gets
			// sent down this path and used to be emitted unscrubbed. Failing to
			// inflate is the proof the guess was wrong, so retry it as what it
			// actually is. A genuine zlib stream is unaffected — it inflates.
			return e.handleLeaf(path, in)
		default:
			e.skip(path, report.StatusPassthrough, report.ReasonMalformed,
				fmt.Sprintf("could not decompress %s: %v", f, err), in)
		}
		return in, false
	}
	e.stage(inner)
	defer inner.Close()
	e.take(inner.Size())

	if meta != nil && meta.Truncated {
		// A stream that ends before its content does -- a partial upload, nearly
		// always. Salvage it only where there are member boundaries to salvage TO.
		//
		// A truncated ARCHIVE still holds N complete entries, and ReadTar carries
		// the unreadable remainder through byte for byte, so scrubbing the entries
		// costs nothing: that is the case worth rescuing, and refusing it used to
		// send every readable log in a partial bundle out untouched.
		//
		// A truncated BARE stream has no such structure. Rebuilding it from the
		// prefix would drop the undecodable tail from the output, and where only a
		// few bytes decoded it would replace the user's file with a stub. That one
		// is passed through whole and flagged; the residual scan decompresses the
		// prefix now, so a truncated log full of live data is still caught there.
		salvage := false
		if head, herr := inner.Head(512); herr == nil {
			switch detect.DetectFormat(head) {
			case detect.Tar, detect.Zip:
				salvage = true
			}
		}
		if !salvage {
			e.skip(path, report.StatusPassthrough, report.ReasonMalformed,
				fmt.Sprintf("%s stream ends before its content does; passed through unchanged and "+
					"NOT scrubbed (%d bytes decoded, and they were scanned for policy matches)",
					f, inner.Size()), in)
			return in, false
		}
		e.Report.NoteMembers(1)
		e.Report.Skip(path, report.StatusPassthrough, report.ReasonMalformed,
			fmt.Sprintf("%s stream ends before its content does; the %d bytes that decoded hold "+
				"complete archive entries, which are scrubbed, and the undecodable tail is dropped",
				f, inner.Size()), int(in.Size()), int(inner.Size()))
	}

	// Charged above, then lent back for the descent to the extent the walk charges
	// what is inside it: for a .tar.gz the members below pay for the same bytes, and
	// only one of the two should count against the operator's expansion budget.
	processed, changed := e.descend(path, inner, depth+1, inner.Size())
	if !changed {
		// Nothing changed inside; keep the original bytes for exact fidelity.
		return in, false
	}
	defer processed.Close()

	out, w, err := e.stageCreated(spill.Create())
	if err != nil {
		e.Report.Rollback(mark, path, report.StatusPassthrough, report.ReasonScratch,
			fmt.Sprintf("could not stage recompressed %s (%v); passed through unchanged and NOT scrubbed", f, err),
			int(in.Size()), int(in.Size()))
		e.residualScan(path, report.ReasonScratch, in)
		return in, false
	}
	cerr := archive.CompressTo(&abortWriter{w: w, e: e, stage: "recompressing the " + f.String()},
		f, processed, meta)
	size, serr := w.Seek(0, io.SeekCurrent)
	if closeErr := w.Close(); cerr == nil {
		cerr = closeErr
	}
	if errors.Is(cerr, errAborted) {
		// Stopped mid-recompress. Hand back the input like every other aborted
		// path, so nothing half-written can reach an output.
		out.Close()
		return in, false
	}
	if cerr != nil || serr != nil {
		out.Close()
		// The scrubbed bytes cannot be repacked, so the original goes out instead.
		// Roll the subtree's accounting back: those replacements never landed.
		e.Report.Rollback(mark, path, report.StatusUnsupported, report.ReasonRepackFailed,
			fmt.Sprintf("cannot re-write %s (%v); passed through unchanged and NOT scrubbed", f, firstErr(cerr, serr)),
			int(in.Size()), int(in.Size()))
		e.residualScan(path, report.ReasonRepackFailed, in)
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
		e.skip(path, report.StatusPassthrough, report.ReasonMalformed, fmt.Sprintf("could not read tar: %v", err), in)
		return in, false
	}
	// Close through a defer so a panic inside ReadTar cannot leak the handle; the
	// closure scopes it to the read rather than to the whole member walk below.
	members, tail, err := func() ([]archive.TarMember, *archive.TarTail, error) {
		defer rc.Close()
		return archive.ReadTar(rc, e.budget, e.Limits.MaxMembers, e.Limits.Spill)
	}()
	if err != nil {
		e.containerFailure(path, "tar", in, err)
		return in, false
	}
	defer archive.CloseTar(members)
	if tail != nil {
		defer tail.Raw.Close()
		// The archive ends early. Every member that WAS readable is still scrubbed
		// below; the unparseable remainder is carried through byte for byte and
		// declared here. Discarding the readable members because the last one was
		// cut short is how a partial upload of a log bundle went out whole and
		// untouched.
		e.Report.NoteMembers(1)
		e.Report.Skip(path, report.StatusPassthrough, report.ReasonMalformed,
			fmt.Sprintf("tar ends before its last entry does (%v); the %d entries that could be "+
				"read are scrubbed and the unreadable remainder is carried through untouched",
				tail.Err, len(members)),
			int(in.Size()), int(in.Size()))
	}
	// Announced before the member loop, so a watcher has a denominator from the very
	// first file rather than only once the archive has finished. Only the regular
	// entries: a directory or a symlink files no report entry, so counting it here
	// would put the denominator permanently out of reach of the numerator.
	walked := 0
	for i := range members {
		if members[i].IsRegular() {
			walked++
		}
	}
	e.noteMembers(walked)

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
		// Size read before the descent: a changed member is replaced by its scrubbed
		// blob, and the lend must be measured against what was charged going in.
		// The member is already in the total noteMembers announced. Say so, so that a
		// member which turns out to be a container replaces itself in the count
		// instead of adding its children on top of it. Cleared straight after: a
		// member that is an ordinary file consumes nothing.
		e.asMember = true
		out, memberChanged := e.descend(memberPath, members[i].Body, depth+1, members[i].Body.Size())
		e.asMember = false
		if memberChanged {
			// Release the original now rather than at the deferred sweep: with many
			// large members the difference is the whole archive's worth of scratch.
			members[i].Body.Close()
			members[i].Body = out
			changed = true
		}
	}
	// See handleZip: an aborted walk must return its input, never a rebuild mixing
	// scrubbed members with raw ones.
	if e.Aborted() {
		return in, false
	}
	if !changed {
		return in, false
	}
	return e.repack(mark, path, "tar", in, func(w io.Writer) error {
		return archive.WriteTarTo(w, members, tail)
	})
}

// handlePack inspects a git packfile and refuses to rewrite it.
//
// This is the one container the engine opens with no intention of changing. Every
// other read path exists to scrub; descending into a format that cannot be
// re-encoded is forbidden elsewhere (see handleCompressed and archive.CanWrite)
// precisely because scrubbing and then discarding the result would leave the
// matches counted as though they had been applied. Nothing is counted as applied
// here: the findings go through NoteResidual, which is the report's channel for
// matches found in content that was NOT scrubbed, and the pack itself is recorded
// as a hole.
//
// The refusal is forced by the format. An object's ID is the SHA-1 of its own
// content and the pack trailer is the SHA-1 of everything before it, so redacting a
// single byte invalidates that object, every tree and commit that reaches it, the
// .idx beside it and the trailer -- git stops being able to read the repository.
// There is no version of "scrub this pack" that leaves a working repository behind,
// so the useful thing to do is say exactly what is in it and to whom.
//
// Which is worth a great deal, because the alternative was silence. A pack is
// high-entropy end to end, so it sniffs as binary, skips correctly, and scans clean
// at every stride -- while holding every secret ever committed to the repository,
// including the ones deleted from the working tree in the very next commit.
func (e *Engine) handlePack(path string, in *spill.Blob) (*spill.Blob, bool) {
	rc, err := in.Reader()
	if err != nil {
		e.skip(path, report.StatusPassthrough, report.ReasonMalformed,
			fmt.Sprintf("could not read git packfile: %v", err), in)
		return in, false
	}
	objects, rerr := func() ([]archive.PackObject, error) {
		defer rc.Close()
		return archive.ReadPack(rc, e.budget, e.Limits.MaxMembers, e.Limits.Spill, e.Abort)
	}()
	defer archive.ClosePack(objects)

	if len(objects) == 0 {
		// A guard trip or a full scratch volume is not a corrupt packfile, and
		// collapsing them is exactly what containerFailure exists to prevent: it
		// sends an operator hunting a bad upload when the real answer is that
		// /work is full or MAX_MEMBERS is too low. Classify those the way every
		// other container does.
		if errors.Is(rerr, archive.ErrTooLarge) || errors.Is(rerr, archive.ErrTooManyMembers) ||
			errors.Is(rerr, spill.ErrSpill) {
			e.containerFailure(path, "git packfile", in, rerr)
			return in, false
		}
		// Genuinely undecodable. Recognised as a pack and yielding nothing readable
		// is an opaque hole rather than an ordinary one: a clean scan of something
		// nobody could open is the absence of a scan, and it makes the run risky on
		// its own.
		e.Report.Skip(path, report.StatusUnsupported, report.ReasonGitPack,
			fmt.Sprintf("git packfile could not be decoded (%v); passed through unchanged "+
				"and NOT scrubbed, and nothing inside it could be examined", rerr),
			int(in.Size()), int(in.Size()))
		e.Report.NoteOpaque()
		return in, false
	}

	for i := range objects {
		e.stage(objects[i].Body)
		e.take(objects[i].Body.Size())
	}

	// Every object is scanned through the residual reader rather than the leaf
	// matcher, because a pack holds four shapes at once: commits and tags are plain
	// text, trees interleave filenames with raw 20-byte IDs, blobs are anything at
	// all, and a delta is an instruction stream whose inserted text is literal.
	// Residual extraction reads text runs out of all four; the leaf path would
	// dismiss three of them as binary.
	//
	// Nothing is recorded on the report inside this loop. NoteResidual and NoteOpaque
	// both amend the MOST RECENT entry, so they are only meaningful straight after a
	// Skip -- calling them per object, before the pack's own Skip, would write each
	// object's hits onto whatever unrelated file happened to be recorded last and
	// corrupt that entry's rollback ledger. So the loop collects, and the report is
	// written once, in order, below.
	var (
		scanned, carrying, hits, opaque, unresolved int
		named                                       []string
	)
	for i := range objects {
		if objects[i].Delta && !objects[i].Resolved {
			unresolved++
		}
	}
	for i := range objects {
		if e.Matcher == nil || e.Limits.ResidualBudget < 0 || e.residualLeft <= 0 {
			break
		}
		res, err := residual.Scan(objects[i].Body, e.Matcher, e.residualLeft)
		if err != nil {
			// Charge nothing for a scan that did not happen, matching residualScan.
			// Charging here let a run of unreadable objects exhaust RESIDUAL_BUDGET
			// without a byte being examined, and then report the budget as spent.
			continue
		}
		if n := objects[i].Body.Size(); n < e.residualLeft {
			e.residualLeft -= n
		} else {
			e.residualLeft = 0
		}
		scanned++
		if res.Opaque {
			// A committed encrypted zip, or an archive in a method Go cannot read.
			// Its content is real and nobody could look at it, which is the case
			// UnscannableHoles exists to count.
			opaque++
		}
		if res.Hits == 0 {
			continue
		}
		carrying++
		hits += res.Hits
		if len(named) < maxNamedPackObjects {
			named = append(named, objects[i].Ref()+": "+res.Summary())
		}
		e.residualHits += res.Hits
		if e.residualLabels == nil {
			e.residualLabels = map[string]int{}
		}
		for k, v := range res.Labels {
			e.residualLabels[k] += v
		}
	}

	// The pack's own entry first, then the annotations that amend it.
	e.Report.Skip(path, report.StatusUnsupported, report.ReasonGitPack,
		packDetail(len(objects), scanned, carrying, hits, unresolved, rerr, e.residualLeft <= 0, named),
		int(in.Size()), int(in.Size()))
	if hits > 0 {
		e.Report.NoteResidual(path, report.ReasonGitPack, hits, packResidualSummary(carrying, hits, named))
	}
	if opaque > 0 {
		e.Report.NoteOpaque()
	}
	return in, false
}

// packDetail writes the sentence an operator acts on.
//
// Long, because a pack is the one finding where the obvious next step is the wrong
// one. Every other hole in this report is answered by changing a setting and running
// it again; this one cannot be, and saying so plainly is the difference between an
// operator fixing their bundle and an operator filing a bug asking why the scrubber
// skipped a file.
// maxNamedPackObjects bounds how many object IDs a single pack contributes to the
// report. The count stays exact; this only bounds the naming, the same way the note
// lists everywhere else are bounded.
const maxNamedPackObjects = 20

// packResidualSummary is the one-line form, carrying the object IDs so they survive
// into ResidualSamples where a person reading the summary will see them.
func packResidualSummary(carrying, hits int, named []string) string {
	s := fmt.Sprintf("%d match(es) in %d git object(s), none redacted", hits, carrying)
	if len(named) > 0 {
		s += " — " + strings.Join(named, "; ")
	}
	if carrying > len(named) {
		s += fmt.Sprintf("; and %d more", carrying-len(named))
	}
	return s
}

func packDetail(total, scanned, carrying, hits, unresolved int, readErr error, budgetSpent bool, named []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "git packfile: %d objects decoded", total)
	if scanned < total {
		fmt.Fprintf(&b, ", %d of them examined", scanned)
	}
	if readErr != nil {
		fmt.Fprintf(&b, " (the pack stopped parsing partway: %v, so the remainder was not examined)", readErr)
	}
	if budgetSpent {
		b.WriteString(" (RESIDUAL_BUDGET was exhausted before every object could be read)")
	}
	b.WriteString(". ")
	if unresolved > 0 {
		fmt.Fprintf(&b, "%d object(s) are deltas that could not be resolved against a base, "+
			"so only the text those deltas INSERT was examined and text they copy from "+
			"their base was not. ", unresolved)
	}
	if carrying == 0 {
		b.WriteString("No object matched this policy. The pack is passed through unchanged " +
			"and NOT scrubbed, which is a limitation of the format rather than a fault: " +
			"a packfile cannot be rewritten without breaking the repository.")
		return b.String()
	}
	fmt.Fprintf(&b, "%d object(s) carry %d match(es) for this policy. ", carrying, hits)
	if len(named) > 0 {
		fmt.Fprintf(&b, "By object ID: %s. ", strings.Join(named, "; "))
		if carrying > len(named) {
			fmt.Fprintf(&b, "(%d further object(s) not named here.) ", carrying-len(named))
		}
	}

	b.WriteString("The pack was passed through UNCHANGED and these matches are NOT " +
		"redacted. They cannot be: an object's ID is the SHA-1 of its own content and " +
		"the trailer is the SHA-1 of the whole file, so editing one byte breaks that " +
		"object, every commit that reaches it, the .idx beside it and the trailer at " +
		"once -- the result would be a repository git cannot open. Inspect an object " +
		"with `git cat-file -p <id>` and find the commits carrying it with " +
		"`git log --all --find-object=<id>`. To ship this bundle safely, remove the " +
		".git directory from it, or rewrite the history with `git filter-repo` and " +
		"repack before uploading again.")
	return b.String()
}

func (e *Engine) handleZip(path string, in *spill.Blob, depth int) (*spill.Blob, bool) {
	mark := e.Report.Mark()
	ra, closer, err := in.ReaderAt()
	if err != nil {
		e.skip(path, report.StatusPassthrough, report.ReasonMalformed, fmt.Sprintf("could not read zip: %v", err), in)
		return in, false
	}
	members, err := func() ([]archive.ZipMember, error) {
		defer closer.Close()
		return archive.ReadZip(ra, in.Size(), e.budget, e.Limits.MaxMembers, e.Limits.Spill)
	}()
	if err != nil {
		e.containerFailure(path, "zip", in, err)
		return in, false
	}
	defer archive.CloseZip(members)
	// See handleTar.
	walked := 0
	for i := range members {
		if !members[i].IsDir() {
			walked++
		}
	}
	e.noteMembers(walked)

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
		if members[i].Raw {
			// This entry could not be decoded, so it travels in the stored form it
			// arrived in and the rest of the archive is scrubbed around it. Before
			// this, one such entry failed the whole zip and every readable log in
			// it was emitted untouched.
			n := int(members[i].Body.Size())
			reason, detail := report.ReasonMalformed,
				fmt.Sprintf("zip entry could not be decoded (%v); carried through in its stored "+
					"form and NOT scrubbed", members[i].Err)
			if members[i].Encrypted {
				reason, detail = report.ReasonEncrypted,
					"zip entry is encrypted, so its contents cannot be read or scrubbed; carried "+
						"through in its stored form. Ask the sender for an unencrypted copy"
			}
			e.Report.Skip(memberPath, report.StatusPassthrough, reason, detail, n, n)
			// Nothing could be read out of it, so nothing can vouch for it either.
			e.Report.NoteOpaque()
			continue
		}
		// See handleTar: charged in the loop above, lent back for whatever the descent
		// charges against this member's own contents.
		// The member is already in the total noteMembers announced. Say so, so that a
		// member which turns out to be a container replaces itself in the count
		// instead of adding its children on top of it. Cleared straight after: a
		// member that is an ordinary file consumes nothing.
		e.asMember = true
		out, memberChanged := e.descend(memberPath, members[i].Body, depth+1, members[i].Body.Size())
		e.asMember = false
		if memberChanged {
			members[i].Body.Close()
			members[i].Body = out
			members[i].Changed = true
			changed = true
		}
	}
	// An aborted walk must not repack. Members before the abort were rewritten and
	// members after it were not, so repacking here would build a well-formed zip of
	// mixed scrubbed and RAW content and hand it back as changed — a bundle of
	// mostly-unscrubbed sensitive logs that looks like a finished scrub. Returning
	// the original input instead collapses `changed` to false at every enclosing
	// level, so the worker receives its own input back and there is nothing to ship.
	if e.Aborted() {
		return in, false
	}
	if !changed {
		return in, false
	}
	return e.repack(mark, path, "zip", in, func(w io.Writer) error {
		// Reopened for the write: every member the walk did not change is copied
		// across from here in its stored form, which is both byte-exact and free
		// of a needless re-deflate.
		src, closer, err := in.ReaderAt()
		if err != nil {
			return err
		}
		defer closer.Close()
		return archive.WriteZipTo(w, members, src, in.Size())
	})
}

// repack streams a rebuilt container to scratch storage.
//
// A failure here lands *after* members have been scrubbed and recorded, so it must
// roll the subtree back rather than merely record: otherwise the report would claim
// replacements that never reached an output, which is the one direction a
// transparency report must never be wrong in.
func (e *Engine) repack(mark report.Mark, path, kind string, in *spill.Blob, write func(io.Writer) error) (*spill.Blob, bool) {
	fail := func(err error) (*spill.Blob, bool) {
		// A full scratch volume is a different problem from a hostile bundle, and
		// the read side has always said so. The write side used to call both
		// "repack-failed", sending an operator hunting a corrupt upload when the
		// real answer was that /work had run out.
		reason := report.ReasonRepackFailed
		detail := fmt.Sprintf("could not rebuild %s (%v); passed through unchanged and NOT scrubbed", kind, err)
		if errors.Is(err, spill.ErrSpill) || errors.Is(err, syscall.ENOSPC) {
			reason = report.ReasonScratch
			detail = fmt.Sprintf("could not write the rebuilt %s to scratch storage (%v); passed "+
				"through unchanged and NOT scrubbed", kind, err)
		}
		e.Report.Rollback(mark, path, report.StatusPassthrough, reason, detail,
			int(in.Size()), int(in.Size()))
		e.residualScan(path, reason, in)
		return in, false
	}
	out, w, err := e.stageCreated(spill.Create())
	if err != nil {
		return fail(err)
	}
	werr := write(&abortWriter{w: w, e: e, stage: "rebuilding the " + kind})
	size, serr := w.Seek(0, io.SeekCurrent)
	if closeErr := w.Close(); werr == nil {
		werr = closeErr
	}
	if errors.Is(werr, errAborted) {
		// Told to stop mid-rebuild. Hand back the input: the enclosing levels
		// collapse to unchanged and nothing half-written can reach an output.
		out.Close()
		return in, false
	}
	if werr != nil || serr != nil {
		out.Close()
		return fail(firstErr(werr, serr))
	}
	out.Done(size)
	return out, true
}
