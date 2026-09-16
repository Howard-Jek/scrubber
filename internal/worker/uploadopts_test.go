package worker

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestUploadOptionsAreClampedNotTrusted is the security property of per-upload
// settings: they arrive through an API with no authentication of any kind, so every
// value is one an anonymous caller chose.
func TestUploadOptionsAreClampedNotTrusted(t *testing.T) {
	lim := OptionLimits{Enabled: true, MaxScrub: time.Hour, MaxFile: 5 * time.Minute}

	for _, tc := range []struct {
		name          string
		in            UploadOptions
		lim           OptionLimits
		wantScrub     time.Duration
		wantFile      time.Duration
		wantNoteAbout string
	}{
		{
			name: "a reasonable request is honoured", in: UploadOptions{ScrubSeconds: 900, FileSeconds: 60},
			lim: lim, wantScrub: 15 * time.Minute, wantFile: time.Minute,
		},
		{
			name: "an absurd scrub budget is reduced to the ceiling",
			in:   UploadOptions{ScrubSeconds: 86400 * 30}, lim: lim,
			wantScrub: time.Hour, wantNoteAbout: "exceeds",
		},
		{
			name: "an absurd file budget is reduced to the ceiling",
			in:   UploadOptions{FileSeconds: 999999}, lim: lim,
			wantFile: 5 * time.Minute, wantNoteAbout: "exceeds",
		},
		{
			name: "negatives are ignored rather than becoming an instant timeout",
			in:   UploadOptions{ScrubSeconds: -1, FileSeconds: -1}, lim: lim,
			wantNoteAbout: "negative",
		},
		{
			name: "disabled means ignored, and said to be ignored",
			in:   UploadOptions{ScrubSeconds: 900},
			lim:  OptionLimits{Enabled: false}, wantNoteAbout: "disabled on this deployment",
		},
		{
			name: "enabled with no ceiling cannot be raised",
			in:   UploadOptions{ScrubSeconds: 900},
			lim:  OptionLimits{Enabled: true}, wantNoteAbout: "does not allow raising",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scrub, file, notes := tc.in.clamp(tc.lim)
			if scrub != tc.wantScrub {
				t.Errorf("scrub = %v, want %v", scrub, tc.wantScrub)
			}
			if file != tc.wantFile {
				t.Errorf("file = %v, want %v", file, tc.wantFile)
			}
			if tc.wantNoteAbout != "" {
				joined := strings.Join(notes, " | ")
				if !strings.Contains(joined, tc.wantNoteAbout) {
					t.Errorf("no note mentioning %q; got %q", tc.wantNoteAbout, joined)
				}
			}
		})
	}
}

// TestUploadOptionsRefusalIsNeverSilent: a caller who asked for two hours and got
// twenty minutes must be told, or the timeout that follows reads as the service
// ignoring its own configuration.
func TestUploadOptionsRefusalIsNeverSilent(t *testing.T) {
	lim := OptionLimits{Enabled: true, MaxScrub: time.Minute, MaxFile: time.Minute}
	_, _, notes := UploadOptions{ScrubSeconds: 7200, FileSeconds: 7200}.clamp(lim)
	if len(notes) < 2 {
		t.Fatalf("two refusals produced %d note(s): %v", len(notes), notes)
	}
	for _, n := range notes {
		if !strings.Contains(n, "1m0s") {
			t.Errorf("a refusal that does not say what was granted instead: %q", n)
		}
	}
}

// TestMalformedUploadOptionsDoNotFailTheObject: the settings arrived from a form
// field and the bundle they accompany is fine. Refusing to scrub a good upload
// because its settings file has a stray comma is a worse outcome than scrubbing it
// with the defaults.
func TestMalformedUploadOptionsDoNotFailTheObject(t *testing.T) {
	opts, note := parseUploadOptions([]byte("{not json"))
	if note == "" {
		t.Error("a malformed settings file produced no explanation")
	}
	if opts.ScrubSeconds != 0 || opts.FileSeconds != 0 {
		t.Error("a malformed settings file yielded non-zero settings")
	}
	if _, empty := parseUploadOptions(nil); empty != "" {
		t.Errorf("an absent settings file should be silent, got %q", empty)
	}
}

// TestSidecarBudgetReachesTheObject is the end-to-end half the clamp tests cannot
// cover: that a settings file sitting next to a bundle in the input bucket is
// actually found, applied to THAT object, and reported on its job record.
//
// The unit tests above prove the arithmetic. This proves the wiring -- that the
// sidecar is read before the deadline is armed rather than after it, that it is not
// itself picked up as an object to scrub, and that it is consumed along with the
// bundle instead of being left behind to accumulate in the bucket forever.
func TestSidecarBudgetReachesTheObject(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	ms.Put(context.Background(), "input", "app.log", []byte("hi from AcmeCorp\n"), "")
	ms.Put(context.Background(), "input", "app.log"+optsSuffix,
		[]byte(`{"scrub_seconds":900,"file_seconds":120}`), "")

	w := newTestWorker(t, ms)
	w.cfg.UploadOptions = OptionLimits{Enabled: true, MaxScrub: time.Hour, MaxFile: 10 * time.Minute}
	w.runOnce(context.Background())

	j, ok := w.jobs.Get("app.log")
	if !ok {
		t.Fatal("no job recorded")
	}
	var joined string
	for _, n := range j.Notes {
		joined += n + " | "
	}
	if !strings.Contains(joined, "scrub budget of 15m") {
		t.Errorf("the per-object scrub budget was not applied or not reported: %q", joined)
	}
	if !strings.Contains(joined, "per-file budget of 2m") {
		t.Errorf("the per-object file budget was not applied or not reported: %q", joined)
	}

	// The bundle is scrubbed normally...
	if _, err := ms.Get(context.Background(), "output", "app.log"); err != nil {
		t.Fatalf("the object was not scrubbed: %v", err)
	}
	// ...and the sidecar is consumed with it rather than left to pile up.
	if ms.has("input", "app.log"+optsSuffix) {
		t.Error("the settings sidecar outlived its bundle; it will accumulate in the input bucket")
	}
	// The sidecar must never be treated as an object to scrub in its own right.
	if ms.has("output", "app.log"+optsSuffix) {
		t.Error("the settings sidecar was scrubbed as if it were an upload")
	}
}

// TestSidecarOverAskIsClampedAndSaidSo covers the case that matters most for trust:
// the API has no authentication, so an anonymous caller can put any number in this
// file. The ceiling must win, and the person must be told it did.
func TestSidecarOverAskIsClampedAndSaidSo(t *testing.T) {
	ms := newMemStore("input", "output", "reports")
	ms.Put(context.Background(), "input", "app.log", []byte("hi from AcmeCorp\n"), "")
	ms.Put(context.Background(), "input", "app.log"+optsSuffix,
		[]byte(`{"scrub_seconds":2592000}`), "") // thirty days
	w := newTestWorker(t, ms)
	w.cfg.UploadOptions = OptionLimits{Enabled: true, MaxScrub: time.Minute, MaxFile: time.Minute}
	w.runOnce(context.Background())

	j, _ := w.jobs.Get("app.log")
	var joined string
	for _, n := range j.Notes {
		joined += n + " | "
	}
	if !strings.Contains(joined, "exceeds") || !strings.Contains(joined, "1m0s") {
		t.Errorf("a thirty-day request was not visibly refused: %q", joined)
	}
}
