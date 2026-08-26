package podres

import "testing"

// TestParseMemLimit covers every shape a cgroup memory-limit file takes.
//
// The failure that matters is a false positive: mistaking "no limit" for a real
// ceiling would make the service size itself from a sentinel and set a spill
// budget of several exabytes, which disables spilling entirely and reproduces the
// pre-spill OOM. Every ambiguous case must therefore report ok=false so the
// caller keeps its measured default.
func TestParseMemLimit(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		present bool
		want    int64
		wantOK  bool
	}{
		{"v2 explicit limit", "2147483648\n", true, 2147483648, true},
		{"v2 limit without newline", "4294967296", true, 4294967296, true},
		{"v2 unlimited", "max\n", true, 0, false},
		{"v1 explicit limit", "8589934592\n", true, 8589934592, true},
		// The v1 "no limit" sentinel. Kernels round it differently, so the check
		// is on magnitude; both of these must be rejected.
		{"v1 sentinel", "9223372036854771712\n", true, 0, false},
		{"v1 sentinel page-rounded", "9223372036854775807", true, 0, false},
		{"file absent", "", false, 0, false},
		{"empty file", "\n", true, 0, false},
		{"garbage", "not-a-number\n", true, 0, false},
		{"zero", "0\n", true, 0, false},
		{"negative", "-1\n", true, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseMemLimit(tt.in, tt.present)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (in %q)", ok, tt.wantOK, tt.in)
			}
			if got != tt.want {
				t.Errorf("bytes = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestDetectNeverPanics pins the contract that detection is advisory: it runs on
// whatever host the tests are on — including one with no cgroup files at all —
// and must return a usable zero rather than failing.
func TestDetectNeverPanics(t *testing.T) {
	l := Detect()
	if l.CPUs < 1 {
		t.Errorf("CPUs = %d, want >= 1", l.CPUs)
	}
	if l.MemoryBytes < 0 {
		t.Errorf("MemoryBytes = %d, want >= 0", l.MemoryBytes)
	}
	if l.MemorySource == "" {
		t.Error("MemorySource must always be set, so the startup log can say where the number came from")
	}
}

// TestDetectPrefersDeclaredMemory: the Downward API value is what the operator wrote
// in deployment.yaml and what the kubelet enforces against. The cgroup normally
// agrees, but a limit in decimal units, a runtime that rounds to a page multiple, or
// a namespace exposing the node's cgroup all make the measured number drift — and
// when they disagree the declaration is the one that is true.
func TestDetectPrefersDeclaredMemory(t *testing.T) {
	t.Setenv(envMemoryLimit, "4294967296")
	l := Detect()
	if l.MemoryBytes != 4294967296 {
		t.Errorf("MemoryBytes = %d, want the declared 4294967296", l.MemoryBytes)
	}
	if want := "downward API " + envMemoryLimit; l.MemorySource != want {
		t.Errorf("MemorySource = %q, want %q", l.MemorySource, want)
	}
}

// TestDetectIgnoresUnusableDeclaredMemory: a Downward API reference that resolves to
// something unusable must fall through to detection rather than being taken at face
// value. The sentinel case is the one that matters — sizing a spill budget from an
// exabyte disables spilling and reproduces the OOM it exists to prevent.
func TestDetectIgnoresUnusableDeclaredMemory(t *testing.T) {
	for _, v := range []string{"", "max", "not-a-number", "0", "-1", "1125899906842624"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv(envMemoryLimit, v)
			if l := Detect(); l.MemorySource == "downward API "+envMemoryLimit {
				t.Errorf("%q was accepted as a memory ceiling (%d)", v, l.MemoryBytes)
			}
		})
	}
}

// TestDetectScratch covers the ceiling that actually bounds how large a bundle may
// expand. It has no measured fallback by design: an emptyDir's sizeLimit is enforced
// by the kubelet, not the filesystem, so statfs would report the node's whole disk —
// authoritative-looking and wrong in the direction that gets the pod evicted.
func TestDetectScratch(t *testing.T) {
	t.Run("undeclared reports zero", func(t *testing.T) {
		t.Setenv("SCRATCH_BYTES", "")
		t.Setenv(envEphemeralLimit, "")
		l := Detect()
		if l.ScratchBytes != 0 {
			t.Errorf("ScratchBytes = %d, want 0 — nothing may be inferred from the node", l.ScratchBytes)
		}
		if l.ScratchSource == "" {
			t.Error("ScratchSource must always be set for the startup log")
		}
	})

	t.Run("downward API ephemeral limit", func(t *testing.T) {
		t.Setenv("SCRATCH_BYTES", "")
		t.Setenv(envEphemeralLimit, "15032385536") // 14Gi
		l := Detect()
		if l.ScratchBytes != 15032385536 {
			t.Errorf("ScratchBytes = %d, want 15032385536", l.ScratchBytes)
		}
	})

	// SCRATCH_BYTES wins so the knob that shipped keeps beating a Downward API
	// reference someone added later without revisiting it — and because
	// limits.ephemeral-storage silently resolves to the NODE's allocatable storage
	// when the container declares none, which is exactly the number that must never
	// size a budget.
	t.Run("SCRATCH_BYTES overrides the downward API", func(t *testing.T) {
		t.Setenv("SCRATCH_BYTES", "4294967296")
		t.Setenv(envEphemeralLimit, "999999999999")
		l := Detect()
		if l.ScratchBytes != 4294967296 {
			t.Errorf("ScratchBytes = %d, want the explicit 4294967296", l.ScratchBytes)
		}
		if l.ScratchSource != "SCRATCH_BYTES" {
			t.Errorf("ScratchSource = %q, want SCRATCH_BYTES", l.ScratchSource)
		}
	})
}

// TestParseMemLimitAcceptsQuantities: SCRATCH_BYTES is typed by an operator into a
// ConfigMap that sits below `sizeLimit: 14Gi` and is documented as "keep these
// equal", so "14Gi" is the form they will write. Rejecting it is not a parse error
// an operator ever sees — the value is discarded, the next source wins, and the pod
// sizes itself from the default while looking configured.
func TestParseMemLimitAcceptsQuantities(t *testing.T) {
	tests := []struct {
		in     string
		want   int64
		wantOK bool
	}{
		{"15032385536", 15032385536, true}, // plain bytes, what the Downward API sends
		{"14Gi", 15032385536, true},        // what an operator writes
		{" 14Gi ", 15032385536, true},
		{"4Gi", 4294967296, true},
		{"512Mi", 536870912, true},
		{"64Ki", 65536, true},
		{"2G", 2000000000, true},  // decimal, as Kubernetes means it
		{"500M", 500000000, true}, // and not 500Mi
		{"1k", 1000, true},
		// Rejections. Every one of these must leave the caller on its own default
		// rather than sizing from a number nobody meant.
		{"", 0, false},
		{"max", 0, false},
		// Kubernetes itself would reject the space, but this is a ConfigMap string
		// nothing validates, and "14 Gi" has exactly one meaning. Accepting it is the
		// point of the change: do not discard what the operator plainly meant.
		{"14 Gi", 15032385536, true},
		{"14GB", 0, false},             // not a Kubernetes suffix
		{"14.5Gi", 0, false},           // fractional quantities are not supported here
		{"-4Gi", 0, false},             // a negative ceiling is not "unlimited"
		{"0", 0, false},                // nor is zero
		{"Gi", 0, false},               // suffix with no number
		{"9000000Pi", 0, false},        // would overflow int64; must not wrap to something modest
		{"1125899906842624", 0, false}, // the cgroup "unlimited" sentinel, unchanged
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, ok := parseMemLimit(tc.in, true)
			if ok != tc.wantOK || got != tc.want {
				t.Errorf("parseMemLimit(%q) = (%d, %v), want (%d, %v)",
					tc.in, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// TestDetectScratchAcceptsGiSuffix is the end-to-end form of the above: the exact
// value docs/MANUAL.md shows an operator writing must reach the caps.
func TestDetectScratchAcceptsGiSuffix(t *testing.T) {
	t.Setenv("SCRATCH_BYTES", "14Gi")
	t.Setenv(envEphemeralLimit, "")
	l := Detect()
	if l.ScratchBytes != 15032385536 {
		t.Errorf("ScratchBytes = %d, want 15032385536 (14Gi)", l.ScratchBytes)
	}
	if l.ScratchSource != "SCRATCH_BYTES" {
		t.Errorf("ScratchSource = %q; a suffixed value was silently discarded", l.ScratchSource)
	}
}
