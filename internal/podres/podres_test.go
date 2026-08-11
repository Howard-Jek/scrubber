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
