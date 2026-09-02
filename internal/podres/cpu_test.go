package podres

import "testing"

// The Downward API renders resourceFieldRef for cpu in the divisor's units, and the
// default divisor is whole cores, which ROUNDS UP: a container requesting 100m is
// handed "1". Both forms therefore reach this, and reading "1" as a full core when
// the pod was promised a tenth of one is the error that makes a timeout look like a
// broken bundle.
func TestParseCPUMilli(t *testing.T) {
	cases := []struct {
		in    string
		want  int64
		ok    bool
		about string
	}{
		{"100", 100, true, "a bare millicore count, which is what divisor 1m produces"},
		{"100m", 100, true, "the same value with the suffix an operator would type"},
		{"4000", 4000, true, "four cores as millicores"},

		{"0.5", 0, false, "fractional: ambiguous under a MILLI name, so refused"},
		{"1", 1, true, "one millicore, not one core -- the name says the unit"},
		{"0", 0, true, "explicitly zero is a value, not an absence"},
		{"", 0, false, "empty means not declared"},
		{"max", 0, false, "the cgroup sentinel for no limit"},
		{"  250m  ", 250, true, "surrounding whitespace"},
		{"-1", 0, false, "negative is nonsense, not a small share"},
		{"abc", 0, false, "unparseable"},
		{"100M", 0, false, "wrong suffix: bytes units are not CPU units"},
	}
	for _, c := range cases {
		got, ok := parseCPUMilli(c.in, true)
		if got != c.want || ok != c.ok {
			t.Errorf("parseCPUMilli(%q) = (%d, %v), want (%d, %v) -- %s",
				c.in, got, ok, c.want, c.ok, c.about)
		}
	}
	if got, ok := parseCPUMilli("", false); got != 0 || ok {
		t.Errorf("an absent variable must report not-present, got (%d, %v)", got, ok)
	}
}

// Detect must report which figures it actually got, because "not declared" and
// "declared as zero" lead an operator to different places.
func TestDetectCPUSource(t *testing.T) {
	cases := []struct {
		name             string
		req, lim         string
		setReq, setLim   bool
		wantReq, wantLim int64
		wantSource       string
	}{
		{"both declared", "100m", "4000m", true, true, 100, 4000,
			"downward API POD_CPU_REQUEST_MILLI + POD_CPU_LIMIT_MILLI"},
		{"request only", "500m", "", true, false, 500, 0,
			"downward API POD_CPU_REQUEST_MILLI"},
		{"limit only", "", "2000m", false, true, 0, 2000,
			"downward API POD_CPU_LIMIT_MILLI"},
		{"neither", "", "", false, false, 0, 0, "not declared"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.setReq {
				t.Setenv(envCPURequest, c.req)
			}
			if c.setLim {
				t.Setenv(envCPULimit, c.lim)
			}
			req, lim, src := detectCPU()
			if req != c.wantReq || lim != c.wantLim || src != c.wantSource {
				t.Errorf("detectCPU() = (%d, %d, %q), want (%d, %d, %q)",
					req, lim, src, c.wantReq, c.wantLim, c.wantSource)
			}
		})
	}
}
