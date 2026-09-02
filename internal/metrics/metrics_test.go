package metrics

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// TestEveryMetricIsRegistered is a cheap guard on an expensive mistake.
//
// A counter that is constructed but left out of MustRegister works perfectly from
// the code's point of view — it increments, it has a name, nothing errors — and is
// simply absent from /metrics. The failure surfaces only when someone builds an
// alert on it and the alert silently never fires, which is the worst possible time
// to discover it. That happened to scrubber_discovery_failures_total.
//
// So: assert the exposed set by name rather than trusting the construction site.
func TestEveryMetricIsRegistered(t *testing.T) {
	reg := prometheus.NewRegistry()
	New(reg)

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	exposed := map[string]bool{}
	for _, f := range families {
		exposed[f.GetName()] = true
	}

	// Every metric the service documents or alerts on. Adding one here without
	// registering it fails, which is the point.
	want := []string{
		"scrubber_objects_total",
		"scrubber_object_verdict_total",
		"scrubber_files_not_inspected_total",
		"scrubber_residual_hits_total",
		"scrubber_matches_total",
		"scrubber_passthrough_total",
		"scrubber_errors_total",
		"scrubber_discovery_failures_total",
		"scrubber_bytes_in_total",
		"scrubber_bytes_out_total",
		"scrubber_process_seconds",
		"scrubber_queue_wait_seconds",
		"scrubber_object_latency_seconds",
	}
	var missing []string
	for _, name := range want {
		if !exposed[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("these metrics are constructed but never reach /metrics, so nothing can "+
			"alert on them: %s", strings.Join(missing, ", "))
	}
}

// TestDiscoveryFailuresIsCounted covers the specific series, since it is the one
// an operator is told to alert on: a rising value with flat object counters means
// no work is being discovered at all.
func TestDiscoveryFailuresIsCounted(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)
	m.DiscoveryFailures.Inc()
	m.DiscoveryFailures.Inc()

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() != "scrubber_discovery_failures_total" {
			continue
		}
		if got := f.GetMetric()[0].GetCounter().GetValue(); got != 2 {
			t.Fatalf("value = %v, want 2", got)
		}
		return
	}
	t.Fatal("scrubber_discovery_failures_total is not exposed")
}

// TestProgressSecondsIsNotPhaseSeconds pins the distinction that a false stall
// warning came from conflating.
//
// A large archive sits in the "scrubbing" phase for as long as the archive takes, so
// PhaseSeconds climbs for the whole run whether or not anything is happening. Judging
// "stalled" on it warned three times about a healthy 19-minute, 60-file bundle whose
// files_done was climbing 25 -> 40 -> 55 throughout. ProgressSeconds is what actually
// answers the question.
func TestProgressSecondsIsNotPhaseSeconds(t *testing.T) {
	now := time.Now()
	j := Job{
		Phase: "scrubbing",
		// In this phase for ten minutes...
		PhaseSince: now.Add(-10 * time.Minute),
		// ...but it finished a file two seconds ago.
		ProgressSince: now.Add(-2 * time.Second),
		FilesDone:     40,
	}
	if got := j.PhaseSeconds(); got < 590 {
		t.Errorf("PhaseSeconds = %.0f, want ~600", got)
	}
	if got := j.ProgressSeconds(); got > 10 {
		t.Errorf("ProgressSeconds = %.0f, want ~2 — a job that finished a file "+
			"two seconds ago is not stalled", got)
	}

	// The genuinely stuck case: in the phase ten minutes, and nothing has moved for
	// ten minutes either. Both agree, and the warning should fire.
	stuck := Job{Phase: "scrubbing", PhaseSince: now.Add(-10 * time.Minute),
		ProgressSince: now.Add(-10 * time.Minute), FilesDone: 53}
	if got := stuck.ProgressSeconds(); got < 590 {
		t.Errorf("ProgressSeconds = %.0f on a stuck job, want ~600", got)
	}
}

// TestProgressSecondsFallsBackForOldRecords: a job written by a process that predates
// the stamp must not report 0, which would read as "just moved" and suppress a real
// warning.
func TestProgressSecondsFallsBackForOldRecords(t *testing.T) {
	j := Job{Phase: "scrubbing", PhaseSince: time.Now().Add(-8 * time.Minute)}
	if got := j.ProgressSeconds(); got < 470 {
		t.Errorf("ProgressSeconds = %.0f with no stamp, want the PhaseSeconds "+
			"fallback (~480), never 0", got)
	}
	// And a finished job reports nothing rather than a number that climbs forever.
	if got := (Job{}).ProgressSeconds(); got != 0 {
		t.Errorf("ProgressSeconds = %.0f on a job with no phase, want 0", got)
	}
}
