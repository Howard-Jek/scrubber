// Tests for the sizing derivation: the chain from what deployment.yaml declares to
// what the engine will actually accept.
//
// This package had no tests at all, which is how a compiled-in 1536Mi cap survived
// being described everywhere as "derived from the pod". The arithmetic is short and
// entirely made of judgement calls about two different resources, so it is exactly
// the kind of code that needs its intent pinned rather than its implementation
// re-read.
package main

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/howard/scrubber/internal/podres"
)

const (
	mib = 1 << 20
	gib = 1 << 30
)

// TestDeriveCapsFollowsDeclaredScratch is the property the whole change exists for:
// the expansion cap tracks the declared ephemeral-storage ceiling, with no ceiling
// of its own. Doubling the volume doubles what the service will expand.
func TestDeriveCapsFollowsDeclaredScratch(t *testing.T) {
	for _, tc := range []struct {
		name    string
		scratch int64
		// wantExpandAtLeast is the expanded CONTENT the pod must accept. Expressed
		// as a lower bound because scratchFactor may be revised upward if a shape
		// with a worse disk profile is found; it must never be revised so far that
		// these stop holding, since each is a size a real bundle arrives at.
		wantExpandAtLeast int64
	}{
		{"4Gi volume", 4 * gib, 1000 * mib},
		{"10Gi volume", 10 * gib, 2800 * mib},
		{"14Gi volume, the 4 GiB target", 14 * gib, 4 * gib},
		{"20Gi volume", 20 * gib, 5 * gib},
		{"100Gi volume, no compiled ceiling", 100 * gib, 28 * gib},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := deriveCaps(podres.Limits{
				MemoryBytes:   2 * gib,
				ScratchBytes:  tc.scratch,
				ScratchSource: "test",
			}, 1)
			if c.expandBytes < tc.wantExpandAtLeast {
				t.Errorf("expandBytes = %d (%.2f GiB), want at least %d (%.2f GiB)",
					c.expandBytes, float64(c.expandBytes)/gib,
					tc.wantExpandAtLeast, float64(tc.wantExpandAtLeast)/gib)
			}
			// The cap is only honest if the volume can hold the peak it implies.
			// scratchFactor is what connects the two, so assert the round trip
			// rather than the constant: whatever the factor is, the disk one object
			// can occupy must fit the declaration.
			if peak := int64(scratchFactor * float64(c.expandBytes)); peak > tc.scratch {
				t.Errorf("peak scratch %d exceeds the declared %d", peak, tc.scratch)
			}
		})
	}
}

// TestDeriveCapsIsLinearInScratch pins that there is no clamp hiding in the
// derivation. The previous default was flat past a point, and flat is precisely the
// bug: a pod given more disk kept refusing bundles it had room for.
func TestDeriveCapsIsLinearInScratch(t *testing.T) {
	base := deriveCaps(podres.Limits{MemoryBytes: 2 * gib, ScratchBytes: 4 * gib}, 1)
	quad := deriveCaps(podres.Limits{MemoryBytes: 2 * gib, ScratchBytes: 16 * gib}, 1)
	if got, want := quad.expandBytes, base.expandBytes*4; got != want {
		t.Errorf("4x the volume gave %d, want exactly %d (%.2fx)",
			got, want, float64(got)/float64(base.expandBytes))
	}
	// objectBytes is a float product of a float quotient, so it is linear to within
	// a rounding step rather than exactly. A few bytes of drift on a gibibyte-scale
	// cap is noise; a proportional drift would not be, which is what this catches.
	if got, want := quad.objectBytes, base.objectBytes*4; got < want-8 || got > want+8 {
		t.Errorf("objectBytes = %d, want %d (+/-8)", got, want)
	}
}

// TestDeriveCapsScratchIsNotMemory guards the mistake the whole design is arranged
// to prevent. The expansion budget is disk; giving the pod more RAM must not license
// it to fill a volume that did not grow.
func TestDeriveCapsScratchIsNotMemory(t *testing.T) {
	small := deriveCaps(podres.Limits{MemoryBytes: 2 * gib, ScratchBytes: 8 * gib}, 1)
	huge := deriveCaps(podres.Limits{MemoryBytes: 64 * gib, ScratchBytes: 8 * gib}, 1)
	if small.expandBytes != huge.expandBytes {
		t.Errorf("expansion cap moved with memory: %d at 2Gi vs %d at 64Gi",
			small.expandBytes, huge.expandBytes)
	}
	// And the converse: the leaf cap is the one that DOES follow memory, because a
	// contiguous string is the one payload that cannot be spilled.
	if huge.leafBytes <= small.leafBytes {
		t.Errorf("leaf cap did not follow memory: %d at 2Gi vs %d at 64Gi",
			small.leafBytes, huge.leafBytes)
	}
}

// TestDeriveCapsUndeclaredScratchFallsBack: an emptyDir sizeLimit cannot be measured
// from inside the container, so an undeclared pod must land on the shipped manifest's
// volume size — never on a guess from the node's disk, which is the number statfs
// would offer and the one that gets a pod evicted.
func TestDeriveCapsUndeclaredScratchFallsBack(t *testing.T) {
	c := deriveCaps(podres.Limits{MemoryBytes: 2 * gib, ScratchSource: "not declared"}, 1)
	if c.scratchBytes != defaultScratchBytes {
		t.Errorf("scratchBytes = %d, want the shipped default %d", c.scratchBytes, defaultScratchBytes)
	}
	if c.scratchSource == "not declared" {
		t.Error("scratchSource still reports the detector's answer; the startup log " +
			"must say the fallback was used, or an operator cannot tell why the cap is what it is")
	}
	if c.expandBytes <= 0 {
		t.Errorf("expandBytes = %d, want a usable budget", c.expandBytes)
	}
}

// TestDeriveCapsObjectCapStaysFirst: MAX_OBJECT_BYTES must remain the limit a user
// hits first, because it is the only one that turns an oversized upload away with a
// clear message. The expansion cap does not reject — it emits the bundle unscrubbed.
func TestDeriveCapsObjectCapStaysFirst(t *testing.T) {
	for _, scratch := range []int64{4 * gib, 14 * gib, 64 * gib} {
		c := deriveCaps(podres.Limits{MemoryBytes: 2 * gib, ScratchBytes: scratch}, 1)
		if c.objectBytes >= c.expandBytes {
			t.Errorf("scratch=%d: objectBytes %d is not below expandBytes %d",
				scratch, c.objectBytes, c.expandBytes)
		}
		if c.objectBytes <= 0 {
			t.Errorf("scratch=%d: objectBytes = %d", scratch, c.objectBytes)
		}
	}
}

// TestDeriveCapsLeafFitsMemoryGate: the leaf cap is the dominant term in the peak-RSS
// estimate, so a default that trips the service's own 60% gate would make every pod
// warn about its shipped configuration on every start. This recomputes the gate the
// way realMain does.
func TestDeriveCapsLeafFitsMemoryGate(t *testing.T) {
	for _, mem := range []int64{2 * gib, 4 * gib, 8 * gib} {
		c := deriveCaps(podres.Limits{MemoryBytes: mem, ScratchBytes: 14 * gib}, 1)
		threshold := int64(float64(4*mib) * c.memScale)
		if threshold < minSpillThreshold {
			threshold = minSpillThreshold
		}
		residentMax := int64(float64(64*mib) * c.memScale)
		estPeak := int64(float64(residentMax+leafCopies*c.leafBytes)*peakRSSFactor) +
			runtimeBaselineBytes + 100000*perMemberBytes
		if gate := mem * peakRSSGatePercent / 100; estPeak > gate {
			t.Errorf("mem=%.0fGi: est peak RSS %d (%.0f MiB) exceeds the %d%% gate %d (%.0f MiB); "+
				"maxLeafBaseline is too large for the shipped defaults to be quiet",
				float64(mem)/gib, estPeak, float64(estPeak)/mib,
				peakRSSGatePercent, gate, float64(gate)/mib)
		}
		_ = threshold
	}
}

// TestDeriveCapsNoOverflow: the derivation must not produce a budget near the top of
// the int64 range. The read guards evaluate budget+1 to tell "at the limit" from
// "over it", and that addition wrapping negative makes io.CopyN read nothing — every
// payload then looks empty and the object ships unscrubbed while the report calls it
// complete. A silent false clean is the worst failure this service has.
func TestDeriveCapsNoOverflow(t *testing.T) {
	for _, scratch := range []int64{math.MaxInt64, math.MaxInt64 / 2, 1 << 60} {
		c := deriveCaps(podres.Limits{MemoryBytes: 2 * gib, ScratchBytes: scratch}, 1)
		if c.expandBytes <= 0 {
			t.Errorf("scratch=%d produced a non-positive budget %d, which the engine "+
				"silently rewrites to a default", scratch, c.expandBytes)
		}
		if c.expandBytes > maxExpandCeiling && scratch != math.MaxInt64 {
			// realMain clamps, so this only records that the clamp is still needed.
			t.Logf("scratch=%d derives %d, above the clamp %d — realMain must clamp it",
				scratch, c.expandBytes, int64(maxExpandCeiling))
		}
	}
}

// TestPodScaleUnknownMemoryKeepsMeasuredDefaults: an undetectable memory limit must
// fall back to the configuration that was actually measured, not extrapolate from a
// number nobody has.
func TestPodScaleUnknownMemoryKeepsMeasuredDefaults(t *testing.T) {
	for _, mem := range []int64{0, -1} {
		if got := podScale(mem); got != 1 {
			t.Errorf("podScale(%d) = %v, want 1", mem, got)
		}
	}
	if got := podScale(baselineMemBytes); got != 1 {
		t.Errorf("podScale(baseline) = %v, want exactly 1 so the measured pod is unchanged", got)
	}
	if got := podScale(4 * gib); got != 2 {
		t.Errorf("podScale(4Gi) = %v, want 2", got)
	}
}

// TestScratchFactorCoversPeakDisk pins the arithmetic behind scratchFactor against
// what the pipeline actually stages, so the constant cannot drift away from the
// reason for its value.
//
// For a .tar.gz holding N bytes of content the volume holds, at once: the staged
// compressed object (at most objectBytes), the decompressed tar (N), the member
// bodies read out of it (N), and the repacked tar (N). The budget counts N once —
// pipeline.descend refunds the container — so the factor has to carry the whole 3x
// plus the object share itself.
func TestScratchFactorCoversPeakDisk(t *testing.T) {
	const liveCopies = 3 // decompressed container + member bodies + repacked result
	need := liveCopies + shippedObjectShare
	if scratchFactor < need {
		t.Errorf("scratchFactor = %v, but a .tar.gz peaks at %v x the budget "+
			"(%d live copies + %.3f for the staged object). Too small a factor "+
			"derives a cap the volume cannot hold, and the pod is evicted rather "+
			"than tripping the guard",
			scratchFactor, need, liveCopies, shippedObjectShare)
	}
}

// TestShippedManifestDerivesItsDocumentedCaps reads the manifest and asserts the
// caps it actually produces.
//
// This exists because the manifest and the code had already drifted apart without
// anyone noticing: the ConfigMap declared SCRATCH_BYTES=4Gi, which derived
// 1,717,986,918 bytes, while the same file's comments, the README, the manual and
// two scripts all said 1536Mi (1,610,612,736). Every published measurement was taken
// at a configuration the shipped manifest did not produce. Prose cannot be trusted to
// stay in step with arithmetic, so the arithmetic is asserted here instead.
//
// The parse is deliberately crude — a line scan, no YAML dependency — because a test
// that needs a new module to run is a test that gets skipped in CI.
func TestShippedManifestDerivesItsDocumentedCaps(t *testing.T) {
	const path = "../../deploy/openshift-manifests.yaml"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the shipped manifest: %v", err)
	}
	text := string(raw)

	scratch := manifestScratchBytes(t, text)
	memory := manifestMemoryLimitBytes(t, text)

	c := deriveCaps(podres.Limits{MemoryBytes: memory, ScratchBytes: scratch, ScratchSource: "manifest"}, 1)

	t.Logf("manifest declares scratch=%d (%.0f Gi), memory=%d (%.0f Gi)",
		scratch, float64(scratch)/gib, memory, float64(memory)/gib)
	t.Logf("derives expand=%d (%.2f GiB) object=%d (%.0f MiB) leaf=%d (%.0f MiB)",
		c.expandBytes, float64(c.expandBytes)/gib,
		c.objectBytes, float64(c.objectBytes)/mib,
		c.leafBytes, float64(c.leafBytes)/mib)

	// The headline promise: the shipped manifest admits a 4 GiB expanded bundle.
	if c.expandBytes != 4*gib {
		t.Errorf("expansion cap = %d, want exactly %d (4 GiB). The manifest's "+
			"SCRATCH_BYTES and its comments must be changed together", c.expandBytes, int64(4*gib))
	}
	// The volume must actually hold the peak the cap implies, or the pod is evicted
	// mid-object instead of tripping the guard.
	if peak := int64(scratchFactor * float64(c.expandBytes)); peak > scratch {
		t.Errorf("peak scratch %d exceeds the declared volume %d", peak, scratch)
	}
	// And the pod must not warn about its own shipped defaults on every start.
	residentMax := int64(float64(64*mib) * c.memScale)
	estPeak := int64(float64(residentMax+leafCopies*c.leafBytes)*peakRSSFactor) +
		runtimeBaselineBytes + 100000*perMemberBytes
	if gate := memory * peakRSSGatePercent / 100; estPeak > gate {
		t.Errorf("est peak RSS %d exceeds the %d%% gate %d; the shipped manifest "+
			"would warn about itself at startup", estPeak, peakRSSGatePercent, gate)
	}
}

// TestManifestDeclaresScratchConsistently: SCRATCH_BYTES, limits.ephemeral-storage
// and the /work emptyDir sizeLimit are three statements about one volume. Disagreeing
// is not a style problem. Each is read by a different component — the kubelet enforces
// the sizeLimit and evicts against limits.ephemeral-storage, the scheduler reserves
// requests.ephemeral-storage on the node, and the process sizes its budget from
// SCRATCH_BYTES — so a mismatch means the service plans for a volume it does not have.
func TestManifestDeclaresScratchConsistently(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/openshift-manifests.yaml")
	if err != nil {
		t.Fatalf("reading the shipped manifest: %v", err)
	}
	text := string(raw)

	scratch := manifestScratchBytes(t, text)
	wantGi := scratch / gib
	if scratch%gib != 0 {
		t.Fatalf("SCRATCH_BYTES=%d is not a whole number of Gi; the Gi-denominated "+
			"declarations below cannot match it", scratch)
	}
	want := fmt.Sprintf("%dGi", wantGi)

	if got := countOccurrences(text, "ephemeral-storage: "+want); got < 2 {
		t.Errorf("found %d of `ephemeral-storage: %s` (want both requests and limits); "+
			"SCRATCH_BYTES declares %d bytes", got, want, scratch)
	}
	if !strings.Contains(text, "sizeLimit: "+want) {
		t.Errorf("the /work emptyDir sizeLimit is not %s, but SCRATCH_BYTES declares "+
			"%d bytes. The volume the pod gets would not be the volume it sizes for",
			want, scratch)
	}
}

// TestManifestWiresTheDownwardAPI: the caps only follow the manifest if the manifest
// actually projects its resources into the pod. Dropping either reference silently
// falls back to cgroup detection for memory and to the compiled default for scratch,
// which is the "declared 14Gi, behaves like 4Gi" failure.
func TestManifestWiresTheDownwardAPI(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/openshift-manifests.yaml")
	if err != nil {
		t.Fatalf("reading the shipped manifest: %v", err)
	}
	text := string(raw)
	for _, want := range []string{
		"name: POD_MEMORY_LIMIT",
		"name: POD_EPHEMERAL_LIMIT",
		"resource: limits.memory",
		"resource: limits.ephemeral-storage",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("manifest is missing %q", want)
		}
	}
	// limits.ephemeral-storage resolves to the NODE's allocatable storage when the
	// container declares no such limit. Projecting it without declaring it hands the
	// service a number many times its share.
	if strings.Contains(text, "resource: limits.ephemeral-storage") &&
		!strings.Contains(text, "ephemeral-storage: ") {
		t.Error("the manifest projects limits.ephemeral-storage but never declares it; " +
			"Kubernetes resolves that to the node's allocatable storage")
	}
}

// manifestScratchBytes reads SCRATCH_BYTES through the SAME parser the service uses,
// so the test cannot pass on a value the service would reject. That is not
// hypothetical: the manifest writes "14Gi" to match the sizeLimit two declarations
// below it, and a plain ParseInt discards that silently.
func manifestScratchBytes(t *testing.T, text string) int64 {
	t.Helper()
	raw := manifestValue(t, text, `SCRATCH_BYTES: "`, `"`)
	n, ok := podres.ParseBytes(raw)
	if !ok {
		t.Fatalf("the manifest declares SCRATCH_BYTES=%q, which podres.ParseBytes "+
			"rejects — the shipped pod would ignore its own declaration and size "+
			"itself from the default", raw)
	}
	return n
}

// manifestMemoryLimitBytes reads the memory limit out of the resources block. Only
// whole-Gi values are understood, which is all the manifest has ever used.
func manifestMemoryLimitBytes(t *testing.T, text string) int64 {
	t.Helper()
	i := strings.Index(text, "limits:")
	if i < 0 {
		t.Fatal("no limits block in the manifest")
	}
	rest := text[i:]
	j := strings.Index(rest, "memory: ")
	if j < 0 {
		t.Fatal("no memory limit in the manifest")
	}
	val := strings.TrimSpace(strings.SplitN(rest[j+len("memory: "):], "\n", 2)[0])
	val = strings.TrimSuffix(val, "Gi")
	n, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		t.Fatalf("memory limit %q is not a whole number of Gi: %v", val, err)
	}
	return n * gib
}

func manifestValue(t *testing.T, text, prefix, suffix string) string {
	t.Helper()
	i := strings.Index(text, prefix)
	if i < 0 {
		t.Fatalf("manifest has no %q", prefix)
	}
	rest := text[i+len(prefix):]
	j := strings.Index(rest, suffix)
	if j < 0 {
		t.Fatalf("unterminated %q in the manifest", prefix)
	}
	return rest[:j]
}

func countOccurrences(hay, needle string) int {
	return strings.Count(hay, needle)
}

// TestEnvInt64 covers the byte-setting parser: the piece every cap actually passes
// through, and the piece that had no test at all.
//
// Two behaviours matter more than the parsing. A value that cannot be read must be
// recorded as a startup FAULT rather than silently replaced by a default — that
// silence is how a pod runs for weeks with a cap nobody chose. And every way of
// writing zero must disable, because the quantity forms this function exists to accept
// are exactly what an operator reaches for after reading the docs.
func TestEnvInt64(t *testing.T) {
	const def = int64(999)

	tests := []struct {
		name      string
		set       string // "" means leave unset
		want      int64
		wantFault bool
	}{
		{"unset uses the default", "", def, false},
		{"plain bytes", "4294967296", 4294967296, false},
		{"binary quantity", "4Gi", 4294967296, false},
		{"binary quantity, small", "192Mi", 201326592, false},
		{"decimal quantity", "2G", 2000000000, false},
		{"zero disables", "0", 0, false},
		{"zero disables in quantity form", "0Gi", 0, false},
		{"zero disables written long", "00", 0, false},
		{"negative disables the residual scan", "-1", -1, false},
		{"negative quantity", "-64Mi", -67108864, false},
		// Unreadable: the return value still falls back, but the process must not be
		// allowed to start on it. Never silently zero — zero means "disabled" to
		// several of these settings, which is the opposite of "I could not read it".
		{"garbage is a fault", "lots", def, true},
		{"unit typo is a fault", "14GB", def, true},
		{"bare suffix is a fault", "Gi", def, true},
		{"fractional is a fault", "1.5Gi", def, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			const key = "SCRUBBER_TEST_BYTES"
			t.Setenv(key, tc.set)
			probs := &startupProblems{}
			got := envInt64(probs, key, def)
			if got != tc.want {
				t.Errorf("envInt64(%q) = %d, want %d", tc.set, got, tc.want)
			}
			if fault := probs.err() != nil; fault != tc.wantFault {
				t.Errorf("envInt64(%q) recorded fault=%v, want %v", tc.set, fault, tc.wantFault)
			}
		})
	}
}

// TestEnvInt64FaultNamesTheVariable pins the half of the contract the return value
// cannot express: the operator has to be able to tell WHICH setting was rejected and
// what it was set to, without grepping the source.
func TestEnvInt64FaultNamesTheVariable(t *testing.T) {
	const key = "SCRUBBER_TEST_BYTES"
	probs := &startupProblems{}

	t.Setenv(key, "14 gigabytes")
	if got := envInt64(probs, key, 123); got != 123 {
		t.Errorf("got %d, want the default 123", got)
	}
	err := probs.err()
	if err == nil {
		t.Fatal("an unreadable value was swallowed; the pod would start with a cap nobody chose")
	}
	for _, want := range []string{key, "14 gigabytes", "Fix:"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the fault does not mention %q; it said: %v", want, err)
		}
	}

	// And a good value must not manufacture one.
	clean := &startupProblems{}
	t.Setenv(key, "4Gi")
	if got := envInt64(clean, key, 123); got != 4294967296 {
		t.Errorf("got %d, want 4294967296", got)
	}
	if err := clean.err(); err != nil {
		t.Errorf("a perfectly good value produced a fault: %v", err)
	}
}

// TestStartupProblemsReportsEverythingAtOnce is the whole point of the accumulator.
// The service used to panic on the first missing variable, so an operator fixed one,
// redeployed, and discovered the next — a restart per fault.
func TestStartupProblemsReportsEverythingAtOnce(t *testing.T) {
	probs := &startupProblems{}
	t.Setenv("SCRUBBER_TEST_A", "")
	t.Setenv("SCRUBBER_TEST_B", "")
	probs.req("SCRUBBER_TEST_A", "the first thing")
	probs.req("SCRUBBER_TEST_B", "the second thing")
	t.Setenv("SCRUBBER_TEST_C", "nonsense")
	envInt64(probs, "SCRUBBER_TEST_C", 1)

	err := probs.err()
	if err == nil {
		t.Fatal("three faults produced no error")
	}
	msg := err.Error()
	for _, want := range []string{"SCRUBBER_TEST_A", "SCRUBBER_TEST_B", "SCRUBBER_TEST_C", "3 configuration problems"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the report omits %q; it said: %s", want, msg)
		}
	}
	if probs2 := (&startupProblems{}); probs2.err() != nil {
		t.Error("a clean configuration produced an error")
	}
}

// TestStartupProblemsNeverEchoesASecret: the fault for a missing credential must not
// quote its value. A partially-set credential is exactly the case where a helpful
// error message leaks one into the pod log.
func TestStartupProblemsNeverEchoesASecret(t *testing.T) {
	probs := &startupProblems{}
	t.Setenv("SCRUBBER_TEST_SECRET", "   ") // whitespace: set, but unusable
	probs.reqSecret("SCRUBBER_TEST_SECRET", "the credential")

	err := probs.err()
	if err == nil {
		t.Fatal("a whitespace-only credential was accepted")
	}
	if strings.Contains(err.Error(), "   ") && strings.Contains(err.Error(), "Value") {
		t.Errorf("the fault quotes the secret's value: %v", err)
	}
	if !strings.Contains(err.Error(), "never logged") {
		t.Errorf("the fault should say the value is not logged; it said: %v", err)
	}
}

// TestSizingFaultCanBeOverridden: the two sizing checks rest on estimates that err
// high, so an operator who has measured their own workload gets a documented way past
// them. Parse failures do not get one — those are unambiguous.
func TestSizingFaultCanBeOverridden(t *testing.T) {
	t.Setenv("ALLOW_UNSAFE_SIZING", "")
	strict := &startupProblems{}
	strict.sizing("estimated peak RSS is too high")
	if strict.err() == nil {
		t.Error("a sizing fault did not stop startup by default")
	}
	if strict.sizingOverridden {
		t.Error("sizingOverridden set without the override being requested")
	}

	t.Setenv("ALLOW_UNSAFE_SIZING", "true")
	lax := &startupProblems{}
	lax.sizing("estimated peak RSS is too high")
	if lax.err() != nil {
		t.Errorf("ALLOW_UNSAFE_SIZING did not downgrade the fault: %v", lax.err())
	}
	if !lax.sizingOverridden {
		t.Error("the override was not recorded, so nothing can warn about it later")
	}
}
