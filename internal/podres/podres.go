// Package podres reports what the container is actually allowed to use, so the
// service can size itself from its real ceiling instead of a number compiled in
// months earlier.
//
// The caps this feeds were calibrated against a 2 GiB pod and then hard-coded as
// defaults. That is fine until the pod is not 2 GiB: on a larger one the service
// leaves most of the memory unused and scrubs no faster, and on a smaller one the
// defaults promise headroom that is not there. Neither failure is visible from
// inside the process, because nothing in it knew how much memory it had.
//
// Detection is advisory. Every derived value stays overridable by its environment
// variable, and an undetectable limit falls back to the measured 2 GiB defaults —
// the behaviour that shipped — rather than to a guess.
package podres

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

// unlimited is the ceiling above which a reported limit means "no limit". cgroup
// v1 reports a sentinel near math.MaxInt64 rounded down to a page multiple, and
// different kernels round it differently, so this tests the magnitude rather than
// matching an exact constant. No real pod is given a pebibyte.
const unlimited = 1 << 50

// Downward API variables. A Deployment can project its own resources block into
// the container's environment, which is the only way the numbers an operator wrote
// in deployment.yaml reach this process as the numbers they wrote — rather than as
// whatever the kernel happens to expose.
//
//	env:
//	  - name: POD_MEMORY_LIMIT
//	    valueFrom: { resourceFieldRef: { containerName: scrubberd,
//	                resource: limits.memory, divisor: "1" } }
//	  - name: POD_EPHEMERAL_LIMIT
//	    valueFrom: { resourceFieldRef: { containerName: scrubberd,
//	                resource: limits.ephemeral-storage, divisor: "1" } }
//
// The ephemeral one carries a trap worth naming: when a container declares no
// limits.ephemeral-storage, Kubernetes resolves the reference to the NODE's
// allocatable storage instead of failing. That is a number many times larger than
// anything this pod may use, and sizing a budget from it would license an eviction.
// So the manifest must declare limits.ephemeral-storage explicitly, SCRATCH_BYTES
// still overrides, and the startup log always names the source it used.
const (
	envMemoryLimit    = "POD_MEMORY_LIMIT"
	envEphemeralLimit = "POD_EPHEMERAL_LIMIT"
	// Named for their units on purpose. The Downward API renders cpu in the
	// divisor's units, and with divisor "1m" the value arrives as a BARE INTEGER
	// COUNT OF MILLICORES -- "100", not "100m". A variable called POD_CPU_REQUEST
	// holding "100" reads as a hundred cores to anyone who has not checked the
	// manifest, and parsing it that way is a 1000x error in the optimistic
	// direction. The name carries the unit so neither the code nor the reader has
	// to guess.
	envCPURequest = "POD_CPU_REQUEST_MILLI"
	envCPULimit   = "POD_CPU_LIMIT_MILLI"
)

// Limits is what the container may use. A zero field means "could not tell",
// which callers must treat as "keep the compiled-in default" and not as zero.
type Limits struct {
	// MemoryBytes is the container's memory ceiling, or 0 when there is none or
	// it could not be read.
	MemoryBytes int64
	// MemorySource names where MemoryBytes came from, for the startup log. An
	// operator sizing a pod needs to know whether the number was measured or
	// assumed.
	MemorySource string
	// ScratchBytes is the ephemeral-storage ceiling this container may fill, or 0
	// when it was not declared.
	//
	// This is the one that actually bounds how large a bundle may expand, because
	// members spill to TMPDIR rather than to the heap. It cannot be measured from
	// inside the container: an emptyDir's sizeLimit is enforced by the kubelet, not
	// by the filesystem, so statfs reports the whole node's disk and would license
	// a budget that gets the pod evicted. It has to be declared.
	ScratchBytes int64
	// ScratchSource names where ScratchBytes came from, for the startup log.
	ScratchSource string
	// CPUs is GOMAXPROCS as the runtime resolved it. Go 1.25 derives this from
	// the cgroup CPU bandwidth limit, so it already reflects `limits.cpu` and
	// needs no separate detection here — it is reported so the startup log shows
	// the whole picture in one place.
	CPUs int
	// CPURequestMilli is `requests.cpu` in millicores, or 0 when not declared.
	//
	// This, not CPUs, is what a scrub is GUARANTEED. limits.cpu becomes the cgroup
	// bandwidth ceiling and is what the pod may burst to on an idle node;
	// requests.cpu becomes its share weight and is what survives a busy one. A pod
	// declaring `requests.cpu: 100m, limits.cpu: 4` looks like four cores to the Go
	// runtime and is one tenth of a core when the node is full — a 40x spread in
	// how long a bundle takes, and the low end is the one an operator gets paged
	// for.
	CPURequestMilli int64
	// CPULimitMilli is `limits.cpu` in millicores, or 0 when not declared. Reported
	// alongside the request so the startup log shows the spread between what the
	// pod may use and what it is promised.
	CPULimitMilli int64
	// CPUSource names where the CPU figures came from, for the startup log.
	CPUSource string
}

// Detect reads the container's limits. It never fails: anything it cannot
// determine is left zero for the caller to fall back on.
func Detect() Limits {
	l := Limits{CPUs: runtime.GOMAXPROCS(0)}
	l.MemoryBytes, l.MemorySource = detectMemory()
	l.ScratchBytes, l.ScratchSource = detectScratch()
	l.CPURequestMilli, l.CPULimitMilli, l.CPUSource = detectCPU()
	return l
}

// detectCPU reads the declared CPU request and limit.
//
// Declared only, like scratch and for the same reason: what a container can measure
// from the inside is the ceiling (the cgroup bandwidth quota), and the ceiling is
// not the guarantee. Nothing in the cgroup tree says what share the scheduler
// promised this pod when the node is contended — cpu.weight is relative to whatever
// else happens to be running — so a measured fallback would produce an authoritative
// number that is wrong in the optimistic direction.
func detectCPU() (req, lim int64, source string) {
	req, okReq := parseCPUMilli(lookupEnv(envCPURequest))
	lim, okLim := parseCPUMilli(lookupEnv(envCPULimit))
	switch {
	case okReq && okLim:
		return req, lim, "downward API " + envCPURequest + " + " + envCPULimit
	case okReq:
		return req, 0, "downward API " + envCPURequest
	case okLim:
		return 0, lim, "downward API " + envCPULimit
	}
	return 0, 0, "not declared"
}

// detectMemory prefers the declared limit over the measured one, then tries cgroup
// v2 and v1.
//
// The Downward API comes first because it is what the operator actually wrote. The
// cgroup normally agrees with it, but not always — a limit expressed in decimal
// units, a runtime that rounds to a page multiple, or a namespace whose cgroup
// mount is the node's rather than the container's all make the measured number
// drift from the declared one, and the declared one is the number the kubelet
// enforces against.
//
// Between the two cgroup versions, v2 is checked first because a host running v2 in
// unified mode has no v1 files at all, while a host in hybrid mode has both — and
// there the v1 tree is often the stub, not the enforced one.
func detectMemory() (int64, string) {
	if n, ok := parseMemLimit(lookupEnv(envMemoryLimit)); ok {
		return n, "downward API " + envMemoryLimit
	}
	if n, ok := parseMemLimit(readFile("/sys/fs/cgroup/memory.max")); ok {
		return n, "cgroup v2 memory.max"
	}
	if n, ok := parseMemLimit(readFile("/sys/fs/cgroup/memory/memory.limit_in_bytes")); ok {
		return n, "cgroup v1 memory.limit_in_bytes"
	}
	return 0, "not detected"
}

// detectScratch reads the declared ephemeral-storage ceiling. There is no measured
// fallback on purpose: statfs inside the container sees the node's filesystem, not
// the emptyDir's kubelet-enforced sizeLimit, so a fallback would be a number that
// looks authoritative and is wrong in the direction that gets the pod evicted.
//
// SCRATCH_BYTES is checked first so the knob that shipped keeps winning over a
// Downward API reference an operator may have added without revisiting it.
func detectScratch() (int64, string) {
	if n, ok := parseMemLimit(lookupEnv("SCRATCH_BYTES")); ok {
		return n, "SCRATCH_BYTES"
	}
	if n, ok := parseMemLimit(lookupEnv(envEphemeralLimit)); ok {
		return n, "downward API " + envEphemeralLimit
	}
	return 0, "not declared"
}

// parseCPUMilli reads a millicore count.
//
// MILLICORES, always, whether or not the "m" suffix is present. That is what the
// manifest's `divisor: "1m"` produces (a bare "100"), and accepting the suffix as
// well only means an operator who sets the variable by hand in the obvious
// Kubernetes spelling gets the same answer rather than a silent 1000x.
//
// Deliberately NOT accepting a fractional core count. "0.5" would have to mean half
// a core here and half a millicore under the variable's own name, and there is no
// reading of that which is safe to guess at: a wrong guess either stretches the
// expected drain time by 1000x or shrinks it by the same, and one of those makes a
// pod look healthy that is about to time out every large bundle.
func parseCPUMilli(s string, present bool) (int64, bool) {
	if !present {
		return 0, false
	}
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, "m")
	if s == "" || s == "max" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// parseMemLimit interprets one byte-valued ceiling, from a cgroup file or from an
// environment variable. It reports ok=false for an absent file, the literal "max",
// an unparseable value, or a sentinel standing in for "unlimited" — all of which
// mean the same thing to a caller: there is no ceiling worth sizing against.
//
// Kubernetes binary (Ki/Mi/Gi/Ti/Pi) and decimal (k/M/G/T/P) suffixes are accepted,
// plus an uppercase "K" that Kubernetes itself does not allow — leniency, since it can
// only mean one thing. They are accepted because the values that reach here are
// not all machine-written. SCRATCH_BYTES is typed by an operator into a ConfigMap
// that sits directly below `sizeLimit: 14Gi` and is documented as "keep these
// equal", so "14Gi" is the form they will naturally write — and a plain ParseInt
// discards it, falls through to the next source, and sizes the pod from the default
// with no error anywhere. A silently ignored declaration is the worst outcome
// available here: the pod looks configured and is not.
func parseMemLimit(s string, present bool) (int64, bool) {
	if !present {
		return 0, false
	}
	return ParseBytes(s)
}

// ParseBytes reads a positive byte count written either as a plain integer or with a
// Kubernetes quantity suffix (Ki/Mi/Gi/Ti/Pi, k/M/G/T/P). It reports ok=false for
// anything it cannot turn into a usable ceiling: empty, "max", a bad suffix, zero or
// negative, or a magnitude at or above the "unlimited" sentinel.
//
// Exported so cmd/scrubberd can read its own byte-valued settings the same way. The
// two used to disagree — the cgroup path here and strconv.ParseInt there — which
// meant an operator could write 14Gi in one variable and have it work, write it in
// the next and have it vanish.
func ParseBytes(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "max" {
		return 0, false
	}
	mult := int64(1)
	// Longest suffixes first: "Ki" must not be matched as "K".
	for _, u := range []struct {
		suffix string
		mult   int64
	}{
		{"Ki", 1 << 10}, {"Mi", 1 << 20}, {"Gi", 1 << 30}, {"Ti", 1 << 40}, {"Pi", 1 << 50},
		{"k", 1e3}, {"K", 1e3}, {"M", 1e6}, {"G", 1e9}, {"T", 1e12}, {"P", 1e15},
	} {
		if rest, ok := strings.CutSuffix(s, u.suffix); ok {
			s, mult = strings.TrimSpace(rest), u.mult
			break
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, false
	}
	// Overflow before the magnitude test, or a hostile "9000000Pi" wraps negative
	// and reads as a modest ceiling.
	if n > unlimited/mult {
		return 0, false
	}
	if n *= mult; n >= unlimited {
		return 0, false
	}
	return n, true
}

func readFile(path string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// lookupEnv gives os.Getenv parseMemLimit's (value, present) shape. Deliberately not
// os.LookupEnv: that reports a variable set to the empty string as present, and an
// unset ConfigMap key looks exactly like that once it has been through envFrom.
func lookupEnv(k string) (string, bool) {
	v := os.Getenv(k)
	return v, v != ""
}
