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
	// CPUs is GOMAXPROCS as the runtime resolved it. Go 1.25 derives this from
	// the cgroup CPU bandwidth limit, so it already reflects `limits.cpu` and
	// needs no separate detection here — it is reported so the startup log shows
	// the whole picture in one place.
	CPUs int
}

// Detect reads the container's limits. It never fails: anything it cannot
// determine is left zero for the caller to fall back on.
func Detect() Limits {
	l := Limits{CPUs: runtime.GOMAXPROCS(0)}
	l.MemoryBytes, l.MemorySource = detectMemory()
	return l
}

// detectMemory tries cgroup v2 then v1.
//
// v2 is checked first because a host running v2 in unified mode has no v1 files
// at all, while a host in hybrid mode has both — and there the v1 tree is often
// the stub, not the enforced one.
func detectMemory() (int64, string) {
	if n, ok := parseMemLimit(readFile("/sys/fs/cgroup/memory.max")); ok {
		return n, "cgroup v2 memory.max"
	}
	if n, ok := parseMemLimit(readFile("/sys/fs/cgroup/memory/memory.limit_in_bytes")); ok {
		return n, "cgroup v1 memory.limit_in_bytes"
	}
	return 0, "not detected"
}

// parseMemLimit interprets one cgroup memory-limit file. It reports ok=false for
// an absent file, the literal "max", an unparseable value, or a sentinel standing
// in for "unlimited" — all of which mean the same thing to a caller: there is no
// ceiling worth sizing against.
func parseMemLimit(s string, present bool) (int64, bool) {
	if !present {
		return 0, false
	}
	s = strings.TrimSpace(s)
	if s == "" || s == "max" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 || n >= unlimited {
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
