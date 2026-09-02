// Command scrubberd is the OCP-hosted service form of scrubber. It runs a
// MinIO/S3 bucket-driven data plane (input -> scrubbed output + report) and a
// data-free control/observability HTTP plane (health, readiness, metrics,
// policies, jobs) that is safe to expose on an external Route.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/howard/scrubber/internal/metrics"
	"github.com/howard/scrubber/internal/pipeline"
	"github.com/howard/scrubber/internal/podres"
	"github.com/howard/scrubber/internal/policy"
	"github.com/howard/scrubber/internal/report"
	"github.com/howard/scrubber/internal/server"
	"github.com/howard/scrubber/internal/spill"
	"github.com/howard/scrubber/internal/store"
	"github.com/howard/scrubber/internal/worker"
	"github.com/prometheus/client_golang/prometheus"
)

// version is the release this binary was built from. It is stamped at build time:
//
//	go build -ldflags "-X main.version=0.8.3" ./cmd/scrubberd
//
// and deploy/Containerfile passes the VERSION build-arg through to exactly that.
// The default is deliberately "dev" rather than a number: a binary that was built
// without the stamp must not claim to be a release, because the whole point of the
// field is answering "which build is actually running in this cluster?" -- and a
// wrong answer there is worse than an obviously missing one.
//
// It reaches an operator three ways: the startup log, GET /api/version, and the
// scrubber_build_info metric. The UI shows it in the footer.
var version = "dev"

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel()}))
	if err := realMain(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// logLevel reads LOG_LEVEL (debug|info|warn|error). Debug emits a line per file
// inside every bundle, which is how an operator sees what is being scrubbed as
// it happens rather than only a single line once the object completes.
func logLevel() slog.Level {
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func realMain(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Every configuration fault below is collected here and reported together, once,
	// before anything starts. See startupProblems for why that is worth the
	// restructuring it costs.
	probs := &startupProblems{}

	// --- required configuration ---
	//
	// Read up front rather than inline, so a deployment missing four variables is told
	// about four variables. Inline reads meant the first one aborted the process and
	// the rest stayed invisible until the next restart.
	var (
		minioEndpoint = probs.req("MINIO_ENDPOINT", "host:port of the MinIO/S3 API, no scheme")
		minioAccess   = probs.reqSecret("MINIO_ACCESS_KEY", "MinIO access key, from the scrubber-secret Secret")
		minioSecret   = probs.reqSecret("MINIO_SECRET_KEY", "MinIO secret key, from the scrubber-secret Secret")
		inputBucket   = probs.req("INPUT_BUCKET", "bucket the worker polls for new uploads")
		outputBucket  = probs.req("OUTPUT_BUCKET", "bucket scrubbed results are written to")
		reportsBucket = probs.req("REPORTS_BUCKET", "bucket per-object reports are written to")
	)

	// --- MinIO store ---
	st, err := store.New(store.Config{
		Endpoint:       minioEndpoint,
		AccessKey:      minioAccess,
		SecretKey:      minioSecret,
		UseTLS:         envBool("MINIO_USE_TLS", true),
		CACert:         os.Getenv("MINIO_CA_CERT"),
		Region:         os.Getenv("MINIO_REGION"),
		PublicEndpoint: os.Getenv("MINIO_PUBLIC_ENDPOINT"),
		PublicTLS:      envBool("MINIO_PUBLIC_TLS", true),
		// Abandon a transfer that has moved no bytes for this long. Not a deadline
		// on the transfer: a large object over a congested link legitimately takes
		// minutes, and a deadline generous enough to allow that is too generous to
		// catch a hang. Negative disables it, restoring the unbounded wait.
		StallTimeout: envDuration("TRANSFER_STALL_TIMEOUT", 60*time.Second),
		// Listings get their own bound: a listing's honest duration scales with the
		// bucket rather than with the network, since it paginates and the input
		// bucket includes processed/. It used to be derived as 10x the stall
		// timeout, which put it at ten minutes by default — long enough that a dead
		// backend looked idle rather than broken.
		ListTimeout: envDuration("LIST_TIMEOUT", 90*time.Second),
	})
	if err != nil {
		probs.addf("the object-storage client could not be built."+NL+
			"      Endpoint: %q"+NL+
			"      Error:    %v"+NL+
			"      Fix:      MINIO_ENDPOINT must be host:port with no scheme. If "+
			"MINIO_USE_TLS is true, MINIO_CA_CERT must point at a readable PEM.",
			minioEndpoint, err)
	}

	// --- policies ---
	policyDir := envDefault("POLICIES_DIR", "/etc/scrubber/policies")
	prefixMap, err := parsePrefixMap(os.Getenv("PREFIX_POLICY_MAP"))
	if err != nil {
		probs.addf("PREFIX_POLICY_MAP is not a usable value."+NL+
			"      Value: %q"+NL+
			"      Error: %v"+NL+
			"      Fix:   a JSON object mapping key prefix to policy name; see the "+
			"PREFIX_POLICY_MAP comment in the ConfigMap for an example. Unset routes "+
			"everything to DEFAULT_POLICY.",
			os.Getenv("PREFIX_POLICY_MAP"), err)
	}
	// Loaded before the gate so a broken policy ConfigMap is reported in the same
	// breath as a missing bucket. It is also the one fault that would otherwise be
	// discovered by the service running perfectly and scrubbing nothing.
	var reg *policy.Registry
	if reg, err = policy.New(policyDir, os.Getenv("DEFAULT_POLICY"), prefixMap); err != nil {
		probs.addf("the policy set could not be loaded."+NL+
			"      Directory:      %s"+NL+
			"      DEFAULT_POLICY: %q"+NL+
			"      Error:          %v"+NL+
			"      Fix:            every *.json there must be a valid terms document, and "+
			"DEFAULT_POLICY must name one of them without the .json suffix. Check the "+
			"scrubber-policies ConfigMap is mounted at POLICIES_DIR.",
			policyDir, os.Getenv("DEFAULT_POLICY"), err)
	}

	// --- metrics + worker ---
	promReg := prometheus.NewRegistry()
	m := metrics.New(promReg)
	// A build_info gauge is the conventional way to answer "what is deployed?" from
	// monitoring rather than by shelling into a pod, and it joins to every other
	// series by instance.
	metrics.RegisterBuildInfo(promReg, version)
	jobs := metrics.NewJobLog(envInt("JOBS_HISTORY", 200))

	// A typo here resolving quietly to "full" would retain matched cleartext in every
	// stored report, so it is a fault rather than a default.
	audit, err := report.ParseAuditLevel(envDefault("AUDIT_LEVEL", "counts"))
	if err != nil {
		probs.addf("AUDIT_LEVEL is not one of the accepted values."+NL+
			"      Value: %q"+NL+
			"      Error: %v"+NL+
			"      Fix:   use full, counts or off. It governs how much matched cleartext "+
			"the stored report keeps, so it is not defaulted.",
			envDefault("AUDIT_LEVEL", "counts"), err)
	}

	// --- size the caps against the pod we actually got ---
	//
	// Every number here was measured on a 2 GiB / 1 CPU pod and then compiled in as
	// a default, which silently made 2 GiB the only size the service was tuned for.
	// On a larger pod it left the extra idle and scrubbed no faster; the operator's
	// only recourse was to raise the knobs by hand, and raising the spill ones too
	// far turns spilling off and reproduces the OOM the spill exists to prevent.
	//
	// So the measured values are ratios to the pod they were measured on, and the
	// ceilings are read at startup — from the Downward API where the manifest
	// projects them, from the cgroup otherwise. See deriveCaps for which resource
	// governs which cap and why the two must not be swapped. An explicit
	// environment variable still wins over all of it: this changes defaults, not
	// policy.
	// First line out of the process, before anything can fail: whatever else goes
	// wrong below, the log says which build produced it.
	log.Info("starting scrubberd", "version", version, "go", runtime.Version())

	res := podres.Detect()
	c := deriveCaps(res)
	memScale := c.memScale
	scaled := func(base int64) int64 { return int64(float64(base) * memScale) }
	scratchBytes, scratchSource := c.scratchBytes, c.scratchSource
	maxExpandDefault, maxObjectDefault := c.expandBytes, c.objectBytes

	// A SCRATCH_BYTES that was set but did not survive parsing is the quietest way to
	// misconfigure this service: detection falls through to the next source, the pod
	// sizes itself from the default, and the only trace is a scratch_source an
	// operator has no reason to be reading. Say it out loud instead.
	// Tested against the raw value, not a trimmed one: a variable set to whitespace is
	// set as far as the operator is concerned, and it is exactly the sort of value that
	// gets there by accident.
	if raw := os.Getenv("SCRATCH_BYTES"); raw != "" && scratchSource != "SCRATCH_BYTES" {
		probs.addf("SCRATCH_BYTES is set but could not be read, so the expansion cap was "+
			"NOT sized from it."+NL+
			"      Value:      %q"+NL+
			"      Sized from: %s (%d bytes)"+NL+
			"      Fix:        write a plain byte count or a Kubernetes quantity, e.g. "+
			"14Gi or 15032385536. This used to be a warning; it is fatal because a pod "+
			"that ignores its own scratch declaration sizes itself from the default and "+
			"refuses bundles it has the disk for.",
			raw, scratchSource, scratchBytes)
	}

	expandBytes := envInt64(probs, "MAX_EXPAND_BYTES", maxExpandDefault)
	// A backstop, and deliberately a redundant one: podres.ParseBytes already refuses
	// any magnitude at or above the same sentinel, so on today's code paths this branch
	// is unreachable and its warning cannot fire. That was checked, not assumed.
	//
	// It stays because the invariant is not local to either place. The read guards add
	// one to their budget to tell "exactly at the limit" from "over it", so a budget
	// near the top of the int64 range wraps negative, io.CopyN then copies nothing,
	// every payload reads as EMPTY, and the object ships unscrubbed while the report
	// certifies it complete. That failure is silent and total, and two independent
	// limits now have to drift apart before it can return.
	if expandBytes > maxExpandCeiling {
		log.Warn("MAX_EXPAND_BYTES is implausibly large and has been clamped; "+
			"the expansion budget is a disk bound, so size it from the declared scratch ceiling",
			"requested", expandBytes, "clamped_to", int64(maxExpandCeiling))
		expandBytes = maxExpandCeiling
	}

	wcfg := worker.Config{
		InputBucket:     inputBucket,
		OutputBucket:    outputBucket,
		ReportsBucket:   reportsBucket,
		InputPrefix:     os.Getenv("INPUT_PREFIX"),
		ProcessedPrefix: envDefault("PROCESSED_PREFIX", "processed/"),
		// Where a result lands when content the scrub did not inspect turns out to
		// contain policy matches. Set empty to keep everything in one place and rely
		// on the flagging alone.
		ReviewPrefix: envDefault("REVIEW_PREFIX", "review/"),
		// Where a withdrawn input lands under PROCESSED_ACTION=move. Never empty:
		// eligibility prefix-matches on it and "" is a prefix of every key.
		CancelledPrefix: envDefault("CANCELLED_PREFIX", "cancelled/"),
		Action:          worker.ProcessedAction(envDefault("PROCESSED_ACTION", "move")),
		PollInterval:    envDuration("POLL_INTERVAL", 15*time.Second),
		// Clamped to 1 by worker.New. Read from the environment anyway so an
		// operator who set it higher gets told it is being ignored.
		Workers:  envInt("WORKERS", 1),
		QueueMax: envInt("QUEUE_MAX", 10000),
		// Defaults match the shipped manifest. They used to disagree with it and
		// with the README, which made the startup memory arithmetic unverifiable.
		MaxObjectBytes: envInt64(probs, "MAX_OBJECT_BYTES", maxObjectDefault),
		FinalizeGrace:  envDuration("FINALIZE_GRACE", 15*time.Second),
		StallWarnAfter: envDuration("STALL_WARN_AFTER", 5*time.Minute),
		// The one bound on the walk itself. See worker.Config.ScrubTimeout for why
		// nothing else is one, and the sizing check below for how this default was
		// picked against MAX_EXPAND_BYTES.
		ScrubTimeout:  envDuration("SCRUB_TIMEOUT", defaultScrubTimeout),
		Audit:         audit,
		RedactReports: envBool("REDACT_REPORTS", false),
		ScrubNames:    envBool("SCRUB_FILENAMES", true),
		Limits: pipeline.Limits{
			MaxDepth: envInt("MAX_DEPTH", 16),
			// Expanded CONTENT one object may hold, derived above from the declared
			// scratch ceiling rather than from a compiled-in number. Since members
			// spill this bounds DISK, and the disk actually touched is ~scratchFactor
			// times it. Set it explicitly only to go BELOW what the declaration
			// allows: setting it above is how a pod gets evicted for ephemeral
			// storage, and startup warns when it does. See
			// deploy/openshift-manifests.yaml for the arithmetic and
			// scripts/memory-matrix.sh for how to re-derive it after any change.
			MaxTotalBytes: expandBytes,
			MaxMembers:    envInt("MAX_MEMBERS", 100000),
			// The largest single text file this pod can hold contiguously, and the
			// one cap that really is a function of limits.memory: the matcher needs
			// its payload as a string, and Bytes/Decode/Scrub/Encode each keep a copy
			// outside the spill accounting. Scaled from the same 2 GiB baseline as
			// the spill knobs so it grows with the pod instead of pinning it.
			//
			// Without it, raising the expansion budget converts a clean guard trip
			// into an OOM crash-loop on the first oversized log. Set 0 to disable.
			MaxLeafBytes: envInt64(probs, "MAX_LEAF_BYTES", c.leafBytes),
			// Bytes the residual scan may read across one object. Negative disables
			// it, which removes the only check that does not depend on the pipeline's
			// own classification being correct — the check that would have caught
			// UTF-16 logs being filed as binary.
			ResidualBudget: envInt64(probs, "RESIDUAL_BUDGET", pipeline.DefaultResidualBudget),
			// Re-scan every scrubbed file to confirm the policy no longer matches it.
			// Off by default because it roughly doubles matcher work (measured at ~70%
			// of the drain rate) and the failure it catches is rejected at policy load
			// instead. Worth turning on if you suspect the matcher itself.
			VerifyOutput: envBool("VERIFY_OUTPUT", false),
			Spill: spill.Policy{
				// Payloads above SPILL_THRESHOLD go to disk on their own; once live
				// in-memory payloads exceed SPILL_RESIDENT_MAX everything spills
				// regardless of size. The second limit is the one that catches an
				// archive of many small members, which the memory matrix ranks worst.
				Threshold:   envInt64(probs, "SPILL_THRESHOLD", max64(scaled(4<<20), minSpillThreshold)),
				ResidentMax: envInt64(probs, "SPILL_RESIDENT_MAX", scaled(64<<20)),
			},
		},
	}
	if os.Getenv("MAX_RATIO") != "" {
		log.Warn("MAX_RATIO is ignored and can be removed from the config. " +
			"An expansion-ratio limit cannot distinguish a decompression bomb from an " +
			"ordinary log file (logs routinely compress 200:1 and beyond), and tripping " +
			"it emitted the object UNSCRUBBED. Expansion is now bounded by MAX_EXPAND_BYTES, " +
			"enforced while decompressing — which bounds scratch, not memory; memory is " +
			"bounded by MAX_LEAF_BYTES and the SPILL_* pair.")
	}
	// Three different ceilings, and conflating them is how a pod gets killed:
	//
	//   budget_bytes  — what the expansion accounting caps. Since archive members
	//                   spill, this bounds mostly DISK on the scratch volume.
	//   est_peak_rss  — resident memory. Only the member being scrubbed is on the
	//                   heap, so this is the aggregate in-memory spill budget, plus
	//                   a few copies of the largest single file (the leaf scrubber
	//                   needs a contiguous string, so MAX_LEAF_BYTES is what bounds
	//                   this term — NOT the spill threshold, which Blob.Bytes reads
	//                   straight past), plus per-member bookkeeping, which spilling
	//                   does not remove and which scales with MAX_MEMBERS, plus
	//                   runtime baseline and GC slack.
	//   scratch_bytes — the disk a single object can occupy. A .tar.gz stages the
	//                   decompressed container, the member bodies and the repacked
	//                   result, so budget well above the expansion cap.
	//
	// Read these as CHECKS on the declaration, not as instructions for writing it.
	// The /work sizeLimit is an input now — the expansion cap is derived by dividing
	// it — so sizing the volume from scratch_bytes would be circular. scratch_bytes
	// is normally scratch_declared echoed back, and the two diverge exactly when
	// someone set MAX_EXPAND_BYTES by hand, which is what the warnings below are for.
	//
	// est_peak_rss is the one still worth sizing against: compare it to limits.memory
	// and lower MAX_LEAF_BYTES, or raise the memory, if it is close. Re-derive both
	// with scripts/memory-matrix.sh after any change.
	budget := wcfg.MaxObjectBytes + wcfg.Limits.MaxTotalBytes
	sp := wcfg.Limits.Spill
	// The leaf term used to be leafCopies*SPILL_THRESHOLD, which quietly assumed the
	// spill threshold bounds the largest payload the matcher holds. It does not:
	// Blob.Bytes reads a spilled leaf back in full whatever the threshold, so the
	// estimate was short by the difference between 4Mi and the biggest file in the
	// bundle — and that gap is exactly what OOM-kills a pod. MAX_LEAF_BYTES is the
	// real bound; with the cap disabled the only bound left is the whole budget,
	// and the gate below should say so rather than flatter the configuration.
	leafBytes := wcfg.Limits.MaxLeafBytes
	if leafBytes <= 0 {
		leafBytes = wcfg.Limits.MaxTotalBytes
	}
	estPeak := int64(float64(sp.ResidentMax+leafCopies*leafBytes)*peakRSSFactor) +
		runtimeBaselineBytes + int64(wcfg.Limits.MaxMembers)*perMemberBytes
	scratch := int64(scratchFactor * float64(wcfg.Limits.MaxTotalBytes))

	// Let the GC know the ceiling too. Go applies GOMEMLIMIT from the environment
	// at init, so setting it here would override an operator's explicit value —
	// only derive one when they have not. Scaled from the same measured baseline
	// as the spill policy: the two have to move together, because GOMEMLIMIT only
	// holds while the live set fits underneath it, and the spill policy is what
	// bounds the live set.
	if os.Getenv("GOMEMLIMIT") == "" && res.MemoryBytes > 0 {
		lim := scaled(1200 << 20)
		debug.SetMemoryLimit(lim)
		log.Info("derived GOMEMLIMIT from the detected pod memory", "bytes", lim)
	}

	log.Info("resource limits",
		"max_object_bytes", wcfg.MaxObjectBytes,
		"max_expand_bytes", wcfg.Limits.MaxTotalBytes,
		"spill_threshold", sp.Threshold,
		"spill_resident_max", sp.ResidentMax,
		// The largest file that can actually be scrubbed, as opposed to the largest
		// bundle that can be opened. Operators conflate the two and then wonder why a
		// bundle came back "incomplete" on a pod with plenty of disk.
		"max_leaf_bytes", wcfg.Limits.MaxLeafBytes,
		"max_members", wcfg.Limits.MaxMembers,
		"queue_concurrency", 1,
		"queue_max", wcfg.QueueMax,
		"budget_bytes", budget,
		"est_peak_rss_bytes", estPeak,
		"scratch_bytes", scratch,
		// What the sizing was derived from, so the numbers above can be checked
		// rather than taken on faith. pod_memory_bytes 0 means detection failed
		// and the measured 2 GiB defaults are in force.
		"pod_memory_bytes", res.MemoryBytes,
		"pod_memory_source", res.MemorySource,
		// The pair that governs how large a bundle may expand. scratch_source is
		// the line to read first when max_expand_bytes is not what was expected:
		// "default (undeclared)" means the manifest never told the pod how much
		// /work it has, so it is sizing itself from the shipped 4Gi regardless of
		// what the emptyDir actually grants.
		"scratch_declared_bytes", scratchBytes,
		"scratch_source", scratchSource,
		"pod_cpus", res.CPUs,
		// The request, not just GOMAXPROCS. A pod can look like four cores to the
		// runtime and be promised a tenth of one; the second number is what decides
		// how long a bundle takes on a busy node.
		"cpu_request_milli", res.CPURequestMilli,
		"cpu_limit_milli", res.CPULimitMilli,
		"cpu_source", res.CPUSource,
		"expected_full_bundle_drain", expectedDrain(res, wcfg.Limits.MaxTotalBytes),
		"mem_scale", memScale,
		// Repeated on this line as well as the startup line above, because this is
		// the line an operator screenshots when the caps are not what they expected,
		// and the first question is always which build produced them.
		"version", version)

	// Two ways to get this wrong that are worth naming at startup rather than
	// leaving to be discovered as an eviction or an OOM under load.
	if res.MemoryBytes > 0 && estPeak > res.MemoryBytes*peakRSSGatePercent/100 {
		probs.sizing("estimated peak RSS is above the safe share of this pod's memory."+NL+
			"      Estimated peak: %d bytes (%d MiB)"+NL+
			"      Pod memory:     %d bytes (%d MiB), gate is %d%% of it"+NL+
			"      Leaf term:      %d bytes (%d MiB) -- MAX_LEAF_BYTES is %d"+NL+
			"      Fix:            lower MAX_LEAF_BYTES, SPILL_RESIDENT_MAX, "+
			"SPILL_THRESHOLD or MAX_MEMBERS, or raise limits.memory. The leaf term "+
			"usually dominates; MAX_LEAF_BYTES=0 disables the cap and falls back to the "+
			"whole expansion budget, which no pod can hold contiguously.",
			estPeak, estPeak>>20, res.MemoryBytes, res.MemoryBytes>>20,
			peakRSSGatePercent, leafBytes, leafBytes>>20, wcfg.Limits.MaxLeafBytes)
	}
	if scratch > scratchBytes {
		probs.sizing("one object can need more scratch than this pod has declared."+NL+
			"      Needed:   %d bytes (%d MiB) -- %.1fx MAX_EXPAND_BYTES"+NL+
			"      Declared: %d bytes (%d MiB), from %s"+NL+
			"      Fix:      lower MAX_EXPAND_BYTES to at most %d, or raise all four "+
			"scratch declarations together (the /work sizeLimit, limits and requests "+
			"ephemeral-storage, and SCRATCH_BYTES). Left alone, a large bundle fills the "+
			"volume and the kubelet evicts the pod mid-object -- no report, no reason "+
			"code, and the same object is picked up again after the restart.",
			scratch, scratch>>20, scratchFactor, scratchBytes, scratchBytes>>20,
			scratchSource, int64(float64(scratchBytes)/scratchFactor))
	}
	// A budget too small for the bundles this pod is configured to accept fails every
	// large object, permanently, and the failure looks like a broken bundle rather
	// than a setting. A warning, not a fault: the operator may know their inputs are
	// nowhere near the cap, and this is the one check whose input is a guess about
	// hardware rather than a declared resource.
	if wcfg.ScrubTimeout > 0 {
		rate, rateWhy := drainRate(res)
		if need := time.Duration(wcfg.Limits.MaxTotalBytes/rate) * time.Second; need > wcfg.ScrubTimeout {
			log.Warn("SCRUB_TIMEOUT is too short for the largest bundle this pod will accept "+
				"at the CPU it is guaranteed; an object that exceeds it FAILS and is not retried",
				"scrub_timeout", wcfg.ScrubTimeout.String(),
				"max_expand_bytes", wcfg.Limits.MaxTotalBytes,
				"needed_at_guaranteed_cpu", need.String(),
				"assumed_bytes_per_sec", rate,
				"rate_basis", rateWhy,
				"cpu_request_milli", res.CPURequestMilli,
				"cpu_limit_milli", res.CPULimitMilli,
				"fix", "raise requests.cpu (a scrub is single-threaded, so one core is the most "+
					"one object can use and anything below that stretches it proportionally), "+
					"or raise SCRUB_TIMEOUT to at least the needed value, or lower "+
					"MAX_EXPAND_BYTES; SCRUB_TIMEOUT=0 removes the bound")
		}
	} else {
		log.Warn("SCRUB_TIMEOUT is 0: nothing bounds a scrub. One large or deeply nested "+
			"bundle can hold the single consumer indefinitely with every upload behind it "+
			"queued. STALL_WARN_AFTER only writes a log line and the transfer timeouts "+
			"bound object-storage calls, not the walk.",
			"fix", "set SCRUB_TIMEOUT to the longest a legitimate bundle may take on this pod")
	}

	// The reverse mistake, and it is the quiet one: an operator raises the volume
	// and forgets that MAX_EXPAND_BYTES is pinned in the ConfigMap, so the pod keeps
	// refusing bundles it now has the disk for — and refusing means emitting them
	// UNSCRUBBED. Only worth saying when the gap is large enough to be an oversight
	// rather than deliberate headroom.
	if headroom := int64(float64(scratchBytes) / scratchFactor); wcfg.Limits.MaxTotalBytes*4 < headroom*3 {
		log.Warn("MAX_EXPAND_BYTES is well below what the declared scratch allows; "+
			"bundles are being refused (and passed through UNSCRUBBED) on a volume "+
			"with room for them. Unset it to size from the declaration instead",
			"max_expand_bytes", wcfg.Limits.MaxTotalBytes, "would_derive", headroom,
			"scratch_bytes_declared", scratchBytes, "scratch_source", scratchSource)
	}

	// Nothing below this line runs on a misconfigured pod.
	//
	// Deliberately placed after every check rather than beside each one: the point of
	// collecting problems is that an operator fixing a deployment gets the whole list,
	// and that only works if the process reaches the end of the checks before it dies.
	if err := probs.err(); err != nil {
		return err
	}

	log.Info("loaded policies", "names", reg.Names())
	go watchPolicies(ctx, policyDir, reg, log)

	if envBool("ENSURE_BUCKETS", false) {
		for _, b := range []string{inputBucket, outputBucket, reportsBucket} {
			if err := st.EnsureBucket(ctx, b); err != nil {
				return fmt.Errorf("creating bucket %q (ENSURE_BUCKETS=true): %w", b, err)
			}
		}
	}

	// Reclaim scratch stranded by a previous process before taking any work.
	// Blob.Close removes spilled files, and a SIGKILL never runs it, so whatever
	// the last object had staged is still on the volume with no owner. Left alone
	// that accumulates across restarts until the emptyDir hits its sizeLimit and
	// the kubelet evicts for ephemeral-storage — which restarts the pod, possibly
	// mid-object again. Safe here because the queue is single-consumer and the
	// Deployment is pinned to one replica, so nothing else owns these files.
	if envBool("SCRATCH_RECLAIM", true) {
		if n, freed, rerr := spill.Reclaim(os.Getenv("TMPDIR")); n > 0 || rerr != nil {
			log.Info("reclaimed orphaned scratch files from a previous run",
				"files", n, "freed_bytes", freed, "err", rerr)
		}
	}

	wk := worker.New(st, reg, m, jobs, wcfg, log)
	metrics.RegisterQueue(promReg,
		func() float64 { return float64(wk.Queue().Depth()) },
		func() float64 { return float64(wk.Queue().Inflight()) })
	// The series that separates "slow" from "wedged". Neither probe below can:
	// /healthz is a pure liveness signal that answers 200 whatever the worker is
	// doing, and /readyz only says the backend is reachable — a stalled read
	// leaves both green indefinitely.
	metrics.RegisterProgress(promReg, wk.InflightPhaseSeconds)

	// --- control + browser API server ---
	// Readiness is checked every few seconds by the kubelet. Probing MinIO on
	// every call with no deadline means a slow backend makes the probe hang, the
	// pod drop out of the Route, and in-flight browser polls fail — so the result
	// is cached briefly and the check is given its own timeout.
	ready := cachedReady(func() bool {
		cctx, cancel := context.WithTimeout(ctx, readyProbeTimeout)
		defer cancel()
		return st.Healthy(cctx, inputBucket)
	}, readyCacheTTL)
	srv := &http.Server{
		Addr: ":" + envDefault("PORT", "8080"),
		Handler: server.New(server.Deps{
			Policies:      reg,
			Jobs:          jobs,
			Prom:          promReg,
			Ready:         ready,
			Presigner:     st,
			Archive:       st,
			Queue:         wk,
			Nudge:         wk.Nudge,
			Version:       version,
			DefaultPolicy: os.Getenv("DEFAULT_POLICY"),
			AllowEdit:     envBool("ALLOW_POLICY_EDIT", true),
			InputBucket:   inputBucket,
			OutputBucket:  outputBucket,
			ReportsBucket: reportsBucket,
			UploadExpiry:  envDuration("UPLOAD_EXPIRY", 15*time.Minute),
			HistoryMax:    envInt("HISTORY_MAX", 100),
			Canceller:     wk,
			// Cancelling is on by default, matching ALLOW_POLICY_EDIT: the operators
			// are insiders and a stuck object blocking the queue is their problem to
			// clear. A cancel still needs the token this server minted for that key
			// at upload time.
			AllowCancel: envBool("ALLOW_CANCEL", true),
			// Cancelling an object this client did not upload is OFF by default and
			// should stay off unless there is real authentication in front of the
			// Route. /api/queue and /api/history both publish live input keys, so
			// with no auth this turns a two-line loop into a durable, restart-
			// surviving evacuation of every user's work.
			AllowCancelAny: envBool("ALLOW_CANCEL_ANY", false),
			CancelBudget:   envDuration("CANCEL_BUDGET", 60*time.Second),
			// Total object-storage time one HTTP request may spend. The store
			// bounds each call; this bounds their sum, which is what a browser
			// polling every second actually experiences. Negative disables it.
			StorageBudget: envDuration("API_STORAGE_BUDGET", 5*time.Second),
		}).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Info("control server listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("control server", "err", err)
			stop()
		}
	}()

	// --- run worker until signal ---
	workerDone := make(chan struct{})
	go func() { defer close(workerDone); wk.Run(ctx) }()

	<-ctx.Done()
	log.Info("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	err = srv.Shutdown(shutCtx)

	// Wait for the worker rather than exiting out from under it. On cancellation it
	// stops taking new work immediately, and an object that has already finished
	// scrubbing persists its output on a detached context, so this is bounded by
	// FinalizeGrace rather than by however long a large bundle takes.
	select {
	case <-workerDone:
	case <-shutCtx.Done():
		log.Warn("worker did not stop within the shutdown budget; exiting anyway",
			"budget", shutdownTimeout)
	}
	return err
}

// caps is the sizing derived from what the pod declares about itself, before any
// explicit environment override is applied.
//
// It is a separate value with a pure constructor because this arithmetic used to be
// twenty lines inline in realMain, where nothing could reach it: cmd/scrubberd had
// no test at all, so the chain from "the manifest says 14Gi" to "the engine accepts
// a 4 GiB bundle" was the least-tested and most load-bearing calculation in the
// service. Every field below is asserted in main_test.go.
type caps struct {
	// scratchBytes is the ephemeral-storage ceiling the caps were sized from, and
	// scratchSource says whether the pod declared it or it was assumed.
	scratchBytes  int64
	scratchSource string
	// expandBytes is the expanded CONTENT one object may hold.
	expandBytes int64
	// objectBytes is the compressed upload ceiling, held at a fixed share of
	// expandBytes so it stays the limit a user hits first.
	objectBytes int64
	// leafBytes is the largest single file the matcher may materialise. Alone among
	// these it follows MEMORY, because it is the one payload the spill policy cannot
	// bound.
	leafBytes int64
	// memScale is the pod's memory relative to the pod every default was measured on.
	memScale float64
}

// deriveCaps sizes the service from the pod's declared ceilings.
//
// Two ceilings, two different resources, and keeping them apart is the whole point:
//
//	scratch (limits.ephemeral-storage / the /work sizeLimit) bounds how large a
//	bundle may EXPAND, because archive members spill to TMPDIR and every expanded
//	byte lands there.
//
//	memory (limits.memory) bounds how large a single FILE may be scrubbed, because
//	the matcher needs one contiguous string and that copy never touches disk.
//
// Sizing either from the other reads plausibly and fails in production: an
// expansion budget from limits.memory evicts the pod for ephemeral-storage, and a
// leaf cap from the volume size OOM-kills it. Both were previously compiled in —
// the expansion cap as a flat 1536Mi that moved only if SCRATCH_BYTES was set, so a
// pod handed 8Gi of /work still refused anything past 1536Mi, and refusing means
// emitting the object UNSCRUBBED. Now the declaration in deployment.yaml is the
// ceiling: raise it and the caps follow on the next rollout.
//
// Scratch has no measured fallback on purpose. An emptyDir's sizeLimit is enforced
// by the kubelet, not the filesystem, so statfs inside the container reports the
// node's whole disk — a number that looks authoritative and is wrong in the
// direction that gets the pod evicted. Undeclared falls back to the sizeLimit the
// shipped manifest carries, so a deployment that never engages with any of this
// behaves as it always has.
func deriveCaps(res podres.Limits) caps {
	c := caps{
		scratchBytes:  res.ScratchBytes,
		scratchSource: res.ScratchSource,
		memScale:      podScale(res.MemoryBytes),
	}
	if c.scratchBytes <= 0 {
		c.scratchBytes, c.scratchSource = defaultScratchBytes, "default (undeclared)"
	}
	c.expandBytes = int64(float64(c.scratchBytes) / scratchFactor)
	c.objectBytes = int64(float64(c.expandBytes) * shippedObjectShare)
	c.leafBytes = int64(float64(maxLeafBaseline) * c.memScale)
	return c
}

// podScale converts a detected pod memory ceiling into the multiplier applied to
// the defaults measured at baselineMemBytes.
//
// Returns 1 when the ceiling is unknown, which reproduces exactly the caps that
// shipped: an undetectable limit must fall back to a measured configuration, not
// to an extrapolation from a number nobody has.
// drainRate estimates how fast this pod can actually scrub, in bytes per second,
// and says what the estimate rests on.
//
// The guarantee, not the ceiling. requests.cpu is the share the scheduler promised
// and the only figure that still holds when the node is busy; limits.cpu is what the
// pod may burst to when it is not. A pod declaring `requests.cpu: 100m, limits.cpu:
// 4` is four cores to the Go runtime and a tenth of one under load — a 40x spread in
// how long a bundle takes, and the slow end is the end that trips a timeout.
//
// Capped at one core because the walk is single-threaded: WORKERS is clamped to 1
// and the Engine is not safe for concurrent Process calls, so a request above 1000m
// makes one object no faster. It makes the pod steadier under load, which is worth
// having, but not shorter.
// expectedDrain is how long a full-sized bundle should take on this pod, rendered
// for the startup line. It is the number to compare against SCRUB_TIMEOUT, and the
// number to check first when someone reports that a scrub is taking hours.
func expectedDrain(res podres.Limits, maxExpand int64) string {
	if maxExpand <= 0 {
		return "unknown"
	}
	rate, _ := drainRate(res)
	return (time.Duration(maxExpand/rate) * time.Second).String()
}

func drainRate(res podres.Limits) (int64, string) {
	if res.CPURequestMilli <= 0 {
		return scrubFloorBytesPerSec, "requests.cpu not declared; assuming a squeezed pod"
	}
	milli := res.CPURequestMilli
	if milli > 1000 {
		milli = 1000
	}
	rate := scrubBytesPerCoreSec * milli / 1000
	if rate < 1 {
		rate = 1
	}
	return rate, fmt.Sprintf("%dm guaranteed of one usable core at %d B/s per core",
		res.CPURequestMilli, int64(scrubBytesPerCoreSec))
}

func podScale(memBytes int64) float64 {
	if memBytes <= 0 {
		return 1
	}
	return float64(memBytes) / float64(baselineMemBytes)
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

const (
	// readyProbeTimeout bounds a single backend reachability check.
	readyProbeTimeout = 3 * time.Second
	// readyCacheTTL is how long a readiness result is reused across probes.
	readyCacheTTL = 5 * time.Second
	// shutdownTimeout bounds the whole graceful stop: draining HTTP plus letting
	// the worker persist whatever it had finished. Keep it inside the pod's
	// terminationGracePeriodSeconds, or the kubelet kills the process first.
	shutdownTimeout = 30 * time.Second
	// leafCopies is how many copies of a payload the leaf scrubber briefly holds:
	// the bytes, the string the matcher needs, and the scrubbed result.
	leafCopies = 3
	// baselineMemBytes is the pod every default in this file was measured on. The
	// caps are stored as a ratio to it rather than as absolutes, so a pod of a
	// different size gets proportional caps instead of 2 GiB's. Changing this
	// invalidates every published measurement — change the ratios instead.
	baselineMemBytes = 2 << 30
	// minSpillThreshold floors the per-payload spill threshold as it scales down.
	// The threshold exists to keep an archive of many small members from creating
	// one file per member; scaled linearly onto a very small pod it would fall low
	// enough to do exactly that, trading memory pressure for inode pressure.
	minSpillThreshold = 512 << 10
	// shippedObjectShare is MAX_OBJECT_BYTES as a fraction of MAX_EXPAND_BYTES in
	// the measured configuration (640Mi of 1536Mi). Held constant as the caps are
	// derived from the declared scratch ceiling so the compressed-object ceiling
	// stays the limit a user hits first, which is the one with a clear error
	// message. It is also the C term in scratchFactor below — change one and the
	// other stops covering the peak.
	shippedObjectShare = 640.0 / 1536.0
	// defaultScratchBytes is the scratch ceiling assumed when the deployment declares
	// none. It is the /work sizeLimit the manifest carried BEFORE this became
	// derivable — the shipped manifest now declares 14Gi — so a deployment that never
	// engages with any of this keeps the volume footprint it already had, rather than
	// inheriting a budget derived from the node's disk or from a larger manifest it
	// did not apply.
	defaultScratchBytes = 4 << 30
	// maxLeafBaseline is the largest single text file the matcher may materialise on
	// the 2 GiB baseline pod, scaled from there like the spill knobs.
	//
	// Not picked, solved: it is the largest leaf that keeps est_peak_rss under the
	// same 60% gate the memory matrix fails on, at the baseline pod and the derived
	// spill policy. Above ~99Mi the estimate crosses the gate and the service would
	// warn about its own defaults on every start. It scales with the pod like
	// everything else here, so a 4 GiB pod takes 192Mi and an 8 GiB pod 384Mi.
	maxLeafBaseline = 96 << 20
	// maxExpandCeiling is an overflow guard, not a policy limit: the read paths
	// evaluate budget+1 to distinguish "at the limit" from "over it", and a budget
	// near math.MaxInt64 wraps that to negative — after which io.CopyN copies
	// nothing, every payload reads as empty, and objects are emitted unscrubbed
	// while looking clean. A pebibyte is far above any real pod's scratch and far
	// below where the arithmetic breaks.
	maxExpandCeiling = 1 << 50
	// peakRSSGatePercent is the share of pod memory the estimate may reach before
	// startup warns. Matches the gate scripts/memory-matrix.sh fails on, so the
	// service and the benchmark agree on what "too close" means.
	peakRSSGatePercent = 60
	// runtimeBaselineBytes is the Go runtime, the compiled policy and the HTTP
	// server — what the process costs before it touches an object.
	runtimeBaselineBytes = 128 << 20
	// scratchFactor is how much scratch disk one object can occupy relative to the
	// expansion budget, and therefore the divisor that turns the declared scratch
	// ceiling into that budget.
	//
	// For a .tar.gz whose content expands to N, three copies are live at once —
	// the decompressed tar, the member bodies read out of it, and the repacked
	// result — on top of the compressed object staged for the download. Peak is
	// C + 3N, and C is at most shippedObjectShare of N, so 3.42 covers it; 3.5 is
	// that rounded up.
	//
	// It was 2.5 while the budget double-counted a .tar.gz (charging both the
	// decompressed container and its members), because 2.5 x 2N already exceeded
	// C + 3N. Now that pipeline.descend lends the container's charge back for the
	// duration of the walk into it, the budget counts N once and the factor has to
	// carry the whole multiple itself. The two changed together and must stay
	// together: leaving this at 2.5 alongside the lend would license 2.5N of disk for
	// a shape that needs 3.42N.
	scratchFactor = 3.5
	// peakRSSFactor converts the spill policy into an estimate of actual resident
	// memory.
	//
	// The budget counts bytes *read* — the compressed object plus everything
	// decompressed out of it. Resident memory holds considerably more at the same
	// instant: the leaf being scrubbed, its scrubbed output, and heap the Go GC has
	// not yet returned. Go does not return freed heap promptly, so live-set
	// arithmetic alone understates RSS. Errs high on purpose — an estimate an
	// operator sizes a pod from should.
	peakRSSFactor = 2.5
	// perMemberBytes is the bookkeeping one archive entry costs regardless of how
	// large its payload is: the tar/zip header, the report's per-file entry, the
	// member path (recorded twice, since a scrubbed name keeps its original as the
	// report label), the blob handle, and the GC slack over all of it.
	//
	// This term exists because the spill policy alone does NOT bound resident
	// memory. Payloads go to disk, but per-member overhead does not, and it scales
	// with MAX_MEMBERS rather than with bytes — which is why the memory matrix
	// ranks a 352MiB archive of 90000 tiny members above a 500MiB one of 50 large
	// ones. Calibrated so the estimate sits above both measured shapes
	// (445MiB peak at MAX_MEMBERS=100000); see scripts/memory-matrix.sh.
	perMemberBytes = 2 << 10
	// defaultScrubTimeout is the budget one object gets before it is abandoned.
	//
	// Sized from measurement, not patience. The matcher runs at roughly 8 MB/s of
	// expanded content on one unthrottled modern core, and about 3.5 MB/s on a
	// container limited to a fraction of one -- so the 4 GiB expansion ceiling is a
	// worst case of about twenty minutes of real work. An hour leaves a wide margin
	// for a slower node and still fails an object long before it can hold the queue
	// for the afternoon.
	//
	// Set SCRUB_TIMEOUT to 0 to disable the bound entirely. That is the behaviour
	// that shipped before it existed, and it is a defensible choice for a deployment
	// with no queue contention -- but it is what lets one bundle run for hours.
	defaultScrubTimeout = time.Hour
	// scrubBytesPerCoreSec is how fast one core drains expanded content.
	//
	// Measured, not guessed: 480 MiB of log content through the real matcher took
	// 59.5s single-threaded on an unthrottled modern core, or 8.4 MB/s. This is set
	// below that because an OpenShift worker core is usually slower than a developer
	// one and the number is used to warn, not to promise.
	//
	// Per CORE, and one object never uses more than one of them: the walk is
	// single-threaded and WORKERS is clamped to 1. That is why limits.cpu buys a
	// single scrub nothing above 1 core, and why the figure that matters for how
	// long a bundle takes is the pod's CPU REQUEST.
	scrubBytesPerCoreSec = 6 << 20 // 6 MiB/s
	// scrubFloorBytesPerSec is the rate assumed when the CPU request is not
	// declared, so the timeout check still has something to judge against. Roughly a
	// third of a core at the rate above -- pessimistic, because an undeclared request
	// is exactly the pod that gets squeezed hardest on a busy node.
	scrubFloorBytesPerSec = 2 << 20 // 2 MiB/s
)

// cachedReady wraps a readiness check so concurrent probes share one in-flight
// call and the result is reused for ttl.
func cachedReady(check func() bool, ttl time.Duration) func() bool {
	var (
		mu       sync.Mutex
		last     time.Time
		lastOK   bool
		hasValue bool
	)
	return func() bool {
		mu.Lock()
		defer mu.Unlock()
		if hasValue && time.Since(last) < ttl {
			return lastOK
		}
		lastOK = check()
		last = time.Now()
		hasValue = true
		return lastOK
	}
}

// watchPolicies hot-reloads the policy registry when the mounted ConfigMap changes.
func watchPolicies(ctx context.Context, dir string, reg *policy.Registry, log *slog.Logger) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		log.Warn("policy watch disabled", "err", err)
		return
	}
	defer w.Close()
	if err := w.Add(dir); err != nil {
		log.Warn("policy watch disabled", "err", err)
		return
	}
	var debounce <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.Events:
			debounce = time.After(500 * time.Millisecond)
		case <-debounce:
			if err := reg.Reload(); err != nil {
				log.Error("policy reload failed; keeping previous set", "err", err)
			} else {
				log.Info("policies reloaded", "names", reg.Names())
			}
		case err := <-w.Errors:
			log.Warn("policy watch error", "err", err)
		}
	}
}

func parsePrefixMap(s string) (map[string]string, error) {
	if s == "" {
		return nil, nil
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil, errors.New("PREFIX_POLICY_MAP must be a JSON object of prefix->policy")
	}
	return m, nil
}

// startupProblems collects configuration faults so that one restart reports all of
// them.
//
// The service used to fail one fault at a time, and two of the ways it did so were
// actively unhelpful. Required variables went through a mustEnv that PANICKED, so a
// deployment missing three of them printed a stack trace naming one, and the operator
// learned about the next only after fixing that one and restarting. Everything else --
// an unreadable MAX_EXPAND_BYTES, a SCRATCH_BYTES the parser could not use, a sizing
// combination that will evict the pod -- was a log.Warn that the process then ran
// happily past, so the pod came up healthy and wrong. Both failure modes are silent in
// the way that matters: nothing in `oc get pods` distinguishes them from a good start.
//
// Faults are therefore accumulated and reported together, with the value seen, what was
// expected, and what to do about it. A misconfigured pod does not start.
type startupProblems struct {
	list []string
	// sizingOverridden records that the operator has explicitly accepted a sizing
	// estimate the service considers unsafe.
	sizingOverridden bool
}

// addf records a fault. Convention for the message: one summary line, then indented
// "Label: value" lines, ending with a "Fix:" that names the knob to turn.
func (p *startupProblems) addf(format string, a ...any) {
	p.list = append(p.list, fmt.Sprintf(format, a...))
}

// sizing records a fault that rests on an ESTIMATE rather than on a value that is
// definitely wrong -- peak RSS, and the scratch a bundle might need.
//
// These get an escape hatch that parse failures do not, because the estimates
// deliberately err high and an operator who has measured their own workload may know
// better than the model. ALLOW_UNSAFE_SIZING=true downgrades them to warnings; it is
// named to be uncomfortable to type, and the warning it leaves behind still says
// exactly what was overridden.
func (p *startupProblems) sizing(format string, a ...any) {
	if envBool("ALLOW_UNSAFE_SIZING", false) {
		p.sizingOverridden = true
		return
	}
	p.addf(format+NL+"      Override: set ALLOW_UNSAFE_SIZING=true to start anyway. "+
		"Both sizing checks are estimates that err high, so this is a supported choice "+
		"if you have measured the real peak with scripts/memory-matrix.sh -- but the pod "+
		"dies under load rather than at rollout if the estimate was right.", a...)
}

// req reads a required variable, recording a fault rather than aborting so the rest of
// the checks still run.
func (p *startupProblems) req(k, what string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		p.addf("%s is required and is not set."+NL+
			"      What it is: %s"+NL+
			"      Fix:        set it in the scrubber-config ConfigMap.", k, what)
	}
	return v
}

// reqSecret is req for a value that must never be echoed. The fault says the variable
// is missing and does not quote it, since a partially-set credential is exactly the
// case where a log line would leak one.
func (p *startupProblems) reqSecret(k, what string) string {
	v := os.Getenv(k)
	if strings.TrimSpace(v) == "" {
		p.addf("%s is required and is not set."+NL+
			"      What it is: %s"+NL+
			"      Fix:        create the scrubber-secret Secret and reference it from "+
			"envFrom in the Deployment. Its value is never logged.", k, what)
	}
	return v
}

// err renders every fault as one error, or nil when there are none.
func (p *startupProblems) err() error {
	if len(p.list) == 0 {
		return nil
	}
	noun := "problems"
	if len(p.list) == 1 {
		noun = "problem"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "refusing to start: %d configuration %s found", len(p.list), noun)
	for i, s := range p.list {
		fmt.Fprintf(&b, NL+NL+"  [%d/%d] %s", i+1, len(p.list), s)
	}
	b.WriteString(NL + NL + "Nothing was started and no object was touched. " +
		"Fix all of the above and roll out again.")
	return errors.New(b.String())
}

// NL is a newline. Named rather than inlined so the fault messages above read as
// structured text rather than as escape soup.
const NL = "\n"

// --- env helpers ---

func envDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envBool(k string, def bool) bool {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	return v == "1" || v == "true" || v == "TRUE" || v == "yes"
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// envInt64 reads a byte-valued setting, accepting Kubernetes quantity suffixes and
// SAYING SO when it cannot read one.
//
// Both halves matter. It used to be a bare strconv.ParseInt that returned the default
// on any error, so "MAX_EXPAND_BYTES: 4Gi" — the form every neighbouring line in the
// manifest is written in — was discarded in silence and the pod ran with a cap the
// operator never chose and had no way to discover short of reading the startup log
// and doing the arithmetic. A configuration that is ignored quietly is worse than one
// that is rejected loudly.
//
// Zero and negatives pass through unparsed because they are meaningful here rather
// than erroneous: MAX_LEAF_BYTES=0 disables the leaf cap and RESIDUAL_BUDGET=-1
// disables the residual scan.
func envInt64(probs *startupProblems, k string, def int64) int64 {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	// Any way of writing zero disables, not just the bare digit. Matching "0" alone
	// meant MAX_LEAF_BYTES=0Gi — the quantity form this function exists to accept —
	// fell through to the warning and restored the derived cap, i.e. the documented
	// way to switch the leaf cap off silently switched it back on.
	if isZeroQuantity(v) {
		return 0
	}
	neg := strings.HasPrefix(v, "-")
	n, ok := podres.ParseBytes(strings.TrimPrefix(v, "-"))
	if !ok {
		probs.addf("%s is set to a value that cannot be read as a byte count."+NL+
			"      Value: %q"+NL+
			"      Fix:   write a plain byte count or a Kubernetes quantity -- "+
			"4Gi, 512Mi, 2G, 1073741824. Use 0 to disable a cap that supports it. "+
			"This is fatal rather than defaulted: a cap the operator set and the "+
			"service ignored is how a pod runs for weeks at a size nobody chose.",
			k, v)
		return def
	}
	if neg {
		return -n
	}
	return n
}

// isZeroQuantity reports whether v means zero in any of the forms envInt64 accepts:
// "0", "-0", "00", "0Gi", "0 Mi". Anything with a non-zero digit is not zero, and
// anything that is not a number at all is left for ParseBytes to reject and warn about.
func isZeroQuantity(v string) bool {
	digits := strings.TrimLeft(strings.TrimPrefix(strings.TrimSpace(v), "-"), "0")
	digits = strings.TrimSpace(digits)
	// What remains is either empty (all zeros) or a bare unit suffix on a zero.
	switch digits {
	case "", "Ki", "Mi", "Gi", "Ti", "Pi", "k", "K", "M", "G", "T", "P":
		// Guard against "Gi" alone, which has no digits at all and is not zero.
		return strings.ContainsAny(v, "0")
	}
	return false
}

func envDuration(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
