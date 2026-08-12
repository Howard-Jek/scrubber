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

	// --- MinIO store ---
	st, err := store.New(store.Config{
		Endpoint:       mustEnv("MINIO_ENDPOINT"),
		AccessKey:      mustEnv("MINIO_ACCESS_KEY"),
		SecretKey:      mustEnv("MINIO_SECRET_KEY"),
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
	})
	if err != nil {
		return err
	}

	inputBucket := mustEnv("INPUT_BUCKET")
	if envBool("ENSURE_BUCKETS", false) {
		for _, b := range []string{inputBucket, mustEnv("OUTPUT_BUCKET"), mustEnv("REPORTS_BUCKET")} {
			if err := st.EnsureBucket(ctx, b); err != nil {
				return err
			}
		}
	}

	// --- policies (fail fast on any invalid policy) ---
	policyDir := envDefault("POLICIES_DIR", "/etc/scrubber/policies")
	prefixMap, err := parsePrefixMap(os.Getenv("PREFIX_POLICY_MAP"))
	if err != nil {
		return err
	}
	reg, err := policy.New(policyDir, os.Getenv("DEFAULT_POLICY"), prefixMap)
	if err != nil {
		return err
	}
	log.Info("loaded policies", "names", reg.Names())
	go watchPolicies(ctx, policyDir, reg, log)

	// --- metrics + worker ---
	promReg := prometheus.NewRegistry()
	m := metrics.New(promReg)
	jobs := metrics.NewJobLog(envInt("JOBS_HISTORY", 200))

	// Fail fast on a bad AUDIT_LEVEL rather than silently picking a default: the
	// setting governs how much sensitive matched text the stored report retains, so
	// a typo quietly resolving to "full" is exactly the wrong failure mode.
	audit, err := report.ParseAuditLevel(envDefault("AUDIT_LEVEL", "counts"))
	if err != nil {
		return fmt.Errorf("AUDIT_LEVEL: %w", err)
	}

	// --- size the caps against the pod we actually got ---
	//
	// Every number below was measured on a 2 GiB / 1 CPU pod and then compiled in
	// as a default, which silently made 2 GiB the only size the service was tuned
	// for. On a 4 or 8 GiB pod it left most of the memory idle and scrubbed no
	// faster; the operator's only recourse was to raise the spill knobs by hand,
	// and raising them too far turns spilling off and reproduces the OOM the spill
	// exists to prevent.
	//
	// So the measured values become a *ratio* to the pod they were measured on,
	// and the ceiling is read from the cgroup at startup. At 2 GiB every derived
	// value is byte-identical to what shipped, which keeps every published
	// measurement valid; at 8 GiB they are 4x. An explicit environment variable
	// still wins over all of it — this changes defaults, not policy.
	res := podres.Detect()
	memScale := podScale(res.MemoryBytes)
	scaled := func(base int64) int64 { return int64(float64(base) * memScale) }

	// Scratch is a separate ceiling and cannot be detected the same way: /work is
	// an emptyDir whose sizeLimit is enforced by the kubelet, not by the
	// filesystem, so statfs inside the container reports the whole node's disk and
	// would license a budget that gets the pod evicted. It has to be declared.
	// Unset means keep the shipped defaults rather than guess.
	maxExpandDefault, maxObjectDefault := int64(1536<<20), int64(640<<20)
	scratchBytes := envInt64("SCRATCH_BYTES", 0)
	if scratchBytes > 0 {
		maxExpandDefault = int64(float64(scratchBytes) / scratchFactor)
		// Preserve the shipped ratio between the compressed-object ceiling and the
		// expansion budget (640Mi of 1536Mi), so raising one raises the other and
		// MAX_OBJECT_BYTES stays the limit a user hits first.
		maxObjectDefault = int64(float64(maxExpandDefault) * shippedObjectShare)
	}

	wcfg := worker.Config{
		InputBucket:     inputBucket,
		OutputBucket:    mustEnv("OUTPUT_BUCKET"),
		ReportsBucket:   mustEnv("REPORTS_BUCKET"),
		InputPrefix:     os.Getenv("INPUT_PREFIX"),
		ProcessedPrefix: envDefault("PROCESSED_PREFIX", "processed/"),
		// Where a result lands when content the scrub did not inspect turns out to
		// contain policy matches. Set empty to keep everything in one place and rely
		// on the flagging alone.
		ReviewPrefix: envDefault("REVIEW_PREFIX", "review/"),
		Action:       worker.ProcessedAction(envDefault("PROCESSED_ACTION", "move")),
		PollInterval: envDuration("POLL_INTERVAL", 15*time.Second),
		// Clamped to 1 by worker.New. Read from the environment anyway so an
		// operator who set it higher gets told it is being ignored.
		Workers:  envInt("WORKERS", 1),
		QueueMax: envInt("QUEUE_MAX", 10000),
		// Defaults match the shipped manifest. They used to disagree with it and
		// with the README, which made the startup memory arithmetic unverifiable.
		MaxObjectBytes: envInt64("MAX_OBJECT_BYTES", maxObjectDefault),
		FinalizeGrace:  envDuration("FINALIZE_GRACE", 15*time.Second),
		StallWarnAfter: envDuration("STALL_WARN_AFTER", 5*time.Minute),
		Audit:          audit,
		RedactReports:  envBool("REDACT_REPORTS", false),
		ScrubNames:     envBool("SCRUB_FILENAMES", true),
		Limits: pipeline.Limits{
			MaxDepth: envInt("MAX_DEPTH", 16),
			// Archive members spill to scratch storage, so this now bounds mostly
			// DISK rather than resident memory. Size the /work volume against it, not
			// just limits.memory — an ephemeral-storage eviction kills a pod as dead
			// as an OOM. See deploy/openshift-manifests.yaml for the arithmetic and
			// scripts/memory-matrix.sh for how to re-derive it after any change.
			MaxTotalBytes: envInt64("MAX_EXPAND_BYTES", maxExpandDefault),
			MaxMembers:    envInt("MAX_MEMBERS", 100000),
			// Bytes the residual scan may read across one object. Negative disables
			// it, which removes the only check that does not depend on the pipeline's
			// own classification being correct — the check that would have caught
			// UTF-16 logs being filed as binary.
			ResidualBudget: envInt64("RESIDUAL_BUDGET", pipeline.DefaultResidualBudget),
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
				Threshold:   envInt64("SPILL_THRESHOLD", max64(scaled(4<<20), minSpillThreshold)),
				ResidentMax: envInt64("SPILL_RESIDENT_MAX", scaled(64<<20)),
			},
		},
	}
	if os.Getenv("MAX_RATIO") != "" {
		log.Warn("MAX_RATIO is ignored and can be removed from the config. " +
			"An expansion-ratio limit cannot distinguish a decompression bomb from an " +
			"ordinary log file (logs routinely compress 200:1 and beyond), and tripping " +
			"it emitted the object UNSCRUBBED. Memory is now bounded by MAX_EXPAND_BYTES, " +
			"enforced while decompressing.")
	}
	// Three different ceilings, and conflating them is how a pod gets killed:
	//
	//   budget_bytes  — what the expansion accounting caps. Since archive members
	//                   spill, this bounds mostly DISK on the scratch volume.
	//   est_peak_rss  — resident memory, which no longer tracks the expansion budget
	//                   at all. Only the member being scrubbed is on the heap, so
	//                   this is a function of the spill policy — the aggregate
	//                   in-memory budget, plus a few multiples of the per-payload
	//                   threshold for the leaf scrubber (which needs a contiguous
	//                   string and therefore briefly holds several copies) — plus
	//                   per-member bookkeeping, which spilling does not remove and
	//                   which scales with MAX_MEMBERS, plus runtime baseline and
	//                   GC slack.
	//   scratch_bytes — the disk a single object can occupy. A .tar.gz stages the
	//                   decompressed container, the member bodies and the repacked
	//                   result, so budget well above the expansion cap.
	//
	// Size limits.memory against est_peak_rss and the /work sizeLimit against
	// scratch_bytes. Re-derive both with scripts/memory-matrix.sh after any change.
	budget := wcfg.MaxObjectBytes + wcfg.Limits.MaxTotalBytes
	sp := wcfg.Limits.Spill
	estPeak := int64(float64(sp.ResidentMax+leafCopies*sp.Threshold)*peakRSSFactor) +
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
		"pod_cpus", res.CPUs,
		"mem_scale", memScale)

	// Two ways to get this wrong that are worth naming at startup rather than
	// leaving to be discovered as an eviction or an OOM under load.
	if res.MemoryBytes > 0 && estPeak > res.MemoryBytes*peakRSSGatePercent/100 {
		log.Warn("estimated peak RSS is above the safe share of the pod's memory; "+
			"lower SPILL_RESIDENT_MAX / SPILL_THRESHOLD / MAX_MEMBERS, or raise limits.memory",
			"est_peak_rss_bytes", estPeak, "pod_memory_bytes", res.MemoryBytes,
			"gate_percent", peakRSSGatePercent)
	}
	if scratchBytes > 0 && scratch > scratchBytes {
		log.Warn("scratch needed for one object exceeds the declared SCRATCH_BYTES; "+
			"an ephemeral-storage eviction kills the pod as dead as an OOM",
			"scratch_bytes_needed", scratch, "scratch_bytes_declared", scratchBytes)
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
			DefaultPolicy: os.Getenv("DEFAULT_POLICY"),
			AllowEdit:     envBool("ALLOW_POLICY_EDIT", true),
			InputBucket:   inputBucket,
			OutputBucket:  mustEnv("OUTPUT_BUCKET"),
			ReportsBucket: mustEnv("REPORTS_BUCKET"),
			UploadExpiry:  envDuration("UPLOAD_EXPIRY", 15*time.Minute),
			HistoryMax:    envInt("HISTORY_MAX", 100),
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

// podScale converts a detected pod memory ceiling into the multiplier applied to
// the defaults measured at baselineMemBytes.
//
// Returns 1 when the ceiling is unknown, which reproduces exactly the caps that
// shipped: an undetectable limit must fall back to a measured configuration, not
// to an extrapolation from a number nobody has.
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
	// the measured configuration (640Mi of 1536Mi). Held constant when the caps
	// are derived from SCRATCH_BYTES so the compressed-object ceiling stays the
	// limit a user hits first, which is the one with a clear error message.
	shippedObjectShare = 640.0 / 1536.0
	// peakRSSGatePercent is the share of pod memory the estimate may reach before
	// startup warns. Matches the gate scripts/memory-matrix.sh fails on, so the
	// service and the benchmark agree on what "too close" means.
	peakRSSGatePercent = 60
	// runtimeBaselineBytes is the Go runtime, the compiled policy and the HTTP
	// server — what the process costs before it touches an object.
	runtimeBaselineBytes = 128 << 20
	// scratchFactor is how much scratch disk one object can occupy relative to the
	// expansion budget: a .tar.gz stages the decompressed container, the member
	// bodies and the repacked result.
	scratchFactor = 2.5
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

// --- env helpers ---

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		panic("required env var not set: " + k)
	}
	return v
}

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

func envInt64(k string, def int64) int64 {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func envDuration(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
