// Command scrubberd is the OCP-hosted service form of scrubber. It runs a
// MinIO/S3 bucket-driven data plane (input -> scrubbed output + report) and a
// data-free control/observability HTTP plane (health, readiness, metrics,
// policies, jobs) that is safe to expose on an external Route.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/howard/scrubber/internal/metrics"
	"github.com/howard/scrubber/internal/pipeline"
	"github.com/howard/scrubber/internal/policy"
	"github.com/howard/scrubber/internal/server"
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

	wcfg := worker.Config{
		InputBucket:     inputBucket,
		OutputBucket:    mustEnv("OUTPUT_BUCKET"),
		ReportsBucket:   mustEnv("REPORTS_BUCKET"),
		InputPrefix:     os.Getenv("INPUT_PREFIX"),
		ProcessedPrefix: envDefault("PROCESSED_PREFIX", "processed/"),
		Action:          worker.ProcessedAction(envDefault("PROCESSED_ACTION", "move")),
		PollInterval:    envDuration("POLL_INTERVAL", 15*time.Second),
		// Clamped to 1 by worker.New. Read from the environment anyway so an
		// operator who set it higher gets told it is being ignored.
		Workers:  envInt("WORKERS", 1),
		QueueMax: envInt("QUEUE_MAX", 10000),
		// Defaults match the shipped manifest. They used to disagree with it and
		// with the README, which made the startup memory arithmetic unverifiable.
		MaxObjectBytes: envInt64("MAX_OBJECT_BYTES", 64<<20),
		FinalizeGrace:  envDuration("FINALIZE_GRACE", 15*time.Second),
		RedactReports:  envBool("REDACT_REPORTS", false),
		ScrubNames:     envBool("SCRUB_FILENAMES", true),
		Limits: pipeline.Limits{
			MaxDepth: envInt("MAX_DEPTH", 16),
			// 256Mi, not 512Mi. Measured: a match-dense .tar.gz drawing 407Mi of a
			// 512Mi budget peaked at 1889Mi RSS — 92% of the 2Gi pod. The same shape
			// drawing 241Mi peaked at 1587Mi. The expansion budget counts bytes read;
			// resident memory is several times that, so a 512Mi budget does not fit
			// the pod it was sized for.
			MaxTotalBytes: envInt64("MAX_EXPAND_BYTES", 256<<20),
			MaxMembers:    envInt("MAX_MEMBERS", 100000),
		},
	}
	if os.Getenv("MAX_RATIO") != "" {
		log.Warn("MAX_RATIO is ignored and can be removed from the config. " +
			"An expansion-ratio limit cannot distinguish a decompression bomb from an " +
			"ordinary log file (logs routinely compress 200:1 and beyond), and tripping " +
			"it emitted the object UNSCRUBBED. Memory is now bounded by MAX_EXPAND_BYTES, " +
			"enforced while decompressing.")
	}
	// Objects are scrubbed one at a time, so only one object is ever resident. Note
	// the two numbers below are NOT the same thing, and conflating them is how you
	// size a pod that then gets OOM-killed:
	//
	//   budget_bytes  — what the expansion accounting caps: compressed input plus
	//                   cumulative decompressed bytes.
	//   est_peak_rss  — what the process actually occupies, which is several times
	//                   larger. The budget counts bytes read; resident memory also
	//                   holds each member's scrubbed output, the repacked archive,
	//                   and GC slack that Go does not return promptly. Measured at
	//                   ~4.6x the budget drawn for a match-dense .tar.gz.
	//
	// Size limits.memory against est_peak_rss, not against budget_bytes.
	budget := wcfg.MaxObjectBytes + wcfg.Limits.MaxTotalBytes
	log.Info("resource limits",
		"max_object_bytes", wcfg.MaxObjectBytes,
		"max_expand_bytes", wcfg.Limits.MaxTotalBytes,
		"queue_concurrency", 1,
		"queue_max", wcfg.QueueMax,
		"budget_bytes", budget,
		"est_peak_rss_bytes", int64(float64(budget)*peakRSSFactor))
	wk := worker.New(st, reg, m, jobs, wcfg, log)
	metrics.RegisterQueue(promReg,
		func() float64 { return float64(wk.Queue().Depth()) },
		func() float64 { return float64(wk.Queue().Inflight()) })

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

const (
	// readyProbeTimeout bounds a single backend reachability check.
	readyProbeTimeout = 3 * time.Second
	// readyCacheTTL is how long a readiness result is reused across probes.
	readyCacheTTL = 5 * time.Second
	// shutdownTimeout bounds the whole graceful stop: draining HTTP plus letting
	// the worker persist whatever it had finished. Keep it inside the pod's
	// terminationGracePeriodSeconds, or the kubelet kills the process first.
	shutdownTimeout = 30 * time.Second
	// peakRSSFactor converts the expansion budget into an estimate of actual
	// resident memory.
	//
	// The budget counts bytes *read* — the compressed object plus everything
	// decompressed out of it. Resident memory holds considerably more at the same
	// instant: each archive member's scrubbed output alongside its input, the
	// repacked archive being assembled, and heap the Go GC has not yet returned.
	// Measured at ~4.6x on a match-dense .tar.gz (a 407MiB budget draw peaked at
	// 1889MiB RSS), so this is rounded down slightly rather than up — it is an
	// estimate to size a pod from, not a guarantee.
	peakRSSFactor = 4.5
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
