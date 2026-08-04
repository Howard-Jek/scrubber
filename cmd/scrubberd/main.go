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
		InputBucket:    inputBucket,
		OutputBucket:   mustEnv("OUTPUT_BUCKET"),
		ReportsBucket:  mustEnv("REPORTS_BUCKET"),
		InputPrefix:    os.Getenv("INPUT_PREFIX"),
		ProcessedPrefix: envDefault("PROCESSED_PREFIX", "processed/"),
		Action:         worker.ProcessedAction(envDefault("PROCESSED_ACTION", "move")),
		PollInterval:   envDuration("POLL_INTERVAL", 15*time.Second),
		Workers:        envInt("WORKERS", 4),
		MaxObjectBytes: envInt64("MAX_OBJECT_BYTES", 256<<20),
		RedactReports:  envBool("REDACT_REPORTS", false),
		ScrubNames:     envBool("SCRUB_FILENAMES", true),
		Limits: pipeline.Limits{
			MaxDepth:      envInt("MAX_DEPTH", 16),
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
	log.Info("resource limits",
		"max_object_bytes", wcfg.MaxObjectBytes,
		"max_expand_bytes", wcfg.Limits.MaxTotalBytes,
		"workers", wcfg.Workers,
		"worst_case_resident_bytes", int64(wcfg.Workers)*(wcfg.MaxObjectBytes+wcfg.Limits.MaxTotalBytes))
	wk := worker.New(st, reg, m, jobs, wcfg, log)

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
	go wk.Run(ctx)
	<-ctx.Done()
	log.Info("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shutCtx)
}

const (
	// readyProbeTimeout bounds a single backend reachability check.
	readyProbeTimeout = 3 * time.Second
	// readyCacheTTL is how long a readiness result is reused across probes.
	readyCacheTTL = 5 * time.Second
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
