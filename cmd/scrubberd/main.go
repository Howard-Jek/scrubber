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
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := realMain(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
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
		MaxObjectBytes: int64(envInt("MAX_OBJECT_BYTES", 512<<20)),
		RedactReports:  envBool("REDACT_REPORTS", false),
		Limits: pipeline.Limits{
			MaxDepth:      envInt("MAX_DEPTH", 16),
			MaxRatio:      envInt("MAX_RATIO", 200),
			MaxTotalBytes: 2 << 30,
			MaxMembers:    100000,
		},
	}
	wk := worker.New(st, reg, m, jobs, wcfg, log)

	// --- control + browser API server ---
	ready := func() bool { return st.Healthy(ctx, inputBucket) }
	srv := &http.Server{
		Addr: ":" + envDefault("PORT", "8080"),
		Handler: server.New(server.Deps{
			Policies:      reg,
			Jobs:          jobs,
			Prom:          promReg,
			Ready:         ready,
			Presigner:     st,
			DefaultPolicy: os.Getenv("DEFAULT_POLICY"),
			AllowEdit:     envBool("ALLOW_POLICY_EDIT", true),
			InputBucket:   inputBucket,
			OutputBucket:  mustEnv("OUTPUT_BUCKET"),
			UploadExpiry:  envDuration("UPLOAD_EXPIRY", 15*time.Minute),
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

func envDuration(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
