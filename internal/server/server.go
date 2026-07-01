// Package server exposes the control/observability plane. It is intentionally
// data-free: no endpoint accepts or returns bundle bytes, so it is safe to expose
// on an external Route even under the network-only auth model. All log data flows
// through internal MinIO buckets, never through here.
package server

import (
	"encoding/json"
	"net/http"

	"github.com/howard/scrubber/internal/metrics"
	"github.com/howard/scrubber/internal/policy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server holds the dependencies for the control endpoints.
type Server struct {
	policies *policy.Registry
	jobs     *metrics.JobLog
	reg      *prometheus.Registry
	ready    func() bool
}

// New builds a control server. ready reports readiness (e.g. MinIO reachable).
func New(pol *policy.Registry, jobs *metrics.JobLog, reg *prometheus.Registry, ready func() bool) *Server {
	return &Server{policies: pol, jobs: jobs, reg: reg, ready: ready}
}

// Handler returns the routed HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.healthz)
	mux.HandleFunc("/readyz", s.readyz)
	mux.Handle("/metrics", promhttp.HandlerFor(s.reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/policies", s.listPolicies)
	mux.HandleFunc("/jobs", s.listJobs)
	return mux
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) readyz(w http.ResponseWriter, _ *http.Request) {
	if s.ready != nil && !s.ready() {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}

func (s *Server) listPolicies(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"policies": s.policies.Names()})
}

func (s *Server) listJobs(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"jobs": s.jobs.Recent()})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
