// Package server exposes the control/observability plane plus a thin browser API.
// No bundle *bytes* pass through the service: uploads/downloads happen directly
// between the browser and MinIO via presigned URLs that this server mints. The API
// serves the operator preparing logs (an insider), so it does surface the policy —
// including literal terms — so they can verify what will be scrubbed. Keep the Route
// on a trusted network (see deploy notes); the scrubbed log content is what must not
// leave, and that is enforced by the scrubbing itself, not by hiding the policy.
package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/howard/scrubber/internal/metrics"
	"github.com/howard/scrubber/internal/policy"
	"github.com/howard/scrubber/internal/scrub"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Presigner mints presigned object URLs (implemented by store.Client).
type Presigner interface {
	PresignPut(ctx context.Context, bucket, key string, expiry time.Duration) (string, error)
	PresignGet(ctx context.Context, bucket, key string, expiry time.Duration) (string, error)
}

// Deps are the server's dependencies.
type Deps struct {
	Policies     *policy.Registry
	Jobs         *metrics.JobLog
	Prom         *prometheus.Registry
	Ready        func() bool
	Presigner     Presigner
	DefaultPolicy string // policy shown/edited in the UI
	AllowEdit     bool   // permit PUT /api/policy from the UI
	InputBucket   string
	OutputBucket  string
	UploadExpiry  time.Duration
}

// Server holds the dependencies for the endpoints.
type Server struct{ d Deps }

// New builds a server from its dependencies.
func New(d Deps) *Server {
	if d.UploadExpiry == 0 {
		d.UploadExpiry = 15 * time.Minute
	}
	return &Server{d: d}
}

// Handler returns the routed HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Control plane.
	mux.HandleFunc("/healthz", s.healthz)
	mux.HandleFunc("/readyz", s.readyz)
	mux.Handle("/metrics", promhttp.HandlerFor(s.d.Prom, promhttp.HandlerOpts{}))
	mux.HandleFunc("/policies", s.listPolicies)
	mux.HandleFunc("/jobs", s.listJobs)
	// Browser API (URL-minting only; bytes go browser <-> MinIO).
	mux.HandleFunc("/api/policy", s.apiPolicy)
	mux.HandleFunc("/api/uploads", s.apiUpload)
	mux.HandleFunc("/api/status", s.apiStatus)
	mux.HandleFunc("/api/downloads", s.apiDownload)
	// Static front page.
	mux.HandleFunc("/", s.index)
	return mux
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) readyz(w http.ResponseWriter, _ *http.Request) {
	if s.d.Ready != nil && !s.d.Ready() {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}

func (s *Server) listPolicies(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"policies": s.d.Policies.Names()})
}

func (s *Server) listJobs(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"jobs": s.d.Jobs.Recent()})
}

// apiPolicy serves the operator's policy view. GET returns the rule summary
// (kind, matched term, replacement label) plus the source terms.json. PUT/POST
// validates + compiles a new terms.json and activates it live.
func (s *Server) apiPolicy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		var rules []scrub.RuleInfo
		if m, ok := s.d.Policies.Get(s.d.DefaultPolicy); ok {
			rules = m.Rules()
		}
		src, _ := s.d.Policies.Raw(s.d.DefaultPolicy)
		writeJSON(w, map[string]any{"name": s.d.DefaultPolicy, "rules": rules, "source": string(src)})
	case http.MethodPut, http.MethodPost:
		if !s.d.AllowEdit {
			writeJSONStatus(w, http.StatusForbidden, map[string]any{"error": "policy editing is disabled (ALLOW_POLICY_EDIT=false)"})
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			writeJSONStatus(w, http.StatusBadRequest, map[string]any{"error": "request body too large"})
			return
		}
		if err := s.d.Policies.Set(s.d.DefaultPolicy, body); err != nil {
			writeJSONStatus(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		m, _ := s.d.Policies.Get(s.d.DefaultPolicy)
		src, _ := s.d.Policies.Raw(s.d.DefaultPolicy)
		writeJSON(w, map[string]any{"name": s.d.DefaultPolicy, "rules": m.Rules(), "source": string(src)})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// apiUpload mints a presigned PUT URL for a new input object.
func (s *Server) apiUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil || body.Name == "" {
		http.Error(w, "expected JSON {\"name\": ...}", http.StatusBadRequest)
		return
	}
	key := newKey(body.Name)
	url, err := s.d.Presigner.PresignPut(r.Context(), s.d.InputBucket, key, s.d.UploadExpiry)
	if err != nil {
		http.Error(w, "could not mint upload URL", http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]any{"key": key, "url": url, "method": "PUT"})
}

// apiStatus reports the outcome of a previously uploaded key (browser-safe fields).
func (s *Server) apiStatus(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "missing key", http.StatusBadRequest)
		return
	}
	for _, j := range s.d.Jobs.Recent() {
		if j.Key == key {
			writeJSON(w, map[string]any{
				"status": j.Status, "policy": j.Policy, "matches": j.Matches,
				"bytes_in": j.BytesIn, "bytes_out": j.BytesOut, "by_label": j.ByLabel, "error": j.Error,
			})
			return
		}
	}
	writeJSON(w, map[string]any{"status": "processing"})
}

// apiDownload mints a presigned GET URL for the scrubbed output object.
func (s *Server) apiDownload(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "missing key", http.StatusBadRequest)
		return
	}
	url, err := s.d.Presigner.PresignGet(r.Context(), s.d.OutputBucket, key, s.d.UploadExpiry)
	if err != nil {
		http.Error(w, "could not mint download URL", http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]any{"url": url})
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(indexHTML)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false) // keep presigned URLs (with &) intact for all clients
	_ = enc.Encode(v)
}

func writeJSONStatus(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
