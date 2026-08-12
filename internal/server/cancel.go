package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"mime"
	"net/http"
	"strings"
)

// cancelSecret is minted once per process and never leaves it. It exists only to
// bind a cancel token to a key this server itself handed out.
var cancelSecret = func() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// A process that cannot read its own CSPRNG has worse problems, but failing
		// closed here would take the whole service down over an optional feature.
		// An unreadable secret makes every token invalid, which denies cancels
		// rather than granting them.
		return nil
	}
	return b
}()

// cancelToken is a capability for one object key.
//
// The browser API has no authentication of any kind: under network-only auth
// anyone who reaches the Route can call it. That is tolerable for read-only
// endpoints and for policy editing by insiders, but cancellation is different in
// kind, because two other endpoints publish the keys to aim it at — /api/queue
// returns up to 50 live pending keys and /api/history returns every recent input
// key. Without scoping, "cancel" is a two-line loop that durably evacuates the
// queue for every user, and the random prefix in the object key protects nothing
// because the server itself hands the keys out.
//
// So a cancel must present a token this server minted for that exact key, at
// upload time. It is not authentication — it proves nothing about who is asking —
// but it reduces the blast radius from "every key the API prints" to "keys this
// browser uploaded", with no identity plumbing the service does not have.
//
// Cancelling somebody else's stuck object is a real operator need and is
// deliberately a separate, off-by-default permission (AllowCancelAny).
func cancelToken(key string) string {
	if cancelSecret == nil {
		return ""
	}
	m := hmac.New(sha256.New, cancelSecret)
	m.Write([]byte(key))
	return hex.EncodeToString(m.Sum(nil))[:32]
}

func validCancelToken(key, tok string) bool {
	want := cancelToken(key)
	if want == "" || tok == "" {
		return false
	}
	return hmac.Equal([]byte(want), []byte(tok))
}

// apiCancel withdraws an object from the queue, or aborts it mid-scrub.
//
// POST with a JSON body, matching the file's convention (apiUpload is POST-only,
// apiPolicy takes PUT or POST) rather than DELETE, and with the method checked
// inside the handler because the mux is registered path-only throughout.
func (s *Server) apiCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.d.Canceller == nil || !s.d.AllowCancel {
		writeJSONStatus(w, http.StatusForbidden, map[string]any{
			"error": "cancelling is disabled (ALLOW_CANCEL=false)"})
		return
	}
	// Require a JSON content type. A browser can be made to POST cross-origin
	// without any preflight using text/plain, form-urlencoded or multipart, so a
	// handler that accepts those is reachable by CSRF from any page the operator
	// happens to visit — and this one is destructive. Requiring application/json
	// forces a preflight, which same-origin policy then blocks.
	if ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || ct != "application/json" {
		writeJSONStatus(w, http.StatusUnsupportedMediaType, map[string]any{
			"error": "Content-Type must be application/json"})
		return
	}

	var body struct {
		Key   string `json:"key"`
		Token string `json:"token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil || body.Key == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]any{
			"error": "expected JSON {\"key\": ..., \"token\": ...}"})
		return
	}
	// Keys are a flat namespace here and every managed prefix is a plain string
	// prefix, so a key containing a separator could name an object under
	// processed/, review/ or cancelled/ and withdraw something already finished.
	if strings.Contains(body.Key, "/") {
		writeJSONStatus(w, http.StatusBadRequest, map[string]any{
			"error": "key must not contain a path separator"})
		return
	}

	if !validCancelToken(body.Key, body.Token) && !s.d.AllowCancelAny {
		// Deliberately the same answer whether the token was wrong or the key does
		// not exist: distinguishing them would turn this endpoint into an oracle for
		// which keys are live.
		writeJSONStatus(w, http.StatusForbidden, map[string]any{
			"error": "a valid cancel token for this key is required; " +
				"cancelling another client's upload needs ALLOW_CANCEL_ANY=true"})
		return
	}

	// Not on the browser-latency budget: the durable disposition is a server-side
	// copy of an object that may be hundreds of megabytes, and answering "cancelled"
	// before it lands would be a claim the service has not yet made true.
	ctx, cancel := s.storageCtxFor(r, s.d.CancelBudget)
	defer cancel()

	outcome, err := s.d.Canceller.Cancel(ctx, body.Key)
	if err != nil {
		writeJSONStatus(w, http.StatusBadGateway, map[string]any{
			"error": "could not withdraw the object: " + err.Error()})
		return
	}
	switch outcome {
	case "not-found":
		writeJSONStatus(w, http.StatusNotFound, map[string]any{
			"outcome": outcome, "error": "no such object in the input bucket"})
	case "too-late":
		// 409, not 200. The scrubbed output is already in the output bucket, and
		// reporting success would tell an operator their data was pulled back when
		// it was published.
		writeJSONStatus(w, http.StatusConflict, map[string]any{
			"outcome": outcome,
			"error":   "the scrub already completed and its output was written; nothing was withdrawn"})
	case "aborting":
		writeJSONStatus(w, http.StatusAccepted, map[string]any{
			"outcome": outcome,
			"note":    "the scrub is being aborted; the walk stops between archive members"})
	default:
		writeJSON(w, map[string]any{"outcome": outcome})
	}
}
