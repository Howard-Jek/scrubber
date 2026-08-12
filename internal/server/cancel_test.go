package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeCanceller struct {
	outcome string
	err     error
	calls   []string
}

func (f *fakeCanceller) Cancel(_ context.Context, key string) (string, error) {
	f.calls = append(f.calls, key)
	if f.err != nil {
		return "", f.err
	}
	if f.outcome == "" {
		return "withdrawn", nil
	}
	return f.outcome, nil
}

func postCancel(t *testing.T, h http.Handler, contentType, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/cancel", bytes.NewBufferString(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
	}
	return rec.Code, out
}

func cancelServer(t *testing.T, c Canceller, allow, allowAny bool) http.Handler {
	t.Helper()
	return newTestServerWith(Deps{
		Archive: newArchive(), InputBucket: "input", ReportsBucket: "reports",
		Canceller: c, AllowCancel: allow, AllowCancelAny: allowAny,
	})
}

// TestCancelRequiresToken is the blast-radius control, and it is the reason this
// endpoint is safe to ship at all.
//
// The browser API has no authentication. /api/queue returns up to 50 live pending
// keys and /api/history returns every recent input key, so without scoping, cancel
// is a two-line loop that durably evacuates the queue for every user — and because
// the withdrawal is a durable bucket move, the victims' objects are never re-listed
// and never recovered without an operator moving them back by hand.
func TestCancelRequiresToken(t *testing.T) {
	c := &fakeCanceller{}
	h := cancelServer(t, c, true, false)

	code, body := postCancel(t, h, "application/json", `{"key":"abc-app.zip"}`)
	if code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403 for a cancel with no token", code)
	}
	if len(c.calls) != 0 {
		t.Errorf("canceller was invoked without a valid token: %v", c.calls)
	}
	_ = body

	// The token this server minted for that exact key is accepted.
	code, _ = postCancel(t, h, "application/json",
		`{"key":"abc-app.zip","token":"`+cancelToken("abc-app.zip")+`"}`)
	if code != http.StatusOK {
		t.Fatalf("code = %d, want 200 with a valid token", code)
	}
	if len(c.calls) != 1 || c.calls[0] != "abc-app.zip" {
		t.Errorf("canceller calls = %v, want one for abc-app.zip", c.calls)
	}
}

// TestCancelTokenIsKeyScoped: a token is a capability for ONE object, not a
// password for the endpoint. Otherwise the first upload any client makes hands it
// the ability to cancel every other key it can enumerate.
func TestCancelTokenIsKeyScoped(t *testing.T) {
	c := &fakeCanceller{}
	h := cancelServer(t, c, true, false)

	code, _ := postCancel(t, h, "application/json",
		`{"key":"victim.zip","token":"`+cancelToken("mine.zip")+`"}`)
	if code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403: a token for one key must not authorise another", code)
	}
	if len(c.calls) != 0 {
		t.Errorf("canceller invoked with a token minted for a different key: %v", c.calls)
	}
}

// TestCancelAllowAnyBypassesToken covers the operator escape hatch: clearing
// somebody else's stuck object is the real problem this feature exists for, and
// the operator will never hold that client's token.
func TestCancelAllowAnyBypassesToken(t *testing.T) {
	c := &fakeCanceller{}
	h := cancelServer(t, c, true, true)

	code, _ := postCancel(t, h, "application/json", `{"key":"someone-elses.zip"}`)
	if code != http.StatusOK {
		t.Fatalf("code = %d, want 200 with ALLOW_CANCEL_ANY", code)
	}
	if len(c.calls) != 1 {
		t.Errorf("canceller calls = %v, want 1", c.calls)
	}
}

// TestCancelRejectsFormContentTypes is the CSRF control. A cross-origin page can
// POST text/plain, form-urlencoded or multipart with no preflight, so a
// destructive handler that accepts them is reachable from any site the operator
// visits. Requiring application/json forces a preflight, which is then blocked.
func TestCancelRejectsFormContentTypes(t *testing.T) {
	for _, ct := range []string{
		"text/plain", "application/x-www-form-urlencoded", "multipart/form-data", "",
	} {
		c := &fakeCanceller{}
		h := cancelServer(t, c, true, true)
		code, _ := postCancel(t, h, ct, `{"key":"abc.zip"}`)
		if code != http.StatusUnsupportedMediaType {
			t.Errorf("Content-Type %q: code = %d, want 415", ct, code)
		}
		if len(c.calls) != 0 {
			t.Errorf("Content-Type %q reached the canceller", ct)
		}
	}
	// The charset parameter must not break a legitimate request.
	c := &fakeCanceller{}
	h := cancelServer(t, c, true, true)
	if code, _ := postCancel(t, h, "application/json; charset=utf-8", `{"key":"abc.zip"}`); code != http.StatusOK {
		t.Errorf("code = %d, want 200 for application/json; charset=utf-8", code)
	}
}

// TestCancelRejectsKeysWithSeparators stops a caller naming an object under a
// managed prefix. Keys are a flat namespace and processed/, review/ and cancelled/
// are plain string prefixes, so a key containing "/" could withdraw a finished run.
func TestCancelRejectsKeysWithSeparators(t *testing.T) {
	c := &fakeCanceller{}
	h := cancelServer(t, c, true, true)
	for _, k := range []string{"processed/abc.zip", "review/abc.zip", "a/b"} {
		code, _ := postCancel(t, h, "application/json", `{"key":"`+k+`"}`)
		if code != http.StatusBadRequest {
			t.Errorf("key %q: code = %d, want 400", k, code)
		}
	}
	if len(c.calls) != 0 {
		t.Errorf("a key with a separator reached the canceller: %v", c.calls)
	}
}

// TestCancelDisabled: with the feature off the route must refuse, not 404, so an
// operator gets told why.
func TestCancelDisabled(t *testing.T) {
	c := &fakeCanceller{}
	h := cancelServer(t, c, false, false)
	code, body := postCancel(t, h, "application/json", `{"key":"abc.zip"}`)
	if code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403 when ALLOW_CANCEL=false", code)
	}
	if body["error"] == nil {
		t.Error("a disabled endpoint must say why")
	}
}

// TestCancelTooLateIsNotSuccess. The scrubbed output is already in the output
// bucket; answering 200 would tell an operator their data was pulled back when it
// was published, which is the one direction this answer must never be wrong in.
func TestCancelTooLateIsNotSuccess(t *testing.T) {
	c := &fakeCanceller{outcome: "too-late"}
	h := cancelServer(t, c, true, true)
	code, body := postCancel(t, h, "application/json", `{"key":"abc.zip"}`)
	if code != http.StatusConflict {
		t.Fatalf("code = %d, want 409 for an object that already published", code)
	}
	if body["outcome"] != "too-late" {
		t.Errorf("outcome = %v, want too-late", body["outcome"])
	}
}

// TestCancelMethodNotAllowed keeps a destructive action off GET, where a link or
// a prefetch could trigger it.
func TestCancelMethodNotAllowed(t *testing.T) {
	c := &fakeCanceller{}
	h := cancelServer(t, c, true, true)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/cancel", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/cancel = %d, want 405", rec.Code)
	}
	if len(c.calls) != 0 {
		t.Error("GET reached the canceller")
	}
}

// TestUploadIssuesCancelToken: the token can only be minted at the moment the
// server knows the caller originated the upload, so it must go out with the key.
func TestUploadIssuesCancelToken(t *testing.T) {
	h := newTestServerWith(Deps{InputBucket: "input"})
	req := httptest.NewRequest(http.MethodPost, "/api/uploads",
		bytes.NewBufferString(`{"name":"bundle.zip"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload = %d, want 200", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	key, _ := body["key"].(string)
	tok, _ := body["cancel_token"].(string)
	if key == "" || tok == "" {
		t.Fatalf("upload response missing key or cancel_token: %v", body)
	}
	if !validCancelToken(key, tok) {
		t.Error("the issued token does not validate for the key it was issued with")
	}
}
