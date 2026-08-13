package homeassistant

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/skandertajine/digestron/internal/digest"
)

func newSink(t *testing.T, url string, extra map[string]any) digest.Sink {
	t.Helper()
	settings := map[string]any{"url": url, "token": "llat-secret", "service": "mobile_app_iphone"}
	for k, v := range extra {
		settings[k] = v
	}
	s, err := New("iphone", settings)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSendUsesSummary(t *testing.T) {
	var gotPath, gotAuth string
	var payload map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &payload)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := digest.Report{Title: "Security digest", Verdict: digest.SeverityCritical, Summary: "bad night"}
	if err := newSink(t, srv.URL, nil).Send(context.Background(), r); err != nil {
		t.Fatal(err)
	}

	if gotPath != "/api/services/notify/mobile_app_iphone" {
		t.Errorf("path = %q", gotPath)
	}
	if gotAuth != "Bearer llat-secret" {
		t.Errorf("auth = %q (token must travel as a header)", gotAuth)
	}
	if payload["title"] != "[CRITICAL] Security digest" {
		t.Errorf("title = %q", payload["title"])
	}
	if payload["message"] != "bad night" {
		t.Errorf("message = %q, want the LLM summary", payload["message"])
	}
}

func TestSendFallsBackToRenderedDigest(t *testing.T) {
	var payload map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &payload)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := digest.Report{Title: "digest", Verdict: digest.SeverityInfo,
		Findings: []digest.Finding{{Title: "ssh failures", Count: 2}}}
	if err := newSink(t, srv.URL, nil).Send(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload["message"], "ssh failures: 2") {
		t.Errorf("fallback message = %q, want raw digest", payload["message"])
	}
}

func TestSendCustomTemplate(t *testing.T) {
	var payload map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &payload)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := newSink(t, srv.URL, map[string]any{"template": "verdict={{.Verdict}}"})
	if err := s.Send(context.Background(), digest.Report{Verdict: digest.SeverityWarning}); err != nil {
		t.Fatal(err)
	}
	if payload["message"] != "verdict=warning" {
		t.Errorf("templated message = %q", payload["message"])
	}
}

func TestCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newSink(t, srv.URL, nil).(digest.Checker)
	if err := c.Check(context.Background()); err != nil {
		t.Errorf("Check() = %v", err)
	}
}

func TestNewValidation(t *testing.T) {
	for _, missing := range []map[string]any{
		{"token": "t", "service": "s"},
		{"url": "http://x", "service": "s"},
		{"url": "http://x", "token": "t"},
	} {
		if _, err := New("ha", missing); err == nil {
			t.Errorf("settings %v must fail validation", missing)
		}
	}
}
