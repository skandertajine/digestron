package webhook

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

func sampleReport() digest.Report {
	return digest.Report{Title: "digest", Verdict: digest.SeverityWarning, Summary: "trouble"}
}

func TestSendDefaultBodyIsReportJSON(t *testing.T) {
	var gotBody []byte
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s, err := New("hook", map[string]any{
		"url":     srv.URL,
		"headers": map[string]any{"Authorization": "Bearer tok123"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send(context.Background(), sampleReport()); err != nil {
		t.Fatal(err)
	}

	if gotHeader != "Bearer tok123" {
		t.Errorf("auth header = %q", gotHeader)
	}
	var decoded digest.Report
	if err := json.Unmarshal(gotBody, &decoded); err != nil {
		t.Fatalf("default body is not the report JSON: %v\n%s", err, gotBody)
	}
	if decoded.Summary != "trouble" {
		t.Errorf("decoded = %+v", decoded)
	}
}

func TestSendCustomTemplate(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	s, err := New("hook", map[string]any{
		"url":  srv.URL,
		"body": `{"text": {{ printf "%q" (rendertext .) }}}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send(context.Background(), sampleReport()); err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(gotBody, &payload); err != nil {
		t.Fatalf("templated body invalid: %v\n%s", err, gotBody)
	}
	if !strings.Contains(payload.Text, "[WARNING] digest") {
		t.Errorf("rendertext output missing: %q", payload.Text)
	}
}

func TestSendErrorOnBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()

	s, err := New("hook", map[string]any{"url": srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send(context.Background(), sampleReport()); err == nil {
		t.Error("non-2xx must be an error")
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New("h", map[string]any{}); err == nil {
		t.Error("url required")
	}
	if _, err := New("h", map[string]any{"url": "http://x", "method": "DELETE"}); err == nil {
		t.Error("unsupported method must fail")
	}
	if _, err := New("h", map[string]any{"url": "http://x", "body": "{{ .Broken"}); err == nil {
		t.Error("invalid template must fail at build time")
	}
}
