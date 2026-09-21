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

// The dangerous path: the LLM answered, so the sink sends the summary and
// never calls RenderText. The summary is written from the findings that
// survived, and the verdict is the max over those same findings — so a run
// that lost four queries out of five arrives as a full-looking [INFO] digest
// unless the sink says otherwise itself.
func TestSendSummaryStillReportsPartialSources(t *testing.T) {
	var payload map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &payload)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := digest.Report{
		Title:    "Security digest",
		Verdict:  digest.SeverityInfo,
		Summary:  "A quiet hour: 936 firewall blocks, nothing else of note.",
		Findings: []digest.Finding{{Title: "firewall blocked flows", Count: 936}},
		Stats: []digest.SourceStats{
			{Source: "es", Findings: 1, Err: `4 of 5 queries failed: query "ssh auth failures": 400 Bad Request`},
		},
	}
	if err := newSink(t, srv.URL, nil).Send(context.Background(), r); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(payload["message"], r.Summary) {
		t.Errorf("the summary must survive, not be replaced: %q", payload["message"])
	}
	if !strings.Contains(payload["message"], "Partial sources: es: 4 of 5 queries failed") {
		t.Errorf("the failed queries must reach the operator on the summary path too: %q", payload["message"])
	}
	if !strings.Contains(payload["title"], "PARTIAL") {
		t.Errorf("title = %q: a locked phone shows the title and nothing else", payload["title"])
	}
}

// ...and the ordinary complete run must stay unmarked, or the marker means
// nothing.
func TestSendCompleteRunIsNotMarkedPartial(t *testing.T) {
	var payload map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &payload)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := digest.Report{
		Title:   "Security digest",
		Verdict: digest.SeverityWarning,
		Summary: "all accounted for",
		Stats:   []digest.SourceStats{{Source: "es", Findings: 5}},
	}
	if err := newSink(t, srv.URL, nil).Send(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if payload["title"] != "[WARNING] Security digest" {
		t.Errorf("title = %q, want no marker on a complete run", payload["title"])
	}
	if payload["message"] != "all accounted for" {
		t.Errorf("message = %q, want the summary untouched", payload["message"])
	}
}

// A source that returned nothing at all is a different diagnosis from one
// that returned an incomplete count, and the fallback path must keep them
// apart: "Unreachable" on an all-queries-failed source sends the operator
// after the network when the problem is in a query body.
func TestSendFallbackNamesFailedAndPartialApart(t *testing.T) {
	var payload map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &payload)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := digest.Report{
		Title:   "digest",
		Verdict: digest.SeverityInfo,
		Stats: []digest.SourceStats{
			{Source: "es", Findings: 2, Err: "1 of 3 queries failed: query \"ssh auth failures\": 400"},
			{Source: "prom", Findings: 0, Err: "3 of 3 queries failed: dial tcp: refused"},
		},
	}
	if err := newSink(t, srv.URL, nil).Send(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	msg := payload["message"]
	if !strings.Contains(msg, "Failed sources: prom") {
		t.Errorf("a source with no findings at all must be named as failed: %q", msg)
	}
	if !strings.Contains(msg, "Partial sources: es") {
		t.Errorf("a source with findings and an error is partial, not failed: %q", msg)
	}
	if strings.Count(msg, "Partial sources:") != 1 {
		t.Errorf("the fallback already renders the block; it must not be appended twice: %q", msg)
	}
}
