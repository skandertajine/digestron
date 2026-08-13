package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/skandertajine/digestron/internal/digest"
	"github.com/skandertajine/digestron/internal/store"
)

func testServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open("", 10)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	Register(mux, st)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, st
}

func TestIndexServed(t *testing.T) {
	srv, _ := testServer(t)
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		t.Errorf("status %d, content-type %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
}

func TestRunsListAndDetail(t *testing.T) {
	srv, st := testServer(t)
	at := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	entry, _ := st.Append(digest.Report{
		Title:       "digest",
		Verdict:     digest.SeverityWarning,
		Summary:     "trouble",
		GeneratedAt: at,
		Findings:    []digest.Finding{{Source: "es", Title: "x", Count: 3, Severity: digest.SeverityWarning}},
		Stats:       []digest.SourceStats{{Source: "es", Findings: 1}, {Source: "prom", Err: "down"}},
		LLM:         digest.LLMStats{Provider: "ollama", Model: "qwen3:8b", PromptTokens: 100, CompletionTokens: 20},
		Sinks:       []digest.SinkStats{{Sink: "iphone"}, {Sink: "mail", Err: "teapot"}},
	})

	resp, err := http.Get(srv.URL + "/api/runs")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var list []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("runs = %d", len(list))
	}
	got := list[0]
	if got["verdict"] != "warning" || got["sources_failed"] != float64(1) ||
		got["sinks_failed"] != float64(1) || got["prompt_tokens"] != float64(100) {
		t.Errorf("summary = %v", got)
	}

	detail, err := http.Get(srv.URL + "/api/runs/" + entry.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer detail.Body.Close()
	var e store.Entry
	if err := json.NewDecoder(detail.Body).Decode(&e); err != nil {
		t.Fatal(err)
	}
	if e.Report.Summary != "trouble" || len(e.Report.Findings) != 1 {
		t.Errorf("detail = %+v", e.Report)
	}

	missing, err := http.Get(srv.URL + "/api/runs/nope")
	if err != nil {
		t.Fatal(err)
	}
	defer missing.Body.Close()
	if missing.StatusCode != http.StatusNotFound {
		t.Errorf("unknown id status = %d", missing.StatusCode)
	}
}
