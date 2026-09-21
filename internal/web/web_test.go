package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skandertajine/digestron/internal/digest"
	"github.com/skandertajine/digestron/internal/store"
)

// fakeTrigger records what the page asked for and lets a test end the run.
type fakeTrigger struct {
	mu      sync.Mutex
	status  RunStatus
	started []bool // the dry flag of every accepted Start
}

func (f *fakeTrigger) Start(dry bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.status.Running {
		return ErrRunInProgress
	}
	f.started = append(f.started, dry)
	f.status = RunStatus{Running: true, Dry: dry, StartedAt: time.Now()}
	return nil
}

func (f *fakeTrigger) Status() RunStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status
}

func (f *fakeTrigger) finish() {
	f.mu.Lock()
	f.status = RunStatus{}
	f.mu.Unlock()
}

func testServer(t *testing.T) (*httptest.Server, *store.Store, *fakeTrigger) {
	t.Helper()
	st, err := store.Open("", 10)
	if err != nil {
		t.Fatal(err)
	}
	trig := &fakeTrigger{}
	mux := http.NewServeMux()
	Register(mux, st, trig)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, st, trig
}

func TestIndexServed(t *testing.T) {
	srv, _, _ := testServer(t)
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
	srv, st, _ := testServer(t)
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

func postRun(t *testing.T, url string, headers ...string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

func getStatus(t *testing.T, url string) RunStatus {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/run status = %d", resp.StatusCode)
	}
	var s RunStatus
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// The button: a run starts in the background and the page follows it through
// the status endpoint. A second press while it runs is refused, not queued —
// the LLM is slow enough without two prompts in line.
func TestManualRunStartsOnceAndReportsStatus(t *testing.T) {
	srv, _, trig := testServer(t)

	if s := getStatus(t, srv.URL+"/api/run"); s.Running {
		t.Fatalf("idle server reports a run: %+v", s)
	}

	code, body := postRun(t, srv.URL+"/api/run?dry=1")
	if code != http.StatusAccepted || body["started"] != true || body["dry"] != true {
		t.Fatalf("POST dry: status %d body %v", code, body)
	}
	if s := getStatus(t, srv.URL+"/api/run"); !s.Running || !s.Dry || s.StartedAt.IsZero() {
		t.Errorf("status while running = %+v", s)
	}

	code, body = postRun(t, srv.URL+"/api/run?dry=0")
	if code != http.StatusConflict || body["error"] == "" {
		t.Errorf("second press: status %d body %v, want 409 with a reason", code, body)
	}

	trig.finish()
	code, body = postRun(t, srv.URL+"/api/run?dry=0")
	if code != http.StatusAccepted || body["dry"] != false {
		t.Errorf("POST ?dry=0 after the run ended: status %d body %v", code, body)
	}
	if got := trig.started; len(got) != 2 || !got[0] || got[1] {
		t.Errorf("starts = %v, want [dry, full]: the flag must reach the trigger", got)
	}
}

// A bare POST is what curl sends, and the one a mistyped URL sends too: it
// must never be the request that buzzes a phone. A delivered run is opt-in.
func TestBareRunIsDryAndBadFlagIsRefused(t *testing.T) {
	srv, _, trig := testServer(t)

	code, body := postRun(t, srv.URL+"/api/run")
	if code != http.StatusAccepted || body["dry"] != true {
		t.Fatalf("bare POST: status %d body %v, want an accepted dry run", code, body)
	}
	trig.finish()

	code, _ = postRun(t, srv.URL+"/api/run?dry=maybe")
	if code != http.StatusBadRequest {
		t.Errorf("?dry=maybe: status %d, want 400 rather than a guess", code)
	}
	if got := trig.started; len(got) != 1 || !got[0] {
		t.Errorf("starts = %v, want exactly the one dry run", got)
	}
}

// The page has no login, so the only thing between another site and the
// button is the browser saying where a request came from. A cross-site POST
// must start nothing; the page's own request and curl must still work.
func TestCrossSiteRunIsRefused(t *testing.T) {
	srv, _, trig := testServer(t)

	for _, h := range [][]string{
		{"Sec-Fetch-Site", "cross-site", "Sec-Fetch-Mode", "navigate"}, // a form on another site
		{"Sec-Fetch-Site", "cross-site", "Sec-Fetch-Mode", "no-cors"},  // fetch(..., {mode: "no-cors"})
		{"Sec-Fetch-Site", "same-site"},                                // a sibling subdomain
		{"Origin", "http://evil.example"},                              // a browser without fetch metadata
	} {
		code, _ := postRun(t, srv.URL+"/api/run?dry=0", h...)
		if code != http.StatusForbidden {
			t.Errorf("POST with %v: status %d, want 403", h, code)
		}
	}
	if len(trig.started) != 0 {
		t.Fatalf("a refused request started %d runs", len(trig.started))
	}

	if code, _ := postRun(t, srv.URL+"/api/run?dry=1", "Sec-Fetch-Site", "same-origin"); code != http.StatusAccepted {
		t.Errorf("the page's own request: status %d, want 202", code)
	}
	trig.finish()
	if code, _ := postRun(t, srv.URL+"/api/run?dry=1"); code != http.StatusAccepted {
		t.Errorf("curl (no browser headers): status %d, want 202", code)
	}
}

// Reading the status must never start anything: the page polls it every two
// seconds.
func TestStatusIsReadOnly(t *testing.T) {
	srv, _, trig := testServer(t)
	for range 3 {
		getStatus(t, srv.URL+"/api/run")
	}
	if len(trig.started) != 0 {
		t.Errorf("polling the status started %d runs", len(trig.started))
	}
}
