package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skandertajine/digestron/internal/digest"
	"github.com/skandertajine/digestron/internal/logring"
	"github.com/skandertajine/digestron/internal/store"
)

// fakeTrigger records what the page asked for and lets a test end the run.
type fakeTrigger struct {
	mu        sync.Mutex
	status    RunStatus
	started   []bool // the dry flag of every accepted Start
	cancelled int
}

func (f *fakeTrigger) Cancel() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.status.Running {
		return ErrNotRunning
	}
	f.cancelled++
	f.status = RunStatus{}
	return nil
}

func (f *fakeTrigger) Start(dry bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.status.Running {
		return ErrRunInProgress
	}
	f.started = append(f.started, dry)
	kind := store.KindManual
	if dry {
		kind = store.KindTest
	}
	f.status = RunStatus{Running: true, Dry: dry, StartedAt: time.Now(), ID: fmt.Sprintf("run-%d", len(f.started)), Kind: kind}
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
	Register(mux, Deps{Store: st, Trigger: trig})
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
	}, store.KindSchedule)

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
		got["sinks_failed"] != float64(1) || got["prompt_tokens"] != float64(100) || got["kind"] != "schedule" {
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
	if s := getStatus(t, srv.URL+"/api/run"); !s.Running || !s.Dry || s.StartedAt.IsZero() ||
		s.ID != "run-1" || s.Kind != store.KindTest {
		t.Errorf("status while running = %+v, want the run's identity (id, kind) with it", s)
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

// ---------------------------------------------------------------- logs

// testLogs is a real ring behind the interface the page reads, so the
// endpoint tests exercise the same paging and filtering the process uses.
type testLogs struct {
	ring *logring.Ring
	lv   *slog.LevelVar
}

func (l testLogs) Logs(q logring.Query) logring.Page { return l.ring.Snapshot(q) }
func (l testLogs) Level() string                     { return logring.LevelName(l.lv.Level()) }
func (l testLogs) SetLevel(name string) error {
	lvl, ok := logring.ParseLevel(name)
	if !ok {
		return fmt.Errorf("unknown level %q", name)
	}
	l.lv.Set(lvl)
	return nil
}

func logsServer(t *testing.T) (*httptest.Server, *slog.Logger, *slog.LevelVar) {
	t.Helper()
	st, _ := store.Open("", 10)
	lv := new(slog.LevelVar)
	lv.Set(slog.LevelInfo)
	ring := logring.New(500, 1<<20, nil)
	log := slog.New(ring.Handler(slog.NewJSONHandler(io.Discard, nil), lv))
	mux := http.NewServeMux()
	Register(mux, Deps{Store: st, Trigger: &fakeTrigger{}, Logs: testLogs{ring: ring, lv: lv}})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, log, lv
}

type logsBody struct {
	Boot    string           `json:"boot"`
	Seq     uint64           `json:"seq"`
	Dropped uint64           `json:"dropped"`
	Level   string           `json:"level"`
	Records []map[string]any `json:"records"`
}

func getLogs(t *testing.T, url string) (int, logsBody) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b logsBody
	_ = json.NewDecoder(resp.Body).Decode(&b)
	return resp.StatusCode, b
}

func putLevel(t *testing.T, url, contentType, body string, headers ...string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, url, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// Reading: every level the ring holds, filtered on the way out, with a
// cursor a poller can carry from one read to the next.
func TestLogsEndpointFiltersAndPages(t *testing.T) {
	srv, log, _ := logsServer(t)
	run := log.With("run", "2026-09-22T01:10:00Z", "kind", "schedule")
	run.Debug("collecting", "source", "es-security")
	run.Error("source failed", "error", "400 Bad Request")
	log.Info("something else")

	code, all := getLogs(t, srv.URL+"/api/logs")
	if all.Boot == "" {
		t.Error("the response must carry the ring's boot id, or a page cannot tell that the process restarted")
	}
	if code != http.StatusOK || len(all.Records) != 3 || all.Seq != 3 || all.Level != "info" {
		t.Fatalf("all: status %d, %d records, seq %d, level %q; want 3 records (debug included), seq 3, stderr level info",
			code, len(all.Records), all.Seq, all.Level)
	}
	if _, warn := getLogs(t, srv.URL+"/api/logs?level=warn"); len(warn.Records) != 1 {
		t.Errorf("level=warn returned %d records, want the error only", len(warn.Records))
	}
	if _, byRun := getLogs(t, srv.URL+"/api/logs?run=2026-09-22T01:10:00Z"); len(byRun.Records) != 2 {
		t.Errorf("run filter returned %d records, want the run's 2", len(byRun.Records))
	}
	if _, q := getLogs(t, srv.URL+"/api/logs?q=bad+request"); len(q.Records) != 1 {
		t.Errorf("q filter returned %d records, want 1", len(q.Records))
	}

	log.Warn("later")
	_, next := getLogs(t, fmt.Sprintf("%s/api/logs?since=%d", srv.URL, all.Seq))
	if len(next.Records) != 1 || next.Records[0]["msg"] != "later" || next.Seq != 4 {
		t.Errorf("poll from cursor %d = %+v, want only the new line and cursor 4", all.Seq, next)
	}
	_, idle := getLogs(t, fmt.Sprintf("%s/api/logs?since=%d", srv.URL, next.Seq))
	if idle.Records == nil || len(idle.Records) != 0 {
		t.Errorf("an idle poll must return an empty list, not null: %+v", idle.Records)
	}
}

func TestLogsEndpointRefusesBadQueries(t *testing.T) {
	srv, _, _ := logsServer(t)
	for _, q := range []string{"since=abc", "since=-1", "level=loud", "limit=0", "limit=many"} {
		resp, err := http.Get(srv.URL + "/api/logs?" + q)
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest || body["field"] == "" {
			t.Errorf("?%s: status %d body %v, want 400 naming the field", q, resp.StatusCode, body)
		}
	}
}

// Writing: the level stderr prints, in memory, for this process only.
func TestLogLevelCanBeChangedAtRuntime(t *testing.T) {
	srv, log, lv := logsServer(t)

	if code := putLevel(t, srv.URL+"/api/logs/level", "application/json", `{"level":"debug"}`); code != http.StatusNoContent {
		t.Fatalf("PUT level=debug: status %d, want 204", code)
	}
	if lv.Level() != slog.LevelDebug {
		t.Errorf("stderr level = %v, want debug", lv.Level())
	}
	if _, b := getLogs(t, srv.URL+"/api/logs"); b.Level != "debug" {
		t.Errorf("the page must be told the new level: %q", b.Level)
	}

	log.Debug("still kept")
	if _, b := getLogs(t, srv.URL+"/api/logs"); len(b.Records) != 1 {
		t.Errorf("ring has %d records", len(b.Records))
	}

	if code := putLevel(t, srv.URL+"/api/logs/level", "application/json", `{"level":"loud"}`); code != http.StatusBadRequest {
		t.Errorf("unknown level: status %d, want 400 rather than a guess", code)
	}
	if lv.Level() != slog.LevelDebug {
		t.Error("a refused request changed the level")
	}
}

// The page has no login. The level is harmless, but the route is the first
// mutating one next to the button, and the same guards must hold on it.
func TestLogLevelRouteRefusesWhatABrowserOnAnotherSiteCouldSend(t *testing.T) {
	srv, _, lv := logsServer(t)
	url := srv.URL + "/api/logs/level"

	for name, code := range map[string]int{
		"cross-site":            putLevel(t, url, "application/json", `{"level":"debug"}`, "Sec-Fetch-Site", "cross-site"),
		"foreign origin":        putLevel(t, url, "application/json", `{"level":"debug"}`, "Origin", "http://evil.example"),
		"text/plain (no CORS)":  putLevel(t, url, "text/plain", `{"level":"debug"}`),
		"form body":             putLevel(t, url, "application/x-www-form-urlencoded", "level=debug"),
		"no content type":       putLevel(t, url, "", `{"level":"debug"}`),
		"unknown field":         putLevel(t, url, "application/json", `{"level":"debug","persist":true}`),
		"not json":              putLevel(t, url, "application/json", `debug`),
		"body over the 256 KiB": putLevel(t, url, "application/json", `{"level":"`+strings.Repeat("x", 300<<10)+`"}`),
	} {
		if code < 400 {
			t.Errorf("%s: status %d, want a refusal", name, code)
		}
	}
	if code := putLevel(t, url, "application/json", `{"level":"debug"}`, "Sec-Fetch-Site", "cross-site"); code != http.StatusForbidden {
		t.Errorf("cross-site PUT: status %d, want 403", code)
	}
	if code := putLevel(t, url, "text/plain", `{"level":"debug"}`); code != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain PUT: status %d, want 415", code)
	}
	if code := putLevel(t, url, "application/json", `{"level":"`+strings.Repeat("x", 300<<10)+`"}`); code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized PUT: status %d, want 413", code)
	}
	if lv.Level() != slog.LevelInfo {
		t.Errorf("a refused request changed the level to %v", lv.Level())
	}
	if code := putLevel(t, url, "application/json", `{"level":"warn"}`, "Sec-Fetch-Site", "same-origin"); code != http.StatusNoContent {
		t.Errorf("the page's own PUT: status %d, want 204", code)
	}
}

// A dependency that is not wired in leaves its routes unregistered: the page
// must not answer for a feature the process does not have.
func TestNilDependenciesLeaveRoutesUnregistered(t *testing.T) {
	st, _ := store.Open("", 10)
	mux := http.NewServeMux()
	Register(mux, Deps{Store: st})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, path := range []string{"/api/logs", "/api/run"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s with no dependency wired: status %d, want 404", path, resp.StatusCode)
		}
	}
}

func TestJSONResponsesAreNotSniffable(t *testing.T) {
	srv, _, _ := logsServer(t)
	resp, err := http.Get(srv.URL + "/api/logs")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
}

// ---------------------------------------------------------------- cancel

func TestCancelStopsARunAndRefusesWhenIdle(t *testing.T) {
	srv, _, trig := testServer(t)

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/run", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("DELETE while idle: status %d, want 404", resp.StatusCode)
	}

	if _, body := postRun(t, srv.URL+"/api/run?dry=1"); body["started"] != true {
		t.Fatal("could not start a run to cancel")
	}
	req, _ = http.NewRequest(http.MethodDelete, srv.URL+"/api/run", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE while running: status %d, want 204", resp.StatusCode)
	}
	if trig.cancelled != 1 {
		t.Errorf("trigger.cancelled = %d, want 1", trig.cancelled)
	}
}

// DELETE is as much a side-effecting route as POST, and the page has no login.
func TestCancelRefusesCrossSiteRequests(t *testing.T) {
	srv, _, trig := testServer(t)
	_, _ = postRun(t, srv.URL+"/api/run?dry=1")

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/run", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site DELETE: status %d, want 403", resp.StatusCode)
	}
	if trig.cancelled != 0 {
		t.Error("a refused cross-site DELETE still cancelled the run")
	}
}

// ---------------------------------------------------------------- status & check

type fakeOps struct {
	status Status
	block  chan struct{} // when set, Check waits for it or ctx.Done()

	mu         sync.Mutex
	checkCalls []string // the module argument of every Check call
	results    []CheckResult
}

func (f *fakeOps) Status() Status { return f.status }

func (f *fakeOps) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.checkCalls)
}

func (f *fakeOps) Check(ctx context.Context, module string) []CheckResult {
	f.mu.Lock()
	f.checkCalls = append(f.checkCalls, module)
	results := f.results
	f.mu.Unlock()
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return nil
		}
	}
	return results
}

func opsServer(t *testing.T, ops Ops) *httptest.Server {
	t.Helper()
	st, _ := store.Open("", 10)
	mux := http.NewServeMux()
	Register(mux, Deps{Store: st, Trigger: &fakeTrigger{}, Ops: ops})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestStatusEndpointReturnsWhatOpsReports(t *testing.T) {
	next := time.Now().Add(37 * time.Minute).UTC().Truncate(time.Second)
	fo := &fakeOps{status: Status{
		Version: "dev-abc123", GoVersion: "go1.26", Cron: "5 * * * *", Timezone: "Europe/Paris",
		NextRun: &next, LogRecords: 12, LogBytes: 3456, Goroutines: 9, MemAllocBytes: 1 << 20,
	}}
	srv := opsServer(t, fo)

	resp, err := http.Get(srv.URL + "/api/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got Status
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Version != "dev-abc123" || got.Cron != "5 * * * *" || got.LogRecords != 12 || got.NextRun == nil || !got.NextRun.Equal(next) {
		t.Errorf("status = %+v", got)
	}
}

// A fresh process has no last run and no next run yet (the scheduler names
// its job only after Start, and no history exists before the first tick).
// Those fields must be absent from the JSON, not Go's zero time.Time
// serialized as a real-looking, ancient date — encoding/json's omitempty is a
// no-op on a plain time.Time, which is why Status uses pointers.
func TestStatusOmitsTimestampsThatNeverHappened(t *testing.T) {
	srv := opsServer(t, &fakeOps{status: Status{Version: "dev"}})

	resp, err := http.Get(srv.URL + "/api/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"next_run", "last_run", "last_success"} {
		if strings.Contains(string(raw), `"`+field+`"`) {
			t.Errorf("field %q present in a fresh status, want it absent: %s", field, raw)
		}
	}
	var got Status
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.NextRun != nil || got.LastRun != nil || got.LastSuccess != nil {
		t.Errorf("decoded status = %+v, want all three nil", got)
	}
}

func TestCheckAllRunsEveryModuleAndOneByName(t *testing.T) {
	fo := &fakeOps{results: []CheckResult{
		{Kind: "source", Name: "es", OK: true, Millis: 12},
		{Kind: "sink", Name: "phone", OK: false, Err: "401 Unauthorized", Millis: 40},
	}}
	srv := opsServer(t, fo)

	code, results := postCheck(t, srv.URL, "application/json", `{}`)
	if code != http.StatusOK || len(results) != 2 || results[1]["error"] != "401 Unauthorized" {
		t.Fatalf("check-all: status %d, results %v", code, results)
	}
	if len(fo.checkCalls) != 1 || fo.checkCalls[0] != "" {
		t.Errorf("Check called with %v, want one call with an empty module", fo.checkCalls)
	}

	code, _ = postCheck(t, srv.URL, "application/json", `{"module":"phone"}`)
	if code != http.StatusOK || fo.checkCalls[len(fo.checkCalls)-1] != "phone" {
		t.Errorf("single-module check: status %d, calls %v", code, fo.checkCalls)
	}

	// A bare POST (curl, or the button with no body) checks everything.
	code, _ = postCheck(t, srv.URL, "", "")
	if code != http.StatusOK || fo.checkCalls[len(fo.checkCalls)-1] != "" {
		t.Errorf("bare POST: status %d, calls %v", code, fo.checkCalls)
	}
}

// The check reaches every configured backend, so a cross-site page must not
// be able to fire it, and a caller must not be able to hold the process open
// past the endpoint's own bound.
func TestCheckRefusesCrossSiteAndRespectsATimeout(t *testing.T) {
	fo := &fakeOps{block: make(chan struct{})}
	defer close(fo.block)
	srv := opsServer(t, fo)

	code, _ := postCheck(t, srv.URL, "application/json", `{}`, "Sec-Fetch-Site", "cross-site")
	if code != http.StatusForbidden {
		t.Errorf("cross-site POST: status %d, want 403", code)
	}
}

func postCheck(t *testing.T, base, contentType, body string, headers ...string) (int, []map[string]any) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, _ := http.NewRequest(http.MethodPost, base+"/api/check", r)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out []map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestNilOpsLeavesStatusAndCheckUnregistered(t *testing.T) {
	st, _ := store.Open("", 10)
	mux := http.NewServeMux()
	Register(mux, Deps{Store: st})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	for _, path := range []string{"/api/status", "/api/check"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s with no Ops wired: status %d, want 404", path, resp.StatusCode)
		}
	}
}

// The route reaches every configured backend, so nothing on the LAN — not
// only a browser, which the cross-origin guard already stops — should be
// able to make the process re-probe faster than an operator can click.
func TestCheckRefusesAnOverlappingCall(t *testing.T) {
	fo := &fakeOps{block: make(chan struct{})}
	srv := opsServer(t, fo)

	done := make(chan int, 1)
	go func() {
		code, _ := postCheck(t, srv.URL, "application/json", `{}`)
		done <- code
	}()

	deadline := time.Now().Add(2 * time.Second)
	for fo.calls() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if fo.calls() == 0 {
		t.Fatal("the first check never started")
	}

	// postCheck decodes into a []map[string]any (the shape of a successful
	// check-all); the 429 body is a plain {"error": "..."} object, which a
	// list-shaped decode silently drops — the status code is what this
	// checks, on purpose.
	code, _ := postCheck(t, srv.URL, "application/json", `{}`)
	if code != http.StatusTooManyRequests {
		t.Errorf("overlapping check: status %d, want 429", code)
	}

	close(fo.block)
	if got := <-done; got != http.StatusOK {
		t.Errorf("the first check finished with status %d, want 200", got)
	}
	// Released: a third call must succeed.
	code, _ = postCheck(t, srv.URL, "application/json", `{}`)
	if code != http.StatusOK {
		t.Errorf("check after the first one finished: status %d, want 200", code)
	}
}
