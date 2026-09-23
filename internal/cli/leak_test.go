package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skandertajine/digestron/internal/digest"
	"github.com/skandertajine/digestron/internal/logring"
	"github.com/skandertajine/digestron/internal/redact"
	"github.com/skandertajine/digestron/internal/store"
	"github.com/skandertajine/digestron/internal/web"
)

// The page shows the process log to anyone who can reach it, and an upstream
// that rejects a request often quotes the request back: a 401 body that repeats
// the Authorization header ends up in an error, and from there in a log line.
// This test builds the shipped example configuration with recognisable
// secrets, lets every one of them "leak" into log lines the way an upstream
// echo would, and asserts none of them can be read back through the endpoint.
//
// It grows with the UI: every slice that adds an endpoint adds it here.
func TestSecretsNeverReachTheLogEndpoint(t *testing.T) {
	sentinels := map[string]string{
		"ES_PASSWORD":   "SENTINEL-es-7f3a91c2",
		"HA_TOKEN":      "SENTINEL-ha-5b8e04d1",
		"SMTP_PASSWORD": "SENTINEL-smtp-c19d7e33",
		"HOOK_TOKEN":    "SENTINEL-hook-2a6f80b4",
	}
	for k, v := range sentinels {
		t.Setenv(k, v)
	}
	app, err := Build("../../config.example.yaml", true)
	if err != nil {
		t.Fatal(err)
	}

	if app.Scrub.Len() < len(sentinels) {
		t.Fatalf("the scrubber holds %d values for %d secrets in the configuration: one was not collected",
			app.Scrub.Len(), len(sentinels))
	}
	for name, v := range sentinels {
		if got := app.Scrub.Scrub("x " + v + " y"); strings.Contains(got, v) {
			t.Errorf("%s was not collected from the configuration", name)
		}
	}

	// Each secret leaks four ways: in the message, in an error attribute the
	// way a quoted upstream body would, inside a JSON echo without its
	// "Bearer" scheme, and through a logger a run built with With().
	tagged := app.Log.With("run", "run-under-test", "kind", "test")
	for _, v := range sentinels {
		app.Log.Warn("auth failed for " + v)
		app.Log.Error("sink failed", "sink", "phone", "error", fmt.Sprintf("homeassistant: 401: {\"received\":\"Bearer %s\"}", v))
		app.Log.Error("source failed", "error", fmt.Sprintf(`{"authorization":%q}`, v))
		tagged.Info("digest run finished", "detail", "echo "+v)
	}

	mux := http.NewServeMux()
	web.Register(mux, web.Deps{Store: app.Store, Trigger: newRunGate(app), Logs: logSource{ring: app.Logs, lv: app.LogLevel}})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, path := range []string{
		"/api/logs?limit=2000",
		"/api/logs?level=debug&q=sentinel",
		"/api/logs?run=run-under-test",
	} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		for name, v := range sentinels {
			if strings.Contains(string(raw), v) {
				t.Errorf("GET %s leaked %s:\n%s", path, name, raw)
			}
		}
	}

	// The scrubbed lines must still be there, saying that something was hidden:
	// a log that silently drops the line would hide the failure it reports.
	resp, err := http.Get(srv.URL + "/api/logs?limit=2000")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var page logring.Page
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 4*len(sentinels) {
		t.Errorf("%d lines read back, want the %d written", len(page.Records), 4*len(sentinels))
	}
	var hidden int
	for _, rec := range page.Records {
		joined := rec.Msg
		for _, v := range rec.Attrs {
			joined += " " + v
		}
		if strings.Contains(joined, redact.Placeholder) {
			hidden++
		}
	}
	if hidden != len(page.Records) {
		t.Errorf("only %d of %d lines show %s where a secret was: the scrubber dropped text instead of replacing it",
			hidden, len(page.Records), redact.Placeholder)
	}
}

// leakySource, leakyLLM and leakySink fail the way a real upstream does when it
// rejects a request and quotes it back: with the credential inside the error.
type leakySource struct{ echoed string }

func (leakySource) Name() string { return "es" }
func (l leakySource) Collect(context.Context, digest.Window) ([]digest.Finding, error) {
	return nil, fmt.Errorf(`query "ssh": 401 Unauthorized: {"authorization":%q}`, l.echoed)
}

type leakyLLM struct{ echoed string }

func (leakyLLM) Name() string { return "ollama" }
func (l leakyLLM) Complete(context.Context, digest.Request) (digest.Response, error) {
	return digest.Response{}, fmt.Errorf("llm 401: Bearer %s", l.echoed)
}

type leakySink struct {
	echoed string
	mu     sync.Mutex
	seen   []digest.Report
}

func (*leakySink) Name() string { return "phone" }
func (l *leakySink) Send(_ context.Context, r digest.Report) error {
	l.mu.Lock()
	l.seen = append(l.seen, r)
	l.mu.Unlock()
	return fmt.Errorf("homeassistant: 401 Unauthorized: %s", l.echoed)
}

// The log endpoint is one way out. The others are stderr (`kubectl logs`), the
// run report that GET /api/runs/{id} serves and the history file on disk: all
// three carry error texts that quote an upstream. A secret must reach none of
// them, and the runs must still say what failed.
func TestSecretsNeverReachStderrTheRunAPIOrTheHistoryFile(t *testing.T) {
	const secret = "SENTINEL-ha-5b8e04d1"
	for k, v := range map[string]string{
		"ES_PASSWORD": "SENTINEL-es-7f3a91c2", "HA_TOKEN": secret,
		"SMTP_PASSWORD": "SENTINEL-smtp-c19d7e33", "HOOK_TOKEN": "SENTINEL-hook-2a6f80b4",
	} {
		t.Setenv(k, v)
	}
	app, err := Build("../../config.example.yaml", true)
	if err != nil {
		t.Fatal(err)
	}

	// 1. stderr: the handler the process prints through, into a buffer.
	var stderr bytes.Buffer
	log, _, _ := newLoggerTo(&stderr, "debug", app.Scrub)
	log.Error("sink failed", "sink", "phone", "error", errors.New("homeassistant: 401: Bearer "+secret))
	log.Warn("auth failed for " + secret)
	log.Info("group", "resp", map[string]string{"body": secret})
	if strings.Contains(stderr.String(), secret) {
		t.Errorf("a secret reached stderr:\n%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), redact.Placeholder) {
		t.Errorf("stderr lost the failure instead of scrubbing it:\n%s", stderr.String())
	}

	// 2 and 3. a real run through the gate with every module failing loudly.
	hist := filepath.Join(t.TempDir(), "history.json")
	if app.Store, err = store.Open(hist, 10); err != nil {
		t.Fatal(err)
	}
	sink := &leakySink{echoed: secret}
	app.Runner.Sources = []digest.RunSource{{Source: leakySource{echoed: secret}, Timeout: 5 * time.Second}}
	app.Runner.LLM = leakyLLM{echoed: secret}
	app.Runner.Sinks = []digest.RunSink{{Sink: sink, Timeout: 5 * time.Second}}

	gate := newRunGate(app)
	mux := http.NewServeMux()
	web.Register(mux, web.Deps{Store: app.Store, Trigger: gate, Logs: logSource{ring: app.Logs, lv: app.LogLevel}})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	if err := gate.Start(false); err != nil {
		t.Fatal(err)
	}
	waitIdle(t, gate)

	entries := app.Store.List()
	if len(entries) != 1 {
		t.Fatalf("history has %d runs, want the one just made", len(entries))
	}
	get := func(path string) string {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return string(raw)
	}
	fromDisk, err := os.ReadFile(hist)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"GET /api/runs/{id}": get("/api/runs/" + entries[0].ID),
		"GET /api/runs":      get("/api/runs"),
		"GET /api/logs":      get("/api/logs?level=debug&limit=2000"),
		"history.json":       string(fromDisk),
	} {
		if strings.Contains(body, secret) {
			t.Errorf("%s leaked the secret:\n%.600s", name, body)
		}
	}

	// The failures are still there, saying what happened.
	rep := entries[0].Report
	if !strings.Contains(rep.Stats[0].Err, "401 Unauthorized") || !strings.Contains(rep.Sinks[0].Err, "401 Unauthorized") ||
		!strings.Contains(rep.LLM.Err, "llm 401") {
		t.Errorf("scrubbing dropped the failure instead of replacing the secret: %+v / %+v / %q",
			rep.Stats[0], rep.Sinks[0], rep.LLM.Err)
	}
	// And what the sink itself was handed, which is what the phone renders.
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.seen) != 1 || strings.Contains(digest.RenderText(sink.seen[0]), secret) {
		t.Errorf("the digest delivered to the sink carries the secret")
	}
}
