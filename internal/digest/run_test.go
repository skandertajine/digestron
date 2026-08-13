package digest

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeSource struct {
	name     string
	findings []Finding
	err      error
	delay    time.Duration
}

func (f fakeSource) Name() string { return f.name }

func (f fakeSource) Collect(ctx context.Context, _ Window) ([]Finding, error) {
	if f.delay > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(f.delay):
		}
	}
	return f.findings, f.err
}

type fakeLLM struct {
	resp Response
	err  error
}

func (f fakeLLM) Name() string { return "fake" }

func (f fakeLLM) Complete(context.Context, Request) (Response, error) { return f.resp, f.err }

type fakeSink struct {
	name string
	err  error

	mu       sync.Mutex
	received []Report
}

func (f *fakeSink) Name() string { return f.name }

func (f *fakeSink) Send(_ context.Context, r Report) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.received = append(f.received, r)
	return f.err
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestRunHappyPath(t *testing.T) {
	sink := &fakeSink{name: "s1"}
	r := &Runner{
		Title:    "test digest",
		Window:   time.Hour,
		Language: "en",
		MaxChars: 500,
		Sources: []RunSource{
			{Source: fakeSource{name: "b", findings: []Finding{{Source: "b", Title: "t2", Count: 1, Severity: SeverityInfo}}}},
			{Source: fakeSource{name: "a", findings: []Finding{{Source: "a", Title: "t1", Count: 9, Severity: SeverityCritical}}}},
		},
		Sinks: []RunSink{{Sink: sink}},
		LLM:   fakeLLM{resp: Response{Text: "trouble brewing", Model: "m1", PromptTokens: 10, CompletionTokens: 5}},
		Log:   quietLogger(),
	}

	report := r.Run(context.Background())

	if report.Verdict != SeverityCritical {
		t.Errorf("verdict = %s, want critical", report.Verdict)
	}
	if report.Findings[0].Title != "t1" {
		t.Errorf("findings not sorted by severity: %+v", report.Findings)
	}
	if report.Summary != "trouble brewing" {
		t.Errorf("summary = %q", report.Summary)
	}
	if report.LLM.Model != "m1" || report.LLM.PromptTokens != 10 || report.LLM.CompletionTokens != 5 {
		t.Errorf("llm stats = %+v", report.LLM)
	}
	if got := report.Window.To.Sub(report.Window.From); got != time.Hour {
		t.Errorf("window span = %s", got)
	}

	if len(sink.received) != 1 {
		t.Fatalf("sink calls = %d", len(sink.received))
	}
	if len(sink.received[0].Sinks) != 0 {
		t.Error("sinks must receive the report before delivery stats exist")
	}
	if len(report.Sinks) != 1 || report.Sinks[0].Sink != "s1" || report.Sinks[0].Err != "" {
		t.Errorf("final sink stats = %+v", report.Sinks)
	}
}

func TestRunSourceFailureIsVisibleNotFatal(t *testing.T) {
	sink := &fakeSink{name: "s"}
	r := &Runner{
		Title: "t", Window: time.Hour, Log: quietLogger(),
		Sources: []RunSource{
			{Source: fakeSource{name: "dead", err: errors.New("connection refused")}},
			{Source: fakeSource{name: "alive", findings: []Finding{{Source: "alive", Title: "x", Count: 2}}}},
		},
		Sinks: []RunSink{{Sink: sink}},
	}
	report := r.Run(context.Background())

	var deadStats SourceStats
	for _, st := range report.Stats {
		if st.Source == "dead" {
			deadStats = st
		}
	}
	if !strings.Contains(deadStats.Err, "connection refused") {
		t.Errorf("dead source error not recorded: %+v", report.Stats)
	}
	if len(report.Findings) != 1 {
		t.Errorf("findings = %+v, want only the alive source's", report.Findings)
	}
	if len(sink.received) != 1 {
		t.Error("digest must still be delivered when a source fails")
	}
}

func TestRunSourceTimeout(t *testing.T) {
	r := &Runner{
		Title: "t", Window: time.Hour, Log: quietLogger(),
		Sources: []RunSource{
			{Source: fakeSource{name: "slow", delay: 5 * time.Second}, Timeout: 50 * time.Millisecond},
		},
	}
	start := time.Now()
	report := r.Run(context.Background())
	if time.Since(start) > 2*time.Second {
		t.Fatal("per-module timeout not applied")
	}
	if report.Stats[0].Err == "" {
		t.Error("timeout must surface in source stats")
	}
}

func TestRunLLMFailureDegradesGracefully(t *testing.T) {
	sink := &fakeSink{name: "s"}
	r := &Runner{
		Title: "t", Window: time.Hour, Log: quietLogger(),
		Sources: []RunSource{{Source: fakeSource{name: "a", findings: []Finding{{Source: "a", Title: "x", Count: 3}}}}},
		Sinks:   []RunSink{{Sink: sink}},
		LLM:     fakeLLM{err: errors.New("model imploded")},
	}
	report := r.Run(context.Background())

	if report.Summary != "" {
		t.Errorf("summary = %q, want empty on llm failure", report.Summary)
	}
	if !strings.Contains(report.LLM.Err, "model imploded") {
		t.Errorf("llm error not recorded: %+v", report.LLM)
	}
	if len(sink.received) != 1 {
		t.Fatal("raw digest must still be delivered when the llm fails")
	}
}

func TestRunSinkFailureRecorded(t *testing.T) {
	bad := &fakeSink{name: "bad", err: errors.New("teapot")}
	good := &fakeSink{name: "good"}
	r := &Runner{
		Title: "t", Window: time.Hour, Log: quietLogger(),
		Sinks: []RunSink{{Sink: bad}, {Sink: good}},
	}
	report := r.Run(context.Background())

	byName := map[string]SinkStats{}
	for _, st := range report.Sinks {
		byName[st.Sink] = st
	}
	if byName["bad"].Err == "" || byName["good"].Err != "" {
		t.Errorf("sink stats = %+v", report.Sinks)
	}
	if len(good.received) != 1 {
		t.Error("one failing sink must not prevent the others")
	}
}

func TestRenderTextDeterministic(t *testing.T) {
	report := Report{
		Title:   "digest",
		Verdict: SeverityWarning,
		Window: Window{
			From: time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC),
			To:   time.Date(2026, 8, 13, 11, 0, 0, 0, time.UTC),
		},
		Summary: "some trouble",
		Findings: []Finding{
			{Source: "es", Title: "ssh failures", Count: 7, Severity: SeverityWarning,
				Details: map[string]int{"b": 2, "a": 2, "c": 3, "d": 1}},
		},
		Stats: []SourceStats{
			{Source: "es", Findings: 1},
			{Source: "prom", Err: "dial tcp: refused"},
		},
	}

	first := RenderText(report)
	for i := 0; i < 20; i++ {
		if got := RenderText(report); got != first {
			t.Fatal("render output varies between calls (map ordering leak)")
		}
	}
	if !strings.Contains(first, "[WARNING] digest — 2026-08-13 10:00 → 11:00 UTC") {
		t.Errorf("header missing:\n%s", first)
	}
	if !strings.Contains(first, "(c=3, a=2, b=2)") {
		t.Errorf("details must be top-3, count desc then key asc:\n%s", first)
	}
	if !strings.Contains(first, "Unreachable sources: prom") {
		t.Errorf("source errors must be visible in the digest:\n%s", first)
	}
}
