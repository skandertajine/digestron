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

// A source may fail halfway and still hand back what it collected. Keeping
// those findings is the whole point: one rejected Elasticsearch query used to
// discard four healthy ones.
func TestRunPartialSourceKeepsFindings(t *testing.T) {
	sink := &fakeSink{name: "s"}
	r := &Runner{
		Title: "t", Window: time.Hour, Log: quietLogger(),
		Sources: []RunSource{{Source: fakeSource{
			name:     "es",
			findings: []Finding{{Source: "es", Title: "firewall blocked flows", Count: 936}},
			err:      errors.New(`1 of 2 queries failed: query "ssh auth failures": 400 Bad Request`),
		}}},
		Sinks: []RunSink{{Sink: sink}},
	}
	report := r.Run(context.Background())

	if len(report.Findings) != 1 || report.Findings[0].Count != 936 {
		t.Fatalf("findings = %+v, want the ones the source did collect", report.Findings)
	}
	st := report.Stats[0]
	if !st.Partial() {
		t.Errorf("stats = %+v, want partial: findings and an error together", st)
	}
	if !strings.Contains(st.Err, "ssh auth failures") {
		t.Errorf("the failed query must be named, not swallowed: %+v", st)
	}
	if len(sink.received) != 1 {
		t.Fatal("a partial digest must still be delivered")
	}
	text := RenderText(sink.received[0])
	if !strings.Contains(text, "Partial sources: es: 1 of 2 queries failed") {
		t.Errorf("the digest must say it is incomplete:\n%s", text)
	}
	if strings.Contains(text, "Failed sources") {
		t.Errorf("a source that answered some queries is partial, not failed:\n%s", text)
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
	if !strings.Contains(first, "Failed sources: prom") {
		t.Errorf("source errors must be visible in the digest:\n%s", first)
	}
}

// A source whose every query failed has zero findings, which used to put it in
// the same sentence as a source nobody could connect to. The two point at
// different things — a query body versus the network — and misreading one for
// the other is what starts an afternoon of debugging the wrong layer.
func TestSourceProblemsSeparatesFailedFromPartial(t *testing.T) {
	r := Report{Stats: []SourceStats{
		{Source: "healthy", Findings: 3},
		{Source: "half_answered", Findings: 4, Err: `1 of 5 queries failed: query "ssh auth failures": 400`},
		{Source: "all_rejected", Findings: 0, Err: `5 of 5 queries failed: query "ssh auth failures": 400`},
		{Source: "offline", Findings: 0, Err: "dial tcp: refused"},
	}}

	got := SourceProblems(r)
	lines := strings.Split(got, "\n")
	if len(lines) != 2 {
		t.Fatalf("SourceProblems() = %q, want one line per kind", got)
	}
	failed, partial := lines[0], lines[1]

	if !strings.HasPrefix(failed, "Failed sources: ") ||
		!strings.Contains(failed, "all_rejected") || !strings.Contains(failed, "offline") {
		t.Errorf("sources that produced nothing belong on the failed line: %q", failed)
	}
	if strings.Contains(failed, "half_answered") {
		t.Errorf("a source that delivered findings is not a failed source: %q", failed)
	}
	if !strings.HasPrefix(partial, "Partial sources: ") || !strings.Contains(partial, "half_answered") {
		t.Errorf("partial line = %q", partial)
	}
	if strings.Contains(partial, "all_rejected") || strings.Contains(partial, "offline") {
		t.Errorf("a source with no findings is not partial, it is failed: %q", partial)
	}
	if strings.Contains(got, "healthy") {
		t.Errorf("a source that answered in full must not be mentioned: %q", got)
	}
	// Sources are joined one level up from the queries inside a source, which
	// source.QueryErrors joins with " | ".
	if !strings.Contains(failed, "refused") || !strings.Contains(failed, "; ") {
		t.Errorf("sources must be separated by \"; \": %q", failed)
	}

	if p := SourceProblems(Report{Stats: []SourceStats{{Source: "healthy", Findings: 3}}}); p != "" {
		t.Errorf("SourceProblems() = %q, want empty when every source answered", p)
	}
}

// A caller that wants a run's ID before the run starts fixes the instant here:
// the ID is derived from GeneratedAt, and the log lines of the run are tagged
// with it while the run is still going.
func TestRunUsesTheInjectedClock(t *testing.T) {
	fixed := time.Date(2026, 9, 22, 1, 10, 0, 3100, time.UTC)
	r := &Runner{Title: "t", Window: time.Hour, Log: quietLogger(), Now: func() time.Time { return fixed }}

	report := r.Run(context.Background())

	if !report.GeneratedAt.Equal(fixed) || !report.Window.To.Equal(fixed) {
		t.Errorf("GeneratedAt %v, Window.To %v; want both %v", report.GeneratedAt, report.Window.To, fixed)
	}
	if !report.Window.From.Equal(fixed.Add(-time.Hour)) {
		t.Errorf("Window.From = %v, want one hour before the injected instant", report.Window.From)
	}
}

func TestRunWithoutClockUsesTimeNow(t *testing.T) {
	before := time.Now()
	report := (&Runner{Title: "t", Window: time.Hour, Log: quietLogger()}).Run(context.Background())
	if report.GeneratedAt.Before(before) || time.Since(report.GeneratedAt) > time.Minute {
		t.Errorf("GeneratedAt = %v, want about now", report.GeneratedAt)
	}
}

// The debug lines say what happened and how long it took. They never carry a
// finding, a prompt or a reply: the README promises that logs hold no
// content, and the UI now shows them to anyone who opens the page.
func TestRunLogsTheStepsAndNeverTheContent(t *testing.T) {
	var buf strings.Builder
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	r := &Runner{
		Title: "t", Window: time.Hour, Log: log, LLMTimeout: time.Second,
		Sources: []RunSource{{Source: fakeSource{name: "es", findings: []Finding{
			{Source: "es", Title: "FINDING-TITLE-MARKER", Count: 3, Details: map[string]int{"10.9.8.7": 3}}}}}},
		LLM:   fakeLLM{resp: Response{Text: "REPLY-TEXT-MARKER", Model: "m", PromptTokens: 5, CompletionTokens: 2}},
		Sinks: []RunSink{{Sink: &fakeSink{name: "phone"}}},
	}
	r.Run(context.Background())

	out := buf.String()
	for _, step := range []string{"run started", "collecting", "source done", "llm request", "llm response", "delivering", "sink done"} {
		if !strings.Contains(out, `msg="`+step+`"`) && !strings.Contains(out, "msg="+step) {
			t.Errorf("no %q line in the debug output:\n%s", step, out)
		}
	}
	for _, content := range []string{"FINDING-TITLE-MARKER", "REPLY-TEXT-MARKER", "10.9.8.7"} {
		if strings.Contains(out, content) {
			t.Errorf("content %q reached the log:\n%s", content, out)
		}
	}
	if !strings.Contains(out, "reply_bytes=17") || !strings.Contains(out, "prompt_tokens=5") {
		t.Errorf("the llm response line must carry sizes and token counts:\n%s", out)
	}
}

// An upstream that rejects a request often quotes it back, and every error
// the runner records goes on to the sinks, to history.json and to the UI. The
// secret must not get past the runner.
func TestRunScrubsErrorsAndSummaryBeforeTheyEnterTheReport(t *testing.T) {
	const secret = "SENTINEL-token-12345"
	scrub := func(s string) string { return strings.ReplaceAll(s, secret, "<redacted>") }
	sink := &fakeSink{name: "phone", err: errors.New("401 Unauthorized: " + secret)}

	failing := &Runner{
		Title: "t", Window: time.Hour, Log: quietLogger(), Scrub: scrub, LLMTimeout: time.Second,
		Sources: []RunSource{{Source: fakeSource{name: "es", err: errors.New(`query "x": 401 {"got":"` + secret + `"}`)}}},
		LLM:     fakeLLM{err: errors.New("llm 500: " + secret)},
		Sinks:   []RunSink{{Sink: sink}},
	}
	report := failing.Run(context.Background())

	for what, text := range map[string]string{
		"source error": report.Stats[0].Err,
		"llm error":    report.LLM.Err,
		"sink error":   report.Sinks[0].Err,
	} {
		if strings.Contains(text, secret) || !strings.Contains(text, "<redacted>") {
			t.Errorf("%s = %q, want the secret replaced and the rest kept", what, text)
		}
	}
	// What the sink was handed is what history and the phone get.
	if got := sink.received[0].Stats[0].Err; strings.Contains(got, secret) {
		t.Errorf("the sink received an unscrubbed source error: %q", got)
	}
	if got := RenderText(sink.received[0]); strings.Contains(got, secret) {
		t.Errorf("the rendered digest carries the secret:\n%s", got)
	}

	chatty := &Runner{
		Title: "t", Window: time.Hour, Log: quietLogger(), Scrub: scrub, LLMTimeout: time.Second,
		LLM: fakeLLM{resp: Response{Text: "all quiet, token " + secret, Model: "m"}},
	}
	if got := chatty.Run(context.Background()).Summary; strings.Contains(got, secret) {
		t.Errorf("the summary carries the secret: %q", got)
	}
}

func TestRunWithoutScrubKeepsErrorsAsTheyAre(t *testing.T) {
	r := &Runner{Title: "t", Window: time.Hour, Log: quietLogger(),
		Sources: []RunSource{{Source: fakeSource{name: "es", err: errors.New("plain failure")}}}}
	if got := r.Run(context.Background()).Stats[0].Err; got != "plain failure" {
		t.Errorf("error = %q, want it untouched when no scrubber is set", got)
	}
}
