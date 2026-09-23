package cli

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/skandertajine/digestron/internal/digest"
	"github.com/skandertajine/digestron/internal/logring"
	"github.com/skandertajine/digestron/internal/metrics"
	"github.com/skandertajine/digestron/internal/store"
	"github.com/skandertajine/digestron/internal/web"
)

// gateSource blocks inside Collect until released, so a test can hold a run
// open and press the button again.
type gateSource struct {
	release chan struct{}
	calls   atomic.Int32
}

func (s *gateSource) Name() string { return "src" }
func (s *gateSource) Collect(ctx context.Context, _ digest.Window) ([]digest.Finding, error) {
	s.calls.Add(1)
	select {
	case <-s.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return []digest.Finding{{Source: "src", Title: "blocked flows", Count: 7}}, nil
}

// gateLLM counts prompts so a test can tell a dry run that kept the model
// from one that quietly dropped it.
type gateLLM struct{ calls atomic.Int32 }

func (l *gateLLM) Name() string { return "fake-llm" }
func (l *gateLLM) Complete(context.Context, digest.Request) (digest.Response, error) {
	l.calls.Add(1)
	return digest.Response{Text: "all quiet", Model: "m", PromptTokens: 1, CompletionTokens: 1}, nil
}

type gateSink struct{ sent atomic.Int32 }

func (s *gateSink) Name() string                              { return "phone" }
func (s *gateSink) Send(context.Context, digest.Report) error { s.sent.Add(1); return nil }

func gateApp(t *testing.T, src digest.Source, sk digest.Sink, llm digest.LLM) *App {
	t.Helper()
	st, err := store.Open("", 10)
	if err != nil {
		t.Fatal(err)
	}
	// A real ring behind the logger, as in the process: the gate's log
	// lines can then be read back and checked.
	lv := new(slog.LevelVar)
	lv.Set(slog.LevelDebug)
	ring := logring.New(2000, 1<<20, nil)
	log := slog.New(ring.Handler(slog.NewJSONHandler(io.Discard, nil), lv))
	app := &App{Log: log, Logs: ring, LogLevel: lv, Metrics: metrics.New(), Store: st}
	app.Runner = &digest.Runner{
		Title: "digest", Window: time.Hour, Log: log,
		Sources: []digest.RunSource{{Source: src, Timeout: 5 * time.Second}},
		Sinks:   []digest.RunSink{{Sink: sk, Timeout: 5 * time.Second}},
		LLM:     llm,
	}
	return app
}

// metricValue reads a counter or gauge the way a scrape would, with the
// client_model types build_test.go already depends on.
func metricValue(t *testing.T, m prometheus.Metric) float64 {
	t.Helper()
	var out dto.Metric
	if err := m.Write(&out); err != nil {
		t.Fatal(err)
	}
	if c := out.GetCounter(); c != nil {
		return c.GetValue()
	}
	return out.GetGauge().GetValue()
}

func waitIdle(t *testing.T, g *runGate) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for g.Status().Running {
		if time.Now().After(deadline) {
			t.Fatal("run never finished")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitFor polls until cond holds; the gate hands work to goroutines, so a
// test cannot assert the moment it presses a button.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (g *runGate) missedTick() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.missed
}

// One lock for both paths: while a manual dry run holds it, a second press is
// refused and a scheduler tick is not run alongside it. A dry run delivers
// nothing, so the tick it held back is replayed when it lets go — and the
// dry run itself must leave the shared Runner exactly as it found it.
func TestRunGateDryRunHoldsBackThenReplaysTheTick(t *testing.T) {
	src := &gateSource{release: make(chan struct{})}
	sk := &gateSink{}
	llm := &gateLLM{}
	app := gateApp(t, src, sk, llm)
	g := newRunGate(app)

	if err := g.Start(true); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the dry run to reach its source", func() bool { return src.calls.Load() == 1 })
	if st := g.Status(); !st.Running || !st.Dry || st.StartedAt.IsZero() {
		t.Fatalf("status during the run = %+v", st)
	}
	if err := g.Start(false); !errors.Is(err, web.ErrRunInProgress) {
		t.Errorf("second Start = %v, want ErrRunInProgress", err)
	}
	g.scheduled() // must return at once, and remember it
	if n := src.calls.Load(); n != 1 {
		t.Errorf("source collected %d times during one run, want 1: a tick must not run alongside it", n)
	}
	if !g.missedTick() {
		t.Error("a tick that lands during a dry run must be remembered: nothing was delivered for its hour")
	}

	close(src.release)
	// The dry run ends, then the replayed scheduled run delivers.
	waitFor(t, "the replayed scheduled run", func() bool { return sk.sent.Load() == 1 })
	waitIdle(t, g)

	entries := app.Store.List()
	if len(entries) != 2 {
		t.Fatalf("history has %d runs, want the dry run and the replayed scheduled one", len(entries))
	}
	var dry, scheduled *digest.Report
	for i := range entries {
		r := &entries[i].Report
		if strings.HasSuffix(r.Title, "(manual, dry)") {
			dry = r
		} else if r.Title == "digest" {
			scheduled = r
		}
	}
	if dry == nil || scheduled == nil {
		t.Fatalf("want one (manual, dry) run and one plain scheduled run, got %q and %q",
			entries[0].Report.Title, entries[1].Report.Title)
	}
	if len(dry.Sinks) != 0 {
		t.Error("a dry run must not reach the sinks")
	}
	if dry.LLM.Model != "m" || llm.calls.Load() != 2 {
		t.Errorf("the dry run must keep the LLM (that is what it tests): report model %q, %d prompts for 2 runs",
			dry.LLM.Model, llm.calls.Load())
	}
	if len(scheduled.Sinks) != 1 {
		t.Error("the replayed run is a real digest and must be delivered")
	}
	if app.Runner.Title != "digest" || len(app.Runner.Sinks) != 1 || app.Runner.LLM == nil ||
		app.Runner.Now != nil || app.Runner.Log != app.Log {
		t.Errorf("a run mutated the shared Runner: title %q, %d sinks, llm %v, clock set %v, logger swapped %v",
			app.Runner.Title, len(app.Runner.Sinks), app.Runner.LLM, app.Runner.Now != nil, app.Runner.Log != app.Log)
	}
	// Only the delivered run counts. last_success_timestamp is what alerting
	// reads, and a test must not be able to refresh it.
	if got := metricValue(t, app.Metrics.RunsTotal.WithLabelValues("success")); got != 1 {
		t.Errorf("runs_total{success} = %v, want 1: the replayed run only", got)
	}
}

// A full manual run delivers the window the tick would have covered, so the
// tick is skipped for good, not replayed into a duplicate digest.
func TestRunGateFullRunSkipsTheTick(t *testing.T) {
	src := &gateSource{release: make(chan struct{})}
	sk := &gateSink{}
	app := gateApp(t, src, sk, &gateLLM{})
	g := newRunGate(app)

	if err := g.Start(false); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the run to reach its source", func() bool { return src.calls.Load() == 1 })
	g.scheduled()
	if g.missedTick() {
		t.Error("a tick during a full manual run must be dropped: that run delivers its window")
	}

	close(src.release)
	waitIdle(t, g)

	if sk.sent.Load() != 1 {
		t.Errorf("sink sent %d, want 1: the manual run only, no replayed duplicate", sk.sent.Load())
	}
	entries := app.Store.List()
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Report.Title, "(manual)") {
		t.Errorf("history = %+v, want one run titled (manual)", entries)
	}
	if got := metricValue(t, app.Metrics.RunsTotal.WithLabelValues("success")); got != 1 {
		t.Errorf("runs_total{success} = %v, want 1", got)
	}
}

// The scheduled path is what production runs every hour: plain title,
// delivered, recorded, and untouched by any of the above.
func TestRunGateScheduledRunIsUnchanged(t *testing.T) {
	src := &gateSource{release: make(chan struct{})}
	close(src.release)
	sk := &gateSink{}
	app := gateApp(t, src, sk, &gateLLM{})
	g := newRunGate(app)

	g.scheduled()
	entries := app.Store.List()
	if len(entries) != 1 || entries[0].Report.Title != "digest" {
		t.Fatalf("history = %+v, want one plain scheduled run", entries)
	}
	if sk.sent.Load() != 1 {
		t.Errorf("sink sent %d, want 1", sk.sent.Load())
	}
	if got := metricValue(t, app.Metrics.RunsTotal.WithLabelValues("success")); got != 1 {
		t.Errorf("runs_total{success} = %v, want 1", got)
	}
	if g.Status().Running {
		t.Error("the gate must be released after a scheduled run")
	}
}

// The run's identity is announced while it is still going: the UI can show the
// lines of a run that has not finished, and the ID it filters by is the one the
// history will store the report under.
func TestRunGateAnnouncesTheRunBeforeItStarts(t *testing.T) {
	src := &gateSource{release: make(chan struct{})}
	app := gateApp(t, src, &gateSink{}, &gateLLM{})
	g := newRunGate(app)

	if err := g.Start(true); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the run to reach its source", func() bool { return src.calls.Load() == 1 })

	st := g.Status()
	if st.ID == "" || st.Kind != store.KindTest {
		t.Fatalf("status during the run = %+v, want an ID and kind %q", st, store.KindTest)
	}
	if st.ID != store.IDFor(st.StartedAt) {
		t.Errorf("ID %q is not derived from StartedAt %v", st.ID, st.StartedAt)
	}
	live := app.Logs.Snapshot(logring.Query{Run: st.ID})
	var sawCollecting bool
	for _, rec := range live.Records {
		sawCollecting = sawCollecting || rec.Msg == "collecting"
	}
	if !sawCollecting {
		t.Errorf("no log line tagged with the running run's ID yet: %+v", live.Records)
	}

	close(src.release)
	waitIdle(t, g)
	entries := app.Store.List()
	if len(entries) != 1 || entries[0].ID != st.ID {
		t.Fatalf("history = %+v, want the finished report stored under the announced ID %q", entries, st.ID)
	}
	if entries[0].Kind != store.KindTest {
		t.Errorf("stored kind = %q, want %q", entries[0].Kind, store.KindTest)
	}
}

// Schedule, button, dry button: each lands in the history under its own kind,
// and every log line of every run carries that run's ID and kind.
func TestRunGateKindsAndTaggedLogs(t *testing.T) {
	src := &gateSource{release: make(chan struct{})}
	close(src.release)
	app := gateApp(t, src, &gateSink{}, &gateLLM{})
	g := newRunGate(app)

	g.scheduled()
	if err := g.Start(false); err != nil {
		t.Fatal(err)
	}
	waitIdle(t, g)
	if err := g.Start(true); err != nil {
		t.Fatal(err)
	}
	waitIdle(t, g)

	entries := app.Store.List() // newest first
	if len(entries) != 3 {
		t.Fatalf("history has %d runs, want 3", len(entries))
	}
	wantKinds := []store.Kind{store.KindTest, store.KindManual, store.KindSchedule}
	for i, e := range entries {
		if e.Kind != wantKinds[i] {
			t.Errorf("entry %d (%s) kind = %q, want %q", i, e.Report.Title, e.Kind, wantKinds[i])
		}
	}

	ids := map[string]store.Kind{}
	for _, e := range entries {
		ids[e.ID] = e.Kind
	}
	perRun := map[string]int{}
	for _, rec := range app.Logs.Snapshot(logring.Query{Limit: logring.MaxLimit}).Records {
		if rec.Run == "" {
			t.Errorf("a line of a run carries no run ID: %q %v", rec.Msg, rec.Attrs)
			continue
		}
		kind, known := ids[rec.Run]
		if !known {
			t.Errorf("line %q is tagged with run %q, which is not in the history", rec.Msg, rec.Run)
			continue
		}
		if rec.Attrs["kind"] != string(kind) {
			t.Errorf("line %q of a %s run carries kind %q", rec.Msg, kind, rec.Attrs["kind"])
		}
		perRun[rec.Run]++
	}
	for id := range ids {
		if perRun[id] < 5 {
			t.Errorf("run %s produced only %d log lines, want the debug steps and the finish line", id, perRun[id])
		}
	}
}
