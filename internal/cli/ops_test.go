package cli

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/skandertajine/digestron/internal/digest"
	"github.com/skandertajine/digestron/internal/logring"
	"github.com/skandertajine/digestron/internal/metrics"
	"github.com/skandertajine/digestron/internal/redact"
)

// GET /api/status has no login, so it must never do request-proportional
// work: runtime.ReadMemStats briefly stops every goroutine in the process.
// The sampler takes that hit on its own schedule instead.
func TestMemSamplerUpdatesOnItsOwnScheduleAndStopsWithItsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	m := newMemSampler(ctx, 10*time.Millisecond)

	first := m.alloc.Load()
	if first == 0 {
		t.Fatal("the first sample must be taken immediately, not on the first tick")
	}

	// Allocate to move the number, then wait for a tick to pick it up.
	grown := false
	junk := make([][]byte, 0, 64)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		junk = append(junk, make([]byte, 1<<20))
		time.Sleep(15 * time.Millisecond)
		if m.alloc.Load() != first {
			grown = true
			break
		}
	}
	if !grown {
		t.Error("alloc never changed after 2s of ticks and active allocation")
	}
	_ = junk

	cancel()
	time.Sleep(30 * time.Millisecond) // let the goroutine observe ctx.Done()
	after := m.alloc.Load()
	time.Sleep(60 * time.Millisecond) // several more would-be ticks
	if m.alloc.Load() != after {
		t.Error("the sampler kept updating after its context was cancelled: goroutine leak")
	}
}

func TestGaugeTimeZeroIsTheZeroTime(t *testing.T) {
	m := metrics.New()
	if got := gaugeTime(m.LastSuccessTimestamp); !got.IsZero() {
		t.Errorf("gaugeTime of an unset gauge = %v, want the zero time", got)
	}
	now := time.Now().Truncate(time.Second)
	m.LastSuccessTimestamp.Set(float64(now.Unix()))
	if got := gaugeTime(m.LastSuccessTimestamp); !got.Equal(now.UTC()) {
		t.Errorf("gaugeTime = %v, want %v", got, now.UTC())
	}
}

func TestTimePtr(t *testing.T) {
	if timePtr(time.Time{}) != nil {
		t.Error("timePtr of the zero time must be nil")
	}
	now := time.Now()
	got := timePtr(now)
	if got == nil || !got.Equal(now) {
		t.Errorf("timePtr(%v) = %v", now, got)
	}
}

type checkableSource struct{ err error }

func (checkableSource) Name() string { return "es" }
func (checkableSource) Collect(context.Context, digest.Window) ([]digest.Finding, error) {
	return nil, nil
}
func (s checkableSource) Check(context.Context) error { return s.err }

// unprobeableSink has no Check method: a webhook, where any request to it may
// act, so probing it is not safe to do just to answer a status question.
type unprobeableSink struct{}

func (unprobeableSink) Name() string                              { return "hook" }
func (unprobeableSink) Send(context.Context, digest.Report) error { return nil }

func opsApp(t *testing.T, src digest.Source, sink digest.Sink) *App {
	t.Helper()
	return &App{
		Log:     slog.New(logring.New(100, 1<<16, nil).Handler(slog.NewJSONHandler(io.Discard, nil), new(slog.LevelVar))),
		Scrub:   redact.New(),
		Sources: []digest.RunSource{{Source: src, Timeout: time.Second}},
		Sinks:   []digest.RunSink{{Sink: sink, Timeout: time.Second}},
	}
}

func TestCheckProbesEveryModuleAndSkipsOnesWithNoChecker(t *testing.T) {
	app := opsApp(t, checkableSource{}, unprobeableSink{})
	o := ops{app: app}

	results := o.Check(context.Background(), "")
	if len(results) != 2 {
		t.Fatalf("results = %+v, want one per module", results)
	}
	byName := map[string]struct {
		ok, skipped bool
	}{}
	for _, r := range results {
		byName[r.Name] = struct{ ok, skipped bool }{r.OK, r.Skipped}
	}
	if !byName["es"].ok || byName["es"].skipped {
		t.Errorf("source with a Checker = %+v, want ok and not skipped", byName["es"])
	}
	if byName["hook"].ok || !byName["hook"].skipped {
		t.Errorf("sink with no Checker = %+v, want skipped, never probed", byName["hook"])
	}
}

func TestCheckByNameProbesOnlyThatModule(t *testing.T) {
	app := opsApp(t, checkableSource{}, unprobeableSink{})
	o := ops{app: app}

	results := o.Check(context.Background(), "es")
	if len(results) != 1 || results[0].Name != "es" {
		t.Fatalf("results = %+v, want only es", results)
	}
}

// An upstream failure quoted into a Check error must not leak a secret any
// more than a run's own errors do.
func TestCheckScrubsTheFailureText(t *testing.T) {
	const secret = "SENTINEL-token-12345"
	app := opsApp(t, checkableSource{err: errors.New("401: Bearer " + secret)}, unprobeableSink{})
	app.Scrub = redact.New(secret)
	o := ops{app: app}

	results := o.Check(context.Background(), "es")
	if len(results) != 1 || results[0].OK {
		t.Fatalf("results = %+v, want one failing result", results)
	}
	if got := results[0].Err; got == "" {
		t.Error("a failed check must say why")
	} else if got == "401: Bearer "+secret {
		t.Errorf("the secret was not scrubbed: %q", got)
	}
}
