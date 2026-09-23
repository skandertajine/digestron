package cli

import (
	"context"
	"sync"
	"time"

	"github.com/skandertajine/digestron/internal/store"
	"github.com/skandertajine/digestron/internal/web"
)

// runGate serializes every digest run of a serve process, whether the
// scheduler fired it or someone pressed the button. Two runs at once would
// queue two prompts on the same LLM, where the hourly run already spends
// most of its budget waiting, and could push the same window to a phone
// twice. gocron's singleton mode only covers the runs it starts itself, so
// the gate is the one lock both paths go through.
//
// Every run also gets its identity here, before it starts: an ID derived from
// the instant it begins, and a kind. The ID is the one the history will store
// the finished report under, and every log line of the run carries it, so the
// UI can show exactly what a given run did while it is still going.
type runGate struct {
	app *App

	mu     sync.Mutex
	state  web.RunStatus
	missed bool // a scheduler tick landed while a dry run held the gate
}

func newRunGate(app *App) *runGate { return &runGate{app: app} }

// Status implements web.Trigger.
func (g *runGate) Status() web.RunStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.state
}

// Start implements web.Trigger: a manual run in the background, or a refusal
// because one is in flight. It never blocks the HTTP handler.
func (g *runGate) Start(dry bool) error {
	kind := store.KindManual
	if dry {
		kind = store.KindTest
	}
	ok, cur := g.begin(kind, dry, false)
	if !ok {
		return web.ErrRunInProgress
	}
	go func() {
		defer g.end()
		g.execute(cur, "manual")
	}()
	return nil
}

// scheduled is the scheduler's task. A tick that lands during a full manual
// run is skipped and logged, not queued: that run delivers the window the
// tick would have covered. A tick that lands during a dry run is different,
// because a dry run delivers nothing: the tick is remembered and replayed
// the moment the dry run lets go, or that hour would never reach the phone.
func (g *runGate) scheduled() {
	ok, cur := g.begin(store.KindSchedule, false, true)
	if !ok {
		g.app.Log.Warn("scheduled run held back, another run is in progress",
			"running", cur.ID, "running_kind", string(cur.Kind), "since", cur.StartedAt,
			"replayed_after_dry_run", cur.Dry)
		return
	}
	defer g.end()
	g.execute(cur, "schedule")
}

// begin takes the gate. It returns the identity of the run it started, or,
// when the gate is taken already, the status of what holds it, and records a
// scheduler tick (tick=true) that a dry run made miss.
func (g *runGate) begin(kind store.Kind, dry, tick bool) (bool, web.RunStatus) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state.Running {
		if tick && g.state.Dry {
			g.missed = true
		}
		return false, g.state
	}
	now := time.Now()
	g.state = web.RunStatus{Running: true, Dry: dry, StartedAt: now, ID: store.IDFor(now), Kind: kind}
	return true, g.state
}

func (g *runGate) end() {
	g.mu.Lock()
	replay := g.missed && g.state.Dry
	g.missed = false
	g.state = web.RunStatus{}
	g.mu.Unlock()
	if replay {
		g.app.Log.Info("replaying the scheduled run a dry run held back")
		go g.scheduled()
	}
}

// execute runs one digest under the identity begin gave it. Every run runs a
// copy of the shared Runner, scheduled ones included, so nothing a run sets
// on it can leak into the next. The copy is told the instant the gate
// started it (so the finished report's ID is the one already announced) and
// logs through a logger tagged with the run's ID and kind.
//
// A manual run is titled so it cannot be mistaken for the hourly digest, in
// the history and on the phone. A dry run also drops the sinks and stays out
// of the metrics: nothing was delivered, and last_success_timestamp is what
// alerting reads.
func (g *runGate) execute(cur web.RunStatus, trigger string) {
	runner := *g.app.Runner // Runner holds no state of its own; a copy is a safe variant
	started := cur.StartedAt
	runner.Now = func() time.Time { return started }
	runner.Log = g.app.Log.With("run", cur.ID, "kind", string(cur.Kind))
	if trigger == "manual" {
		switch {
		case cur.Dry:
			runner.Title += " (manual, dry)"
			runner.Sinks = nil
		default:
			runner.Title += " (manual)"
		}
	}

	report := runner.Run(context.Background())

	success := false
	if !cur.Dry {
		success = g.app.Record(report, time.Since(started))
	}
	if _, err := g.app.Store.Append(report, cur.Kind); err != nil {
		runner.Log.Warn("history not persisted", "error", err)
	}
	runner.Log.Info("digest run finished", "trigger", trigger, "dry", cur.Dry,
		"verdict", report.Verdict.String(), "findings", len(report.Findings),
		"success", success, "duration", time.Since(started).Round(time.Millisecond).String())
}
