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
	missed bool               // a scheduler tick landed while a dry run held the gate
	cancel context.CancelFunc // stops the run in flight; nil when idle
}

func newRunGate(app *App) *runGate { return &runGate{app: app} }

// Status implements web.Trigger.
func (g *runGate) Status() web.RunStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.state
}

// Cancel implements web.Trigger: stop the run in flight. The run still
// finishes its own cleanup (it notices the cancelled context between stages,
// see digest.Runner.Run) and is still recorded in the history, marked as
// cancelled; it is only never counted as a success, or last_success_timestamp
// would move for a digest that was told to stop.
func (g *runGate) Cancel() error {
	g.mu.Lock()
	if !g.state.Running {
		g.mu.Unlock()
		return web.ErrNotRunning
	}
	cancel := g.cancel
	g.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return nil
}

// Start implements web.Trigger: a manual run in the background, or a refusal
// because one is in flight. It never blocks the HTTP handler.
func (g *runGate) Start(dry bool) error {
	kind := store.KindManual
	if dry {
		kind = store.KindTest
	}
	ok, cur, ctx := g.begin(kind, dry, false)
	if !ok {
		return web.ErrRunInProgress
	}
	go func() {
		var cancelled bool
		defer func() { g.end(cancelled) }()
		cancelled = g.execute(ctx, cur, "manual")
	}()
	return nil
}

// scheduled is the scheduler's task. A tick that lands during a full manual
// run is skipped and logged, not queued: that run delivers the window the
// tick would have covered. A tick that lands during a dry run is different,
// because a dry run delivers nothing: the tick is remembered and replayed
// the moment the dry run lets go, or that hour would never reach the phone.
func (g *runGate) scheduled() {
	ok, cur, ctx := g.begin(store.KindSchedule, false, true)
	if !ok {
		g.app.Log.Warn("scheduled run held back, another run is in progress",
			"running", cur.ID, "running_kind", string(cur.Kind), "since", cur.StartedAt,
			"replayed_after_dry_run", cur.Dry)
		return
	}
	var cancelled bool
	defer func() { g.end(cancelled) }()
	cancelled = g.execute(ctx, cur, "schedule")
}

// begin takes the gate. It returns the identity of the run it started and the
// context to run it under, or, when the gate is taken already, the status of
// what holds it, and records a scheduler tick (tick=true) that landed while
// something else held the gate — dry or not, since a full run can now be
// stopped mid-flight and deliver nothing too; end() decides whether that
// actually calls for a replay once it knows how the run in question ended.
func (g *runGate) begin(kind store.Kind, dry, tick bool) (bool, web.RunStatus, context.Context) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state.Running {
		if tick {
			g.missed = true
		}
		return false, g.state, nil
	}
	now := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	g.cancel = cancel
	g.state = web.RunStatus{Running: true, Dry: dry, StartedAt: now, ID: store.IDFor(now), Kind: kind}
	return true, g.state, ctx
}

func (g *runGate) setPhase(phase string) {
	g.mu.Lock()
	g.state.Phase = phase
	g.mu.Unlock()
}

// end releases the gate. cancelled says whether the run that just finished
// was stopped before it delivered (see execute): a tick held back during that
// run is replayed exactly when the run it waited on — dry or cancelled —
// never got to attempt delivery for its window, and never otherwise: a full
// run that completed, even with failures, did attempt delivery, and
// replaying on top of it would risk a duplicate digest.
func (g *runGate) end(cancelled bool) {
	g.mu.Lock()
	replay := g.missed && (g.state.Dry || cancelled)
	g.missed = false
	cancel := g.cancel
	g.cancel = nil
	g.state = web.RunStatus{}
	g.mu.Unlock()
	if cancel != nil {
		cancel() // release the context's resources even when the run finished on its own
	}
	if replay {
		g.app.Log.Info("replaying the scheduled run a dry or cancelled run held back")
		go g.scheduled()
	}
}

// execute runs one digest under the identity begin gave it, on the context
// begin created (so Cancel can stop it). Every run runs a copy of the shared
// Runner, scheduled ones included, so nothing a run sets on it can leak into
// the next. The copy is told the instant the gate started it (so the
// finished report's ID is the one already announced), logs through a logger
// tagged with the run's ID and kind, and mirrors its phase into the status
// the page polls.
//
// A manual run is titled so it cannot be mistaken for the hourly digest, in
// the history and on the phone. A dry run also drops the sinks and stays out
// of the metrics: nothing was delivered, and last_success_timestamp is what
// alerting reads.
//
// execute reports whether it was cancelled, for end() to
// decide about a held-back tick. Whether the run was cancelled comes from the
// Report itself (report.Cancelled, set by Runner.Run at the exact point it
// notices and stops), never from a separate, later read of ctx.Err(): Cancel
// can still be called for a little while after execute reads report — the
// gate only releases in end(), after this function returns — and a second,
// unsynchronized check at that point could catch a Cancel that arrived after
// the run had already fully delivered, and wrongly relabel a delivered
// digest as cancelled.
func (g *runGate) execute(ctx context.Context, cur web.RunStatus, trigger string) bool {
	runner := *g.app.Runner // Runner holds no state of its own; a copy is a safe variant
	started := cur.StartedAt
	runner.Now = func() time.Time { return started }
	runner.Log = g.app.Log.With("run", cur.ID, "kind", string(cur.Kind))
	runner.OnPhase = g.setPhase
	if trigger == "manual" {
		switch {
		case cur.Dry:
			runner.Title += " (manual, dry)"
			runner.Sinks = nil
		default:
			runner.Title += " (manual)"
		}
	}

	report := runner.Run(ctx)
	if report.Cancelled {
		report.Title += " (cancelled)"
	}

	// Every non-dry run is recorded, cancelled or not: LastRunTimestamp and
	// whatever module stats it gathered before stopping are real. Record
	// itself refuses to call a cancelled run a success.
	success := false
	if !cur.Dry {
		success = g.app.Record(report, time.Since(started))
	}
	if _, err := g.app.Store.Append(report, cur.Kind); err != nil {
		runner.Log.Warn("history not persisted", "error", err)
	}
	runner.Log.Info("digest run finished", "trigger", trigger, "dry", cur.Dry, "cancelled", report.Cancelled,
		"verdict", report.Verdict.String(), "findings", len(report.Findings),
		"success", success, "duration", time.Since(started).Round(time.Millisecond).String())
	return report.Cancelled
}
