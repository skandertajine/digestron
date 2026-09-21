package cli

import (
	"context"
	"sync"
	"time"

	"github.com/skandertajine/digestron/internal/web"
)

// runGate serializes every digest run of a serve process, whether the
// scheduler fired it or someone pressed the button. Two runs at once would
// queue two prompts on the same LLM, where the hourly run already spends
// most of its budget waiting, and could push the same window to a phone
// twice. gocron's singleton mode only covers the runs it starts itself, so
// the gate is the one lock both paths go through.
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
	if ok, _ := g.begin(dry, false); !ok {
		return web.ErrRunInProgress
	}
	go func() {
		defer g.end()
		g.execute(dry, "manual")
	}()
	return nil
}

// scheduled is the scheduler's task. A tick that lands during a full manual
// run is skipped and logged, not queued: that run delivers the window the
// tick would have covered. A tick that lands during a dry run is different,
// because a dry run delivers nothing: the tick is remembered and replayed
// the moment the dry run lets go, or that hour would never reach the phone.
func (g *runGate) scheduled() {
	ok, inflight := g.begin(false, true)
	if !ok {
		g.app.Log.Warn("scheduled run held back, another run is in progress",
			"since", inflight.StartedAt, "dry", inflight.Dry, "replayed_after_dry_run", inflight.Dry)
		return
	}
	defer g.end()
	g.execute(false, "schedule")
}

// begin takes the gate. When it is taken already it reports what holds it,
// and records a scheduler tick (tick=true) that a dry run made miss.
func (g *runGate) begin(dry, tick bool) (bool, web.RunStatus) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state.Running {
		if tick && g.state.Dry {
			g.missed = true
		}
		return false, g.state
	}
	g.state = web.RunStatus{Running: true, Dry: dry, StartedAt: time.Now()}
	return true, web.RunStatus{}
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

// execute runs one digest. A manual run is titled so it cannot be mistaken
// for the hourly digest, in the history and on the phone. A dry run also
// drops the sinks and stays out of the metrics: nothing was delivered, and
// last_success_timestamp is what alerting reads.
func (g *runGate) execute(dry bool, trigger string) {
	start := time.Now()
	runner := g.app.Runner
	if trigger == "manual" {
		manual := *runner // Runner holds no state of its own; a copy is a safe variant
		switch {
		case dry:
			manual.Title += " (manual, dry)"
			manual.Sinks = nil
		default:
			manual.Title += " (manual)"
		}
		runner = &manual
	}
	report := runner.Run(context.Background())

	success := false
	if !dry {
		success = g.app.Record(report, time.Since(start))
	}
	if _, err := g.app.Store.Append(report); err != nil {
		g.app.Log.Warn("history not persisted", "error", err)
	}
	g.app.Log.Info("digest run finished", "trigger", trigger, "dry", dry,
		"verdict", report.Verdict.String(), "findings", len(report.Findings),
		"success", success, "duration", time.Since(start).Round(time.Millisecond).String())
}
