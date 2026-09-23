package cli

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-co-op/gocron/v2"
	dto "github.com/prometheus/client_model/go"

	"github.com/skandertajine/digestron/internal/digest"
	"github.com/skandertajine/digestron/internal/version"
	"github.com/skandertajine/digestron/internal/web"
)

// checkModuleTimeout bounds one module's probe inside a check-all: sources
// and sinks answer in milliseconds when they answer at all, and a hung one
// must not hold up the rest.
const checkModuleTimeout = 10 * time.Second

// memSampleInterval is how often the background sampler refreshes the
// process's heap size. GET /api/status has no login, so it must never do
// work proportional to it being called often; runtime.ReadMemStats briefly
// stops every goroutine in the process, which a request handler must never
// trigger on demand.
const memSampleInterval = 5 * time.Second

// memSampler caches runtime.MemStats.Alloc, refreshed on a timer in the
// background rather than read synchronously per request.
type memSampler struct{ alloc atomic.Uint64 }

// newMemSampler takes one reading immediately and then keeps it current on
// every tick of interval until ctx is done.
func newMemSampler(ctx context.Context, interval time.Duration) *memSampler {
	m := &memSampler{}
	m.sample()
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.sample()
			}
		}
	}()
	return m
}

func (m *memSampler) sample() {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	m.alloc.Store(mem.Alloc)
}

// ops answers the header strip and the check-all button. It holds nothing a
// run needs, only what describes the process around the runs.
type ops struct {
	app       *App
	startedAt time.Time
	job       gocron.Job // nil before the scheduler names it, or with no schedule
	cron      string
	timezone  string
	mem       *memSampler
}

// Status implements web.Ops.
func (o ops) Status() web.Status {
	var next time.Time
	if o.job != nil {
		if n, err := o.job.NextRun(); err == nil {
			next = n
		}
	}
	records, bytes := 0, 0
	if o.app.Logs != nil {
		records, bytes = o.app.Logs.Stats()
	}
	var alloc uint64
	if o.mem != nil {
		alloc = o.mem.alloc.Load()
	}
	return web.Status{
		Version: version.Version, Commit: version.Commit, GoVersion: runtime.Version(),
		StartedAt: o.startedAt, Cron: o.cron, Timezone: o.timezone, NextRun: timePtr(next),
		LastRun:       timePtr(gaugeTime(o.app.Metrics.LastRunTimestamp)),
		LastSuccess:   timePtr(gaugeTime(o.app.Metrics.LastSuccessTimestamp)),
		LogRecords:    records,
		LogBytes:      bytes,
		Goroutines:    runtime.NumGoroutine(),
		MemAllocBytes: alloc,
	}
}

// timePtr turns the zero Time into a nil pointer, so encoding/json's
// omitempty — a no-op on a plain time.Time field, which always marshals to a
// non-empty string even at its zero value — actually omits it. The page
// reads a missing field as "never happened", which is the honest answer for
// a fresh process with no completed run yet.
func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// gaugeTime reads a Prometheus gauge the way the scrape would, and turns the
// Unix seconds digestron already publishes as metrics back into a time.Time
// for the page — one definition of "last success", the one already alerted
// on, instead of a second one computed from the history file.
func gaugeTime(g interface{ Write(*dto.Metric) error }) time.Time {
	var m dto.Metric
	if err := g.Write(&m); err != nil {
		return time.Time{}
	}
	v := m.GetGauge().GetValue()
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(int64(v), 0).UTC()
}

// Check implements web.Ops: every configured module in parallel, or one by
// name. A module with no Checker (the noop LLM, a webhook sink: any request
// to it may act, so it is not probed) answers Skipped rather than silently
// missing from the list.
//
// The web layer serializes calls to this (one check-all in flight at a
// time): probing every backend on request is already the point of the
// button, but nothing should be able to make the process re-probe faster
// than an operator can click.
func (o ops) Check(ctx context.Context, module string) []web.CheckResult {
	type task struct {
		kind string
		name string
		mod  any
	}
	var tasks []task
	for _, s := range o.app.Sources {
		tasks = append(tasks, task{"source", s.Name(), s.Source})
	}
	if o.app.LLM != nil {
		tasks = append(tasks, task{"llm", o.app.LLM.Name(), o.app.LLM})
	}
	for _, s := range o.app.Sinks {
		tasks = append(tasks, task{"sink", s.Name(), s.Sink})
	}
	if module != "" {
		var only []task
		for _, t := range tasks {
			if t.name == module {
				only = append(only, t)
			}
		}
		tasks = only
	}

	results := make([]web.CheckResult, len(tasks))
	var wg sync.WaitGroup
	for i, t := range tasks {
		wg.Add(1)
		go func(i int, t task) {
			defer wg.Done()
			results[i] = probe(ctx, t.kind, t.name, t.mod, o.app.Scrub.Scrub)
		}(i, t)
	}
	wg.Wait()
	return results
}

func probe(ctx context.Context, kind, name string, mod any, scrub func(string) string) web.CheckResult {
	r := web.CheckResult{Kind: kind, Name: name}
	c, ok := mod.(digest.Checker)
	if !ok {
		r.Skipped = true
		return r
	}
	cctx, cancel := context.WithTimeout(ctx, checkModuleTimeout)
	defer cancel()
	start := time.Now()
	err := c.Check(cctx)
	r.Millis = time.Since(start).Milliseconds()
	if err != nil {
		r.Err = scrub(err.Error())
		return r
	}
	r.OK = true
	return r
}
