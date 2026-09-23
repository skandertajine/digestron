package digest

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"time"
)

// RunSource pairs a source with its per-module timeout.
type RunSource struct {
	Source
	Timeout time.Duration
}

// RunSink pairs a sink with its per-module timeout.
type RunSink struct {
	Sink
	Timeout time.Duration
}

// Runner executes one digest cycle: collect from every source in parallel,
// aggregate and score deterministically, summarize with the LLM (optional —
// the digest degrades to raw counters when it fails), then deliver to every
// sink in parallel. It records outcomes in the Report; translating them to
// metrics and exit codes is the caller's business.
type Runner struct {
	Title      string
	Window     time.Duration
	Language   string
	Context    string
	MaxChars   int
	LLMTimeout time.Duration
	Sources    []RunSource
	Sinks      []RunSink
	LLM        LLM
	Log        *slog.Logger

	// Scrub, when set, runs over every error text and the LLM summary before
	// it enters the report. An upstream that rejects a request often quotes it
	// back, and the report goes to the sinks, to history.json and to the UI:
	// a secret must not get further than the runner.
	Scrub func(string) string

	// Now is the clock for the run's window and its GeneratedAt; nil means
	// time.Now. A caller that wants to know the run's ID before it starts
	// (so it can tag the log lines with it) fixes the instant here.
	Now func() time.Time
}

func (r *Runner) scrub(s string) string {
	if r.Scrub == nil {
		return s
	}
	return r.Scrub(s)
}

func (r *Runner) Run(ctx context.Context) Report {
	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	report := Report{
		Title:       r.Title,
		Window:      Window{From: now.Add(-r.Window), To: now},
		GeneratedAt: now,
	}
	r.Log.Debug("run started", "window_from", report.Window.From, "window_to", report.Window.To,
		"sources", len(r.Sources), "sinks", len(r.Sinks), "llm", r.LLM != nil)

	report.Findings, report.Stats = r.collect(ctx, report.Window)
	sortFindings(report.Findings)
	report.Verdict = Verdict(report.Findings)

	r.summarize(ctx, &report)

	report.Sinks = r.deliver(ctx, report)
	return report
}

func (r *Runner) collect(ctx context.Context, w Window) ([]Finding, []SourceStats) {
	type result struct {
		stats    SourceStats
		findings []Finding
	}
	results := make([]result, len(r.Sources))

	var wg sync.WaitGroup
	for i, src := range r.Sources {
		wg.Add(1)
		go func(i int, src RunSource) {
			defer wg.Done()
			cctx := ctx
			if src.Timeout > 0 {
				var cancel context.CancelFunc
				cctx, cancel = context.WithTimeout(ctx, src.Timeout)
				defer cancel()
			}
			r.Log.Debug("collecting", "source", src.Name(), "timeout", src.Timeout.String())
			start := time.Now()
			findings, err := src.Collect(cctx, w)
			stats := SourceStats{Source: src.Name(), Findings: len(findings), Duration: time.Since(start)}
			r.Log.Debug("source done", "source", src.Name(), "findings", len(findings),
				"ms", stats.Duration.Milliseconds(), "failed", err != nil)
			if err != nil {
				// A source may fail and still hand back findings (some of its
				// queries worked). Keep them: half a digest beats none, as
				// long as the error travels with them.
				stats.Err = r.scrub(err.Error())
				r.Log.Error("source failed", "source", src.Name(), "findings", len(findings), "error", err)
			}
			results[i] = result{stats: stats, findings: findings}
		}(i, src)
	}
	wg.Wait()

	var findings []Finding
	stats := make([]SourceStats, 0, len(results))
	for _, res := range results {
		findings = append(findings, res.findings...)
		stats = append(stats, res.stats)
	}
	return findings, stats
}

func (r *Runner) summarize(ctx context.Context, report *Report) {
	if r.LLM == nil {
		return
	}
	req, err := BuildRequest(*report, r.Language, r.Context)
	if err != nil {
		report.LLM = LLMStats{Provider: r.LLM.Name(), Err: r.scrub(err.Error())}
		return
	}

	lctx := ctx
	if r.LLMTimeout > 0 {
		var cancel context.CancelFunc
		lctx, cancel = context.WithTimeout(ctx, r.LLMTimeout)
		defer cancel()
	}
	// Sizes, never content: the prompt and the raw reply are not log material.
	r.Log.Debug("llm request", "provider", r.LLM.Name(), "system_bytes", len(req.System),
		"user_bytes", len(req.User), "timeout", r.LLMTimeout.String())
	start := time.Now()
	resp, err := r.LLM.Complete(lctx, req)
	r.Log.Debug("llm response", "provider", r.LLM.Name(), "model", resp.Model,
		"prompt_tokens", resp.PromptTokens, "completion_tokens", resp.CompletionTokens,
		"ms", time.Since(start).Milliseconds(), "reply_bytes", len(resp.Text), "failed", err != nil)
	report.LLM = LLMStats{
		Provider:         r.LLM.Name(),
		Model:            resp.Model,
		PromptTokens:     resp.PromptTokens,
		CompletionTokens: resp.CompletionTokens,
		Duration:         time.Since(start),
	}
	if err != nil {
		report.LLM.Err = r.scrub(err.Error())
		r.Log.Warn("llm failed, sending raw digest", "provider", r.LLM.Name(), "error", err)
		return
	}
	report.Summary = r.scrub(PostProcess(resp.Text, r.MaxChars))
}

func (r *Runner) deliver(ctx context.Context, report Report) []SinkStats {
	stats := make([]SinkStats, len(r.Sinks))
	var wg sync.WaitGroup
	for i, sk := range r.Sinks {
		wg.Add(1)
		go func(i int, sk RunSink) {
			defer wg.Done()
			sctx := ctx
			if sk.Timeout > 0 {
				var cancel context.CancelFunc
				sctx, cancel = context.WithTimeout(ctx, sk.Timeout)
				defer cancel()
			}
			r.Log.Debug("delivering", "sink", sk.Name(), "timeout", sk.Timeout.String())
			start := time.Now()
			err := sk.Send(sctx, report)
			stats[i] = SinkStats{Sink: sk.Name(), Duration: time.Since(start)}
			r.Log.Debug("sink done", "sink", sk.Name(), "ms", stats[i].Duration.Milliseconds(), "failed", err != nil)
			if err != nil {
				stats[i].Err = r.scrub(err.Error())
				r.Log.Error("sink failed", "sink", sk.Name(), "error", err)
			}
		}(i, sk)
	}
	wg.Wait()
	return stats
}

// sortFindings orders by severity (critical first), then source, then title,
// so the same input always renders the same report.
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity != fs[j].Severity {
			return fs[i].Severity > fs[j].Severity
		}
		if fs[i].Source != fs[j].Source {
			return fs[i].Source < fs[j].Source
		}
		return fs[i].Title < fs[j].Title
	})
}
