package cli

import (
	"log/slog"
	"runtime"
	"time"

	"github.com/skandertajine/digestron/internal/config"
	"github.com/skandertajine/digestron/internal/digest"
	"github.com/skandertajine/digestron/internal/llm"
	"github.com/skandertajine/digestron/internal/logring"
	"github.com/skandertajine/digestron/internal/metrics"
	"github.com/skandertajine/digestron/internal/redact"
	"github.com/skandertajine/digestron/internal/sink"
	"github.com/skandertajine/digestron/internal/source"
	"github.com/skandertajine/digestron/internal/store"
	"github.com/skandertajine/digestron/internal/version"
)

const defaultModuleTimeout = 30 * time.Second

// App is everything a subcommand needs, built once from the configuration.
type App struct {
	Cfg      *config.Config
	Log      *slog.Logger
	Logs     *logring.Ring    // every log line of this process, for the web UI
	LogLevel *slog.LevelVar   // what stderr prints; changeable at runtime
	Scrub    *redact.Scrubber // hides configured secrets from text that leaves the process
	Metrics  *metrics.Metrics
	Store    *store.Store
	Sources  []digest.RunSource
	Sinks    []digest.RunSink
	LLM      digest.LLM // unwrapped, for check probes; nil with --no-llm
	Runner   *digest.Runner
}

// Build loads the configuration and instantiates every module. Any invalid
// module fails here, with its name — never silently at 3am.
func Build(cfgPath string, noLLM bool) (*App, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, err
	}
	scrub := redact.FromConfig(cfg)
	log, ring, level := newLogger(cfg.Log.Level, scrub)

	m := metrics.New()
	m.SetBuildInfo(version.Version, version.Commit, runtime.Version())

	app := &App{Cfg: cfg, Log: log, Logs: ring, LogLevel: level, Scrub: scrub, Metrics: m}

	for _, mc := range cfg.Sources {
		s, err := source.Build(mc.Type, mc.Name, mc.Settings)
		if err != nil {
			return nil, err
		}
		app.Sources = append(app.Sources, digest.RunSource{Source: s, Timeout: timeoutOr(mc.Timeout)})
	}
	for _, mc := range cfg.Sinks {
		s, err := sink.Build(mc.Type, mc.Name, mc.Settings)
		if err != nil {
			return nil, err
		}
		app.Sinks = append(app.Sinks, digest.RunSink{Sink: s, Timeout: timeoutOr(mc.Timeout)})
	}
	if !noLLM {
		client, err := llm.Build(cfg.LLM.Type, cfg.LLM.Settings)
		if err != nil {
			return nil, err
		}
		app.LLM = client
	}

	st, err := store.Open(cfg.History.Path, cfg.History.Keep)
	if err != nil {
		log.Warn("history unavailable, keeping runs in memory only", "error", err)
		st, _ = store.Open("", cfg.History.Keep)
	}
	app.Store = st

	var runnerLLM digest.LLM
	if app.LLM != nil {
		runnerLLM = llm.WithRetry(app.LLM, cfg.LLM.Retries)
	}
	app.Runner = &digest.Runner{
		Title:      cfg.Digest.Title,
		Window:     cfg.Digest.Window,
		Language:   cfg.Digest.Language,
		Context:    cfg.Digest.Context,
		MaxChars:   cfg.LLM.MaxChars,
		LLMTimeout: cfg.LLM.Timeout,
		Sources:    app.Sources,
		Sinks:      app.Sinks,
		LLM:        runnerLLM,
		Log:        log,
		Scrub:      scrub.Scrub,
	}
	return app, nil
}

func timeoutOr(d time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return defaultModuleTimeout
}

// Record translates a finished report into metrics. Success means: at least
// one source produced findings and every sink delivered — a failed LLM only
// degrades.
//
// A source that lost some queries but still delivered findings counts as a
// success here, recorded under status="partial". The run it produced is a
// real digest and the operator already has it on their phone; exiting
// non-zero would only make Kubernetes rerun the CronJob (backoffLimit 1,
// restartPolicy Never) and push the same window a second time.
func (a *App) Record(r digest.Report, wall time.Duration) (success bool) {
	a.Metrics.LastRunTimestamp.Set(float64(r.GeneratedAt.Unix()))
	a.Metrics.RunDuration.Observe(wall.Seconds())

	sourcesFailed := 0
	for _, st := range r.Stats {
		a.Metrics.ModuleDuration.WithLabelValues(st.Source).Observe(st.Duration.Seconds())
		status := "success"
		switch {
		case st.Partial():
			// Visible in metrics — alert on it if you want — but not a
			// failed run: the digest went out with the counts that survived.
			status = "partial"
		case st.Err != "":
			status = "error"
			sourcesFailed++
		}
		a.Metrics.ModuleRunsTotal.WithLabelValues(st.Source, status).Inc()
	}
	for _, f := range r.Findings {
		a.Metrics.FindingsTotal.WithLabelValues(f.Source, f.Severity.String()).Add(float64(f.Count))
	}
	if r.LLM.Model != "" {
		a.Metrics.LLMTokensTotal.WithLabelValues(r.LLM.Model, "prompt").Add(float64(r.LLM.PromptTokens))
		a.Metrics.LLMTokensTotal.WithLabelValues(r.LLM.Model, "completion").Add(float64(r.LLM.CompletionTokens))
		a.Metrics.LLMDuration.Observe(r.LLM.Duration.Seconds())
	}

	sinksFailed := 0
	for _, st := range r.Sinks {
		status := "success"
		if st.Err != "" {
			status = "error"
			sinksFailed++
		}
		a.Metrics.NotificationsTotal.WithLabelValues(st.Sink, status).Inc()
	}

	success = sinksFailed == 0 && (len(r.Stats) == 0 || sourcesFailed < len(r.Stats))
	if success {
		a.Metrics.RunsTotal.WithLabelValues("success").Inc()
		a.Metrics.LastSuccessTimestamp.Set(float64(time.Now().Unix()))
	} else {
		a.Metrics.RunsTotal.WithLabelValues("failure").Inc()
	}
	return success
}
