package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/skandertajine/digestron/internal/web"
)

// securityHeaders wraps every response, JSON and HTML alike, with headers a
// browser enforces and a server-side check cannot: the page is single-file,
// inline styles and scripts only, no external resource of any kind, so
// default-src 'none' plus explicit allows for exactly those two categories
// costs nothing and blocks anything injected from elsewhere (an <iframe>
// embedding the page, a <script src> pointed off-host, a fetch to a foreign
// origin).
func securityHeaders(h http.Handler) http.Handler {
	const csp = "default-src 'none'; connect-src 'self'; style-src 'unsafe-inline'; " +
		"script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		h.ServeHTTP(w, r)
	})
}

func serveCmd(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/digestron/config.yaml", "path to the configuration file")
	noLLM := fs.Bool("no-llm", false, "skip the LLM summary, deliver raw counters")
	_ = fs.Parse(args)

	app, err := Build(*cfgPath, *noLLM)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	if app.Cfg.Schedule.Cron == "" {
		fmt.Fprintln(os.Stderr, "error: schedule.cron is required in serve mode")
		return 2
	}

	loc := time.UTC
	if tz := app.Cfg.Schedule.Timezone; tz != "" {
		loc, _ = time.LoadLocation(tz) // validated at config load
	}

	gate := newRunGate(app)
	startedAt := time.Now()

	// Created early so the memory sampler's background goroutine (and
	// anything else in serve mode that runs on a ticker) shares the
	// process's own shutdown signal instead of running forever.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	scheduler, err := gocron.NewScheduler(gocron.WithLocation(loc))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	job, err := scheduler.NewJob(
		gocron.CronJob(app.Cfg.Schedule.Cron, false),
		gocron.NewTask(gate.scheduled),
		// Never two overlapping runs: a slow LLM must not stack digests. The
		// gate enforces it across manual runs too; this keeps gocron from
		// even trying.
		gocron.WithSingletonMode(gocron.LimitModeReschedule),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid schedule.cron %q: %v\n", app.Cfg.Schedule.Cron, err)
		return 2
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(app.Metrics.Registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	web.Register(mux, web.Deps{
		Store:   app.Store,
		Trigger: gate,
		Logs:    logSource{ring: app.Logs, lv: app.LogLevel},
		Ops:     ops{app: app, startedAt: startedAt, job: job, cron: app.Cfg.Schedule.Cron, timezone: loc.String(), mem: newMemSampler(ctx, memSampleInterval)},
	})

	server := &http.Server{
		Addr:              app.Cfg.Metrics.Listen,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	scheduler.Start()
	if app.Cfg.Schedule.RunOnStart {
		go gate.scheduled()
	}

	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServe() }()
	app.Log.Info("serving", "listen", app.Cfg.Metrics.Listen, "cron", app.Cfg.Schedule.Cron, "timezone", loc.String())

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
	case <-ctx.Done():
	}

	app.Log.Info("shutting down")
	_ = scheduler.Shutdown()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
	return 0
}
