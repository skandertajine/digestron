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

	scheduler, err := gocron.NewScheduler(gocron.WithLocation(loc))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	_, err = scheduler.NewJob(
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
	})

	server := &http.Server{
		Addr:              app.Cfg.Metrics.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	scheduler.Start()
	if app.Cfg.Schedule.RunOnStart {
		go gate.scheduled()
	}

	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServe() }()
	app.Log.Info("serving", "listen", app.Cfg.Metrics.Listen, "cron", app.Cfg.Schedule.Cron, "timezone", loc.String())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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
