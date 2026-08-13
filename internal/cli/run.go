package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/skandertajine/digestron/internal/digest"
)

func runCmd(args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/digestron/config.yaml", "path to the configuration file")
	noLLM := fs.Bool("no-llm", false, "skip the LLM summary, deliver raw counters")
	_ = fs.Parse(args)

	app, err := Build(*cfgPath, *noLLM)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	start := time.Now()
	report := app.Runner.Run(ctx)
	success := app.Record(report, time.Since(start))
	if _, err := app.Store.Append(report); err != nil {
		app.Log.Warn("history not persisted", "error", err)
	}

	fmt.Print(digest.RenderText(report))
	if !success {
		return 1
	}
	return 0
}
