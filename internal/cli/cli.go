// Package cli wires configuration, modules and the runner behind the
// digestron subcommands. Exit codes: 0 success (including a degraded run
// where the LLM failed), 1 operational failure (all sources down or a sink
// failed), 2 usage or configuration error.
package cli

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/skandertajine/digestron/internal/version"
)

func Main(args []string) int {
	if len(args) < 1 {
		usage()
		return 2
	}
	switch args[0] {
	case "run":
		return runCmd(args[1:])
	case "check":
		return checkCmd(args[1:])
	case "serve":
		return serveCmd(args[1:])
	case "version":
		fmt.Println(version.String())
		return 0
	default:
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: digestron <command> [flags]

commands:
  run      collect, summarize and deliver one digest, then exit
  serve    run on a cron schedule, with /metrics and the web UI
  check    probe every configured module and report connectivity
  version  print build information
`)
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}
