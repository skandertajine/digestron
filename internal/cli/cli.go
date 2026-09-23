// Package cli wires configuration, modules and the runner behind the
// digestron subcommands. Exit codes: 0 success (including a degraded run
// where the LLM failed), 1 operational failure (all sources down or a sink
// failed), 2 usage or configuration error.
package cli

import (
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/skandertajine/digestron/internal/logring"
	"github.com/skandertajine/digestron/internal/redact"
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

// Ring bounds: about 25 lines per run with the debug lines, so this is days of
// history, and small enough to fit a 128Mi pod next to everything else.
const (
	logMaxRecords = 4000
	logMaxBytes   = 2 << 20
)

// newLogger builds the process logger. stderr keeps printing exactly what the
// configured level asks for, with configured secrets replaced: an upstream
// that echoes a token into an error must not put it in `kubectl logs` any more
// than in the UI. The ring behind it keeps every level for the web UI, and the
// returned LevelVar changes what stderr prints at runtime.
func newLogger(level string, scrub *redact.Scrubber) (*slog.Logger, *logring.Ring, *slog.LevelVar) {
	return newLoggerTo(os.Stderr, level, scrub)
}

func newLoggerTo(w io.Writer, level string, scrub *redact.Scrubber) (*slog.Logger, *logring.Ring, *slog.LevelVar) {
	lv := new(slog.LevelVar)
	l, ok := logring.ParseLevel(level)
	if !ok {
		l = slog.LevelInfo
	}
	lv.Set(l)
	ring := logring.New(logMaxRecords, logMaxBytes, scrub.Scrub)
	// The child handler prints whatever it is handed; the fan-out decides.
	out := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug, ReplaceAttr: scrub.ReplaceAttr})
	return slog.New(ring.Handler(out, lv)), ring, lv
}
