package cli

import (
	"fmt"
	"log/slog"

	"github.com/skandertajine/digestron/internal/logring"
)

// logSource hands the process's log ring and stderr level to the web UI.
type logSource struct {
	ring *logring.Ring
	lv   *slog.LevelVar
}

func (l logSource) Logs(q logring.Query) logring.Page { return l.ring.Snapshot(q) }

func (l logSource) Level() string { return logring.LevelName(l.lv.Level()) }

// SetLevel changes what stderr prints for the life of this process. It does
// not touch the ring, which keeps every level regardless, and it is not
// persisted: a restart returns to the configured level.
func (l logSource) SetLevel(name string) error {
	lvl, ok := logring.ParseLevel(name)
	if !ok {
		return fmt.Errorf("unknown level %q, want debug, info, warn or error", name)
	}
	l.lv.Set(lvl)
	return nil
}
