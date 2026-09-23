// Package store keeps the run history the web UI reads: every finished
// Report, capped at a configurable count, optionally persisted to a single
// JSON file. A plain file keeps digestron dependency-free and portable; at a
// few hundred reports the volume never justifies a database.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/skandertajine/digestron/internal/digest"
)

// Kind says why a run happened, which decides how long it is kept and how it
// is read.
type Kind string

const (
	// KindSchedule is a cron tick: the hourly digest.
	KindSchedule Kind = "schedule"
	// KindManual is the button pressed with the sinks on: a real digest that
	// was delivered and recorded in the metrics.
	KindManual Kind = "manual"
	// KindTest is a dry run: sources and LLM, no sinks, no metrics.
	KindTest Kind = "test"
)

type Entry struct {
	ID string `json:"id"`
	// Kind is empty in history files written before it existed; Open reads
	// those as schedule, which is what every run then was.
	Kind   Kind          `json:"kind,omitempty"`
	Report digest.Report `json:"report"`
}

// IDFor is the ID an entry gets for a report generated at t. It is exported
// so a run can learn its ID before it starts, and tag its log lines with it.
func IDFor(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// maxTestEntries bounds how many test runs are kept, whatever keep is.
const maxTestEntries = 50

type Store struct {
	mu      sync.Mutex
	path    string // empty = in-memory only
	keep    int
	entries []Entry // oldest first
}

// Open loads the history file when it exists. A corrupt file is an error —
// the caller decides whether to continue with an in-memory store.
func Open(path string, keep int) (*Store, error) {
	if keep <= 0 {
		keep = 200
	}
	s := &Store{path: path, keep: keep}
	if path == "" {
		return s, nil
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-provided history location
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	if err := json.Unmarshal(raw, &s.entries); err != nil {
		return nil, fmt.Errorf("store: corrupt history file %s: %w", path, err)
	}
	for i := range s.entries {
		if s.entries[i].Kind == "" {
			s.entries[i].Kind = KindSchedule
		}
	}
	s.truncate()
	return s, nil
}

// Append records a finished report and persists when a path is configured.
func (s *Store) Append(r digest.Report, kind Kind) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if kind == "" {
		kind = KindSchedule
	}
	e := Entry{ID: IDFor(r.GeneratedAt), Kind: kind, Report: r}
	s.entries = append(s.entries, e)
	s.truncate()

	if s.path == "" {
		return e, nil
	}
	return e, s.persist()
}

// List returns entries newest first.
func (s *Store) List() []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Entry, len(s.entries))
	for i, e := range s.entries {
		out[len(s.entries)-1-i] = e
	}
	return out
}

func (s *Store) Get(id string) (Entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.entries {
		if e.ID == id {
			return e, true
		}
	}
	return Entry{}, false
}

// truncate keeps the last keep real digests (schedule and manual) and,
// separately, the last few test runs. A busy afternoon of dry runs must not
// be able to push the hourly digests out of the history.
func (s *Store) truncate() {
	keepTest := min(max(s.keep/4, 1), maxTestEntries)
	var digests, test int
	for _, e := range s.entries {
		if e.Kind == KindTest {
			test++
		} else {
			digests++
		}
	}
	dropReal, dropTest := max(digests-s.keep, 0), max(test-keepTest, 0)
	if dropReal == 0 && dropTest == 0 {
		return
	}
	kept := s.entries[:0:0]
	for _, e := range s.entries { // oldest first: drop from the front of each kind
		switch {
		case e.Kind == KindTest && dropTest > 0:
			dropTest--
		case e.Kind != KindTest && dropReal > 0:
			dropReal--
		default:
			kept = append(kept, e)
		}
	}
	s.entries = kept
}

// persist writes atomically: temp file in the same directory, then rename.
func (s *Store) persist() error {
	raw, err := json.Marshal(s.entries)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".digestron-history-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}
