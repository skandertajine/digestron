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

type Entry struct {
	ID     string        `json:"id"`
	Report digest.Report `json:"report"`
}

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
	s.truncate()
	return s, nil
}

// Append records a finished report and persists when a path is configured.
func (s *Store) Append(r digest.Report) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e := Entry{ID: r.GeneratedAt.UTC().Format(time.RFC3339Nano), Report: r}
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

func (s *Store) truncate() {
	if len(s.entries) > s.keep {
		s.entries = s.entries[len(s.entries)-s.keep:]
	}
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
