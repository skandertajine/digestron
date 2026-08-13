package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/skandertajine/digestron/internal/digest"
)

func report(at time.Time, verdict digest.Severity) digest.Report {
	return digest.Report{Title: "t", Verdict: verdict, GeneratedAt: at}
}

func TestAppendListGet(t *testing.T) {
	s, err := Open("", 10)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	e1, _ := s.Append(report(t0, digest.SeverityInfo))
	e2, _ := s.Append(report(t0.Add(time.Hour), digest.SeverityCritical))

	list := s.List()
	if len(list) != 2 || list[0].ID != e2.ID || list[1].ID != e1.ID {
		t.Errorf("List must be newest first: %+v", list)
	}

	got, ok := s.Get(e1.ID)
	if !ok || got.Report.Verdict != digest.SeverityInfo {
		t.Errorf("Get(%s) = %+v, %v", e1.ID, got, ok)
	}
	if _, ok := s.Get("nope"); ok {
		t.Error("Get of unknown id must miss")
	}
}

func TestCap(t *testing.T) {
	s, _ := Open("", 3)
	base := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		_, _ = s.Append(report(base.Add(time.Duration(i)*time.Hour), digest.SeverityInfo))
	}
	list := s.List()
	if len(list) != 3 {
		t.Fatalf("len = %d, want capped at 3", len(list))
	}
	if list[0].Report.GeneratedAt != base.Add(9*time.Hour) {
		t.Errorf("newest entry lost by the cap: %+v", list[0])
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.json")
	s, err := Open(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	if _, err := s.Append(report(at, digest.SeverityWarning)); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	list := reopened.List()
	if len(list) != 1 || list[0].Report.Verdict != digest.SeverityWarning {
		t.Errorf("reloaded = %+v", list)
	}
}

func TestCorruptFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, 10); err == nil {
		t.Error("corrupt history must be a visible error, not silence")
	}
}
