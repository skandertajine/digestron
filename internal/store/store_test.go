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
	e1, _ := s.Append(report(t0, digest.SeverityInfo), KindSchedule)
	e2, _ := s.Append(report(t0.Add(time.Hour), digest.SeverityCritical), KindSchedule)

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
		_, _ = s.Append(report(base.Add(time.Duration(i)*time.Hour), digest.SeverityInfo), KindSchedule)
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
	if _, err := s.Append(report(at, digest.SeverityWarning), KindManual); err != nil {
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
	if list[0].Kind != KindManual {
		t.Errorf("kind = %q after a round trip through the file, want %q", list[0].Kind, KindManual)
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

// A run learns its ID before it starts, so its log lines can carry it. The ID
// the store derives for the finished report must be the same string.
func TestIDForMatchesTheIDAppendDerives(t *testing.T) {
	s, _ := Open("", 10)
	at := time.Date(2026, 9, 22, 1, 10, 0, 3100, time.FixedZone("CEST", 2*3600))
	e, err := s.Append(report(at, digest.SeverityInfo), KindSchedule)
	if err != nil {
		t.Fatal(err)
	}
	if e.ID != IDFor(at) {
		t.Errorf("Append ID %q != IDFor %q", e.ID, IDFor(at))
	}
	if IDFor(at) != "2026-09-21T23:10:00.0000031Z" {
		t.Errorf("IDFor = %q, want the UTC RFC3339Nano form the history has always used", IDFor(at))
	}
}

// History written before kinds existed has no "kind" field. Every run then
// was a scheduled one.
func TestOlderFileWithoutKindLoadsAsSchedule(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.json")
	old := `[{"id":"2026-08-13T10:00:00Z","report":{"title":"t","generated_at":"2026-08-13T10:00:00Z"}}]`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.List()[0].Kind; got != KindSchedule {
		t.Errorf("kind of an old entry = %q, want %q", got, KindSchedule)
	}
}

func TestAppendWithoutKindIsSchedule(t *testing.T) {
	s, _ := Open("", 10)
	e, _ := s.Append(report(time.Now(), digest.SeverityInfo), "")
	if e.Kind != KindSchedule {
		t.Errorf("kind = %q, want the default %q", e.Kind, KindSchedule)
	}
}

// A busy afternoon of dry runs must not push the hourly digests out.
func TestTestRunsHaveTheirOwnBudget(t *testing.T) {
	s, _ := Open("", 8) // 8 real digests, 2 test runs
	base := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 6; i++ {
		_, _ = s.Append(report(base.Add(time.Duration(i)*time.Hour), digest.SeverityInfo), KindSchedule)
	}
	for i := 0; i < 30; i++ {
		_, _ = s.Append(report(base.Add(time.Duration(10+i)*time.Minute), digest.SeverityInfo), KindTest)
	}
	var digests, test int
	for _, e := range s.List() {
		if e.Kind == KindTest {
			test++
		} else {
			digests++
		}
	}
	if digests != 6 {
		t.Errorf("%d real digests kept, want all 6: test runs evicted them", digests)
	}
	if test != 2 {
		t.Errorf("%d test runs kept, want 2 (keep/4)", test)
	}
}

func TestRealDigestsAreStillCappedAtKeep(t *testing.T) {
	s, _ := Open("", 4)
	base := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 9; i++ {
		kind := KindSchedule
		if i%2 == 1 {
			kind = KindManual
		}
		_, _ = s.Append(report(base.Add(time.Duration(i)*time.Hour), digest.SeverityInfo), kind)
	}
	list := s.List()
	if len(list) != 4 || !list[0].Report.GeneratedAt.Equal(base.Add(8*time.Hour)) {
		t.Errorf("schedule and manual share one budget of 4, newest kept: got %d entries, newest %v", len(list), list[0].Report.GeneratedAt)
	}
}
