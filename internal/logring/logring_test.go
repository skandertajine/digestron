package logring

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

func at(l slog.Level) *slog.Level { return &l }

// newLogger wires a Ring the way the application does: a fan-out handler in
// front of a stderr handler, here a buffer so a test can see what stderr got.
func newLogger(ring *Ring, level slog.Level) (*slog.Logger, *bytes.Buffer, *slog.LevelVar) {
	var stderr bytes.Buffer
	lv := new(slog.LevelVar)
	lv.Set(level)
	h := ring.Handler(slog.NewJSONHandler(&stderr, &slog.HandlerOptions{Level: slog.LevelDebug}), lv)
	return slog.New(h), &stderr, lv
}

func TestRingKeepsEverythingWhileStderrKeepsOnlyTheLevel(t *testing.T) {
	ring := New(100, 1<<20, nil)
	log, stderr, lv := newLogger(ring, slog.LevelInfo)

	log.Debug("collecting", "source", "es")
	log.Info("run finished")
	log.Error("sink failed", "sink", "phone")

	page := ring.Snapshot(Query{})
	if len(page.Records) != 3 {
		t.Fatalf("ring kept %d records, want all 3 including the debug one", len(page.Records))
	}
	out := stderr.String()
	if strings.Contains(out, "collecting") {
		t.Errorf("stderr printed a debug line while set to info:\n%s", out)
	}
	if !strings.Contains(out, "run finished") || !strings.Contains(out, "sink failed") {
		t.Errorf("stderr lost lines it must print:\n%s", out)
	}

	// Raising the level at runtime governs stderr from then on, and only it.
	lv.Set(slog.LevelDebug)
	log.Debug("now visible")
	if !strings.Contains(stderr.String(), "now visible") {
		t.Error("lowering the level did not reach stderr")
	}
}

// slog's zero Level is Info, so a Query whose level filter were a plain field
// would hide every debug record from a caller that set no filter at all.
func TestEmptyQueryReturnsDebugRecords(t *testing.T) {
	ring := New(10, 1<<20, nil)
	log, _, _ := newLogger(ring, slog.LevelError)
	log.Debug("collecting")
	if got := len(ring.Snapshot(Query{}).Records); got != 1 {
		t.Errorf("empty Query returned %d records, want the debug one", got)
	}
	if got := len(ring.Snapshot(Query{MinLevel: at(slog.LevelInfo)}).Records); got != 0 {
		t.Errorf("an explicit info filter returned %d records, want none", got)
	}
}

func TestRecordFieldsAndRunIsLifted(t *testing.T) {
	ring := New(100, 1<<20, nil)
	log, _, _ := newLogger(ring, slog.LevelDebug)

	log.With("run", "2026-09-22T01:10:00Z", "kind", "schedule").Warn("llm failed", "provider", "ollama")

	rec := ring.Snapshot(Query{}).Records[0]
	if rec.Level != "WARN" || rec.Msg != "llm failed" || rec.Run != "2026-09-22T01:10:00Z" {
		t.Errorf("record = %+v", rec)
	}
	if rec.Attrs["kind"] != "schedule" || rec.Attrs["provider"] != "ollama" {
		t.Errorf("attrs = %v", rec.Attrs)
	}
	if _, ok := rec.Attrs["run"]; ok {
		t.Errorf("run must be lifted out of the attributes: %v", rec.Attrs)
	}
}

// slog.Logger.With and WithGroup must reach the ring, not just stderr: this
// is how every line of a run comes to carry its run ID.
func TestWithAttrsAndGroupsAreFlattened(t *testing.T) {
	ring := New(100, 1<<20, nil)
	log, _, _ := newLogger(ring, slog.LevelDebug)

	log.WithGroup("llm").With("model", "qwen").Info("done", slog.Group("tokens", "prompt", 12), "ms", 40)

	a := ring.Snapshot(Query{}).Records[0].Attrs
	for k, want := range map[string]string{"llm.model": "qwen", "llm.tokens.prompt": "12", "llm.ms": "40"} {
		if a[k] != want {
			t.Errorf("attrs[%q] = %q, want %q (all: %v)", k, a[k], want, a)
		}
	}
}

type secretValue string

func (secretValue) LogValue() slog.Value { return slog.StringValue("<redacted>") }

func TestLogValuerIsResolved(t *testing.T) {
	ring := New(100, 1<<20, nil)
	log, _, _ := newLogger(ring, slog.LevelDebug)
	log.Info("configured", "token", secretValue("hunter2-hunter2"))
	if got := ring.Snapshot(Query{}).Records[0].Attrs["token"]; got != "<redacted>" {
		t.Errorf("token = %q: a LogValuer must be resolved, as config.Secret relies on", got)
	}
}

func TestScrubRunsOverMessageAndEveryAttribute(t *testing.T) {
	scrub := func(s string) string { return strings.ReplaceAll(s, "hunter2-hunter2", "<redacted>") }
	ring := New(100, 1<<20, scrub)
	log, _, _ := newLogger(ring, slog.LevelDebug)

	log.Error("auth failed for hunter2-hunter2", "error", "401 body: Bearer hunter2-hunter2")

	rec := ring.Snapshot(Query{}).Records[0]
	if strings.Contains(rec.Msg, "hunter2") || strings.Contains(rec.Attrs["error"], "hunter2") {
		t.Errorf("a secret reached the ring: %+v", rec)
	}
}

func TestCapByCountEvictsOldestAndReaderIsToldWhatItMissed(t *testing.T) {
	ring := New(5, 1<<20, nil)
	log, _, _ := newLogger(ring, slog.LevelDebug)
	for i := 1; i <= 3; i++ {
		log.Info(fmt.Sprintf("line %d", i))
	}
	first := ring.Snapshot(Query{})
	if len(first.Records) != 3 || first.Seq != 3 || first.Dropped != 0 {
		t.Fatalf("first read = seq %d, %d records, dropped %d", first.Seq, len(first.Records), first.Dropped)
	}

	for i := 4; i <= 12; i++ { // 9 more into a ring of 5: lines 8..12 remain
		log.Info(fmt.Sprintf("line %d", i))
	}
	second := ring.Snapshot(Query{Since: first.Seq})
	if len(second.Records) != 5 || second.Records[0].Msg != "line 8" {
		t.Fatalf("second read = %d records starting %q, want lines 8..12", len(second.Records), second.Records[0].Msg)
	}
	if second.Dropped != 4 {
		t.Errorf("dropped = %d, want 4 (lines 4..7 were evicted before this reader saw them)", second.Dropped)
	}
	if n, _ := ring.Stats(); n != 5 {
		t.Errorf("ring holds %d records, want its cap of 5", n)
	}
}

func TestCapByBytes(t *testing.T) {
	ring := New(1000, 4096, nil)
	log, _, _ := newLogger(ring, slog.LevelDebug)
	for i := 0; i < 200; i++ {
		log.Info("padding", "blob", strings.Repeat("x", 300))
	}
	n, bytes := ring.Stats()
	if bytes > 4096+maxRecordBytes {
		t.Errorf("ring holds %d bytes, want it near its 4096 cap", bytes)
	}
	if n == 0 || n >= 200 {
		t.Errorf("ring holds %d records, want some evicted but not all", n)
	}
}

func TestOneRecordIsCapped(t *testing.T) {
	ring := New(10, 1<<20, nil)
	log, _, _ := newLogger(ring, slog.LevelDebug)
	big := strings.Repeat("é", 5000) // multi-byte on purpose: never split a rune
	log.Error(big, "a", big, "b", big, "c", big)

	rec := ring.Snapshot(Query{}).Records[0]
	if sizeOf(rec) > maxRecordBytes+minAttrBytes*3 {
		t.Errorf("record is %d bytes, want it near the %d cap", sizeOf(rec), maxRecordBytes)
	}
	for _, v := range append([]string{rec.Msg}, rec.Attrs["a"], rec.Attrs["b"], rec.Attrs["c"]) {
		if !strings.HasSuffix(v, "…") {
			t.Errorf("a clipped value must say so: %.20q…", v)
		}
		if strings.ContainsRune(v, '�') {
			t.Errorf("a rune was split: %.20q", v)
		}
	}
}

func TestFiltersLevelRunAndSubstring(t *testing.T) {
	ring := New(100, 1<<20, nil)
	log, _, _ := newLogger(ring, slog.LevelDebug)
	a := log.With("run", "run-a")
	b := log.With("run", "run-b")
	a.Debug("collecting", "source", "es-security")
	a.Error("source failed", "error", "400 Bad Request")
	b.Info("run finished")

	if got := len(ring.Snapshot(Query{MinLevel: at(slog.LevelWarn)}).Records); got != 1 {
		t.Errorf("level filter: %d records, want only the error", got)
	}
	if got := len(ring.Snapshot(Query{Run: "run-a"}).Records); got != 2 {
		t.Errorf("run filter: %d records, want run-a's 2", got)
	}
	if got := len(ring.Snapshot(Query{Substr: "BAD request"}).Records); got != 1 {
		t.Errorf("substring filter must be case-insensitive and reach attributes: %d records", got)
	}
	if got := len(ring.Snapshot(Query{Substr: "ES-SECURITY"}).Records); got != 1 {
		t.Errorf("substring filter must reach attribute values: %d records", got)
	}
}

// A first read of a busy ring gets the newest lines; a follow-up read pages
// forward from the cursor so a reader that keeps up never skips a line.
func TestFirstReadIsNewestAndLaterReadsPageForward(t *testing.T) {
	ring := New(100, 1<<20, nil)
	log, _, _ := newLogger(ring, slog.LevelDebug)
	for i := 1; i <= 50; i++ {
		log.Info(fmt.Sprintf("line %d", i))
	}

	newest := ring.Snapshot(Query{Limit: 10})
	if len(newest.Records) != 10 || newest.Records[0].Msg != "line 41" || newest.Seq != 50 {
		t.Fatalf("first read = %d records from %q, seq %d; want the newest 10 (41..50)",
			len(newest.Records), newest.Records[0].Msg, newest.Seq)
	}

	p1 := ring.Snapshot(Query{Since: 20, Limit: 10})
	if p1.Records[0].Msg != "line 21" || p1.Records[9].Msg != "line 30" || p1.Seq != 30 {
		t.Errorf("paging forward: from %q to %q, seq %d; want 21..30 and a cursor at 30",
			p1.Records[0].Msg, p1.Records[9].Msg, p1.Seq)
	}
	p2 := ring.Snapshot(Query{Since: p1.Seq, Limit: 100})
	if len(p2.Records) != 20 || p2.Seq != 50 {
		t.Errorf("last page = %d records, seq %d; want 31..50", len(p2.Records), p2.Seq)
	}

	idle := ring.Snapshot(Query{Since: 50})
	if len(idle.Records) != 0 || idle.Seq != 50 || idle.Records == nil {
		t.Errorf("nothing new: %+v, want an empty non-nil list and the same cursor", idle)
	}
}

func TestLimitIsClamped(t *testing.T) {
	ring := New(5000, 1<<22, nil)
	log, _, _ := newLogger(ring, slog.LevelDebug)
	for i := 0; i < 2500; i++ {
		log.Info("x")
	}
	if got := len(ring.Snapshot(Query{Limit: 99999}).Records); got != MaxLimit {
		t.Errorf("limit 99999 returned %d records, want it clamped to %d", got, MaxLimit)
	}
	if got := len(ring.Snapshot(Query{}).Records); got != DefaultLimit {
		t.Errorf("no limit returned %d records, want %d", got, DefaultLimit)
	}
}

// The ring sits under every log call in the process, from every goroutine.
func TestConcurrentWritersAndReaders(t *testing.T) {
	ring := New(200, 1<<20, nil)
	log, _, _ := newLogger(ring, slog.LevelDebug)

	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			l := log.With("run", fmt.Sprintf("run-%d", w))
			for i := 0; i < 300; i++ {
				l.Info("tick", "i", i)
			}
		}(w)
	}
	stop := make(chan struct{})
	var readers sync.WaitGroup
	for r := 0; r < 4; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			var since uint64
			for {
				select {
				case <-stop:
					return
				default:
					since = ring.Snapshot(Query{Since: since, Substr: "tick"}).Seq
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	readers.Wait()

	if page := ring.Snapshot(Query{}); page.Seq != 2400 {
		t.Errorf("seq = %d after 2400 writes, want 2400: a write was lost or duplicated", page.Seq)
	}
	if n, _ := ring.Stats(); n != 200 {
		t.Errorf("ring holds %d, want its cap of 200", n)
	}
}

func TestParseLevelAndName(t *testing.T) {
	for in, want := range map[string]slog.Level{"debug": slog.LevelDebug, "INFO": slog.LevelInfo, "Warn": slog.LevelWarn, "warning": slog.LevelWarn, "error": slog.LevelError} {
		if got, ok := ParseLevel(in); !ok || got != want {
			t.Errorf("ParseLevel(%q) = %v, %v", in, got, ok)
		}
	}
	if _, ok := ParseLevel("loud"); ok {
		t.Error("an unknown level must be refused, not guessed")
	}
	for l, want := range map[slog.Level]string{slog.LevelDebug: "debug", slog.LevelInfo: "info", slog.LevelWarn: "warn", slog.LevelError: "error"} {
		if got := LevelName(l); got != want {
			t.Errorf("LevelName(%v) = %q, want %q", l, got, want)
		}
	}
}

// The ring is memory-only and numbers from 1 again after a restart. A reader
// that outlives the process must be able to tell, or it adopts the new,
// smaller cursor and never shows the new process's first lines.
func TestBootIdChangesWithTheRing(t *testing.T) {
	first := New(10, 1<<20, nil)
	time.Sleep(2 * time.Millisecond) // rings created in the same instant would share a clock reading
	restarted := New(10, 1<<20, nil)

	boot := first.Snapshot(Query{}).Boot
	if boot == "" {
		t.Fatal("a page must carry a boot id")
	}
	if again := first.Snapshot(Query{}).Boot; again != boot {
		t.Errorf("the boot id changed within one ring: %q then %q", boot, again)
	}
	if restarted.Snapshot(Query{}).Boot == boot {
		t.Error("a new ring (a restarted process) must have a different boot id")
	}
}

// A cursor larger than anything this ring has issued came from a previous
// process. Returning nothing until the numbers catch up would hide the new
// process's first lines, which are the ones that explain a restart.
func TestCursorFromBeforeARestartReadsFromTheTop(t *testing.T) {
	ring := New(100, 1<<20, nil)
	log, _, _ := newLogger(ring, slog.LevelDebug)
	for i := 1; i <= 4; i++ {
		log.Info(fmt.Sprintf("line %d", i))
	}
	page := ring.Snapshot(Query{Since: 2500})
	if len(page.Records) != 4 || page.Records[0].Msg != "line 1" || page.Dropped != 0 {
		t.Errorf("stale cursor: %d records from %q, dropped %d; want all 4 from line 1",
			len(page.Records), page.Records[0].Msg, page.Dropped)
	}
}

// Substring queries scan a search text prepared when the record was added; it
// must find what the old per-poll lower-casing found: message, run, attribute
// keys and values, in any case.
func TestSubstringSearchStillReachesEveryField(t *testing.T) {
	ring := New(100, 1<<20, nil)
	log, _, _ := newLogger(ring, slog.LevelDebug)
	log.With("run", "2026-09-22T01:10:00Z").Error("Source Failed", "Error", "Connection REFUSED", "SourceName", "prom")

	for _, q := range []string{"source failed", "CONNECTION refused", "sourcename", "prom", "01:10:00", "error=connection"} {
		if got := len(ring.Snapshot(Query{Substr: q}).Records); got != 1 {
			t.Errorf("query %q found %d records, want 1", q, got)
		}
	}
	// A match must not straddle two fields.
	if got := len(ring.Snapshot(Query{Substr: "failedconnection"}).Records); got != 0 {
		t.Errorf("a query spanning the message and an attribute matched %d records", got)
	}
}
