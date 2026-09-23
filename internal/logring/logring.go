// Package logring keeps the process's recent log lines in memory so the web UI
// can show them. It is a slog.Handler that sits in front of the usual stderr
// handler: stderr prints exactly what it always printed, and the ring keeps
// everything, debug included, so an operator can raise the level and still
// see what happened a minute ago.
//
// The ring is bounded twice, by record count and by bytes, and evicts the
// oldest first. A reader that falls behind is told how many records it missed
// rather than silently skipping them.
package logring

import (
	"context"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// maxRecordBytes caps one record: the message, then attribute values,
	// are cut with an ellipsis. A log line is a pointer to a problem, not a
	// place to store a response body.
	maxRecordBytes = 2048
	maxMsgBytes    = 512
	maxAttrBytes   = 1024
	// minAttrBytes is the least an attribute keeps when a record is over
	// budget, enough to tell what it was.
	minAttrBytes = 32

	// DefaultLimit and MaxLimit bound how many records one read returns.
	DefaultLimit = 500
	MaxLimit     = 2000
)

// Record is one log line as the UI sees it.
type Record struct {
	Seq   uint64            `json:"seq"`
	Time  time.Time         `json:"t"`
	Level string            `json:"level"`
	Msg   string            `json:"msg"`
	Run   string            `json:"run,omitempty"`   // the "run" attribute, lifted so it can be filtered on
	Attrs map[string]string `json:"attrs,omitempty"` // groups flattened with dots, values as text
}

type stored struct {
	Record
	level slog.Level
	size  int
	// hay is the record's searchable text, lower-cased once when it is added.
	// A substring query then scans it under the lock without allocating,
	// instead of lower-casing 4000 records' worth of text on every poll.
	hay string
}

// Query selects records. The zero value returns everything retained, up to
// DefaultLimit.
type Query struct {
	Since uint64 // only records with a greater Seq
	// MinLevel is a pointer because slog's zero Level is Info: a plain
	// field would make the empty Query silently drop every debug record.
	MinLevel *slog.Level
	Run      string // exact run ID, "" for all
	Substr   string // case-insensitive, over the message and every attribute
	Limit    int
}

// Page is one read of the ring.
type Page struct {
	// Boot identifies the ring: it changes when the process restarts, and
	// Seq numbers from 1 again when it does. A reader that sees Boot change
	// must drop its cursor, or it would skip the new process's first lines.
	Boot string `json:"boot"`
	// Seq is the cursor to pass as Since next time.
	Seq uint64 `json:"seq"`
	// Dropped counts records the reader never saw because they were evicted
	// between two reads. It is 0 on a first read.
	Dropped uint64   `json:"dropped"`
	Records []Record `json:"records"`
}

// Ring is a bounded in-memory log store. It is safe for concurrent use.
type Ring struct {
	mu       sync.Mutex
	buf      []stored // circular, capacity fixed at New
	head     int      // index of the oldest record
	n        int
	bytes    int
	maxBytes int
	seq      uint64
	boot     string
	scrub    func(string) string
}

// New returns a Ring keeping at most maxRecords records and maxBytes bytes.
// scrub, when not nil, runs over the message and every attribute value before
// a record is stored.
func New(maxRecords, maxBytes int, scrub func(string) string) *Ring {
	if maxRecords < 1 {
		maxRecords = 1
	}
	return &Ring{
		buf: make([]stored, maxRecords), maxBytes: maxBytes, scrub: scrub,
		boot: strconv.FormatInt(time.Now().UnixNano(), 36),
	}
}

// ParseLevel maps a level name to its slog level. It is what the query string
// and the stderr level selector both speak.
func ParseLevel(s string) (slog.Level, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, true
	case "info":
		return slog.LevelInfo, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error":
		return slog.LevelError, true
	}
	return 0, false
}

// LevelName is the inverse of ParseLevel.
func LevelName(l slog.Level) string {
	switch {
	case l <= slog.LevelDebug:
		return "debug"
	case l <= slog.LevelInfo:
		return "info"
	case l <= slog.LevelWarn:
		return "warn"
	}
	return "error"
}

type attr struct{ k, v string }

func (r *Ring) add(t time.Time, level slog.Level, msg string, attrs []attr) {
	rec := Record{Time: t.UTC(), Level: strings.ToUpper(level.String()), Msg: r.clean(msg, maxMsgBytes)}
	if len(attrs) > 0 {
		rec.Attrs = make(map[string]string, len(attrs))
		for _, a := range attrs {
			v := r.clean(a.v, maxAttrBytes)
			if a.k == "run" {
				rec.Run = v
				continue
			}
			rec.Attrs[a.k] = v
		}
		if len(rec.Attrs) == 0 {
			rec.Attrs = nil
		}
	}
	fit(&rec)
	hay := haystack(rec)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	rec.Seq = r.seq
	s := stored{Record: rec, level: level, hay: hay, size: sizeOf(rec) + len(hay)}

	if r.n == len(r.buf) { // full by count: overwrite the oldest
		r.evictOldest()
	}
	r.buf[(r.head+r.n)%len(r.buf)] = s
	r.n++
	r.bytes += s.size
	for r.n > 1 && r.bytes > r.maxBytes {
		r.evictOldest()
	}
}

func (r *Ring) evictOldest() {
	r.bytes -= r.buf[r.head].size
	r.buf[r.head] = stored{}
	r.head = (r.head + 1) % len(r.buf)
	r.n--
}

func (r *Ring) clean(s string, limit int) string {
	if r.scrub != nil {
		s = r.scrub(s)
	}
	return truncate(s, limit)
}

// fit brings a record under maxRecordBytes by shortening attribute values, the
// longest first, never below minAttrBytes. The message keeps its own cap.
func fit(rec *Record) {
	for sizeOf(*rec) > maxRecordBytes {
		keys := make([]string, 0, len(rec.Attrs))
		for k := range rec.Attrs {
			keys = append(keys, k)
		}
		if len(keys) == 0 {
			rec.Msg = truncate(rec.Msg, maxRecordBytes/2)
			return
		}
		sort.Slice(keys, func(i, j int) bool {
			if len(rec.Attrs[keys[i]]) != len(rec.Attrs[keys[j]]) {
				return len(rec.Attrs[keys[i]]) > len(rec.Attrs[keys[j]])
			}
			return keys[i] < keys[j]
		})
		longest := keys[0]
		if len(rec.Attrs[longest]) <= minAttrBytes {
			return // everything is already short: accept the overage
		}
		next := len(rec.Attrs[longest]) * 3 / 4
		if next < minAttrBytes {
			next = minAttrBytes
		}
		rec.Attrs[longest] = truncate(rec.Attrs[longest], next)
	}
}

// haystack is what a substring query searches: the message, the run and every
// attribute, lower-cased, with a separator no query contains so a match cannot
// straddle two fields.
func haystack(rec Record) string {
	var b strings.Builder
	b.WriteString(rec.Msg)
	b.WriteByte(0)
	b.WriteString(rec.Run)
	for k, v := range rec.Attrs {
		b.WriteByte(0)
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(v)
	}
	return strings.ToLower(b.String())
}

func sizeOf(rec Record) int {
	n := len(rec.Msg) + len(rec.Run) + len(rec.Level) + 48
	for k, v := range rec.Attrs {
		n += len(k) + len(v) + 4
	}
	return n
}

// truncate cuts s to at most limit bytes, ellipsis included, without
// splitting a rune, so a reader can tell a whole value from a clipped one.
func truncate(s string, limit int) string {
	const ellipsis = "…"
	if len(s) <= limit {
		return s
	}
	cut := limit - len(ellipsis)
	if cut < 0 {
		cut = 0
	}
	for cut > 0 && s[cut]&0xC0 == 0x80 { // inside a multi-byte rune
		cut--
	}
	return strings.TrimRight(s[:cut], " ") + ellipsis
}

// Snapshot returns the records matching q. A first read (Since 0) that has
// more matches than the limit gets the newest ones; a later read gets the
// oldest ones after Since, so a reader that pages catches up without gaps.
func (r *Ring) Snapshot(q Query) Page {
	limit := q.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}
	needle := strings.ToLower(q.Substr)

	r.mu.Lock()
	defer r.mu.Unlock()

	page := Page{Boot: r.boot, Seq: r.seq, Records: []Record{}}
	since := q.Since
	if since > r.seq {
		// A cursor from the future can only come from before a restart: read
		// from the top rather than return nothing until the numbers catch up.
		since = 0
	}
	if r.n > 0 && since > 0 {
		if oldest := r.buf[r.head].Seq; oldest > since+1 {
			page.Dropped = oldest - since - 1
		}
	}

	var matches []Record
	for i := 0; i < r.n; i++ {
		s := r.buf[(r.head+i)%len(r.buf)]
		if s.Seq <= since || (q.MinLevel != nil && s.level < *q.MinLevel) {
			continue
		}
		if q.Run != "" && s.Run != q.Run {
			continue
		}
		if needle != "" && !strings.Contains(s.hay, needle) {
			continue
		}
		matches = append(matches, s.Record)
	}

	switch {
	case len(matches) <= limit:
		page.Records = append(page.Records, matches...)
	case since == 0:
		page.Records = append(page.Records, matches[len(matches)-limit:]...)
	default:
		page.Records = append(page.Records, matches[:limit]...)
		page.Seq = page.Records[len(page.Records)-1].Seq // more to come: resume here
	}
	return page
}

// Stats reports how many records and bytes the ring holds.
func (r *Ring) Stats() (count, bytes int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n, r.bytes
}

// Handler fans a logger out to the ring and to stderr. Everything is kept in
// the ring; a record reaches stderr only when it is at or above lv, so
// stderr prints exactly what the configured level asks for and lv can be
// changed at runtime without touching the ring.
func (r *Ring) Handler(stderr slog.Handler, lv *slog.LevelVar) slog.Handler {
	return &handler{ring: r, child: stderr, lv: lv}
}

type handler struct {
	ring   *Ring
	child  slog.Handler
	lv     *slog.LevelVar
	prefix string // "group." for the groups opened so far
	attrs  []attr // attributes bound with WithAttrs, keys already prefixed
}

// Enabled is always true: the ring keeps every level.
func (h *handler) Enabled(context.Context, slog.Level) bool { return true }

func (h *handler) Handle(ctx context.Context, rec slog.Record) error {
	attrs := append([]attr(nil), h.attrs...)
	rec.Attrs(func(a slog.Attr) bool {
		attrs = flatten(attrs, h.prefix, a)
		return true
	})
	h.ring.add(rec.Time, rec.Level, rec.Message, attrs)
	if rec.Level >= h.lv.Level() {
		return h.child.Handle(ctx, rec)
	}
	return nil
}

func (h *handler) WithAttrs(as []slog.Attr) slog.Handler {
	n := *h
	n.child = h.child.WithAttrs(as)
	n.attrs = append([]attr(nil), h.attrs...)
	for _, a := range as {
		n.attrs = flatten(n.attrs, h.prefix, a)
	}
	return &n
}

func (h *handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	n := *h
	n.child = h.child.WithGroup(name)
	n.prefix = h.prefix + name + "."
	return &n
}

// flatten renders one attribute as text, groups as dotted keys.
func flatten(out []attr, prefix string, a slog.Attr) []attr {
	a.Value = a.Value.Resolve() // LogValuer, so config.Secret renders <redacted>
	if a.Equal(slog.Attr{}) {
		return out
	}
	if a.Value.Kind() == slog.KindGroup {
		p := prefix
		if a.Key != "" {
			p += a.Key + "."
		}
		for _, g := range a.Value.Group() {
			out = flatten(out, p, g)
		}
		return out
	}
	return append(out, attr{k: prefix + a.Key, v: a.Value.String()})
}
