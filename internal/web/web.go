// Package web serves the built-in UI: what each run received from its
// sources, what was sent to each sink, and what the LLM cost in tokens. One
// embedded HTML page, a few JSON endpoints, no framework. It also carries the
// one button the page has, "Run now", through a Trigger the caller provides.
package web

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/skandertajine/digestron/internal/logring"
	"github.com/skandertajine/digestron/internal/store"
)

//go:embed static/index.html
var indexHTML []byte

// ErrRunInProgress is what a Trigger returns when a run — scheduled or
// manual — is already executing. The page shows it as "already running".
var ErrRunInProgress = errors.New("a run is already in progress")

// ErrNotRunning is what a Trigger's Cancel returns when there is nothing to
// cancel.
var ErrNotRunning = errors.New("no run is in progress")

// Trigger starts a digest run outside the schedule. Start must return at
// once: a run can spend two minutes on the LLM, longer than the proxy in
// front of this page will hold a request. The page polls Status until
// Running turns false, then reloads the history. A dry run keeps the sources
// and the LLM, which is what there is to test, and skips the sinks, so no
// phone buzzes for a test.
type Trigger interface {
	Start(dry bool) error
	Status() RunStatus
	// Cancel stops the run in flight, or reports ErrNotRunning when idle.
	Cancel() error
}

// RunStatus is what the page polls while a run is in flight. ID and Kind are
// the run's identity, known before it starts: the ID is the one its finished
// report will be stored under, and every log line of the run carries it.
type RunStatus struct {
	Running   bool       `json:"running"`
	Dry       bool       `json:"dry"`
	StartedAt time.Time  `json:"started_at"`
	ID        string     `json:"id,omitempty"`
	Kind      store.Kind `json:"kind,omitempty"`
	// Phase is what the run is doing right now: "collecting", "summarizing"
	// or "delivering". Empty until the run reports its first phase.
	Phase string `json:"phase,omitempty"`
}

// Status is the header strip's single read: build, schedule, the last two
// outcomes and how much of the process's memory budget the rings are using.
// Everything here is safe on an unauthenticated page: no setting, no secret,
// no address more specific than what /metrics already exposes.
type Status struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	GoVersion string `json:"go_version"`

	StartedAt time.Time `json:"started_at"`
	Cron      string    `json:"cron,omitempty"`
	Timezone  string    `json:"timezone,omitempty"`
	// NextRun, LastRun and LastSuccess are pointers so that "never happened"
	// serializes as an absent field, not as Go's zero time.Time (which
	// encoding/json always renders as "0001-01-01T00:00:00Z" — omitempty is a
	// no-op on a struct-typed field, so a plain time.Time here would have
	// made a fresh process's "no run yet" look like a real, ancient timestamp
	// to anything parsing it).
	NextRun     *time.Time `json:"next_run,omitempty"`
	LastRun     *time.Time `json:"last_run,omitempty"`
	LastSuccess *time.Time `json:"last_success,omitempty"`

	LogRecords    int    `json:"log_records"`
	LogBytes      int    `json:"log_bytes"`
	Goroutines    int    `json:"goroutines"`
	MemAllocBytes uint64 `json:"mem_alloc_bytes"`
}

// CheckResult is one module's answer to a probe.
type CheckResult struct {
	Kind    string `json:"kind"` // source | sink | llm
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Skipped bool   `json:"skipped,omitempty"` // the module has no cheap probe
	Err     string `json:"error,omitempty"`
	Millis  int64  `json:"ms"`
}

// Ops is the header strip's data and the check-all button. Check probes every
// configured module (or one, by name) with its own timeout, in parallel, and
// returns as soon as they are all done or the context given to it expires.
type Ops interface {
	Status() Status
	Check(ctx context.Context, module string) []CheckResult
}

// LogSource is the process's recent log lines and its stderr level.
type LogSource interface {
	Logs(q logring.Query) logring.Page
	Level() string
	SetLevel(name string) error
}

// Deps is everything the page can show or do. A dependency left nil leaves
// its routes unregistered, so a slice of the UI that is not wired in does not
// answer, rather than answering with nothing.
type Deps struct {
	Store   *store.Store
	Trigger Trigger
	Logs    LogSource
	Ops     Ops
}

type runSummary struct {
	ID               string     `json:"id"`
	GeneratedAt      time.Time  `json:"generated_at"`
	Title            string     `json:"title"`
	Kind             store.Kind `json:"kind,omitempty"`
	Verdict          string     `json:"verdict"`
	Findings         int        `json:"findings"`
	SourcesFailed    int        `json:"sources_failed"`
	SinksFailed      int        `json:"sinks_failed"`
	Model            string     `json:"model,omitempty"`
	PromptTokens     int        `json:"prompt_tokens"`
	CompletionTokens int        `json:"completion_tokens"`
	LLMMillis        int64      `json:"llm_ms"`
	Summary          string     `json:"summary"`
}

func Register(mux *http.ServeMux, d Deps) {
	st, trig := d.Store, d.Trigger

	// The page has no login, and it now has endpoints that do something
	// rather than show something, so a browser must not be able to press
	// them on behalf of another site: any page the operator has open could
	// otherwise POST here. The stdlib guard refuses cross-origin browser
	// requests (Sec-Fetch-Site, or Origin against Host) and lets curl and the
	// page's own fetch through.
	cop := http.NewCrossOriginProtection()

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexHTML)
	})

	mux.HandleFunc("GET /api/runs", func(w http.ResponseWriter, _ *http.Request) {
		entries := st.List()
		out := make([]runSummary, 0, len(entries))
		for _, e := range entries {
			r := e.Report
			s := runSummary{
				ID:               e.ID,
				GeneratedAt:      r.GeneratedAt,
				Title:            r.Title,
				Kind:             e.Kind,
				Verdict:          r.Verdict.String(),
				Findings:         len(r.Findings),
				Model:            r.LLM.Model,
				PromptTokens:     r.LLM.PromptTokens,
				CompletionTokens: r.LLM.CompletionTokens,
				LLMMillis:        r.LLM.Duration.Milliseconds(),
				Summary:          r.Summary,
			}
			for _, src := range r.Stats {
				if src.Err != "" {
					s.SourcesFailed++
				}
			}
			for _, sk := range r.Sinks {
				if sk.Err != "" {
					s.SinksFailed++
				}
			}
			out = append(out, s)
		}
		writeJSON(w, http.StatusOK, out)
	})

	mux.HandleFunc("GET /api/runs/{id}", func(w http.ResponseWriter, r *http.Request) {
		entry, ok := st.Get(r.PathValue("id"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, entry)
	})

	if trig != nil {
		mux.HandleFunc("GET /api/run", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, trig.Status())
		})

		// The button. 202 because the run continues after this response; 409
		// when one is already in flight, whoever started it.
		//
		// dry defaults to true: a bare `curl -X POST` must not buzz a phone, so
		// a delivered run is opt-in with ?dry=0. The page always sends it.
		mux.Handle("POST /api/run", cop.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			dry := true
			if v := r.URL.Query().Get("dry"); v != "" {
				b, err := strconv.ParseBool(v)
				if err != nil {
					writeJSON(w, http.StatusBadRequest, map[string]string{"error": "dry must be 1 or 0"})
					return
				}
				dry = b
			}
			switch err := trig.Start(dry); {
			case errors.Is(err, ErrRunInProgress):
				writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			case err != nil:
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			default:
				writeJSON(w, http.StatusAccepted, map[string]any{"started": true, "dry": dry})
			}
		})))

		// The button's "stop" side. 204 when it was told to stop (it may
		// still take a moment to actually unwind); 404 when nothing runs.
		mux.Handle("DELETE /api/run", cop.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			switch err := trig.Cancel(); {
			case errors.Is(err, ErrNotRunning):
				writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			case err != nil:
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			default:
				w.WriteHeader(http.StatusNoContent)
			}
		})))
	}

	if d.Logs != nil {
		registerLogs(mux, d.Logs, cop)
	}

	if d.Ops != nil {
		mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, d.Ops.Status())
		})

		// Reaches every configured backend, so it goes through the same guard
		// as the mutating routes even though it changes nothing here: a
		// cross-site page must not be able to use this process to probe the
		// operator's LAN or time its responses. checking is a one-at-a-time
		// gate, not queued: an overlapping call is refused rather than made
		// to wait, since a caller on the LAN (the cop guard only stops a
		// browser) could otherwise keep every backend under permanent probe
		// load with no upper bound on concurrency.
		var checking atomic.Bool
		mux.Handle("POST /api/check", cop.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Module string `json:"module"`
			}
			if r.ContentLength != 0 || r.Header.Get("Content-Type") != "" {
				if !readJSON(w, r, &body) {
					return
				}
			}
			if !checking.CompareAndSwap(false, true) {
				writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "a check is already in progress"})
				return
			}
			defer checking.Store(false)
			ctx, cancel := context.WithTimeout(r.Context(), checkTotalTimeout)
			defer cancel()
			writeJSON(w, http.StatusOK, d.Ops.Check(ctx, body.Module))
		})))
	}
}

// checkTotalTimeout bounds one POST /api/check call: modules are probed in
// parallel, so this is per call, not per module.
const checkTotalTimeout = 20 * time.Second

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// maxBody bounds any request body: a mutating endpoint reads a few hundred
// bytes of JSON, and an unauthenticated page must not buffer more than that.
const maxBody = 256 << 10

// readJSON decodes a mutating request's JSON body into v, or answers the
// request itself and returns false. The content type must be JSON: a form or
// text/plain body is what a cross-site page can send without a preflight,
// so refusing it closes that door even if the origin guard were bypassed.
// Unknown fields are refused, so a typo is an error rather than a no-op.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "Content-Type must be application/json"})
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request body too large"})
		} else {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		return false
	}
	return true
}

type logsResponse struct {
	logring.Page
	Level string `json:"level"` // what stderr prints right now
}

func registerLogs(mux *http.ServeMux, src LogSource, cop *http.CrossOriginProtection) {
	// GET /api/logs?since=<seq>&level=<debug|info|warn|error>&run=<id>&q=<text>&limit=<n>
	// The ring keeps every level; level here only filters what is returned.
	mux.HandleFunc("GET /api/logs", func(w http.ResponseWriter, r *http.Request) {
		q, field, err := parseLogQuery(r)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error(), "field": field})
			return
		}
		writeJSON(w, http.StatusOK, logsResponse{Page: src.Logs(q), Level: src.Level()})
	})

	// PUT /api/logs/level {"level":"debug"}: what stderr prints, for the life
	// of this process. It never changes what the ring keeps.
	mux.Handle("PUT /api/logs/level", cop.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Level string `json:"level"`
		}
		if !readJSON(w, r, &body) {
			return
		}
		if err := src.SetLevel(body.Level); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error(), "field": "level"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})))
}

func parseLogQuery(r *http.Request) (logring.Query, string, error) {
	v := r.URL.Query()
	q := logring.Query{Run: v.Get("run"), Substr: v.Get("q")}
	if s := v.Get("since"); s != "" {
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return q, "since", errors.New("since must be a non-negative integer")
		}
		q.Since = n
	}
	if s := v.Get("level"); s != "" {
		lvl, ok := logring.ParseLevel(s)
		if !ok {
			return q, "level", errors.New("level must be debug, info, warn or error")
		}
		q.MinLevel = &lvl
	}
	if s := v.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			return q, "limit", errors.New("limit must be a positive integer")
		}
		q.Limit = n
	}
	return q, "", nil
}
