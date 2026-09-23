// Package web serves the built-in UI: what each run received from its
// sources, what was sent to each sink, and what the LLM cost in tokens. One
// embedded HTML page, a few JSON endpoints, no framework. It also carries the
// one button the page has, "Run now", through a Trigger the caller provides.
package web

import (
	_ "embed"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/skandertajine/digestron/internal/logring"
	"github.com/skandertajine/digestron/internal/store"
)

//go:embed static/index.html
var indexHTML []byte

// ErrRunInProgress is what a Trigger returns when a run — scheduled or
// manual — is already executing. The page shows it as "already running".
var ErrRunInProgress = errors.New("a run is already in progress")

// Trigger starts a digest run outside the schedule. Start must return at
// once: a run can spend two minutes on the LLM, longer than the proxy in
// front of this page will hold a request. The page polls Status until
// Running turns false, then reloads the history. A dry run keeps the sources
// and the LLM, which is what there is to test, and skips the sinks, so no
// phone buzzes for a test.
type Trigger interface {
	Start(dry bool) error
	Status() RunStatus
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
}

type runSummary struct {
	ID               string    `json:"id"`
	GeneratedAt      time.Time `json:"generated_at"`
	Title            string    `json:"title"`
	Verdict          string    `json:"verdict"`
	Findings         int       `json:"findings"`
	SourcesFailed    int       `json:"sources_failed"`
	SinksFailed      int       `json:"sinks_failed"`
	Model            string    `json:"model,omitempty"`
	PromptTokens     int       `json:"prompt_tokens"`
	CompletionTokens int       `json:"completion_tokens"`
	LLMMillis        int64     `json:"llm_ms"`
	Summary          string    `json:"summary"`
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
	}

	if d.Logs != nil {
		registerLogs(mux, d.Logs, cop)
	}
}

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
