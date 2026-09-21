// Package web serves the built-in UI: what each run received from its
// sources, what was sent to each sink, and what the LLM cost in tokens. One
// embedded HTML page, a few JSON endpoints, no framework. It also carries the
// one button the page has, "Run now", through a Trigger the caller provides.
package web

import (
	_ "embed"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

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

// RunStatus is what the page polls while a run is in flight.
type RunStatus struct {
	Running   bool      `json:"running"`
	Dry       bool      `json:"dry"`
	StartedAt time.Time `json:"started_at"`
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

func Register(mux *http.ServeMux, st *store.Store, trig Trigger) {
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

	mux.HandleFunc("GET /api/run", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, trig.Status())
	})

	// The button. 202 because the run continues after this response; 409
	// when one is already in flight, whoever started it.
	//
	// dry defaults to true: a bare `curl -X POST` must not buzz a phone, so
	// a delivered run is opt-in with ?dry=0. The page always sends it.
	//
	// The page has no login and this is the first endpoint that does
	// something rather than show something, so a browser must not be able
	// to press it on behalf of another site: any page the operator has open
	// could otherwise POST here and fire a delivered digest. The stdlib
	// guard refuses cross-origin browser requests (Sec-Fetch-Site, or Origin
	// against Host) and lets curl and the page's own fetch through.
	cop := http.NewCrossOriginProtection()
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
