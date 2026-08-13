// Package web serves the built-in UI: what each run received from its
// sources, what was sent to each sink, and what the LLM cost in tokens. One
// embedded HTML page, two JSON endpoints, no framework.
package web

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"time"

	"github.com/skandertajine/digestron/internal/store"
)

//go:embed static/index.html
var indexHTML []byte

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

func Register(mux *http.ServeMux, st *store.Store) {
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
		writeJSON(w, out)
	})

	mux.HandleFunc("GET /api/runs/{id}", func(w http.ResponseWriter, r *http.Request) {
		entry, ok := st.Get(r.PathValue("id"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, entry)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
