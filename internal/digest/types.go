// Package digest defines the core types and interfaces every module
// implements. It depends on nothing else in this repository.
package digest

import (
	"encoding/json"
	"fmt"
	"time"
)

type Severity int

const (
	SeverityInfo Severity = iota
	SeverityWarning
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "critical"
	case SeverityWarning:
		return "warning"
	default:
		return "info"
	}
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *Severity) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch v {
	case "info":
		*s = SeverityInfo
	case "warning":
		*s = SeverityWarning
	case "critical":
		*s = SeverityCritical
	default:
		return fmt.Errorf("unknown severity %q", v)
	}
	return nil
}

// Window is the time range covered by one run.
type Window struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// Finding is one aggregated observation from a source. Severity is always
// computed in Go (see severity.go), never by the LLM.
type Finding struct {
	Source   string         `json:"source"`
	Title    string         `json:"title"`
	Count    int            `json:"count"`
	Severity Severity       `json:"severity"`
	Details  map[string]int `json:"details,omitempty"` // breakdown, e.g. IP -> count
}

// SourceStats records one module's outcome for rendering, the UI and metrics.
type SourceStats struct {
	Source   string        `json:"source"`
	Findings int           `json:"findings"`
	Duration time.Duration `json:"duration"`
	Err      string        `json:"error,omitempty"`
}

// Partial reports a source that failed yet still delivered findings: some of
// its queries answered and some did not. Derived rather than stored, so the
// run history written by older versions keeps the same meaning.
func (s SourceStats) Partial() bool { return s.Err != "" && s.Findings > 0 }

// LLMStats records the summarization cost of one run.
type LLMStats struct {
	Provider         string        `json:"provider,omitempty"`
	Model            string        `json:"model,omitempty"`
	PromptTokens     int           `json:"prompt_tokens,omitempty"`
	CompletionTokens int           `json:"completion_tokens,omitempty"`
	Duration         time.Duration `json:"duration,omitempty"`
	Err              string        `json:"error,omitempty"`
}

// SinkStats records one delivery attempt.
type SinkStats struct {
	Sink     string        `json:"sink"`
	Duration time.Duration `json:"duration"`
	Err      string        `json:"error,omitempty"`
}

// Report is the single canonical type flowing between stages. Sinks receive
// it with Sinks empty; the run history stores it with Sinks filled in.
type Report struct {
	Title       string        `json:"title"`
	Window      Window        `json:"window"`
	Verdict     Severity      `json:"verdict"`
	Summary     string        `json:"summary"` // LLM text; empty in degraded mode
	Findings    []Finding     `json:"findings"`
	Stats       []SourceStats `json:"stats"`
	LLM         LLMStats      `json:"llm"`
	Sinks       []SinkStats   `json:"sinks,omitempty"`
	GeneratedAt time.Time     `json:"generated_at"`
	// Cancelled is set by Run itself, at the exact point it notices its
	// context is done and stops early — never inferred afterwards from a
	// second, separately-timed read of the context. A caller that checked
	// ctx.Err() only after Run returned could see a context cancelled a
	// moment too late, after the run had already delivered in full, and
	// wrongly mark a delivered digest as cancelled.
	Cancelled bool `json:"cancelled,omitempty"`
}

// Request is the LLM input: System carries instructions, User carries the
// fenced untrusted data.
type Request struct {
	System string
	User   string
}

// Response is the LLM output with its token cost.
type Response struct {
	Text             string
	Model            string
	PromptTokens     int
	CompletionTokens int
}
