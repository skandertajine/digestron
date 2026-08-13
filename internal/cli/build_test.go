package cli

import (
	"testing"
	"time"

	"github.com/skandertajine/digestron/internal/digest"

	_ "github.com/skandertajine/digestron/internal/llm/noop"
	_ "github.com/skandertajine/digestron/internal/llm/ollama"
	_ "github.com/skandertajine/digestron/internal/llm/openai"
	_ "github.com/skandertajine/digestron/internal/sink/email"
	_ "github.com/skandertajine/digestron/internal/sink/homeassistant"
	_ "github.com/skandertajine/digestron/internal/sink/webhook"
	_ "github.com/skandertajine/digestron/internal/source/elasticsearch"
	_ "github.com/skandertajine/digestron/internal/source/prometheus"
)

// The example configuration must not only parse: every module in it must
// instantiate through the real registries. This breaks in CI the moment a
// setting is renamed without updating the example.
func TestExampleConfigBuildsEveryModule(t *testing.T) {
	t.Setenv("ES_PASSWORD", "x")
	t.Setenv("HA_TOKEN", "x")
	t.Setenv("SMTP_PASSWORD", "x")
	t.Setenv("HOOK_TOKEN", "x")

	app, err := Build("../../config.example.yaml", false)
	if err != nil {
		t.Fatalf("example config must build: %v", err)
	}
	if len(app.Sources) != 2 || len(app.Sinks) != 3 || app.LLM == nil {
		t.Errorf("modules built: %d sources, %d sinks, llm=%v", len(app.Sources), len(app.Sinks), app.LLM)
	}
	if app.Runner == nil || app.Store == nil {
		t.Error("runner and store must be wired")
	}
}

func TestRecordSuccessPolicy(t *testing.T) {
	cases := []struct {
		name    string
		report  digest.Report
		success bool
	}{
		{"all good", digest.Report{
			Stats: []digest.SourceStats{{Source: "a"}},
			Sinks: []digest.SinkStats{{Sink: "s"}},
		}, true},
		{"llm failed only", digest.Report{
			Stats: []digest.SourceStats{{Source: "a"}},
			LLM:   digest.LLMStats{Err: "down"},
			Sinks: []digest.SinkStats{{Sink: "s"}},
		}, true},
		{"one source failed", digest.Report{
			Stats: []digest.SourceStats{{Source: "a"}, {Source: "b", Err: "down"}},
			Sinks: []digest.SinkStats{{Sink: "s"}},
		}, true},
		{"all sources failed", digest.Report{
			Stats: []digest.SourceStats{{Source: "a", Err: "down"}, {Source: "b", Err: "down"}},
			Sinks: []digest.SinkStats{{Sink: "s"}},
		}, false},
		{"a sink failed", digest.Report{
			Stats: []digest.SourceStats{{Source: "a"}},
			Sinks: []digest.SinkStats{{Sink: "s", Err: "teapot"}},
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ES_PASSWORD", "x")
			t.Setenv("HA_TOKEN", "x")
			t.Setenv("SMTP_PASSWORD", "x")
			t.Setenv("HOOK_TOKEN", "x")
			app, err := Build("../../config.example.yaml", true)
			if err != nil {
				t.Fatal(err)
			}
			if got := app.Record(tc.report, time.Second); got != tc.success {
				t.Errorf("Record() success = %v, want %v", got, tc.success)
			}
		})
	}
}
