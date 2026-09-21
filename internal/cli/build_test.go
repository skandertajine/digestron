package cli

import (
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

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
		// The production shape: one elasticsearch source, one preset of five
		// rejected. The digest went out with four real counts. Exiting
		// non-zero here fails the Job, and with backoffLimit 1 Kubernetes
		// reruns it and pushes the same window to the phone a second time.
		{"the only source was partial", digest.Report{
			Stats: []digest.SourceStats{{Source: "es", Findings: 4,
				Err: `1 of 5 queries failed: query "ssh auth failures": 400 Bad Request`}},
			Sinks: []digest.SinkStats{{Sink: "s"}},
		}, true},
		{"the only source produced nothing", digest.Report{
			Stats: []digest.SourceStats{{Source: "es", Findings: 0,
				Err: `5 of 5 queries failed: query "ssh auth failures": 400 Bad Request`}},
			Sinks: []digest.SinkStats{{Sink: "s"}},
		}, false},
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

// A partial source must not vanish into the success bucket: the run succeeded,
// but something is broken and the metric is where that gets alerted on.
func TestRecordLabelsPartialSourcesDistinctly(t *testing.T) {
	t.Setenv("ES_PASSWORD", "x")
	t.Setenv("HA_TOKEN", "x")
	t.Setenv("SMTP_PASSWORD", "x")
	t.Setenv("HOOK_TOKEN", "x")
	app, err := Build("../../config.example.yaml", true)
	if err != nil {
		t.Fatal(err)
	}

	app.Record(digest.Report{
		Stats: []digest.SourceStats{
			{Source: "es", Findings: 4, Err: "1 of 5 queries failed"},
			{Source: "prom", Findings: 0, Err: "dial tcp: refused"},
			{Source: "quiet", Findings: 2},
		},
		Sinks: []digest.SinkStats{{Sink: "s"}},
	}, time.Second)

	for _, tc := range []struct{ module, status string }{
		{"es", "partial"},
		{"prom", "error"},
		{"quiet", "success"},
	} {
		c, err := app.Metrics.ModuleRunsTotal.GetMetricWithLabelValues(tc.module, tc.status)
		if err != nil {
			t.Fatal(err)
		}
		var out dto.Metric
		if err := c.Write(&out); err != nil {
			t.Fatal(err)
		}
		if got := out.GetCounter().GetValue(); got != 1 {
			t.Errorf("module_runs_total{module=%q,status=%q} = %v, want 1", tc.module, tc.status, got)
		}
	}
}
