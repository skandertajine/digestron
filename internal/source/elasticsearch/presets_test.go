package elasticsearch

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/skandertajine/digestron/internal/digest"
)

// Every embedded preset must render into valid JSON once the window is
// templated in — this is what breaks in CI when someone edits a body.
func TestPresetsRenderToValidJSON(t *testing.T) {
	if len(presets) == 0 {
		t.Fatal("no presets embedded")
	}
	for name, p := range presets {
		t.Run(name, func(t *testing.T) {
			tmpl, err := template.New(name).Parse(p.Body)
			if err != nil {
				t.Fatalf("body does not parse as a template: %v", err)
			}
			var buf bytes.Buffer
			err = tmpl.Execute(&buf, map[string]string{
				"From": time.Now().UTC().Format(time.RFC3339),
				"To":   time.Now().UTC().Format(time.RFC3339),
			})
			if err != nil {
				t.Fatal(err)
			}
			var body map[string]any
			if err := json.Unmarshal(buf.Bytes(), &body); err != nil {
				t.Fatalf("rendered body is not valid JSON: %v\n%s", err, buf.String())
			}
			if !strings.Contains(p.Body, "{{.From}}") || !strings.Contains(p.Body, "{{.To}}") {
				t.Error("preset body must template the time window")
			}
			// The two conventions elasticsearch.go reads the response with:
			// hits.total is the count (so documents are pure overhead) and
			// the detail map comes from the agg named "breakdown".
			if body["size"] != float64(0) {
				t.Errorf(`size = %v, want 0`, body["size"])
			}
			// Without this Elasticsearch stops counting at 10000 and reports
			// exactly that, flagged only by a hits.total.relation of "gte" —
			// so a busy hour, the one that matters, is silently flattened.
			if body["track_total_hits"] != true {
				t.Errorf(`track_total_hits = %v, want true: hits.total caps at 10000 otherwise`, body["track_total_hits"])
			}
			aggs, _ := body["aggs"].(map[string]any)
			if _, ok := aggs["breakdown"]; !ok {
				t.Errorf("aggs = %v, want one named breakdown", body["aggs"])
			}
			if p.Title == "" {
				t.Error("preset needs a title")
			}
		})
	}
}

func TestPresetResolutionWithOverrides(t *testing.T) {
	q, err := resolve(QueryConfig{Preset: "fail2ban"})
	if err != nil {
		t.Fatal(err)
	}
	if q.title != "fail2ban bans" {
		t.Errorf("title = %q", q.title)
	}
	if q.thresholds != (digest.Thresholds{Warning: 1, Critical: 5}) {
		t.Errorf("thresholds = %+v", q.thresholds)
	}

	q, err = resolve(QueryConfig{
		Preset:   "fail2ban",
		Name:     "bans du pi",
		Severity: digest.Thresholds{Warning: 10, Critical: 100},
	})
	if err != nil {
		t.Fatal(err)
	}
	if q.title != "bans du pi" {
		t.Errorf("overridden title = %q", q.title)
	}
	if q.thresholds != (digest.Thresholds{Warning: 10, Critical: 100}) {
		t.Errorf("overridden thresholds = %+v", q.thresholds)
	}
}
