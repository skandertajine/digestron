package prometheus

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/skandertajine/digestron/internal/digest"
)

func TestCollectInstantQuery(t *testing.T) {
	var gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = r.ParseForm()
		gotQuery = r.Form.Get("query")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[
			{"metric":{"instance":"node1"},"value":[1755080000,"3"]},
			{"metric":{"instance":"node2"},"value":[1755080000,"2"]}
		]}}`))
	}))
	defer srv.Close()

	src, err := New("prom", map[string]any{
		"url": srv.URL,
		"queries": []any{
			map[string]any{
				"name":     "targets down",
				"query":    "count(up == 0)",
				"severity": map[string]any{"warning": 1, "critical": 5},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	to := time.Date(2026, 8, 13, 11, 0, 0, 0, time.UTC)
	findings, err := src.Collect(context.Background(), digest.Window{From: to.Add(-time.Hour), To: to})
	if err != nil {
		t.Fatal(err)
	}

	if gotPath != "/api/v1/query" {
		t.Errorf("path = %q, want /api/v1/query", gotPath)
	}
	if gotQuery != "count(up == 0)" {
		t.Errorf("query = %q", gotQuery)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	f := findings[0]
	if f.Count != 5 || f.Severity != digest.SeverityCritical {
		t.Errorf("finding = %+v, want count 5 critical", f)
	}
	if f.Details[`{instance="node1"}`] != 3 {
		t.Errorf("details = %v", f.Details)
	}
}

func TestCollectEmptyVector(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
	}))
	defer srv.Close()

	src, err := New("prom", map[string]any{
		"url":     srv.URL,
		"queries": []any{map[string]any{"name": "x", "query": "up", "severity": map[string]any{"warning": 1}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	findings, err := src.Collect(context.Background(), digest.Window{To: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Count != 0 || findings[0].Severity != digest.SeverityInfo {
		t.Errorf("empty vector finding = %+v, want count 0 info", findings[0])
	}
}

func TestNewValidation(t *testing.T) {
	cases := []struct {
		name     string
		settings map[string]any
		wantErr  string
	}{
		{"missing url", map[string]any{"queries": []any{map[string]any{"name": "x", "query": "up"}}}, "url is required"},
		{"no queries", map[string]any{"url": "http://x"}, "at least one query"},
		{"unnamed", map[string]any{"url": "http://x", "queries": []any{map[string]any{"query": "up"}}}, "name and query"},
		{"range without step", map[string]any{"url": "http://x", "queries": []any{map[string]any{"name": "x", "query": "up", "range": true}}}, "need a step"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New("prom", tc.settings)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}
