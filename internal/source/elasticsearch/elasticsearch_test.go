package elasticsearch

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/skandertajine/digestron/internal/digest"
)

func settingsWithCustomQuery(url string) map[string]any {
	return map[string]any{
		"url":      url,
		"index":    "logs-*",
		"username": "elastic",
		"password": "hunter2",
		"queries": []any{
			map[string]any{
				"name":     "http 500s",
				"severity": map[string]any{"warning": 1, "critical": 20},
				"body": map[string]any{
					"size": 0,
					"query": map[string]any{
						"bool": map[string]any{
							"filter": []any{
								map[string]any{"range": map[string]any{"@timestamp": map[string]any{"gte": "{{.From}}", "lte": "{{.To}}"}}},
								map[string]any{"term": map[string]any{"http.response.status_code": 500}},
							},
						},
					},
					"aggs": map[string]any{
						"breakdown": map[string]any{"terms": map[string]any{"field": "client.ip", "size": 10}},
					},
				},
			},
		},
	}
}

func TestCollect(t *testing.T) {
	var gotPath, gotAuth string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{
			"hits": {"total": {"value": 42}},
			"aggregations": {"breakdown": {"buckets": [
				{"key": "1.2.3.4", "doc_count": 30},
				{"key": "5.6.7.8", "doc_count": 12}
			]}}
		}`))
	}))
	defer srv.Close()

	src, err := New("es-test", settingsWithCustomQuery(srv.URL))
	if err != nil {
		t.Fatal(err)
	}

	from := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	findings, err := src.Collect(context.Background(), digest.Window{From: from, To: from.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}

	if gotPath != "/logs-*/_search" {
		t.Errorf("path = %q, want /logs-*/_search", gotPath)
	}
	if !strings.HasPrefix(gotAuth, "Basic ") {
		t.Errorf("missing basic auth, got %q", gotAuth)
	}
	var sent map[string]any
	if err := json.Unmarshal(gotBody, &sent); err != nil {
		t.Fatalf("body is not valid JSON after templating: %v\n%s", err, gotBody)
	}
	if !strings.Contains(string(gotBody), "2026-08-13T10:00:00Z") ||
		!strings.Contains(string(gotBody), "2026-08-13T11:00:00Z") {
		t.Errorf("window not templated into the body: %s", gotBody)
	}

	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	f := findings[0]
	if f.Source != "es-test" || f.Title != "http 500s" || f.Count != 42 {
		t.Errorf("finding = %+v", f)
	}
	if f.Severity != digest.SeverityCritical {
		t.Errorf("severity = %s, want critical (42 >= 20)", f.Severity)
	}
	if f.Details["1.2.3.4"] != 30 || f.Details["5.6.7.8"] != 12 {
		t.Errorf("details = %v", f.Details)
	}
}

func TestCollectServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusBadRequest)
	}))
	defer srv.Close()

	src, err := New("es-test", settingsWithCustomQuery(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.Collect(context.Background(), digest.Window{}); err == nil {
		t.Error("want error on non-200 response")
	}
}

func TestNewValidation(t *testing.T) {
	cases := []struct {
		name     string
		settings map[string]any
		wantErr  string
	}{
		{"missing url", map[string]any{"queries": []any{map[string]any{"name": "x", "body": map[string]any{}}}}, "url is required"},
		{"no queries", map[string]any{"url": "http://x"}, "at least one query"},
		{"custom without name", map[string]any{"url": "http://x", "queries": []any{map[string]any{"body": map[string]any{"size": 0}}}}, "need a name"},
		{"neither preset nor body", map[string]any{"url": "http://x", "queries": []any{map[string]any{"name": "x"}}}, "either preset or body"},
		{"unknown preset", map[string]any{"url": "http://x", "queries": []any{map[string]any{"preset": "nope"}}}, "unknown preset"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New("es", tc.settings)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}
