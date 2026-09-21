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

func settingsWithTwoQueries(url string) map[string]any {
	query := func(name, marker string) map[string]any {
		return map[string]any{
			"name": name,
			"body": map[string]any{
				"size": 0,
				"query": map[string]any{"bool": map[string]any{"filter": []any{
					map[string]any{"range": map[string]any{"@timestamp": map[string]any{"gte": "{{.From}}", "lte": "{{.To}}"}}},
					map[string]any{"term": map[string]any{"tag": marker}},
				}}},
			},
		}
	}
	return map[string]any{
		"url":     url,
		"index":   "logs-*",
		"queries": []any{query("ssh auth failures", "rejected"), query("firewall blocked flows", "accepted")},
	}
}

// A body Elasticsearch rejects must cost its own finding and nothing else.
// The first query failing used to abort the source, so the blocked flows the
// second one counts never reached the digest at all.
func TestCollectPartialFailure(t *testing.T) {
	var ran int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ran++
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "rejected") {
			http.Error(w, `{"error":{"type":"query_shard_exception"}}`, http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"hits": {"total": {"value": 936}}}`))
	}))
	defer srv.Close()

	src, err := New("es-test", settingsWithTwoQueries(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	findings, err := src.Collect(context.Background(), digest.Window{})

	if ran != 2 {
		t.Errorf("queries executed = %d, want 2: one failure must not skip the rest", ran)
	}
	if len(findings) != 1 || findings[0].Title != "firewall blocked flows" || findings[0].Count != 936 {
		t.Fatalf("findings = %+v, want the surviving query's", findings)
	}
	if err == nil {
		t.Fatal("a failed query must not be silent")
	}
	if !strings.Contains(err.Error(), "1 of 2 queries failed") ||
		!strings.Contains(err.Error(), "ssh auth failures") {
		t.Errorf("error must name the count and the query: %v", err)
	}
	if strings.Contains(err.Error(), "\n") {
		t.Errorf("error must stay on one line, it is rendered into the digest: %q", err)
	}
}

// Elasticsearch answers 200 with partial results when it gives up on a shard
// or runs out of time, and when hits.total hits its 10000 ceiling. Each one
// yields a number that looks like a measurement and is not one — the count
// has to be refused, not quietly reported.
func TestCollectRefusesUntrustworthyCounts(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			"timed out",
			`{"timed_out": true, "_shards": {"total": 3, "successful": 3, "failed": 0}, "hits": {"total": {"value": 12, "relation": "eq"}}}`,
			"timed out",
		},
		{
			"shard failed",
			`{"timed_out": false, "_shards": {"total": 3, "successful": 2, "failed": 1}, "hits": {"total": {"value": 12, "relation": "eq"}}}`,
			"1 of 3 shards failed",
		},
		{
			"hits.total truncated at the default ceiling",
			`{"timed_out": false, "_shards": {"total": 1, "successful": 1, "failed": 0}, "hits": {"total": {"value": 10000, "relation": "gte"}}}`,
			"track_total_hits",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			src, err := New("es-test", settingsWithCustomQuery(srv.URL))
			if err != nil {
				t.Fatal(err)
			}
			findings, err := src.Collect(context.Background(), digest.Window{})

			if len(findings) != 0 {
				t.Errorf("findings = %+v, want none: an undercount reported as a fact is worse than a gap", findings)
			}
			if err == nil {
				t.Fatalf("a partial response must not pass for a complete one")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// The ordinary case must stay ordinary: a complete response says so, and an
// older server that omits hits.total.relation is not treated as truncated.
func TestCollectAcceptsCompleteResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"timed_out": false, "_shards": {"total": 1, "successful": 1, "failed": 0},
			"hits": {"total": {"value": 7}}}`))
	}))
	defer srv.Close()

	src, err := New("es-test", settingsWithCustomQuery(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	findings, err := src.Collect(context.Background(), digest.Window{})
	if err != nil {
		t.Fatalf("Collect() = %v, want no error", err)
	}
	if len(findings) != 1 || findings[0].Count != 7 {
		t.Errorf("findings = %+v, want one count of 7", findings)
	}
}
