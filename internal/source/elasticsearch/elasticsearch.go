// Package elasticsearch pulls aggregated counts from an Elasticsearch or
// OpenSearch cluster. Each configured query yields one Finding: hits.total
// becomes the count, and by convention a single terms aggregation named
// "breakdown" becomes the detail map.
//
// A count is only reported when the cluster says it is complete: a timeout, a
// failed shard or a truncated hits.total all turn the query into a named
// failure instead of a number that reads like a fact.
package elasticsearch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"text/template"
	"time"

	"github.com/skandertajine/digestron/internal/config"
	"github.com/skandertajine/digestron/internal/digest"
	"github.com/skandertajine/digestron/internal/httpx"
	"github.com/skandertajine/digestron/internal/source"
)

func init() {
	source.Register("elasticsearch", New)
}

type Config struct {
	URL      string        `koanf:"url"`
	Index    string        `koanf:"index"`
	Username string        `koanf:"username"`
	Password config.Secret `koanf:"password"`
	Queries  []QueryConfig `koanf:"queries"`
}

type QueryConfig struct {
	Preset   string            `koanf:"preset"`
	Name     string            `koanf:"name"`
	Severity digest.Thresholds `koanf:"severity"`
	Body     map[string]any    `koanf:"body"`
}

type query struct {
	title      string
	thresholds digest.Thresholds
	body       *template.Template
}

type Source struct {
	name     string
	url      string
	index    string
	username string
	password config.Secret
	queries  []query
}

func New(name string, settings map[string]any) (digest.Source, error) {
	var cfg Config
	if err := config.DecodeSettings(settings, &cfg); err != nil {
		return nil, err
	}
	if cfg.URL == "" {
		return nil, fmt.Errorf("url is required")
	}
	if cfg.Index == "" {
		cfg.Index = "filebeat-*"
	}
	if len(cfg.Queries) == 0 {
		return nil, fmt.Errorf("at least one query is required")
	}

	s := &Source{name: name, url: cfg.URL, index: cfg.Index, username: cfg.Username, password: cfg.Password}
	for i, qc := range cfg.Queries {
		q, err := resolve(qc)
		if err != nil {
			return nil, fmt.Errorf("queries[%d]: %w", i, err)
		}
		s.queries = append(s.queries, q)
	}
	return s, nil
}

// resolve turns a query config into an executable query: either an embedded
// preset (optionally overridden) or a fully custom body.
func resolve(qc QueryConfig) (query, error) {
	var (
		title    string
		th       digest.Thresholds
		bodyText string
	)
	switch {
	case qc.Preset != "":
		p, err := lookupPreset(qc.Preset)
		if err != nil {
			return query{}, err
		}
		title, th, bodyText = p.Title, p.Thresholds, p.Body
		if qc.Name != "" {
			title = qc.Name
		}
	case qc.Body != nil:
		if qc.Name == "" {
			return query{}, fmt.Errorf("custom queries need a name")
		}
		raw, err := json.Marshal(qc.Body)
		if err != nil {
			return query{}, err
		}
		title, bodyText = qc.Name, string(raw)
	default:
		return query{}, fmt.Errorf("either preset or body is required")
	}

	if qc.Severity != (digest.Thresholds{}) {
		th = qc.Severity
	}
	tmpl, err := template.New(title).Parse(bodyText)
	if err != nil {
		return query{}, fmt.Errorf("query body: %w", err)
	}
	return query{title: title, thresholds: th, body: tmpl}, nil
}

func (s *Source) Name() string { return s.name }

// Collect runs every query even after one fails: a rejected body on one query
// must not blind the other four. Failures come back as an error alongside the
// findings that did succeed, so the run is partial and says so.
func (s *Source) Collect(ctx context.Context, w digest.Window) ([]digest.Finding, error) {
	findings := make([]digest.Finding, 0, len(s.queries))
	var errs []error
	for _, q := range s.queries {
		f, err := s.run(ctx, q, w)
		if err != nil {
			errs = append(errs, fmt.Errorf("query %q: %w", q.title, err))
			continue
		}
		findings = append(findings, f)
	}
	return findings, source.QueryErrors(len(s.queries), errs)
}

func (s *Source) run(ctx context.Context, q query, w digest.Window) (digest.Finding, error) {
	var body bytes.Buffer
	err := q.body.Execute(&body, map[string]string{
		"From": w.From.UTC().Format(time.RFC3339),
		"To":   w.To.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return digest.Finding{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.url+"/"+s.index+"/_search", bytes.NewReader(body.Bytes()))
	if err != nil {
		return digest.Finding{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.username != "" {
		req.SetBasicAuth(s.username, s.password.Reveal())
	}

	resp, err := httpx.Do(req, 2)
	if err != nil {
		return digest.Finding{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return digest.Finding{}, fmt.Errorf("elasticsearch: %s: %s", resp.Status, msg)
	}

	var out esResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return digest.Finding{}, err
	}
	// A _search that timed out or lost shards still answers 200 with a body
	// full of plausible partial results. Reporting that count as a fact is
	// the failure this whole source guards against, so the query is treated
	// as failed: a named gap beats a number that is quietly too small.
	if out.TimedOut {
		return digest.Finding{}, fmt.Errorf("elasticsearch: search timed out, the count would be an undercount")
	}
	if out.Shards.Failed > 0 {
		return digest.Finding{}, fmt.Errorf("elasticsearch: %d of %d shards failed, the count would be an undercount",
			out.Shards.Failed, out.Shards.Total)
	}
	// hits.total stops counting at 10000 unless the body sets
	// "track_total_hits": true, and says so with relation "gte". The embedded
	// presets set it; a custom query that does not must not pass a ceiling
	// off as a measurement — on a busy hour that is exactly 10000 every time.
	if rel := out.Hits.Total.Relation; rel != "" && rel != "eq" {
		return digest.Finding{}, fmt.Errorf("elasticsearch: hits.total is a lower bound (relation %q): set \"track_total_hits\": true in the query body", rel)
	}

	f := digest.Finding{
		Source:   s.name,
		Title:    q.title,
		Count:    out.Hits.Total.Value,
		Severity: digest.Score(out.Hits.Total.Value, q.thresholds),
	}
	if buckets := out.Aggregations.Breakdown.Buckets; len(buckets) > 0 {
		f.Details = make(map[string]int, len(buckets))
		for _, b := range buckets {
			f.Details[fmt.Sprint(b.Key)] = b.DocCount
		}
	}
	return f, nil
}

// Check probes the cluster root endpoint.
func (s *Source) Check(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url+"/", nil)
	if err != nil {
		return err
	}
	if s.username != "" {
		req.SetBasicAuth(s.username, s.password.Reveal())
	}
	resp, err := httpx.Do(req, 1)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("elasticsearch: %s", resp.Status)
	}
	return nil
}

type esResponse struct {
	// TimedOut and Shards carry the partial-failure signal: a _search that
	// gave up on a shard returns 200 with results from the rest.
	TimedOut bool `json:"timed_out"`
	Shards   struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Failed     int `json:"failed"`
	} `json:"_shards"`
	Hits struct {
		Total struct {
			Value int `json:"value"`
			// Relation is "eq" for a real count, "gte" for the 10000 ceiling.
			Relation string `json:"relation"`
		} `json:"total"`
	} `json:"hits"`
	Aggregations struct {
		Breakdown struct {
			Buckets []struct {
				Key      any `json:"key"`
				DocCount int `json:"doc_count"`
			} `json:"buckets"`
		} `json:"breakdown"`
	} `json:"aggregations"`
}

// investigateFacets are the fields worth a top-N for one IP: together they
// say what the address did (ports probed, URLs tried, jails hit) without
// shipping raw logs. A field absent from the matching documents simply
// yields no buckets.
var investigateFacets = []struct{ name, field string }{
	{"log_source", "source.keyword"},
	{"app", "log.syslog.appname.keyword"},
	{"fail2ban_jail", "fail2ban.jail.keyword"},
	{"dst_port", "destination.port"},
	{"protocol", "network.transport.keyword"},
	{"http_method", "http.request.method.keyword"},
	{"http_status", "http.response.status_code"},
	{"url", "url.original.keyword"},
	{"user_agent", "user_agent.original.keyword"},
}

const (
	facetSize   = 8
	sampleCount = 6
	sampleChars = 220
)

// Investigate drills into one IP over the window: first and last activity,
// a top-N per facet and a few distinct raw lines. One _search per IP.
func (s *Source) Investigate(ctx context.Context, w digest.Window, a *digest.Actor) error {
	aggs := map[string]any{
		"first": map[string]any{"min": map[string]any{"field": "@timestamp"}},
		"last":  map[string]any{"max": map[string]any{"field": "@timestamp"}},
	}
	for _, f := range investigateFacets {
		aggs["facet_"+f.name] = map[string]any{"terms": map[string]any{"field": f.field, "size": facetSize}}
	}
	body, err := json.Marshal(map[string]any{
		// The latest raw lines come as plain hits: a terms aggregation on
		// message.keyword builds an ordinal map over every message of the
		// index and trips the request circuit breaker on a small cluster.
		"size":             sampleCount,
		"_source":          []string{"message"},
		"sort":             []any{map[string]any{"@timestamp": "desc"}},
		"track_total_hits": false,
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"range": map[string]any{"@timestamp": map[string]any{
				"gte": w.From.UTC().Format(time.RFC3339), "lte": w.To.UTC().Format(time.RFC3339)}}},
			map[string]any{"term": map[string]any{"client.ip.keyword": a.IP}},
		}}},
		"aggs": aggs,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.url+"/"+s.index+"/_search", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.username != "" {
		req.SetBasicAuth(s.username, s.password.Reveal())
	}
	resp, err := httpx.Do(req, 1)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("elasticsearch: %s: %s", resp.Status, msg)
	}

	var out struct {
		Hits struct {
			Hits []struct {
				Source struct {
					Message string `json:"message"`
				} `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
		Aggregations map[string]struct {
			ValueAsString string `json:"value_as_string"`
			Buckets       []struct {
				Key      any `json:"key"`
				DocCount int `json:"doc_count"`
			} `json:"buckets"`
		} `json:"aggregations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}

	if t, err := time.Parse(time.RFC3339, out.Aggregations["first"].ValueAsString); err == nil {
		a.FirstSeen = t
	}
	if t, err := time.Parse(time.RFC3339, out.Aggregations["last"].ValueAsString); err == nil {
		a.LastSeen = t
	}
	for _, f := range investigateFacets {
		buckets := out.Aggregations["facet_"+f.name].Buckets
		if len(buckets) == 0 {
			continue
		}
		if a.Facets == nil {
			a.Facets = map[string]map[string]int{}
		}
		m := make(map[string]int, len(buckets))
		for _, b := range buckets {
			m[fmt.Sprint(b.Key)] = b.DocCount
		}
		a.Facets[f.name] = m
	}
	seen := map[string]bool{}
	for _, h := range out.Hits.Hits {
		line := strings.TrimSpace(h.Source.Message)
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
		if r := []rune(line); len(r) > sampleChars {
			line = string(r[:sampleChars]) + "…"
		}
		a.Samples = append(a.Samples, line)
	}
	return nil
}
