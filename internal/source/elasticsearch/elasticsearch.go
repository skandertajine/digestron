// Package elasticsearch pulls aggregated counts from an Elasticsearch or
// OpenSearch cluster. Each configured query yields one Finding: hits.total
// becomes the count, and by convention a single terms aggregation named
// "breakdown" becomes the detail map.
package elasticsearch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

func (s *Source) Collect(ctx context.Context, w digest.Window) ([]digest.Finding, error) {
	findings := make([]digest.Finding, 0, len(s.queries))
	for _, q := range s.queries {
		f, err := s.run(ctx, q, w)
		if err != nil {
			return nil, fmt.Errorf("query %q: %w", q.title, err)
		}
		findings = append(findings, f)
	}
	return findings, nil
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
	Hits struct {
		Total struct {
			Value int `json:"value"`
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
