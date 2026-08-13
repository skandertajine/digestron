// Package prometheus pulls counts from a Prometheus-compatible API. Each
// configured query yields one Finding: the summed sample values become the
// count, one detail entry per series. Instant queries are evaluated at the
// end of the window — pair them with increase()/rate() over the window
// duration. Range queries take the last sample of each series.
package prometheus

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/prometheus/client_golang/api"
	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"

	"github.com/skandertajine/digestron/internal/config"
	"github.com/skandertajine/digestron/internal/digest"
	"github.com/skandertajine/digestron/internal/httpx"
	"github.com/skandertajine/digestron/internal/source"
)

func init() {
	source.Register("prometheus", New)
}

type Config struct {
	URL     string        `koanf:"url"`
	Queries []QueryConfig `koanf:"queries"`
}

type QueryConfig struct {
	Name     string            `koanf:"name"`
	Query    string            `koanf:"query"`
	Range    bool              `koanf:"range"`
	Step     time.Duration     `koanf:"step"`
	Severity digest.Thresholds `koanf:"severity"`
}

type Source struct {
	name    string
	api     v1.API
	queries []QueryConfig
}

func New(name string, settings map[string]any) (digest.Source, error) {
	var cfg Config
	if err := config.DecodeSettings(settings, &cfg); err != nil {
		return nil, err
	}
	if cfg.URL == "" {
		return nil, fmt.Errorf("url is required")
	}
	if len(cfg.Queries) == 0 {
		return nil, fmt.Errorf("at least one query is required")
	}
	for i, q := range cfg.Queries {
		if q.Name == "" || q.Query == "" {
			return nil, fmt.Errorf("queries[%d]: name and query are required", i)
		}
		if q.Range && q.Step <= 0 {
			return nil, fmt.Errorf("query %q: range queries need a step", q.Name)
		}
	}

	client, err := api.NewClient(api.Config{Address: cfg.URL, RoundTripper: httpx.Client.Transport})
	if err != nil {
		return nil, err
	}
	return &Source{name: name, api: v1.NewAPI(client), queries: cfg.Queries}, nil
}

func (s *Source) Name() string { return s.name }

func (s *Source) Collect(ctx context.Context, w digest.Window) ([]digest.Finding, error) {
	findings := make([]digest.Finding, 0, len(s.queries))
	for _, q := range s.queries {
		var (
			value model.Value
			err   error
		)
		if q.Range {
			value, _, err = s.api.QueryRange(ctx, q.Query, v1.Range{Start: w.From, End: w.To, Step: q.Step})
		} else {
			value, _, err = s.api.Query(ctx, q.Query, w.To)
		}
		if err != nil {
			return nil, fmt.Errorf("query %q: %w", q.Name, err)
		}

		count, details := flatten(value)
		findings = append(findings, digest.Finding{
			Source:   s.name,
			Title:    q.Name,
			Count:    count,
			Severity: digest.Score(count, q.Severity),
			Details:  details,
		})
	}
	return findings, nil
}

// flatten reduces any Prometheus result type to a count and a per-series
// breakdown.
func flatten(value model.Value) (int, map[string]int) {
	switch v := value.(type) {
	case model.Vector:
		if len(v) == 0 {
			return 0, nil
		}
		details := make(map[string]int, len(v))
		total := 0.0
		for _, sample := range v {
			total += float64(sample.Value)
			details[sample.Metric.String()] = int(math.Round(float64(sample.Value)))
		}
		return int(math.Round(total)), details
	case model.Matrix:
		if len(v) == 0 {
			return 0, nil
		}
		details := make(map[string]int, len(v))
		total := 0.0
		for _, series := range v {
			if len(series.Values) == 0 {
				continue
			}
			last := float64(series.Values[len(series.Values)-1].Value)
			total += last
			details[series.Metric.String()] = int(math.Round(last))
		}
		return int(math.Round(total)), details
	case *model.Scalar:
		return int(math.Round(float64(v.Value))), nil
	default:
		return 0, nil
	}
}

// Check probes the build info endpoint.
func (s *Source) Check(ctx context.Context) error {
	_, err := s.api.Buildinfo(ctx)
	return err
}
