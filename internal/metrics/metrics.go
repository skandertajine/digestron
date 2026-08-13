// Package metrics holds the digestron_* Prometheus metrics on a custom
// registry, so tests stay deterministic and /metrics only exposes what we
// mean to expose.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

type Metrics struct {
	Registry *prometheus.Registry

	LastSuccessTimestamp prometheus.Gauge
	LastRunTimestamp     prometheus.Gauge
	RunDuration          prometheus.Histogram
	RunsTotal            *prometheus.CounterVec // status
	ModuleDuration       *prometheus.HistogramVec
	ModuleRunsTotal      *prometheus.CounterVec // module, status
	FindingsTotal        *prometheus.CounterVec // module, severity
	NotificationsTotal   *prometheus.CounterVec // sink, status
	LLMTokensTotal       *prometheus.CounterVec // model, kind (prompt|completion)
	LLMDuration          prometheus.Histogram
	BuildInfo            *prometheus.GaugeVec // version, commit, goversion
}

func New() *Metrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	m := &Metrics{
		Registry: reg,
		LastSuccessTimestamp: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "digestron_last_success_timestamp_seconds",
			Help: "Unix time of the last fully successful run.",
		}),
		LastRunTimestamp: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "digestron_last_run_timestamp_seconds",
			Help: "Unix time of the last run, successful or not.",
		}),
		RunDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "digestron_run_duration_seconds",
			Help:    "Wall time of a whole digest run.",
			Buckets: prometheus.ExponentialBuckets(0.5, 2, 10),
		}),
		RunsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "digestron_runs_total",
			Help: "Digest runs by outcome.",
		}, []string{"status"}),
		ModuleDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "digestron_module_duration_seconds",
			Help:    "Time spent in each source module.",
			Buckets: prometheus.ExponentialBuckets(0.1, 2, 10),
		}, []string{"module"}),
		ModuleRunsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "digestron_module_runs_total",
			Help: "Source module executions by outcome.",
		}, []string{"module", "status"}),
		FindingsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "digestron_findings_total",
			Help: "Findings collected, by module and severity.",
		}, []string{"module", "severity"}),
		NotificationsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "digestron_notifications_total",
			Help: "Digest deliveries by sink and outcome.",
		}, []string{"sink", "status"}),
		LLMTokensTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "digestron_llm_tokens_total",
			Help: "Tokens consumed by the LLM, by model and kind.",
		}, []string{"model", "kind"}),
		LLMDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "digestron_llm_duration_seconds",
			Help:    "Latency of LLM completions.",
			Buckets: prometheus.ExponentialBuckets(0.5, 2, 10),
		}),
		BuildInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "digestron_build_info",
			Help: "Build metadata; value is always 1.",
		}, []string{"version", "commit", "goversion"}),
	}

	reg.MustRegister(
		m.LastSuccessTimestamp, m.LastRunTimestamp, m.RunDuration, m.RunsTotal,
		m.ModuleDuration, m.ModuleRunsTotal, m.FindingsTotal,
		m.NotificationsTotal, m.LLMTokensTotal, m.LLMDuration, m.BuildInfo,
	)
	return m
}

// SetBuildInfo stamps the build metadata gauge.
func (m *Metrics) SetBuildInfo(version, commit, goversion string) {
	m.BuildInfo.WithLabelValues(version, commit, goversion).Set(1)
}
