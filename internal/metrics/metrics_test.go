package metrics

import (
	"strings"
	"testing"
)

func TestAllMetricsRegistered(t *testing.T) {
	m := New()
	m.SetBuildInfo("v0.1.0", "abc1234", "go1.26")
	m.RunsTotal.WithLabelValues("success").Inc()
	m.ModuleRunsTotal.WithLabelValues("es", "success").Inc()
	m.FindingsTotal.WithLabelValues("es", "warning").Add(3)
	m.NotificationsTotal.WithLabelValues("iphone", "success").Inc()
	m.LLMTokensTotal.WithLabelValues("qwen3:8b", "prompt").Add(100)
	m.LastRunTimestamp.Set(1)
	m.LastSuccessTimestamp.Set(1)
	m.RunDuration.Observe(1)
	m.ModuleDuration.WithLabelValues("es").Observe(0.2)
	m.LLMDuration.Observe(2)

	fams, err := m.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range fams {
		got[f.GetName()] = true
	}
	for _, want := range []string{
		"digestron_last_success_timestamp_seconds",
		"digestron_last_run_timestamp_seconds",
		"digestron_run_duration_seconds",
		"digestron_runs_total",
		"digestron_module_duration_seconds",
		"digestron_module_runs_total",
		"digestron_findings_total",
		"digestron_notifications_total",
		"digestron_llm_tokens_total",
		"digestron_llm_duration_seconds",
		"digestron_build_info",
	} {
		if !got[want] {
			t.Errorf("metric %s not gathered", want)
		}
	}
}

func TestBuildInfoLabels(t *testing.T) {
	m := New()
	m.SetBuildInfo("v1.2.3", "deadbeef", "go1.26")
	fams, err := m.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		if f.GetName() != "digestron_build_info" {
			continue
		}
		labels := map[string]string{}
		for _, l := range f.GetMetric()[0].GetLabel() {
			labels[l.GetName()] = l.GetValue()
		}
		if labels["version"] != "v1.2.3" || labels["commit"] != "deadbeef" || !strings.HasPrefix(labels["goversion"], "go") {
			t.Errorf("build_info labels = %v", labels)
		}
		return
	}
	t.Error("digestron_build_info not found")
}
