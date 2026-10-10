package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/knadh/koanf/parsers/yaml"
)

// The dev ConfigMap is applied by ArgoCD as soon as it lands on dev, and the
// pod restarts on it: a key the code no longer accepts (the ollama settings
// are strict) would crash-loop the instance. Build it here, offline, the way
// serve does at start.
func TestDevConfigMapBuildsEveryModule(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/dev/configmap.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cm, err := yaml.Parser().Unmarshal(raw)
	if err != nil {
		t.Fatalf("configmap: %v", err)
	}
	data, _ := cm["data"].(map[string]any)
	cfgYAML, _ := data["config.yaml"].(string)
	if cfgYAML == "" {
		t.Fatal("configmap has no data.config.yaml")
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ES_PASSWORD", "x")
	t.Setenv("HA_TOKEN", "x")

	app, err := Build(path, false)
	if err != nil {
		t.Fatalf("dev config must build: %v", err)
	}
	if len(app.Sources) == 0 || len(app.Sinks) == 0 || app.LLM == nil {
		t.Errorf("modules built: %d sources, %d sinks, llm=%v", len(app.Sources), len(app.Sinks), app.LLM)
	}
}
