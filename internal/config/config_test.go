package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadExample(t *testing.T) {
	cfg, err := Load("../../config.example.yaml")
	if err != nil {
		t.Fatalf("config.example.yaml must load: %v", err)
	}
	if cfg.Digest.Window <= 0 {
		t.Errorf("window not set: %s", cfg.Digest.Window)
	}
}

func TestDefaults(t *testing.T) {
	p := writeTemp(t, "digest:\n  title: t\n")
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Digest.Window != time.Hour {
		t.Errorf("default window = %s, want 1h", cfg.Digest.Window)
	}
	if cfg.LLM.Type != "noop" {
		t.Errorf("default llm.type = %q, want noop", cfg.LLM.Type)
	}
	if cfg.LLM.Timeout != 120*time.Second {
		t.Errorf("default llm.timeout = %s, want 120s", cfg.LLM.Timeout)
	}
}

func TestEnvOverride(t *testing.T) {
	t.Setenv("DIGESTRON_DIGEST__WINDOW", "2h")
	t.Setenv("DIGESTRON_LLM__MAX_CHARS", "900")
	p := writeTemp(t, "digest:\n  window: 1h\n")
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Digest.Window != 2*time.Hour {
		t.Errorf("window = %s, want 2h (env override)", cfg.Digest.Window)
	}
	if cfg.LLM.MaxChars != 900 {
		t.Errorf("max_chars = %d, want 900 (env override)", cfg.LLM.MaxChars)
	}
}

func TestExpandEnv(t *testing.T) {
	t.Setenv("MY_TOKEN", "s3cret")
	out, err := ExpandEnv([]byte("token: ${MY_TOKEN}\nquery: cost > $100"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "token: s3cret") {
		t.Errorf("variable not expanded: %s", out)
	}
	if !strings.Contains(string(out), "cost > $100") {
		t.Errorf("bare $ must stay intact: %s", out)
	}
	if _, err := ExpandEnv([]byte("x: ${DIGESTRON_TEST_UNSET_VAR}")); err == nil {
		t.Error("unset variable must be an error")
	}
}

func TestValidation(t *testing.T) {
	cases := []struct {
		name, yaml, wantErr string
	}{
		{"bad log level", "log:\n  level: loud\n", "log.level"},
		{"zero window", "digest:\n  window: 0s\n", "window"},
		{"bad timezone", "schedule:\n  timezone: Mars/Olympus\n", "timezone"},
		{"unnamed source", "sources:\n  - type: elasticsearch\n", "name is required"},
		{"untyped source", "sources:\n  - name: x\n", "type is required"},
		{"duplicate sink", "sinks:\n  - {name: a, type: webhook}\n  - {name: a, type: webhook}\n", "duplicate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeTemp(t, tc.yaml))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestSecretNeverLeaks(t *testing.T) {
	s := Secret("hunter2")
	for name, got := range map[string]string{
		"fmt %v":  fmt.Sprintf("%v", s),
		"String":  s.String(),
		"fmt %#v": fmt.Sprintf("%#v", s),
	} {
		if strings.Contains(got, "hunter2") {
			t.Errorf("%s leaks the secret: %s", name, got)
		}
	}

	j, err := json.Marshal(struct{ P Secret }{s})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(j, []byte("hunter2")) {
		t.Errorf("json leaks the secret: %s", j)
	}

	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "password", s)
	if bytes.Contains(buf.Bytes(), []byte("hunter2")) {
		t.Errorf("slog leaks the secret: %s", buf.String())
	}

	if s.Reveal() != "hunter2" {
		t.Errorf("Reveal() = %q", s.Reveal())
	}
}
