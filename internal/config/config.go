// Package config loads and validates the digestron configuration from a YAML
// file, with ${VAR} expansion for secrets and DIGESTRON_* env overrides
// ("__" is the nesting separator: DIGESTRON_LLM__TIMEOUT=180s → llm.timeout).
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/knadh/koanf/v2"
)

const envPrefix = "DIGESTRON_"

type Config struct {
	Log      LogConfig      `koanf:"log"`
	Digest   DigestConfig   `koanf:"digest"`
	Schedule ScheduleConfig `koanf:"schedule"`
	Metrics  MetricsConfig  `koanf:"metrics"`
	History  HistoryConfig  `koanf:"history"`
	Sources  []ModuleConfig `koanf:"sources"`
	LLM      LLMConfig      `koanf:"llm"`
	Sinks    []ModuleConfig `koanf:"sinks"`
}

type LogConfig struct {
	Level string `koanf:"level"` // debug | info | warn | error
}

type DigestConfig struct {
	Title    string        `koanf:"title"`
	Window   time.Duration `koanf:"window"`   // time range each run covers
	Language string        `koanf:"language"` // language of the LLM summary
	Context  string        `koanf:"context"`  // free text appended to the system prompt
}

type ScheduleConfig struct {
	Cron       string `koanf:"cron"`     // serve mode only
	Timezone   string `koanf:"timezone"` // IANA name, e.g. Europe/Paris
	RunOnStart bool   `koanf:"run_on_start"`
}

type MetricsConfig struct {
	Listen string `koanf:"listen"` // serve mode: /metrics, /healthz and the UI
}

type HistoryConfig struct {
	Path string `koanf:"path"` // run history file; empty disables persistence
	Keep int    `koanf:"keep"` // max runs kept in the file
}

// ModuleConfig describes one source or sink. Settings is opaque here and
// decoded by the module factory, so an invalid module fails with its name.
type ModuleConfig struct {
	Name     string         `koanf:"name"`
	Type     string         `koanf:"type"`
	Timeout  time.Duration  `koanf:"timeout"`
	Settings map[string]any `koanf:"settings"`
}

type LLMConfig struct {
	Type     string         `koanf:"type"` // ollama | openai-compatible | noop
	Timeout  time.Duration  `koanf:"timeout"`
	Retries  int            `koanf:"retries"`   // on rate-limit / unavailable only
	MaxChars int            `koanf:"max_chars"` // hard cap on the summary
	Settings map[string]any `koanf:"settings"`
}

func Defaults() *Config {
	return &Config{
		Log:     LogConfig{Level: "info"},
		Digest:  DigestConfig{Title: "Security digest", Window: time.Hour, Language: "en"},
		Metrics: MetricsConfig{Listen: ":9090"},
		History: HistoryConfig{Keep: 200},
		LLM:     LLMConfig{Type: "noop", Timeout: 120 * time.Second, Retries: 2, MaxChars: 1500},
	}
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- path is the operator-provided config location
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	expanded, err := ExpandEnv(raw)
	if err != nil {
		return nil, err
	}

	k := koanf.New(".")
	if err := k.Load(rawbytes.Provider(expanded), yaml.Parser()); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if err := k.Load(env.Provider(envPrefix, ".", envKey), nil); err != nil {
		return nil, fmt.Errorf("config: env overrides: %w", err)
	}

	cfg := Defaults()
	uc := koanf.UnmarshalConf{Tag: "koanf", DecoderConfig: &mapstructure.DecoderConfig{
		DecodeHook:       mapstructure.StringToTimeDurationHookFunc(),
		Result:           cfg,
		WeaklyTypedInput: true,
	}}
	if err := k.UnmarshalWithConf("", cfg, uc); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// envKey maps DIGESTRON_DIGEST__WINDOW to digest.window: "__" separates
// nesting levels so single underscores survive inside key names.
func envKey(s string) string {
	s = strings.TrimPrefix(s, envPrefix)
	return strings.ReplaceAll(strings.ToLower(s), "__", ".")
}

func (c *Config) Validate() error {
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config: invalid log.level %q", c.Log.Level)
	}
	if c.Digest.Window <= 0 {
		return fmt.Errorf("config: digest.window must be positive, got %s", c.Digest.Window)
	}
	if c.Schedule.Timezone != "" {
		if _, err := time.LoadLocation(c.Schedule.Timezone); err != nil {
			return fmt.Errorf("config: invalid schedule.timezone %q: %w", c.Schedule.Timezone, err)
		}
	}
	if c.LLM.Type == "" {
		return fmt.Errorf("config: llm.type is required (use \"noop\" to disable)")
	}
	if err := validateModules("sources", c.Sources); err != nil {
		return err
	}
	return validateModules("sinks", c.Sinks)
}

func validateModules(kind string, mods []ModuleConfig) error {
	seen := map[string]bool{}
	for i, m := range mods {
		if m.Name == "" {
			return fmt.Errorf("config: %s[%d]: name is required", kind, i)
		}
		if m.Type == "" {
			return fmt.Errorf("config: %s %q: type is required", kind, m.Name)
		}
		if seen[m.Name] {
			return fmt.Errorf("config: duplicate %s name %q", kind, m.Name)
		}
		seen[m.Name] = true
	}
	return nil
}
