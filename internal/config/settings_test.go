package config

import (
	"strings"
	"testing"
	"time"
)

func TestDecodeSettings(t *testing.T) {
	type target struct {
		URL       string        `koanf:"url"`
		Password  Secret        `koanf:"password"`
		KeepAlive time.Duration `koanf:"keep_alive"`
		NumCtx    int           `koanf:"num_ctx"`
	}
	var out target
	err := DecodeSettings(map[string]any{
		"url":        "http://x:9200",
		"password":   "hunter2",
		"keep_alive": "10m",
		"num_ctx":    8192,
	}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if out.URL != "http://x:9200" || out.Password.Reveal() != "hunter2" ||
		out.KeepAlive != 10*time.Minute || out.NumCtx != 8192 {
		t.Errorf("decoded = %+v", out)
	}
}

func TestDecodeSettingsStrictRejectsUnknownKeys(t *testing.T) {
	type target struct {
		Model       string   `koanf:"model"`
		Temperature *float64 `koanf:"temperature"`
	}
	settings := map[string]any{"model": "m", "temprature": 0.2}

	var lax target
	if err := DecodeSettings(settings, &lax); err != nil {
		t.Fatalf("the lax decoder must keep ignoring unknown keys: %v", err)
	}

	var strict target
	err := DecodeSettingsStrict(settings, &strict)
	if err == nil || !strings.Contains(err.Error(), "temprature") {
		t.Fatalf("err = %v, want the misspelt key named", err)
	}

	ok := map[string]any{"model": "m", "temperature": 0.2}
	if err := DecodeSettingsStrict(ok, &strict); err != nil || strict.Temperature == nil || *strict.Temperature != 0.2 {
		t.Errorf("known keys only: err = %v, decoded = %+v", err, strict)
	}
}
