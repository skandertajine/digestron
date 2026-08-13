package config

import (
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
