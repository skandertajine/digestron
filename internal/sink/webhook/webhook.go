// Package webhook is the generic escape hatch: any HTTP endpoint, custom
// method, headers and body template. Tokens go in headers, never in the URL —
// URLs end up in logs and proxies.
package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"text/template"

	"github.com/skandertajine/digestron/internal/config"
	"github.com/skandertajine/digestron/internal/digest"
	"github.com/skandertajine/digestron/internal/httpx"
	"github.com/skandertajine/digestron/internal/sink"
)

func init() {
	sink.Register("webhook", New)
}

type Config struct {
	URL     string                   `koanf:"url"`
	Method  string                   `koanf:"method"`
	Headers map[string]config.Secret `koanf:"headers"`
	Body    string                   `koanf:"body"`
}

type Sink struct {
	name    string
	cfg     Config
	bodyTpl *template.Template
}

// Funcs available in body templates; the data is the digest.Report.
func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"rendertext": digest.RenderText,
		"tojson": func(v any) (string, error) {
			b, err := json.Marshal(v)
			return string(b), err
		},
	}
}

func New(name string, settings map[string]any) (digest.Sink, error) {
	cfg := Config{Method: http.MethodPost, Body: "{{ tojson . }}"}
	if err := config.DecodeSettings(settings, &cfg); err != nil {
		return nil, err
	}
	if cfg.URL == "" {
		return nil, fmt.Errorf("url is required")
	}
	switch cfg.Method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		return nil, fmt.Errorf("unsupported method %q", cfg.Method)
	}
	tpl, err := template.New(name).Funcs(templateFuncs()).Parse(cfg.Body)
	if err != nil {
		return nil, fmt.Errorf("body template: %w", err)
	}
	return &Sink{name: name, cfg: cfg, bodyTpl: tpl}, nil
}

func (s *Sink) Name() string { return s.name }

func (s *Sink) Send(ctx context.Context, r digest.Report) error {
	var body strings.Builder
	if err := s.bodyTpl.Execute(&body, r); err != nil {
		return fmt.Errorf("body template: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, s.cfg.Method, s.cfg.URL, strings.NewReader(body.String()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range s.cfg.Headers {
		req.Header.Set(k, v.Reveal())
	}

	resp, err := httpx.Do(req, 2)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("webhook: %s: %s", resp.Status, msg)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}
