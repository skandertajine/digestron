// Package homeassistant delivers the digest as a Home Assistant notification
// (POST /api/services/notify/<service>). The message defaults to the LLM
// summary, falling back to the raw text digest when the LLM was skipped or
// failed. Either way it carries the sources that did not fully answer, and
// the title is marked when they exist: a push notification on a locked phone
// is often read as a title and nothing more.
package homeassistant

import (
	"bytes"
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
	sink.Register("homeassistant", New)
}

type Config struct {
	URL      string        `koanf:"url"`
	Token    config.Secret `koanf:"token"`
	Service  string        `koanf:"service"`
	Template string        `koanf:"template"`
}

type Sink struct {
	name       string
	cfg        Config
	messageTpl *template.Template // nil = default message
}

func New(name string, settings map[string]any) (digest.Sink, error) {
	var cfg Config
	if err := config.DecodeSettings(settings, &cfg); err != nil {
		return nil, err
	}
	if cfg.URL == "" || cfg.Token == "" || cfg.Service == "" {
		return nil, fmt.Errorf("url, token and service are required")
	}
	s := &Sink{name: name, cfg: cfg}
	if cfg.Template != "" {
		tpl, err := template.New(name).Parse(cfg.Template)
		if err != nil {
			return nil, fmt.Errorf("template: %w", err)
		}
		s.messageTpl = tpl
	}
	return s, nil
}

func (s *Sink) Name() string { return s.name }

func (s *Sink) Send(ctx context.Context, r digest.Report) error {
	problems := digest.SourceProblems(r)

	message := r.Summary
	switch {
	case message == "":
		message = digest.RenderText(r) // already ends with the problems block
	case problems != "":
		// The summary is written from the findings that survived, so it reads
		// like a quiet night even when most of the queries never ran. Append
		// the casualties verbatim instead of hoping the model mentions them.
		message += "\n\n" + problems
	}
	if s.messageTpl != nil {
		var buf strings.Builder
		if err := s.messageTpl.Execute(&buf, r); err != nil {
			return fmt.Errorf("template: %w", err)
		}
		message = buf.String()
	}

	// Verdict is the max over the findings that survived, so a run that lost
	// four queries out of five still comes out [INFO]. Mark the title too:
	// it is the one part of the notification a locked screen always shows.
	verdict := strings.ToUpper(r.Verdict.String())
	if problems != "" {
		verdict += "\u00b7PARTIAL"
	}
	payload, err := json.Marshal(map[string]string{
		"title":   fmt.Sprintf("[%s] %s", verdict, r.Title),
		"message": message,
	})
	if err != nil {
		return err
	}

	url := strings.TrimSuffix(s.cfg.URL, "/") + "/api/services/notify/" + s.cfg.Service
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.cfg.Token.Reveal())

	resp, err := httpx.Do(req, 2)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("homeassistant: %s: %s", resp.Status, msg)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// Check probes the API root with the configured token.
func (s *Sink) Check(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimSuffix(s.cfg.URL, "/")+"/api/", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.Token.Reveal())
	resp, err := httpx.Do(req, 1)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("homeassistant: %s", resp.Status)
	}
	return nil
}
