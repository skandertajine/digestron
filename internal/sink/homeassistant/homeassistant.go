// Package homeassistant delivers the digest as a Home Assistant notification
// (POST /api/services/notify/<service>). The message defaults to the LLM
// summary, falling back to the raw text digest when the LLM was skipped or
// failed. Either way it carries the sources that did not fully answer, and
// the title is marked when they exist: a push notification on a locked phone
// is often read as a title and nothing more.
//
// How it rings follows the verdict (HA companion app, iOS): a quiet hour is
// delivered without sound and replaces the previous quiet one, a warning
// rings, a critical breaks through Focus. See pushData.
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
	"time"

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
	// Link, when set, makes the notification a teaser of the full report:
	// the headline and one line per top IP, then the link — and tapping the
	// notification opens it (iOS url, Android clickAction). The run ID is
	// appended as #run=<id> so the UI opens that run.
	Link string `koanf:"link"`
	// MaxChars caps the message; 0 = no cap. Push notifications show a few
	// hundred characters at most, the full analysis lives behind Link.
	MaxChars int `koanf:"max_chars"`
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
	link := ""
	if s.cfg.Link != "" {
		link = s.cfg.Link + "#run=" + r.GeneratedAt.UTC().Format(time.RFC3339Nano)
		if r.Summary != "" {
			message = Teaser(r.Summary)
			if problems != "" {
				message += "\n\n" + problems
			}
		}
	}
	if s.cfg.MaxChars > 0 {
		message = digest.PostProcess(message, s.cfg.MaxChars)
	}
	if link != "" {
		message += "\n" + link
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
	data := pushData(r.Verdict, problems != "")
	if link != "" {
		data["url"] = link         // iOS
		data["clickAction"] = link // Android
	}
	body := map[string]any{
		"title":   fmt.Sprintf("[%s] %s", verdict, r.Title),
		"message": message,
		"data":    data,
	}
	payload, err := json.Marshal(body)
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

// Every digest goes to one thread on the phone; quiet hours share one slot
// in it.
const (
	pushGroup = "digestron"
	infoTag   = "digestron-info"
)

// pushData sets how the notification is delivered, in the companion app's
// keys: data.group (the iOS thread), data.tag (a later notification with the
// same tag replaces this one) and data.push.interruption-level.
//
//   - INFO: passive (no sound, no screen wake) under a fixed tag, so the
//     hourly all-clear stops ringing and stops piling up: the lock screen
//     holds the latest one.
//   - WARNING: active, and no tag: each one stays until it is read.
//   - CRITICAL: time-sensitive, which gets through a Focus.
//
// A run that lost sources is not a quiet hour whatever its verdict, which
// is computed from the findings that survived: it is delivered as active and
// kept, or a silent [INFO·PARTIAL] would replace the last all-clear without
// a sound while the digest is half blind.
func pushData(verdict digest.Severity, incomplete bool) map[string]any {
	data := map[string]any{"group": pushGroup}
	level := "active"
	switch {
	case verdict == digest.SeverityCritical:
		level = "time-sensitive"
	case verdict == digest.SeverityInfo && !incomplete:
		level = "passive"
		data["tag"] = infoTag
	}
	data["push"] = map[string]any{"interruption-level": level}
	return data
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

// Teaser keeps what fits a lock screen from the analyst's report: the
// headline (first paragraph) and the first line of each numbered IP block.
func Teaser(summary string) string {
	paras := strings.SplitN(strings.TrimSpace(summary), "\n\n", 2)
	out := []string{strings.TrimSpace(paras[0])}
	if len(paras) == 2 {
		for _, line := range strings.Split(paras[1], "\n") {
			line = strings.TrimSpace(line)
			if len(line) > 2 && line[0] >= '1' && line[0] <= '9' && line[1] == '.' {
				out = append(out, line)
			}
		}
	}
	return strings.Join(out, "\n")
}
