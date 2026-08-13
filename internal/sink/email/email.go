// Package email delivers the digest over SMTP via go-mail — the one place
// stdlib is not enough: net/smtp is frozen and handles STARTTLS and modern
// auth poorly.
package email

import (
	"context"
	"fmt"
	"strings"
	"text/template"

	gomail "github.com/wneessen/go-mail"

	"github.com/skandertajine/digestron/internal/config"
	"github.com/skandertajine/digestron/internal/digest"
	"github.com/skandertajine/digestron/internal/sink"
)

func init() {
	sink.Register("email", New)
}

type Config struct {
	Host     string        `koanf:"host"`
	Port     int           `koanf:"port"`
	Username string        `koanf:"username"`
	Password config.Secret `koanf:"password"`
	From     string        `koanf:"from"`
	To       []string      `koanf:"to"`
	Subject  string        `koanf:"subject"`
	TLS      string        `koanf:"tls"` // mandatory | opportunistic | none
}

type Sink struct {
	name       string
	cfg        Config
	subjectTpl *template.Template
	tlsPolicy  gomail.TLSPolicy
}

func New(name string, settings map[string]any) (digest.Sink, error) {
	cfg := Config{Port: 587, Subject: "[{{.Verdict}}] {{.Title}}", TLS: "opportunistic"}
	if err := config.DecodeSettings(settings, &cfg); err != nil {
		return nil, err
	}
	if cfg.Host == "" || cfg.From == "" || len(cfg.To) == 0 {
		return nil, fmt.Errorf("host, from and to are required")
	}

	var policy gomail.TLSPolicy
	switch cfg.TLS {
	case "mandatory":
		policy = gomail.TLSMandatory
	case "opportunistic":
		policy = gomail.TLSOpportunistic
	case "none":
		policy = gomail.NoTLS
	default:
		return nil, fmt.Errorf("unsupported tls policy %q", cfg.TLS)
	}

	tpl, err := template.New(name).Parse(cfg.Subject)
	if err != nil {
		return nil, fmt.Errorf("subject template: %w", err)
	}
	return &Sink{name: name, cfg: cfg, subjectTpl: tpl, tlsPolicy: policy}, nil
}

func (s *Sink) Name() string { return s.name }

// Message builds the outgoing mail without touching the network.
func (s *Sink) Message(r digest.Report) (*gomail.Msg, error) {
	var subject strings.Builder
	if err := s.subjectTpl.Execute(&subject, r); err != nil {
		return nil, fmt.Errorf("subject template: %w", err)
	}

	msg := gomail.NewMsg()
	if err := msg.From(s.cfg.From); err != nil {
		return nil, err
	}
	if err := msg.To(s.cfg.To...); err != nil {
		return nil, err
	}
	msg.Subject(subject.String())
	msg.SetBodyString(gomail.TypeTextPlain, digest.RenderText(r))
	return msg, nil
}

func (s *Sink) client() (*gomail.Client, error) {
	opts := []gomail.Option{
		gomail.WithPort(s.cfg.Port),
		gomail.WithTLSPolicy(s.tlsPolicy),
	}
	if s.cfg.Username != "" {
		opts = append(opts,
			gomail.WithSMTPAuth(gomail.SMTPAuthPlain),
			gomail.WithUsername(s.cfg.Username),
			gomail.WithPassword(s.cfg.Password.Reveal()),
		)
	}
	return gomail.NewClient(s.cfg.Host, opts...)
}

func (s *Sink) Send(ctx context.Context, r digest.Report) error {
	msg, err := s.Message(r)
	if err != nil {
		return err
	}
	client, err := s.client()
	if err != nil {
		return err
	}
	return client.DialAndSendWithContext(ctx, msg)
}

// Check dials the SMTP server and closes without sending.
func (s *Sink) Check(ctx context.Context) error {
	client, err := s.client()
	if err != nil {
		return err
	}
	if err := client.DialWithContext(ctx); err != nil {
		return err
	}
	return client.Close()
}
