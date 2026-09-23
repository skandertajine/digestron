package redact

import (
	"bytes"
	"encoding/base64"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/skandertajine/digestron/internal/config"
)

func TestScrubReplacesEverySecretEverywhere(t *testing.T) {
	s := New("hunter2-hunter2", "token-abcdef-123")
	got := s.Scrub("auth failed for hunter2-hunter2, retry with token-abcdef-123 (hunter2-hunter2)")
	if strings.Contains(got, "hunter2") || strings.Contains(got, "abcdef") {
		t.Errorf("a secret survived: %q", got)
	}
	if strings.Count(got, Placeholder) != 3 {
		t.Errorf("want each of the 3 occurrences replaced: %q", got)
	}
}

// A short value would shred unrelated text ("on", "1234"), and no real
// credential is that short.
func TestShortValuesAreIgnored(t *testing.T) {
	s := New("on", "1234", "seven77")
	if s.Len() != 0 {
		t.Errorf("Len = %d, want 0: values under 8 bytes must be ignored", s.Len())
	}
	if got := s.Scrub("turn on 1234 seven77"); got != "turn on 1234 seven77" {
		t.Errorf("short values were scrubbed: %q", got)
	}
}

// A longer secret that contains a shorter one must go first, or the shorter
// replacement would leave the tail of the longer one behind.
func TestLongestSecretFirst(t *testing.T) {
	s := New("pass-word", "pass-word-and-more")
	got := s.Scrub("x pass-word-and-more y")
	if strings.Contains(got, "and-more") {
		t.Errorf("the tail of the longer secret leaked: %q", got)
	}
}

func TestNilScrubberIsHarmless(t *testing.T) {
	var s *Scrubber
	if got := s.Scrub("anything"); got != "anything" {
		t.Errorf("nil Scrubber changed the text: %q", got)
	}
	if s.Len() != 0 {
		t.Error("nil Scrubber has no values")
	}
}

func TestURLDropsCredentialsQueryAndFragment(t *testing.T) {
	got := URL("https://user:s3cretpass@es.example:9200/filebeat-*/_search?token=abc#frag")
	if got != "https://es.example:9200/filebeat-*/_search" {
		t.Errorf("URL() = %q", got)
	}
	if got := URL("not a url"); got != Placeholder {
		t.Errorf("an unparseable URL must not be echoed: %q", got)
	}
}

// Every credential the example configuration references must be found, and
// the limits that merely have "token" in their name must not be mistaken for
// secrets.
func TestFromConfigFindsCredentialsAndOnlyCredentials(t *testing.T) {
	cfg := &config.Config{
		Sources: []config.ModuleConfig{{Name: "es", Settings: map[string]any{
			"url":      "http://elastic:urlpassword1@es:9200",
			"password": "es-password-value",
			"index":    "filebeat-*",
		}}},
		Sinks: []config.ModuleConfig{
			{Name: "ha", Settings: map[string]any{"token": "ha-token-value-1", "service": "mobile_app_iphone"}},
			{Name: "hook", Settings: map[string]any{"headers": map[string]any{"X-Anything": "header-value-xyz"}}},
			{Name: "mail", Settings: map[string]any{"password": "smtp-password-1"}},
		},
		LLM: config.LLMConfig{Settings: map[string]any{
			"api_key":          "llm-api-key-value",
			"max_tokens":       800,
			"max_tokens_field": "max_tokens",
			"model":            "qwen3.5:9b",
		}},
	}
	s := FromConfig(cfg)

	for _, secret := range []string{
		"es-password-value", "urlpassword1", "ha-token-value-1",
		"header-value-xyz", "smtp-password-1", "llm-api-key-value",
	} {
		if got := s.Scrub("boom " + secret + " boom"); strings.Contains(got, secret) {
			t.Errorf("secret %q was not collected from the configuration", secret)
		}
	}
	for _, notSecret := range []string{"mobile_app_iphone", "filebeat-*", "qwen3.5:9b", "max_tokens"} {
		if got := s.Scrub(notSecret); got != notSecret {
			t.Errorf("%q is a setting, not a credential, and must survive: %q", notSecret, got)
		}
	}
}

// "Authorization: Bearer <token>" is configured as one header value, but an
// upstream that echoes the request as JSON prints the token without the
// scheme. The credential alone must be hidden too.
func TestHeaderCredentialIsHiddenWithoutItsScheme(t *testing.T) {
	cfg := &config.Config{Sinks: []config.ModuleConfig{{Name: "hook", Settings: map[string]any{
		"headers": map[string]any{"Authorization": "Bearer hook-token-123456"},
	}}}}
	s := FromConfig(cfg)
	for _, echoed := range []string{"Bearer hook-token-123456", `{"authorization":"hook-token-123456"}`} {
		if got := s.Scrub(echoed); strings.Contains(got, "hook-token-123456") {
			t.Errorf("token survived in %q -> %q", echoed, got)
		}
	}
	if got := s.Scrub("Bearer scheme word alone"); !strings.Contains(got, "Bearer") {
		t.Errorf("the scheme word is not a secret and must survive: %q", got)
	}
}

// An upstream that echoes a request back does not print the secret as it was
// typed: a JSON body escapes quotes, ampersands and angle brackets, a query
// string percent-encodes, and a Basic credential is base64. A normal
// generated password has all of those characters.
func TestEncodedFormsOfASecretAreHiddenToo(t *testing.T) {
	const secret = `p&ss"w0rd/x+y<z>`
	s := New(secret)
	for name, echoed := range map[string]string{
		"json (html-escaped)": `{"password":"p\u0026ss\"w0rd/x+y\u003cz\u003e"}`,
		"json (raw)":          `{"password":"p&ss\"w0rd/x+y<z>"}`,
		"query string":        `?password=p%26ss%22w0rd%2Fx%2By%3Cz%3E`,
		"path segment":        `/p&ss%22w0rd%2Fx+y%3Cz%3E/`,
		"base64":              base64.StdEncoding.EncodeToString([]byte(secret)),
		"base64 unpadded":     base64.RawURLEncoding.EncodeToString([]byte(secret)),
	} {
		got := s.Scrub("echo: " + echoed)
		// The secret itself must be gone, whatever the form, and the text
		// around it must stay so the log still says what happened.
		if !strings.Contains(got, Placeholder) || strings.Contains(got, "w0rd") ||
			strings.Contains(got, "0YXNz") || strings.Contains(got, "cGFzcy") || !strings.HasPrefix(got, "echo: ") {
			t.Errorf("%s form survived: %q -> %q", name, echoed, got)
		}
	}
}

// Elasticsearch takes its credentials through SetBasicAuth, so the only place
// they can be echoed is an "Authorization: Basic base64(user:password)" header.
func TestBasicCredentialPairIsHidden(t *testing.T) {
	cfg := &config.Config{Sources: []config.ModuleConfig{{Name: "es", Settings: map[string]any{
		"username": "elastic", "password": "es-password-value",
	}}}}
	s := FromConfig(cfg)
	pair := base64.StdEncoding.EncodeToString([]byte("elastic:es-password-value"))
	for _, echoed := range []string{"Authorization: Basic " + pair, "elastic:es-password-value", "es-password-value"} {
		if got := s.Scrub(echoed); strings.Contains(got, "es-password-value") || strings.Contains(got, pair) {
			t.Errorf("credential survived in %q -> %q", echoed, got)
		}
	}
}

// An all-digit password is a number once the YAML is parsed, and the module
// still sends it as text: a scrubber that only looked at strings missed it.
func TestNumericSecretsAreHidden(t *testing.T) {
	cfg := &config.Config{
		Sources: []config.ModuleConfig{{Name: "es", Settings: map[string]any{"password": int64(48151623420)}}},
		Sinks:   []config.ModuleConfig{{Name: "hook", Settings: map[string]any{"headers": map[string]any{"X-Key": 987654321012}}}},
	}
	s := FromConfig(cfg)
	for _, secret := range []string{"48151623420", "987654321012"} {
		if got := s.Scrub("es said: " + secret + " rejected"); strings.Contains(got, secret) {
			t.Errorf("numeric secret %s survived: %q", secret, got)
		}
	}
}

// A webhook URL IS the credential (Slack, Discord, ntfy), and an unreachable
// host makes the HTTP client quote the whole URL into the error it returns.
func TestWebhookURLAndQueryTokensAreHidden(t *testing.T) {
	const hook = "https://hooks.example.com/services/T0/B0/SLACKSECRETPATH1234?token=qs9f8d7s6a5"
	cfg := &config.Config{
		Sinks: []config.ModuleConfig{{Name: "hook", Type: "webhook", Settings: map[string]any{"url": hook}}},
		Sources: []config.ModuleConfig{{Name: "prom", Type: "prometheus", Settings: map[string]any{
			"url": "http://prom.example:9090/api?apikey=queryvalue123",
		}}},
	}
	s := FromConfig(cfg)

	got := s.Scrub(`Post "` + hook + `": dial tcp: lookup hooks.example.com: no such host`)
	if strings.Contains(got, "SLACKSECRETPATH1234") || strings.Contains(got, "qs9f8d7s6a5") {
		t.Errorf("the webhook URL reached the text: %q", got)
	}
	if !strings.Contains(got, "dial tcp: lookup") {
		t.Errorf("the reason for the failure must survive, only the URL goes: %q", got)
	}
	if got := s.Scrub("GET /api?apikey=queryvalue123"); strings.Contains(got, "queryvalue123") {
		t.Errorf("a token in a query string survived: %q", got)
	}
	// A plain endpoint URL is an address, not a credential.
	if got := s.Scrub("dial tcp prom.example:9090: refused"); got != "dial tcp prom.example:9090: refused" {
		t.Errorf("an endpoint address was scrubbed: %q", got)
	}
}

// The handler that prints to stderr gets the same protection as the ring.
func TestReplaceAttrScrubsMessageStringsErrorsAndGroups(t *testing.T) {
	const secret = "SENTINEL-token-12345"
	s := New(secret)
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{ReplaceAttr: s.ReplaceAttr}))

	log.Error("auth failed for "+secret,
		"text", "Bearer "+secret,
		"error", errors.New("401: "+secret),
		slog.Group("resp", "body", secret),
		"count", 12345678,
	)
	out := buf.String()
	if strings.Contains(out, secret) {
		t.Errorf("a secret reached the printed line: %s", out)
	}
	if strings.Count(out, Placeholder) != 4 {
		t.Errorf("want the message, a string, an error and a grouped value replaced: %s", out)
	}
	if !strings.Contains(out, `"count":12345678`) {
		t.Errorf("a number is not text and must be left alone: %s", out)
	}
}

func TestReplaceAttrOnANilScrubber(t *testing.T) {
	var s *Scrubber
	a := slog.String("k", "v")
	if got := s.ReplaceAttr(nil, a); !got.Equal(a) {
		t.Errorf("a nil Scrubber changed an attribute: %v", got)
	}
}

// A structured value is printed as JSON by the handler. A secret inside one
// must not get through because it is not a plain string; a clean one must
// keep its shape.
func TestReplaceAttrScrubsStructuredValuesWithoutReshapingCleanOnes(t *testing.T) {
	const secret = "SENTINEL-token-12345"
	s := New(secret)
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{ReplaceAttr: s.ReplaceAttr}))

	log.Info("x",
		"leaky", map[string]string{"body": secret},
		"clean", map[string]string{"body": "fine"},
		"list", []string{"a", secret},
	)
	out := buf.String()
	if strings.Contains(out, secret) {
		t.Errorf("a secret inside a structured value reached the line: %s", out)
	}
	if !strings.Contains(out, `"clean":{"body":"fine"}`) {
		t.Errorf("a value with no secret must keep its JSON shape: %s", out)
	}
}
