// Package redact removes secret values from text that is about to leave the
// process: a log line shown in the web UI, an error quoted into a payload.
//
// The type system already keeps secrets out of what digestron serialises
// (config.Secret renders as <redacted>), but it cannot see a secret an
// upstream echoes back. A Home Assistant 401 whose body repeats the
// Authorization header is quoted into an error, and from there into a log
// line; the scrubber is the layer that catches that.
package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/skandertajine/digestron/internal/config"
)

const (
	// Placeholder replaces every secret found in a string.
	Placeholder = "<redacted>"

	// minSecretLen is the shortest value worth hiding. A short "secret" such
	// as "on" or "1234" would shred unrelated text, and a real credential is
	// never that short.
	minSecretLen = 8
)

// Scrubber replaces known secret values inside arbitrary text. A nil
// *Scrubber is valid and leaves text untouched, so callers never need to
// check whether redaction is configured.
type Scrubber struct {
	values []string // longest first: a value that contains another goes first
}

// New builds a Scrubber from secret values, and from the forms an upstream is
// likely to echo them in: JSON-escaped, URL-encoded and base64 (which is what
// a Basic Authorization header carries). Values shorter than minSecretLen are
// ignored, and duplicates are dropped.
func New(values ...string) *Scrubber {
	seen := map[string]bool{}
	var kept []string
	add := func(v string) {
		if len(v) < minSecretLen || seen[v] {
			return
		}
		seen[v] = true
		kept = append(kept, v)
	}
	for _, v := range values {
		if len(v) < minSecretLen {
			continue
		}
		add(v)
		for _, form := range forms(v) {
			add(form)
		}
	}
	sort.Slice(kept, func(i, j int) bool { return len(kept[i]) > len(kept[j]) })
	return &Scrubber{values: kept}
}

// forms lists the ways a secret shows up when an upstream echoes a request:
// a JSON body escapes quotes, ampersands and angle brackets, a query string
// percent-encodes, and a Basic credential is base64. Each is only worth
// keeping when it differs from the plain value.
func forms(v string) []string {
	var out []string
	if b, err := json.Marshal(v); err == nil { // escapes <, > and & as \u003c...
		out = append(out, strings.Trim(string(b), `"`))
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if enc.Encode(v) == nil {
		out = append(out, strings.Trim(strings.TrimSpace(buf.String()), `"`))
	}
	out = append(out,
		url.QueryEscape(v), url.PathEscape(v),
		base64.StdEncoding.EncodeToString([]byte(v)),
		base64.RawStdEncoding.EncodeToString([]byte(v)),
		base64.URLEncoding.EncodeToString([]byte(v)),
		base64.RawURLEncoding.EncodeToString([]byte(v)),
	)
	return out
}

// Scrub returns s with every known secret replaced by Placeholder.
func (s *Scrubber) Scrub(str string) string {
	if s == nil {
		return str
	}
	for _, v := range s.values {
		if strings.Contains(str, v) {
			str = strings.ReplaceAll(str, v, Placeholder)
		}
	}
	return str
}

// ReplaceAttr is a slog.HandlerOptions.ReplaceAttr that scrubs the message and
// every string or error attribute, so what a handler prints has the same
// protection as what the ring stores. Values of other kinds (numbers, times,
// durations) cannot hold a secret and are left alone.
func (s *Scrubber) ReplaceAttr(_ []string, a slog.Attr) slog.Attr {
	if s == nil {
		return a
	}
	switch a.Value.Kind() {
	case slog.KindString:
		a.Value = slog.StringValue(s.Scrub(a.Value.String()))
	case slog.KindAny:
		v := a.Value.Any()
		// An error is where an upstream's echoed body arrives: sinks and
		// sources quote it into the error they return.
		if err, ok := v.(error); ok && err != nil {
			a.Value = slog.StringValue(s.Scrub(err.Error()))
			return a
		}
		// A structured value (a map, a struct) is printed as JSON by the
		// handler, so scrub its JSON form. A value with no secret in it keeps
		// its shape; one that had a secret becomes the scrubbed text.
		if b, err := json.Marshal(v); err == nil {
			if text := string(b); s.Scrub(text) != text {
				a.Value = slog.StringValue(s.Scrub(text))
			}
		}
	}
	return a
}

// Len reports how many distinct secret values are being hidden; tests and the
// status endpoint use it to prove the scrubber is not silently empty.
func (s *Scrubber) Len() int {
	if s == nil {
		return 0
	}
	return len(s.values)
}

// URL drops what a URL can carry besides an address: credentials, the query
// string and the fragment. Anything that fails to parse is replaced whole
// rather than echoed.
func URL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return Placeholder
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// secretKey matches setting names that hold credentials. max_tokens and its
// siblings are limits, not secrets, and are excluded below.
var (
	secretKey    = regexp.MustCompile(`(?i)secret|passw(or)?d|token|api[_-]?key|authorization|credential`)
	notSecretKey = regexp.MustCompile(`(?i)^max_|_field$|^num_`)
)

// FromConfig collects every secret a configuration holds: any scalar setting
// whose key looks like a credential, every value under a headers map, a
// password embedded in a URL, the query values of a URL, and the whole URL of
// a webhook sink, which is a credential by nature (a Slack, Discord or ntfy
// address IS the secret). A Basic credential is a username and a password
// joined, so that pair is collected too. It reads the expanded settings, so it
// sees the plaintext that ${VAR} references resolved to.
func FromConfig(cfg *config.Config) *Scrubber {
	var values []string
	for _, m := range cfg.Sources {
		values = collect(values, m.Settings, "")
	}
	for _, m := range cfg.Sinks {
		values = collect(values, m.Settings, "")
		if m.Type == "webhook" {
			if u, ok := m.Settings["url"].(string); ok {
				values = append(values, u)
			}
		}
	}
	values = collect(values, cfg.LLM.Settings, "")
	return New(values...)
}

func collect(out []string, v any, key string) []string {
	switch t := v.(type) {
	case map[string]any:
		if user, ok := t["username"].(string); ok {
			if pw, ok := scalar(t["password"]); ok {
				out = append(out, user+":"+pw) // what an Authorization: Basic header carries
			}
		}
		for k, val := range t {
			if k == "headers" {
				out = allStrings(out, val)
				continue
			}
			out = collect(out, val, k)
		}
	case []any:
		for _, val := range t {
			out = collect(out, val, key)
		}
	default:
		text, ok := scalar(t)
		if !ok {
			return out
		}
		switch {
		case notSecretKey.MatchString(key):
		case secretKey.MatchString(key):
			out = append(out, text)
		case strings.EqualFold(key, "url"):
			out = append(out, urlSecrets(text)...)
		}
	}
	return out
}

// scalar renders a setting the way it was configured. A password that is all
// digits is a number once the YAML is parsed, and the module still sends it
// as text: a scrubber that only saw strings would let it through.
func scalar(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return fmt.Sprint(t), true
	}
	return "", false
}

// urlSecrets returns what a URL can hide: the password in its userinfo and
// every query value, which is where API tokens travel.
func urlSecrets(raw string) []string {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	var out []string
	if u.User != nil {
		if pw, ok := u.User.Password(); ok {
			out = append(out, pw)
		}
	}
	for _, vals := range u.Query() {
		out = append(out, vals...)
	}
	return out
}

// allStrings gathers every leaf of a headers map: header values are
// credentials as often as not, whatever the header is called.
func allStrings(out []string, v any) []string {
	switch t := v.(type) {
	case map[string]any:
		for _, val := range t {
			out = allStrings(out, val)
		}
	case map[string]string:
		for _, val := range t {
			out = appendHeaderValue(out, val)
		}
	case []any:
		for _, val := range t {
			out = allStrings(out, val)
		}
	default:
		if text, ok := scalar(t); ok {
			out = appendHeaderValue(out, text)
		}
	}
	return out
}

// appendHeaderValue adds a header value and, for "Bearer abc" or "Basic xyz",
// the credential on its own: an upstream that echoes a JSON body may print
// the token without the scheme in front of it, and the scheme word is not
// what needs hiding.
func appendHeaderValue(out []string, v string) []string {
	out = append(out, v)
	if i := strings.LastIndexByte(v, ' '); i > 0 {
		out = append(out, v[i+1:])
	}
	return out
}
