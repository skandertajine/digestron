package email

import (
	"strings"
	"testing"

	"github.com/skandertajine/digestron/internal/digest"
)

func TestMessageConstruction(t *testing.T) {
	s, err := New("mail", map[string]any{
		"host": "smtp.example.com",
		"from": "digest@example.com",
		"to":   []any{"ops@example.com", "sec@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	r := digest.Report{Title: "Security digest", Verdict: digest.SeverityWarning,
		Findings: []digest.Finding{{Title: "fail2ban bans", Count: 3, Severity: digest.SeverityWarning}}}
	msg, err := s.(*Sink).Message(r)
	if err != nil {
		t.Fatal(err)
	}

	var buf strings.Builder
	if _, err := msg.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	raw := buf.String()
	if !strings.Contains(raw, "Subject: [warning] Security digest") {
		t.Errorf("default subject missing:\n%s", raw)
	}
	if !strings.Contains(raw, "fail2ban bans: 3") {
		t.Errorf("body missing findings:\n%s", raw)
	}
	if !strings.Contains(raw, "To: <ops@example.com>, <sec@example.com>") {
		t.Errorf("recipients missing:\n%s", raw)
	}
}

func TestCustomSubjectTemplate(t *testing.T) {
	s, err := New("mail", map[string]any{
		"host":    "smtp.example.com",
		"from":    "a@b.c",
		"to":      []any{"d@e.f"},
		"subject": "digest {{.Verdict}} !",
	})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := s.(*Sink).Message(digest.Report{Verdict: digest.SeverityCritical})
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	if _, err := msg.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Subject: digest critical !") {
		t.Errorf("templated subject missing:\n%s", buf.String())
	}
}

func TestNewValidation(t *testing.T) {
	cases := []struct {
		name     string
		settings map[string]any
	}{
		{"missing host", map[string]any{"from": "a@b.c", "to": []any{"d@e.f"}}},
		{"missing from", map[string]any{"host": "h", "to": []any{"d@e.f"}}},
		{"missing to", map[string]any{"host": "h", "from": "a@b.c"}},
		{"bad tls policy", map[string]any{"host": "h", "from": "a@b.c", "to": []any{"d@e.f"}, "tls": "maybe"}},
		{"bad subject template", map[string]any{"host": "h", "from": "a@b.c", "to": []any{"d@e.f"}, "subject": "{{ broken"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New("mail", tc.settings); err == nil {
				t.Error("must fail validation")
			}
		})
	}
}
