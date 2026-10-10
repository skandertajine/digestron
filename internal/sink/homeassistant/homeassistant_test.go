package homeassistant

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/skandertajine/digestron/internal/digest"
)

func newSink(t *testing.T, url string, extra map[string]any) digest.Sink {
	t.Helper()
	settings := map[string]any{"url": url, "token": "llat-secret", "service": "mobile_app_iphone"}
	for k, v := range extra {
		settings[k] = v
	}
	s, err := New("iphone", settings)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSendUsesSummary(t *testing.T) {
	var gotPath, gotAuth string
	var payload map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &payload)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := digest.Report{Title: "Security digest", Verdict: digest.SeverityCritical, Summary: "bad night"}
	if err := newSink(t, srv.URL, nil).Send(context.Background(), r); err != nil {
		t.Fatal(err)
	}

	if gotPath != "/api/services/notify/mobile_app_iphone" {
		t.Errorf("path = %q", gotPath)
	}
	if gotAuth != "Bearer llat-secret" {
		t.Errorf("auth = %q (token must travel as a header)", gotAuth)
	}
	if payload["title"] != "[CRITICAL] Security digest" {
		t.Errorf("title = %q", payload["title"])
	}
	if payload["message"] != "bad night" {
		t.Errorf("message = %q, want the LLM summary", payload["message"])
	}
}

func TestSendFallsBackToRenderedDigest(t *testing.T) {
	var payload map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &payload)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := digest.Report{Title: "digest", Verdict: digest.SeverityInfo,
		Findings: []digest.Finding{{Title: "ssh failures", Count: 2}}}
	if err := newSink(t, srv.URL, nil).Send(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload["message"], "ssh failures: 2") {
		t.Errorf("fallback message = %q, want raw digest", payload["message"])
	}
}

func TestSendCustomTemplate(t *testing.T) {
	var payload map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &payload)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := newSink(t, srv.URL, map[string]any{"template": "verdict={{.Verdict}}"})
	if err := s.Send(context.Background(), digest.Report{Verdict: digest.SeverityWarning}); err != nil {
		t.Fatal(err)
	}
	if payload["message"] != "verdict=warning" {
		t.Errorf("templated message = %q", payload["message"])
	}
}

func TestCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newSink(t, srv.URL, nil).(digest.Checker)
	if err := c.Check(context.Background()); err != nil {
		t.Errorf("Check() = %v", err)
	}
}

func TestNewValidation(t *testing.T) {
	for _, missing := range []map[string]any{
		{"token": "t", "service": "s"},
		{"url": "http://x", "service": "s"},
		{"url": "http://x", "token": "t"},
	} {
		if _, err := New("ha", missing); err == nil {
			t.Errorf("settings %v must fail validation", missing)
		}
	}
}

// The dangerous path: the LLM answered, so the sink sends the summary and
// never calls RenderText. The summary is written from the findings that
// survived, and the verdict is the max over those same findings — so a run
// that lost four queries out of five arrives as a full-looking [INFO] digest
// unless the sink says otherwise itself.
func TestSendSummaryStillReportsPartialSources(t *testing.T) {
	var payload map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &payload)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := digest.Report{
		Title:    "Security digest",
		Verdict:  digest.SeverityInfo,
		Summary:  "A quiet hour: 936 firewall blocks, nothing else of note.",
		Findings: []digest.Finding{{Title: "firewall blocked flows", Count: 936}},
		Stats: []digest.SourceStats{
			{Source: "es", Findings: 1, Err: `4 of 5 queries failed: query "ssh auth failures": 400 Bad Request`},
		},
	}
	if err := newSink(t, srv.URL, nil).Send(context.Background(), r); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(payload["message"], r.Summary) {
		t.Errorf("the summary must survive, not be replaced: %q", payload["message"])
	}
	if !strings.Contains(payload["message"], "Partial sources: es: 4 of 5 queries failed") {
		t.Errorf("the failed queries must reach the operator on the summary path too: %q", payload["message"])
	}
	if !strings.Contains(payload["title"], "PARTIAL") {
		t.Errorf("title = %q: a locked phone shows the title and nothing else", payload["title"])
	}
}

// ...and the ordinary complete run must stay unmarked, or the marker means
// nothing.
func TestSendCompleteRunIsNotMarkedPartial(t *testing.T) {
	var payload map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &payload)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := digest.Report{
		Title:   "Security digest",
		Verdict: digest.SeverityWarning,
		Summary: "all accounted for",
		Stats:   []digest.SourceStats{{Source: "es", Findings: 5}},
	}
	if err := newSink(t, srv.URL, nil).Send(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if payload["title"] != "[WARNING] Security digest" {
		t.Errorf("title = %q, want no marker on a complete run", payload["title"])
	}
	if payload["message"] != "all accounted for" {
		t.Errorf("message = %q, want the summary untouched", payload["message"])
	}
}

// A source that returned nothing at all is a different diagnosis from one
// that returned an incomplete count, and the fallback path must keep them
// apart: "Unreachable" on an all-queries-failed source sends the operator
// after the network when the problem is in a query body.
func TestSendFallbackNamesFailedAndPartialApart(t *testing.T) {
	var payload map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &payload)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := digest.Report{
		Title:   "digest",
		Verdict: digest.SeverityInfo,
		Stats: []digest.SourceStats{
			{Source: "es", Findings: 2, Err: "1 of 3 queries failed: query \"ssh auth failures\": 400"},
			{Source: "prom", Findings: 0, Err: "3 of 3 queries failed: dial tcp: refused"},
		},
	}
	if err := newSink(t, srv.URL, nil).Send(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	msg := payload["message"]
	if !strings.Contains(msg, "Failed sources: prom") {
		t.Errorf("a source with no findings at all must be named as failed: %q", msg)
	}
	if !strings.Contains(msg, "Partial sources: es") {
		t.Errorf("a source with findings and an error is partial, not failed: %q", msg)
	}
	if strings.Count(msg, "Partial sources:") != 1 {
		t.Errorf("the fallback already renders the block; it must not be appended twice: %q", msg)
	}
}

func TestTeaserKeepsHeadlineAndIPLines(t *testing.T) {
	got := Teaser("Headline.\n\n1. 1.2.3.4 | Net | 5 events\n   did things\n   Pattern : x\n\n2. 5.6.7.8 | Other | 2 events\n\nActions :\n- ban")
	want := "Headline.\n1. 1.2.3.4 | Net | 5 events\n2. 5.6.7.8 | Other | 2 events"
	if got != want {
		t.Errorf("Teaser =\n%q\nwant\n%q", got, want)
	}
}

// capture records the payload of each notification as generic JSON.
func capture(t *testing.T) (*httptest.Server, func() map[string]any) {
	t.Helper()
	var payload map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		payload = nil
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Errorf("payload is not JSON: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, func() map[string]any { return payload }
}

// How each verdict reaches the phone, in the companion app's keys: a quiet
// hour must neither ring nor pile up, a warning rings and stays, a critical
// gets through a Focus. The link keeps opening the run on both platforms.
func TestSendDeliveryFollowsTheVerdict(t *testing.T) {
	at := time.Date(2026, 10, 10, 11, 5, 0, 0, time.UTC)
	link := "http://digestron.example/#run=2026-10-10T11:05:00Z"
	complete := []digest.SourceStats{{Source: "es", Findings: 5}}
	partial := []digest.SourceStats{{Source: "es", Findings: 2, Err: "3 of 5 queries failed"}}

	cases := []struct {
		name    string
		verdict digest.Severity
		stats   []digest.SourceStats
		level   string
		tag     any // nil = no tag: the notification stays
	}{
		{"info", digest.SeverityInfo, complete, "passive", "digestron-info"},
		{"warning", digest.SeverityWarning, complete, "active", nil},
		{"critical", digest.SeverityCritical, complete, "time-sensitive", nil},
		{"info, sources lost", digest.SeverityInfo, partial, "active", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, got := capture(t)
			s := newSink(t, srv.URL, map[string]any{"link": "http://digestron.example/"})
			r := digest.Report{Title: "Security digest [dev]", Verdict: tc.verdict, Summary: "Headline.",
				Stats: tc.stats, GeneratedAt: at}
			if err := s.Send(context.Background(), r); err != nil {
				t.Fatal(err)
			}

			data, ok := got()["data"].(map[string]any)
			if !ok {
				t.Fatalf("no data block: %v", got())
			}
			if data["group"] != "digestron" {
				t.Errorf("data.group = %v", data["group"])
			}
			if data["tag"] != tc.tag {
				t.Errorf("data.tag = %v, want %v", data["tag"], tc.tag)
			}
			push, _ := data["push"].(map[string]any)
			if push["interruption-level"] != tc.level {
				t.Errorf("data.push.interruption-level = %v, want %s", push["interruption-level"], tc.level)
			}
			if data["url"] != link || data["clickAction"] != link {
				t.Errorf("url = %v, clickAction = %v, want both %s", data["url"], data["clickAction"], link)
			}
		})
	}
}

// Without a link there is nothing to open, but the delivery level stays.
func TestSendWithoutLinkStillSetsTheDeliveryLevel(t *testing.T) {
	srv, got := capture(t)
	if err := newSink(t, srv.URL, nil).Send(context.Background(),
		digest.Report{Title: "digest", Verdict: digest.SeverityInfo}); err != nil {
		t.Fatal(err)
	}
	data, _ := got()["data"].(map[string]any)
	if _, ok := data["url"]; ok {
		t.Errorf("url set without a link: %v", data)
	}
	if _, ok := data["clickAction"]; ok {
		t.Errorf("clickAction set without a link: %v", data)
	}
	if push, _ := data["push"].(map[string]any); push["interruption-level"] != "passive" || data["tag"] != "digestron-info" {
		t.Errorf("data = %v, want a passive, replaceable info", data)
	}
}

// Two instances on one phone keep apart: each has its own thread, and an
// all-clear from one never replaces the other's. Unset, the group is
// "digestron".
func TestSendGroupSeparatesInstances(t *testing.T) {
	cases := []struct {
		settings  map[string]any
		group     string
		infoTag   string
		verdict   digest.Severity
		wantNoTag bool
	}{
		{map[string]any{"group": "digestron-dev"}, "digestron-dev", "digestron-dev-info", digest.SeverityInfo, false},
		{map[string]any{"group": "digestron-prod"}, "digestron-prod", "digestron-prod-info", digest.SeverityInfo, false},
		{map[string]any{"group": "digestron-dev"}, "digestron-dev", "", digest.SeverityWarning, true},
		{map[string]any{"group": ""}, "digestron", "digestron-info", digest.SeverityInfo, false},
		{nil, "digestron", "digestron-info", digest.SeverityInfo, false},
	}
	for _, tc := range cases {
		srv, got := capture(t)
		if err := newSink(t, srv.URL, tc.settings).Send(context.Background(),
			digest.Report{Title: "digest", Verdict: tc.verdict}); err != nil {
			t.Fatal(err)
		}
		data, _ := got()["data"].(map[string]any)
		if data["group"] != tc.group {
			t.Errorf("%v: data.group = %v, want %s", tc.settings, data["group"], tc.group)
		}
		tag, hasTag := data["tag"]
		switch {
		case tc.wantNoTag && hasTag:
			t.Errorf("%v %s: data.tag = %v, want none", tc.settings, tc.verdict, tag)
		case !tc.wantNoTag && tag != tc.infoTag:
			t.Errorf("%v: data.tag = %v, want %s", tc.settings, tag, tc.infoTag)
		}
	}
}
