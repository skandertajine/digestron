package ollama

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skandertajine/digestron/internal/digest"
	"github.com/skandertajine/digestron/internal/llm"
)

func newClient(t *testing.T, url string) digest.LLM {
	t.Helper()
	c, err := New(map[string]any{"url": url, "model": "qwen3:8b", "num_ctx": 4096})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCompleteRequestShape(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		_, _ = w.Write([]byte(`{"message":{"role":"assistant","content":"all quiet"},
			"done":true,"done_reason":"stop","prompt_eval_count":120,"eval_count":30}`))
	}))
	defer srv.Close()

	resp, err := newClient(t, srv.URL).Complete(context.Background(),
		digest.Request{System: "you are", User: "data"})
	if err != nil {
		t.Fatal(err)
	}

	if got["stream"] != false {
		t.Error("stream must be explicitly false, or the response is NDJSON")
	}
	if got["think"] != false {
		t.Error("think must be explicitly false by default: a reasoning model " +
			"spends the whole num_predict budget on its trace and returns empty content")
	}
	if got["keep_alive"] != "10m" {
		t.Errorf("keep_alive = %v", got["keep_alive"])
	}
	opts := got["options"].(map[string]any)
	if opts["num_ctx"] != float64(4096) {
		t.Errorf("options.num_ctx = %v: without it Ollama silently truncates", opts["num_ctx"])
	}
	msgs := got["messages"].([]any)
	if len(msgs) != 2 {
		t.Fatalf("messages = %d, want system + user", len(msgs))
	}

	if resp.Text != "all quiet" || resp.Model != "qwen3:8b" ||
		resp.PromptTokens != 120 || resp.CompletionTokens != 30 {
		t.Errorf("resp = %+v", resp)
	}
}

func TestCompleteErrorMapping(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		wantErr error
	}{
		{"rate limited", 429, `too many`, llm.ErrRateLimited},
		{"auth", 401, `no`, llm.ErrAuth},
		{"unavailable", 500, `boom`, llm.ErrUnavailable},
		{"thinking ate the budget", 200, `{"message":{"content":""},"done_reason":"length"}`, llm.ErrTruncated},
		{"empty response", 200, `{"message":{"content":""},"done_reason":"stop"}`, llm.ErrEmpty},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			_, err := newClient(t, srv.URL).Complete(context.Background(), digest.Request{})
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestCheckVerifiesModelPresence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"models":[{"name":"llama3.2:1b"},{"name":"qwen3:8b"}]}`))
	}))
	defer srv.Close()

	c := newClient(t, srv.URL).(interface {
		Check(context.Context) error
	})
	if err := c.Check(context.Background()); err != nil {
		t.Errorf("model present, Check() = %v", err)
	}

	missing, err := New(map[string]any{"url": srv.URL, "model": "gpt-oss:120b"})
	if err != nil {
		t.Fatal(err)
	}
	if err := missing.(interface {
		Check(context.Context) error
	}).Check(context.Background()); err == nil {
		t.Error("missing model must fail Check()")
	}
}

func TestNewRequiresModel(t *testing.T) {
	if _, err := New(map[string]any{"url": "http://x"}); err == nil {
		t.Error("model is required")
	}
}

// Off by default, but the operator keeps the switch: a model that only
// answers well with a trace is a configuration problem, not a code change.
func TestThinkIsOverridable(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		_, _ = w.Write([]byte(`{"message":{"content":"all quiet"},"done_reason":"stop"}`))
	}))
	defer srv.Close()

	c, err := New(map[string]any{"url": srv.URL, "model": "qwen3:8b", "think": true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Complete(context.Background(), digest.Request{}); err != nil {
		t.Fatal(err)
	}
	if got["think"] != true {
		t.Errorf("think = %v, want true when the operator asks for it", got["think"])
	}
}

// The Modelfile's chat defaults (temperature 1, presence_penalty 1.5) are
// what the operator overrides here; an explicit 0 must reach the server, or
// presence_penalty can never be switched off.
func TestSamplingOptionsAreSentWhenSet(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		_, _ = w.Write([]byte(`{"message":{"content":"ok"},"done_reason":"stop"}`))
	}))
	defer srv.Close()

	c, err := New(map[string]any{"url": srv.URL, "model": "qwen3:8b",
		"temperature": 0.2, "top_p": 0.8, "presence_penalty": 0, "seed": 42})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Complete(context.Background(), digest.Request{}); err != nil {
		t.Fatal(err)
	}
	opts := got["options"].(map[string]any)
	want := map[string]any{"temperature": 0.2, "top_p": 0.8, "presence_penalty": float64(0), "seed": float64(42)}
	for k, v := range want {
		if opts[k] != v {
			t.Errorf("options.%s = %v, want %v", k, opts[k], v)
		}
	}
}

func TestSamplingOptionsLeftToTheModelfileWhenUnset(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		_, _ = w.Write([]byte(`{"message":{"content":"ok"},"done_reason":"stop"}`))
	}))
	defer srv.Close()

	if _, err := newClient(t, srv.URL).Complete(context.Background(), digest.Request{}); err != nil {
		t.Fatal(err)
	}
	opts := got["options"].(map[string]any)
	for _, k := range []string{"temperature", "top_p", "presence_penalty", "seed"} {
		if v, ok := opts[k]; ok {
			t.Errorf("options.%s = %v sent although not configured", k, v)
		}
	}
}

// A misspelt key used to be dropped without a word, leaving the model on its
// Modelfile default while the config claimed otherwise.
func TestNewRejectsUnknownSettings(t *testing.T) {
	_, err := New(map[string]any{"url": "http://x", "model": "qwen3:8b", "presence_penalt": 0})
	if err == nil || !strings.Contains(err.Error(), "presence_penalt") {
		t.Errorf("err = %v, want the unknown key named", err)
	}
}

// fakeOllama answers /api/chat with a fixed reply and /api/tags with whatever
// tags holds at the time of the call, counting the tags lookups.
type fakeOllama struct {
	mu        sync.Mutex
	tags      string
	tagsCalls int
}

func (f *fakeOllama) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/chat":
		_, _ = w.Write([]byte(`{"message":{"content":"ok"},"done_reason":"stop","prompt_eval_count":1,"eval_count":1}`))
	case "/api/tags":
		f.mu.Lock()
		defer f.mu.Unlock()
		f.tagsCalls++
		if f.tags == "" {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(f.tags))
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeOllama) set(tags string) { f.mu.Lock(); f.tags = tags; f.mu.Unlock() }

func (f *fakeOllama) calls() int { f.mu.Lock(); defer f.mu.Unlock(); return f.tagsCalls }

const tagsAliasTo4B = `{"models":[
	{"name":"qwen3:8b","digest":"aaaa","details":{"parameter_size":"8.2B","quantization_level":"Q4_K_M"}},
	{"name":"qwen3.5:9b","digest":"5b0d1a4e","details":{"parameter_size":"4.7B","quantization_level":"Q4_K_M"}}]}`

// The name in the config is an alias: "qwen3.5:9b" served a 4.7B build. The
// run records the digest and size the server reports for it, looked up once
// and reused while fresh.
func TestCompleteRecordsTheModelActuallyServed(t *testing.T) {
	fake := &fakeOllama{tags: tagsAliasTo4B}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	c, err := New(map[string]any{"url": srv.URL, "model": "qwen3.5:9b"})
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 10, 10, 10, 5, 0, 0, time.UTC)
	c.(*Client).now = func() time.Time { return clock }

	for range 2 {
		resp, err := c.Complete(context.Background(), digest.Request{})
		if err != nil {
			t.Fatal(err)
		}
		if resp.Model != "qwen3.5:9b" || resp.ModelDigest != "5b0d1a4e" || resp.ModelSize != "4.7B Q4_K_M" {
			t.Errorf("resp = %+v, want the alias, its digest and the size it really is", resp)
		}
	}
	if fake.calls() != 1 {
		t.Errorf("/api/tags called %d times, want 1: the lookup is cached", fake.calls())
	}

	// Re-tagged while a serve process keeps running: the next hourly run
	// must name the new weights, not the cached ones.
	fake.set(`{"models":[{"name":"qwen3.5:9b","digest":"9e9e","details":{"parameter_size":"9.1B","quantization_level":"Q4_K_M"}}]}`)
	clock = clock.Add(time.Hour)
	resp, err := c.Complete(context.Background(), digest.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.ModelDigest != "9e9e" || resp.ModelSize != "9.1B Q4_K_M" {
		t.Errorf("after a re-tag: resp = %+v", resp)
	}
}

// The lookup is best effort: the reply is already in hand.
func TestServedModelLookupFailureKeepsTheReply(t *testing.T) {
	fake := &fakeOllama{} // /api/tags answers 500
	srv := httptest.NewServer(fake)
	defer srv.Close()

	resp, err := newClient(t, srv.URL).Complete(context.Background(), digest.Request{})
	if err != nil {
		t.Fatalf("a failed /api/tags must not fail the completion: %v", err)
	}
	if resp.Text != "ok" || resp.ModelDigest != "" || resp.ModelSize != "" {
		t.Errorf("resp = %+v, want the reply and no identification", resp)
	}

	fake.set(tagsAliasTo4B)
	if resp, _ := newClient(t, srv.URL).Complete(context.Background(), digest.Request{}); resp.ModelDigest != "aaaa" {
		t.Errorf("model_digest = %q once /api/tags answers", resp.ModelDigest)
	}
}

func TestSameModelReadsAMissingTagAsLatest(t *testing.T) {
	for _, tc := range []struct {
		listed, configured string
		want               bool
	}{
		{"qwen3:8b", "qwen3:8b", true},
		{"llama3:latest", "llama3", true},
		{"llama3:8b", "llama3", false},
		{"qwen3:8b", "qwen3:4b", false},
	} {
		if got := sameModel(tc.listed, tc.configured); got != tc.want {
			t.Errorf("sameModel(%q, %q) = %v", tc.listed, tc.configured, got)
		}
	}
}
