package ollama

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

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
