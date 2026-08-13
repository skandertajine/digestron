package openai

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

func TestCompleteRequestShape(t *testing.T) {
	var got map[string]any
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"quiet night"},"finish_reason":"stop"}],
			"usage":{"prompt_tokens":200,"completion_tokens":40}}`))
	}))
	defer srv.Close()

	c, err := New(map[string]any{
		"url":              srv.URL,
		"api_key":          "sk-test",
		"model":            "gpt-4o-mini",
		"max_tokens":       800,
		"max_tokens_field": "max_completion_tokens",
		"extra":            map[string]any{"top_p": 0.9},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Complete(context.Background(), digest.Request{System: "sys", User: "data"})
	if err != nil {
		t.Fatal(err)
	}

	if gotPath != "/v1/chat/completions" {
		t.Errorf("path = %q", gotPath)
	}
	if gotAuth != "Bearer sk-test" {
		t.Errorf("auth header = %q", gotAuth)
	}
	if got["max_completion_tokens"] != float64(800) {
		t.Errorf("configurable max tokens field missing: %v", got)
	}
	if _, present := got["max_tokens"]; present {
		t.Error("default field name must not leak when overridden")
	}
	if _, present := got["temperature"]; present {
		t.Error("temperature must be omitted when unset (some models reject it)")
	}
	if got["top_p"] != 0.9 {
		t.Errorf("extra body not merged: %v", got)
	}
	if resp.Text != "quiet night" || resp.PromptTokens != 200 || resp.CompletionTokens != 40 {
		t.Errorf("resp = %+v", resp)
	}
}

func TestURLNormalization(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("path = %q, double /v1 in URL", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"x"},"finish_reason":"stop"}]}`))
	}))
	defer srv.Close()

	for _, base := range []string{srv.URL, srv.URL + "/", srv.URL + "/v1", srv.URL + "/v1/"} {
		c, err := New(map[string]any{"url": base, "model": "m"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Complete(context.Background(), digest.Request{}); err != nil {
			t.Errorf("base %q: %v", base, err)
		}
	}
}

func TestCompleteErrorMapping(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		wantErr error
	}{
		{"rate limited", 429, `{}`, llm.ErrRateLimited},
		{"auth", 401, `{}`, llm.ErrAuth},
		{"unavailable", 503, `{}`, llm.ErrUnavailable},
		{"no choices", 200, `{"choices":[]}`, llm.ErrEmpty},
		{"reasoning ate the budget", 200, `{"choices":[{"message":{"content":""},"finish_reason":"length"}]}`, llm.ErrTruncated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			c, err := New(map[string]any{"url": srv.URL, "model": "m"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Complete(context.Background(), digest.Request{}); !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New(map[string]any{"model": "m"}); err == nil {
		t.Error("url is required")
	}
	if _, err := New(map[string]any{"url": "http://x"}); err == nil {
		t.Error("model is required")
	}
}
