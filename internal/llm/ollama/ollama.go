// Package ollama talks to Ollama's native /api/chat endpoint. The native API
// is deliberate: the OpenAI-compatible /v1 endpoint silently drops num_ctx
// (truncating long prompts without any error) and ignores think:false.
package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/skandertajine/digestron/internal/config"
	"github.com/skandertajine/digestron/internal/digest"
	"github.com/skandertajine/digestron/internal/httpx"
	"github.com/skandertajine/digestron/internal/llm"
)

func init() {
	llm.Register("ollama", New)
}

type Config struct {
	URL         string   `koanf:"url"`
	Model       string   `koanf:"model"`
	NumCtx      int      `koanf:"num_ctx"`
	NumPredict  int      `koanf:"num_predict"`
	KeepAlive   string   `koanf:"keep_alive"`
	Temperature *float64 `koanf:"temperature"`
	// Think stays off unless asked for: on a reasoning model the trace eats
	// num_predict before a single character of the digest is written.
	Think bool `koanf:"think"`
}

type Client struct {
	cfg Config
}

func New(settings map[string]any) (digest.LLM, error) {
	cfg := Config{
		URL:        "http://localhost:11434",
		NumCtx:     8192,
		NumPredict: 512,
		KeepAlive:  "10m",
	}
	if err := config.DecodeSettings(settings, &cfg); err != nil {
		return nil, err
	}
	if cfg.Model == "" {
		return nil, fmt.Errorf("model is required")
	}
	return &Client{cfg: cfg}, nil
}

func (c *Client) Name() string { return "ollama" }

type chatRequest struct {
	Model     string         `json:"model"`
	Messages  []chatMessage  `json:"messages"`
	Stream    bool           `json:"stream"`
	Think     bool           `json:"think"`
	KeepAlive string         `json:"keep_alive,omitempty"`
	Options   map[string]any `json:"options"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	Message struct {
		Content string `json:"content"`
	} `json:"message"`
	DoneReason      string `json:"done_reason"`
	PromptEvalCount int    `json:"prompt_eval_count"`
	EvalCount       int    `json:"eval_count"`
	Error           string `json:"error"`
}

func (c *Client) Complete(ctx context.Context, req digest.Request) (digest.Response, error) {
	options := map[string]any{
		"num_ctx":     c.cfg.NumCtx,
		"num_predict": c.cfg.NumPredict,
	}
	if c.cfg.Temperature != nil {
		options["temperature"] = *c.cfg.Temperature
	}
	body, err := json.Marshal(chatRequest{
		Model: c.cfg.Model,
		Messages: []chatMessage{
			{Role: "system", Content: req.System},
			{Role: "user", Content: req.User},
		},
		Stream:    false,
		Think:     c.cfg.Think,
		KeepAlive: c.cfg.KeepAlive,
		Options:   options,
	})
	if err != nil {
		return digest.Response{}, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.cfg.URL+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return digest.Response{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := httpx.Do(httpReq, 1)
	if err != nil {
		return digest.Response{}, fmt.Errorf("%w: %w", llm.ErrUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		switch {
		case resp.StatusCode == http.StatusTooManyRequests:
			return digest.Response{}, fmt.Errorf("%w: %s", llm.ErrRateLimited, msg)
		case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
			return digest.Response{}, fmt.Errorf("%w: %s", llm.ErrAuth, msg)
		case resp.StatusCode >= 500:
			return digest.Response{}, fmt.Errorf("%w: %s: %s", llm.ErrUnavailable, resp.Status, msg)
		default:
			return digest.Response{}, fmt.Errorf("ollama: %s: %s", resp.Status, msg)
		}
	}

	var out chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return digest.Response{}, fmt.Errorf("ollama: decode response: %w", err)
	}
	if out.Error != "" {
		return digest.Response{}, fmt.Errorf("ollama: %s", out.Error)
	}
	if out.Message.Content == "" {
		if out.DoneReason == "length" {
			return digest.Response{}, fmt.Errorf("%w: the whole budget went to thinking (done_reason=length)", llm.ErrTruncated)
		}
		return digest.Response{}, llm.ErrEmpty
	}

	return digest.Response{
		Text:             out.Message.Content,
		Model:            c.cfg.Model,
		PromptTokens:     out.PromptEvalCount,
		CompletionTokens: out.EvalCount,
	}, nil
}

// Check verifies the server answers and knows the configured model.
func (c *Client) Check(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.URL+"/api/tags", nil)
	if err != nil {
		return err
	}
	resp, err := httpx.Do(req, 1)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ollama: %s", resp.Status)
	}
	var tags struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return err
	}
	for _, m := range tags.Models {
		if m.Name == c.cfg.Model {
			return nil
		}
	}
	return fmt.Errorf("ollama: model %q not found on the server", c.cfg.Model)
}
