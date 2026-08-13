// Package openai talks to any OpenAI-compatible /v1/chat/completions
// endpoint: OpenAI itself, a LiteLLM proxy (and through it 100+ providers),
// vLLM, LM Studio, Groq, Mistral... The name of the max-tokens field is
// configurable because implementations disagree (Mistral rejects
// max_completion_tokens with a 422, newer OpenAI models reject max_tokens).
package openai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/skandertajine/digestron/internal/config"
	"github.com/skandertajine/digestron/internal/digest"
	"github.com/skandertajine/digestron/internal/httpx"
	"github.com/skandertajine/digestron/internal/llm"
)

func init() {
	llm.Register("openai-compatible", New)
}

type Config struct {
	URL            string         `koanf:"url"`
	APIKey         config.Secret  `koanf:"api_key"`
	Model          string         `koanf:"model"`
	MaxTokens      int            `koanf:"max_tokens"`
	MaxTokensField string         `koanf:"max_tokens_field"`
	Temperature    *float64       `koanf:"temperature"`
	Extra          map[string]any `koanf:"extra"`
}

type Client struct {
	cfg      Config
	endpoint string
}

func New(settings map[string]any) (digest.LLM, error) {
	cfg := Config{MaxTokens: 512, MaxTokensField: "max_tokens"}
	if err := config.DecodeSettings(settings, &cfg); err != nil {
		return nil, err
	}
	if cfg.URL == "" {
		return nil, fmt.Errorf("url is required")
	}
	if cfg.Model == "" {
		return nil, fmt.Errorf("model is required")
	}
	base := strings.TrimSuffix(strings.TrimSuffix(cfg.URL, "/"), "/v1")
	return &Client{cfg: cfg, endpoint: base + "/v1/chat/completions"}, nil
}

func (c *Client) Name() string { return "openai-compatible" }

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

func (c *Client) Complete(ctx context.Context, req digest.Request) (digest.Response, error) {
	payload := map[string]any{
		"model": c.cfg.Model,
		"messages": []map[string]string{
			{"role": "system", "content": req.System},
			{"role": "user", "content": req.User},
		},
		"stream": false,
	}
	payload[c.cfg.MaxTokensField] = c.cfg.MaxTokens
	if c.cfg.Temperature != nil {
		payload["temperature"] = *c.cfg.Temperature
	}
	for k, v := range c.cfg.Extra {
		payload[k] = v
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return digest.Response{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return digest.Response{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.cfg.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.cfg.APIKey.Reveal())
	}

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
			return digest.Response{}, fmt.Errorf("openai-compatible: %s: %s", resp.Status, msg)
		}
	}

	var out chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return digest.Response{}, fmt.Errorf("openai-compatible: decode response: %w", err)
	}
	if len(out.Choices) == 0 {
		return digest.Response{}, llm.ErrEmpty
	}
	choice := out.Choices[0]
	if choice.Message.Content == "" {
		if choice.FinishReason == "length" {
			return digest.Response{}, fmt.Errorf("%w: the whole budget went to reasoning (finish_reason=length)", llm.ErrTruncated)
		}
		return digest.Response{}, llm.ErrEmpty
	}

	return digest.Response{
		Text:             choice.Message.Content,
		Model:            c.cfg.Model,
		PromptTokens:     out.Usage.PromptTokens,
		CompletionTokens: out.Usage.CompletionTokens,
	}, nil
}

// Check probes the models listing endpoint.
func (c *Client) Check(ctx context.Context) error {
	base := strings.TrimSuffix(c.endpoint, "/chat/completions")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/models", nil)
	if err != nil {
		return err
	}
	if c.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey.Reveal())
	}
	resp, err := httpx.Do(req, 1)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("openai-compatible: %s", resp.Status)
	}
	return nil
}
