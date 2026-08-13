// Package noop is the null LLM provider: it returns no summary, which makes
// the pipeline emit the raw counter digest. Used by tests and --no-llm.
package noop

import (
	"context"

	"github.com/skandertajine/digestron/internal/digest"
	"github.com/skandertajine/digestron/internal/llm"
)

func init() {
	llm.Register("noop", func(map[string]any) (digest.LLM, error) { return Client{}, nil })
}

type Client struct{}

func (Client) Name() string { return "noop" }

func (Client) Complete(context.Context, digest.Request) (digest.Response, error) {
	return digest.Response{}, nil
}
