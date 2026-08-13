package llm

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/skandertajine/digestron/internal/digest"
)

// WithRetry wraps any provider with a retry policy: only rate limits and
// backend unavailability are retried (with exponential backoff and jitter);
// auth failures, truncation and empty responses fail fast.
func WithRetry(inner digest.LLM, attempts int) digest.LLM {
	if attempts < 1 {
		attempts = 1
	}
	return retrier{inner: inner, attempts: attempts}
}

type retrier struct {
	inner    digest.LLM
	attempts int
}

func (r retrier) Name() string { return r.inner.Name() }

func (r retrier) Complete(ctx context.Context, req digest.Request) (digest.Response, error) {
	var lastErr error
	for i := 0; i < r.attempts; i++ {
		if i > 0 {
			backoff := time.Duration(1<<uint(i-1)) * time.Second  // #nosec G115 -- small loop index
			backoff += time.Duration(rand.Int64N(int64(backoff))) // #nosec G404 -- jitter, not crypto
			select {
			case <-ctx.Done():
				return digest.Response{}, ctx.Err()
			case <-time.After(backoff):
			}
		}
		resp, err := r.inner.Complete(ctx, req)
		if err == nil {
			return resp, nil
		}
		if !errors.Is(err, ErrRateLimited) && !errors.Is(err, ErrUnavailable) {
			return digest.Response{}, err
		}
		lastErr = err
	}
	return digest.Response{}, lastErr
}
