// Package httpx provides the one shared HTTP client and a small retry
// helper. Modules must not create their own http.Client: a client per call
// leaks sockets, and scattering timeouts breaks the run deadline.
package httpx

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net/http"
	"time"
)

// Client is shared by every module. It deliberately has no global timeout:
// every request carries a context deadline (module timeout for sources and
// sinks, the longer llm.timeout for completions), so a single knob here
// would silently undercut one of them.
var Client = &http.Client{
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	},
}

// Retryable reports whether a response status is worth retrying.
func Retryable(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

// Do sends the request, retrying on 429/5xx and transport errors with
// exponential backoff and jitter. The caller's context bounds the whole
// exchange, retries included. Requests built with NewRequestWithContext and
// a bytes.Reader body rewind automatically between attempts via GetBody.
// The final response body is the caller's to close; intermediate bodies are
// drained and closed here.
func Do(req *http.Request, attempts int) (*http.Response, error) {
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			backoff := time.Duration(1<<uint(i-1)) * 500 * time.Millisecond // #nosec G115 -- small loop index
			backoff += time.Duration(rand.Int64N(int64(backoff)))           // #nosec G404 -- jitter, not crypto
			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case <-time.After(backoff):
			}
			if req.GetBody != nil {
				body, err := req.GetBody()
				if err != nil {
					return nil, err
				}
				req.Body = body
			}
		}

		resp, err := Client.Do(req) // #nosec G704 -- URLs come from operator-provided configuration
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
			lastErr = err
			continue
		}
		if !Retryable(resp.StatusCode) || i == attempts-1 {
			return resp, nil
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		lastErr = errors.New("http: " + resp.Status)
	}
	return nil, lastErr
}
