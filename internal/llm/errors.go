package llm

import "errors"

// Sentinel errors every provider maps its transport and API failures onto,
// so retry policy lives in one place (retry.go) instead of in each provider.
var (
	ErrRateLimited = errors.New("llm: rate limited")
	ErrUnavailable = errors.New("llm: backend unavailable")
	ErrAuth        = errors.New("llm: authentication failed")
	ErrTruncated   = errors.New("llm: response truncated")
	ErrEmpty       = errors.New("llm: empty response")
)
