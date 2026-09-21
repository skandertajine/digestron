package digest

import "context"

// Source pulls security-relevant data for a time window. Collect may return
// findings and a non-nil error together: a source made of several queries
// reports what it got plus what it lost, and the runner keeps both.
type Source interface {
	Name() string
	Collect(ctx context.Context, w Window) ([]Finding, error)
}

// Sink delivers a rendered report to a notification channel.
type Sink interface {
	Name() string
	Send(ctx context.Context, r Report) error
}

// LLM turns aggregated findings into a short natural-language summary.
type LLM interface {
	Name() string
	Complete(ctx context.Context, req Request) (Response, error)
}

// Checker is optionally implemented by modules that support a cheap
// connectivity probe, used by `digestron check`.
type Checker interface {
	Check(ctx context.Context) error
}
