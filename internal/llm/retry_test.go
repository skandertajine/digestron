package llm

import (
	"context"
	"errors"
	"testing"

	"github.com/skandertajine/digestron/internal/digest"
)

type scripted struct {
	errs  []error
	calls int
}

func (s *scripted) Name() string { return "scripted" }

func (s *scripted) Complete(context.Context, digest.Request) (digest.Response, error) {
	err := s.errs[s.calls]
	s.calls++
	if err != nil {
		return digest.Response{}, err
	}
	return digest.Response{Text: "ok"}, nil
}

func TestRetryOnTransientErrors(t *testing.T) {
	for _, transient := range []error{ErrRateLimited, ErrUnavailable} {
		s := &scripted{errs: []error{transient, transient, nil}}
		resp, err := WithRetry(s, 3).Complete(context.Background(), digest.Request{})
		if err != nil || resp.Text != "ok" {
			t.Errorf("%v: resp=%+v err=%v, want success after retries", transient, resp, err)
		}
		if s.calls != 3 {
			t.Errorf("%v: calls = %d, want 3", transient, s.calls)
		}
	}
}

func TestNoRetryOnFatalErrors(t *testing.T) {
	for _, fatal := range []error{ErrAuth, ErrTruncated, ErrEmpty, errors.New("boom")} {
		s := &scripted{errs: []error{fatal, nil}}
		_, err := WithRetry(s, 3).Complete(context.Background(), digest.Request{})
		if !errors.Is(err, fatal) {
			t.Errorf("err = %v, want %v", err, fatal)
		}
		if s.calls != 1 {
			t.Errorf("%v: calls = %d, want 1 (no retry)", fatal, s.calls)
		}
	}
}

func TestRetryExhaustion(t *testing.T) {
	s := &scripted{errs: []error{ErrUnavailable, ErrUnavailable, ErrUnavailable}}
	_, err := WithRetry(s, 3).Complete(context.Background(), digest.Request{})
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("err = %v, want ErrUnavailable after exhaustion", err)
	}
	if s.calls != 3 {
		t.Errorf("calls = %d, want 3", s.calls)
	}
}
