package source

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	sep = " | "
	// maxQueryMessage caps one failed query's message. The head carries what
	// identifies the failure — the query name, the status, the first line of
	// the upstream reason — and the tail is the rest of a quoted JSON error.
	maxQueryMessage = 200
	// minQueryMessage is the shortest excerpt still worth keeping: about the
	// length of `query "app_login_failures": elasticsearch: 400 Bad Request`.
	// Below this the per-message budget stops shrinking and the whole line is
	// cut at the end instead.
	minQueryMessage = 64
	// maxQueryErrors caps the joined detail. The message is pushed to a phone
	// verbatim: Firebase rejects a notification payload over 4 KB, and five
	// Elasticsearch rejections quoted at the 512-byte body cap in
	// elasticsearch.go reach ~2.8 KB on their own.
	maxQueryErrors = 800
)

// QueryErrors summarizes the queries that failed inside one source, for the
// error Collect returns next to the findings that did succeed. A source runs
// every query and reports the casualties here: one broken query costs its own
// finding and nothing else.
//
// The message is folded onto a single line and length-capped — it reaches the
// operator verbatim, in a push notification, and the upstream bodies quoted in
// it (an Elasticsearch rejection, say) come with newlines and kilobytes of
// their own. The budget is split evenly across the failures rather than spent
// first-come: naming every query that failed matters more than quoting any one
// of them in full. Queries are separated by " | ", one level below the "; "
// that separates sources in digest.SourceProblems, so the nesting stays
// readable.
//
// Trade-off: the failures are flattened to text with %s rather than wrapped
// with %w, so errors.Is and errors.As cannot reach them. Nothing unwraps a
// source error today — every caller renders it — and wrapping several errors
// while keeping this one-line shape would cost more than it buys. Revisit if
// a caller ever needs to match on a cause.
func QueryErrors(total int, errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	budget := (maxQueryErrors - (len(errs)-1)*len(sep)) / len(errs)
	budget = min(max(budget, minQueryMessage), maxQueryMessage)

	msgs := make([]string, len(errs))
	for i, err := range errs {
		msgs[i] = truncate(strings.Join(strings.Fields(err.Error()), " "), budget)
	}
	detail := truncate(strings.Join(msgs, sep), maxQueryErrors)
	return fmt.Errorf("%d of %d queries failed: %s", len(errs), total, detail)
}

// truncate cuts s to at most max bytes, ellipsis included, without splitting a
// rune: a reader must be able to tell a full message from a clipped one.
func truncate(s string, max int) string {
	const ellipsis = "…"
	if len(s) <= max {
		return s
	}
	cut := max - len(ellipsis)
	if cut < 0 {
		cut = 0
	}
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return strings.TrimRight(s[:cut], " ") + ellipsis
}
