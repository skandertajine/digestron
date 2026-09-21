package source

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestQueryErrors(t *testing.T) {
	if err := QueryErrors(3, nil); err != nil {
		t.Errorf("no failures must be no error, got %v", err)
	}

	err := QueryErrors(5, []error{
		errors.New("query \"ssh_auth\": elasticsearch: 400 Bad Request:\n{\"error\":\n  \"nope\"}"),
		errors.New("query \"nginx_public\": dial tcp: refused"),
	})
	if err == nil {
		t.Fatal("failures must surface")
	}
	if !strings.HasPrefix(err.Error(), "2 of 5 queries failed: ") {
		t.Errorf("error must lead with the ratio: %v", err)
	}
	if !strings.Contains(err.Error(), "ssh_auth") || !strings.Contains(err.Error(), "nginx_public") {
		t.Errorf("every failed query must be named: %v", err)
	}
	if strings.ContainsAny(err.Error(), "\n\r\t") {
		t.Errorf("message is rendered into a push notification, keep it on one line: %q", err)
	}
	// One separator per nesting level: sources are joined with "; " in
	// digest.SourceProblems, so the queries inside one source must not be.
	if !strings.Contains(err.Error(), " | ") {
		t.Errorf("queries must be separated by \" | \", not the \"; \" used between sources: %q", err)
	}
}

// Five Elasticsearch rejections quoted at the 512-byte body cap reach ~2.8 KB,
// and the whole thing is pushed to a phone where Firebase drops a payload over
// 4 KB. Cap it, but never at the cost of naming every query that failed.
func TestQueryErrorsIsCapped(t *testing.T) {
	errs := make([]error, 5)
	for i := range errs {
		errs[i] = fmt.Errorf("query %q: elasticsearch: 400 Bad Request: %s",
			fmt.Sprintf("preset_%d", i), strings.Repeat("x", 512))
	}
	err := QueryErrors(5, errs)

	if len(err.Error()) > 900 {
		t.Errorf("message is %d bytes, too close to the 4 KB push payload limit", len(err.Error()))
	}
	if !strings.HasPrefix(err.Error(), "5 of 5 queries failed: ") {
		t.Errorf("the ratio must never be the part that gets cut: %q", err)
	}
	for i := range errs {
		if !strings.Contains(err.Error(), fmt.Sprintf("preset_%d", i)) {
			t.Errorf("query preset_%d was truncated away; every failed query must be named: %q", i, err)
		}
	}
}
