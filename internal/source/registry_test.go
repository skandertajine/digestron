package source

import (
	"context"
	"strings"
	"testing"

	"github.com/skandertajine/digestron/internal/digest"
)

type fakeSource struct{ name string }

func (f fakeSource) Name() string { return f.name }
func (f fakeSource) Collect(context.Context, digest.Window) ([]digest.Finding, error) {
	return nil, nil
}

func TestRegistry(t *testing.T) {
	Register("fake", func(name string, _ map[string]any) (digest.Source, error) {
		return fakeSource{name: name}, nil
	})

	s, err := Build("fake", "mine", nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.Name() != "mine" {
		t.Errorf("name = %q, want mine", s.Name())
	}

	_, err = Build("nope", "x", nil)
	if err == nil || !strings.Contains(err.Error(), `unknown source type "nope"`) ||
		!strings.Contains(err.Error(), "fake") {
		t.Errorf("unknown type error must list available types, got: %v", err)
	}

	defer func() {
		if recover() == nil {
			t.Error("duplicate Register must panic")
		}
	}()
	Register("fake", nil)
}
