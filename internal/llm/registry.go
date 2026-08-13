// Package llm registers language model providers and defines the error
// taxonomy shared by all of them.
package llm

import (
	"fmt"
	"sort"
	"strings"

	"github.com/skandertajine/digestron/internal/digest"
)

// Factory builds a provider from its opaque settings block.
type Factory func(settings map[string]any) (digest.LLM, error)

var registry = map[string]Factory{}

// Register is called from a provider's init(); a duplicate type is a
// programming error.
func Register(typ string, f Factory) {
	if _, dup := registry[typ]; dup {
		panic("llm: duplicate type " + typ)
	}
	registry[typ] = f
}

// Build instantiates the configured provider. Unknown types list what is
// available.
func Build(typ string, settings map[string]any) (digest.LLM, error) {
	f, ok := registry[typ]
	if !ok {
		return nil, fmt.Errorf("unknown llm type %q (available: %s)", typ, strings.Join(Types(), ", "))
	}
	c, err := f(settings)
	if err != nil {
		return nil, fmt.Errorf("llm %q: %w", typ, err)
	}
	return c, nil
}

func Types() []string {
	out := make([]string, 0, len(registry))
	for t := range registry {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
