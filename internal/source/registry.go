// Package source registers pull-based data source modules.
package source

import (
	"fmt"
	"sort"
	"strings"

	"github.com/skandertajine/digestron/internal/digest"
)

// Factory builds a source from its opaque settings block.
type Factory func(name string, settings map[string]any) (digest.Source, error)

var registry = map[string]Factory{}

// Register is called from a provider's init(); a duplicate type is a
// programming error.
func Register(typ string, f Factory) {
	if _, dup := registry[typ]; dup {
		panic("source: duplicate type " + typ)
	}
	registry[typ] = f
}

// Build instantiates a configured source. Errors carry the module name and,
// for unknown types, the list of what is available.
func Build(typ, name string, settings map[string]any) (digest.Source, error) {
	f, ok := registry[typ]
	if !ok {
		return nil, fmt.Errorf("unknown source type %q (available: %s)", typ, strings.Join(Types(), ", "))
	}
	s, err := f(name, settings)
	if err != nil {
		return nil, fmt.Errorf("source %q: %w", name, err)
	}
	return s, nil
}

func Types() []string {
	out := make([]string, 0, len(registry))
	for t := range registry {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
