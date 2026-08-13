package elasticsearch

import (
	"fmt"
	"sort"
	"strings"

	"github.com/skandertajine/digestron/internal/digest"
)

// Preset is a ready-made query shipped with digestron: a _search body
// templated on {{.From}}/{{.To}} plus a default title and thresholds.
type Preset struct {
	Title      string
	Thresholds digest.Thresholds
	Body       string
}

var presets = map[string]Preset{}

func lookupPreset(name string) (Preset, error) {
	p, ok := presets[name]
	if !ok {
		return Preset{}, fmt.Errorf("unknown preset %q (available: %s)", name, strings.Join(presetNames(), ", "))
	}
	return p, nil
}

func presetNames() []string {
	out := make([]string, 0, len(presets))
	for n := range presets {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
