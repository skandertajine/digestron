package elasticsearch

import (
	"embed"
	"fmt"
	"sort"
	"strings"

	"github.com/skandertajine/digestron/internal/digest"
)

//go:embed presets/*.json
var presetFS embed.FS

// Preset is a ready-made query shipped with digestron: a _search body
// templated on {{.From}}/{{.To}} plus a default title and thresholds. The
// bodies live in presets/*.json; titles and thresholds live here and are
// overridable per query in the configuration.
type Preset struct {
	Title      string
	Thresholds digest.Thresholds
	Body       string
}

var presetMeta = map[string]struct {
	title string
	th    digest.Thresholds
}{
	"fail2ban":           {"fail2ban bans", digest.Thresholds{Warning: 1, Critical: 5}},
	"ssh_auth":           {"ssh auth failures", digest.Thresholds{Warning: 3, Critical: 20}},
	"app_login_failures": {"application login failures", digest.Thresholds{Warning: 1, Critical: 10}},
	"ufw_blocks":         {"firewall blocked flows", digest.Thresholds{Warning: 200, Critical: 2000}},
	"nginx_public":       {"public edge http errors", digest.Thresholds{Warning: 20, Critical: 200}},
}

var presets = loadPresets()

func loadPresets() map[string]Preset {
	out := make(map[string]Preset, len(presetMeta))
	for name, meta := range presetMeta {
		body, err := presetFS.ReadFile("presets/" + name + ".json")
		if err != nil {
			panic(fmt.Sprintf("elasticsearch: preset %q has no body file: %v", name, err))
		}
		out[name] = Preset{Title: meta.title, Thresholds: meta.th, Body: string(body)}
	}
	return out
}

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
