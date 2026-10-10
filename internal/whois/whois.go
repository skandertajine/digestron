// Package whois identifies who an IP belongs to: its reverse DNS name and
// the network owner and country from the public RDAP registries (rdap.org
// redirects to the right RIR). No API key, no local database. Best effort:
// a lookup that fails leaves the field empty and the run goes on.
package whois

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/skandertajine/digestron/internal/digest"
	"github.com/skandertajine/digestron/internal/httpx"
)

// Enricher caches answers for the life of the process: in serve mode the
// same scanners come back hour after hour.
type Enricher struct {
	RDAPURL string // base, e.g. https://rdap.org/ip/

	mu    sync.Mutex
	cache map[string]result
}

type result struct{ hostname, network, country string }

func New(rdapURL string) *Enricher {
	if rdapURL == "" {
		rdapURL = "https://rdap.org/ip/"
	}
	return &Enricher{RDAPURL: rdapURL, cache: map[string]result{}}
}

// Enrich fills Hostname, Network and Country on a.
func (e *Enricher) Enrich(ctx context.Context, a *digest.Actor) {
	e.mu.Lock()
	res, ok := e.cache[a.IP]
	e.mu.Unlock()
	if !ok {
		res.hostname = reverse(ctx, a.IP)
		res.network, res.country = e.rdap(ctx, a.IP)
		if res.network != "" || res.hostname != "" {
			e.mu.Lock()
			e.cache[a.IP] = res
			e.mu.Unlock()
		}
	}
	a.Hostname, a.Network, a.Country = res.hostname, res.network, res.country
}

func reverse(ctx context.Context, ip string) string {
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

func (e *Enricher) rdap(ctx context.Context, ip string) (network, country string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.RDAPURL+ip, nil)
	if err != nil {
		return "", ""
	}
	req.Header.Set("Accept", "application/rdap+json")
	resp, err := httpx.Do(req, 1)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", ""
	}
	var out rdapIP
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", ""
	}
	return out.network(), out.Country
}

type rdapEntity struct {
	Roles      []string          `json:"roles"`
	VCardArray []json.RawMessage `json:"vcardArray"`
	Entities   []rdapEntity      `json:"entities"`
}

type rdapIP struct {
	Name     string       `json:"name"`
	Country  string       `json:"country"`
	Entities []rdapEntity `json:"entities"`
}

// network joins the range name with the first human-looking owner: the
// registrant or administrative contact, skipping maintainer handles and
// role objects, which name the registry process rather than the operator.
func (r rdapIP) network() string {
	owner := ""
	var walk func([]rdapEntity)
	walk = func(es []rdapEntity) {
		for _, en := range es {
			if owner != "" {
				return
			}
			if hasRole(en.Roles, "registrant", "administrative") {
				if fn := en.fn(); fn != "" && !isHandle(fn) {
					owner = fn
					return
				}
			}
			walk(en.Entities)
		}
	}
	walk(r.Entities)
	switch {
	case owner == "":
		return r.Name
	case r.Name == "":
		return owner
	default:
		return owner + " (" + r.Name + ")"
	}
}

func hasRole(roles []string, want ...string) bool {
	for _, r := range roles {
		for _, w := range want {
			if r == w {
				return true
			}
		}
	}
	return false
}

// fn extracts the formatted name from a jCard: ["vcard", [["fn", {}, "text", "Name"], ...]].
func (en rdapEntity) fn() string {
	if len(en.VCardArray) < 2 {
		return ""
	}
	var props [][]any
	if err := json.Unmarshal(en.VCardArray[1], &props); err != nil {
		return ""
	}
	for _, p := range props {
		if len(p) >= 4 && p[0] == "fn" {
			if s, ok := p[3].(string); ok {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

// isHandle spots maintainer handles ("MNT-NETERRA", "aeza-mnt") and role
// objects, which name the registry process rather than the operator.
func isHandle(fn string) bool {
	l := strings.ToLower(fn)
	return strings.HasPrefix(l, "mnt-") || strings.HasSuffix(l, "-mnt") || strings.Contains(l, "role object")
}
