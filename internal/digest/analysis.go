package digest

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Analysis is what the LLM is asked for: judgments only. Every number, owner
// and timestamp in the final report comes from Go (RenderAnalysis); a small
// local model writing free text invents ports, repeats IPs and loops until
// its token budget runs out.
type Analysis struct {
	Headline string          `json:"headline"`
	Actors   []ActorAnalysis `json:"actors"`
	Campaign string          `json:"campaign"`
	Actions  []string        `json:"actions"`
}

type ActorAnalysis struct {
	IP       string `json:"ip"`
	Activity string `json:"activity"` // what it did, in one or two sentences
	Pattern  string `json:"pattern"`
	Threat   string `json:"threat"`
	Success  bool   `json:"success"`
}

var patterns = []string{"port_scan", "ssh_bruteforce", "web_login_bruteforce", "web_vuln_scan", "bot_crawler", "internal_device", "unclear"}

// AnalysisSchema constrains the reply (Ollama "format", JSON schema). The
// actors array is pinned to the run's IPs, in number and in value: a small
// model otherwise skips the first one or adds IPs it saw in the details.
func AnalysisSchema(actors []Actor) json.RawMessage {
	ips := make([]string, 0, len(actors))
	for _, a := range actors {
		ips = append(ips, a.IP)
	}
	ipSchema := map[string]any{"type": "string"}
	if len(ips) > 0 {
		ipSchema["enum"] = ips
	}
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"headline": map[string]any{"type": "string"},
			"actors": map[string]any{
				"type": "array", "minItems": len(ips), "maxItems": len(ips),
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"ip":       ipSchema,
						"activity": map[string]any{"type": "string"},
						"pattern":  map[string]any{"type": "string", "enum": patterns},
						"threat":   map[string]any{"type": "string", "enum": []string{"low", "medium", "high"}},
						"success":  map[string]any{"type": "boolean"},
					},
					"required": []string{"ip", "activity", "pattern", "threat", "success"},
				},
			},
			"campaign": map[string]any{"type": "string"},
			"actions":  map[string]any{"type": "array", "maxItems": 3, "items": map[string]any{"type": "string"}},
		},
		"required": []string{"headline", "actors", "campaign", "actions"},
	}
	raw, _ := json.Marshal(schema)
	return raw
}

// ParseAnalysis reads the model's JSON, tolerating code fences and text
// around the object.
func ParseAnalysis(text string) (Analysis, error) {
	var a Analysis
	i, j := strings.Index(text, "{"), strings.LastIndex(text, "}")
	if i < 0 || j <= i {
		return a, fmt.Errorf("no JSON object in the reply")
	}
	if err := json.Unmarshal([]byte(text[i:j+1]), &a); err != nil {
		return a, err
	}
	if strings.TrimSpace(a.Headline) == "" {
		return a, fmt.Errorf("reply has no headline")
	}
	return a, nil
}

// labels hold French words that misspell reads as English typos.
//
//nolint:misspell
var labels = map[string]map[string]string{
	"fr": {
		"events": "événements", "ports": "ports", "urls": "URLs", "apps": "apps", "jails": "jails", "status": "HTTP",
		"pattern": "Pattern", "threat": "Menace", "success": "SIGNE DE SUCCÈS", "nosuccess": "aucun signe de succès",
		"campaign": "Campagne", "actions": "Actions", "internal": "réseau local", "unknown": "propriétaire inconnu",
		"low": "faible", "medium": "moyenne", "high": "haute",
		"port_scan": "scan de ports", "ssh_bruteforce": "brute force SSH", "web_login_bruteforce": "brute force login web",
		"web_vuln_scan": "scan de vulnérabilités web", "bot_crawler": "bot/crawler", "internal_device": "appareil interne", "unclear": "indéterminé",
	},
	"en": {
		"events": "events", "ports": "ports", "urls": "URLs", "apps": "apps", "jails": "jails", "status": "HTTP",
		"pattern": "Pattern", "threat": "Threat", "success": "SIGN OF SUCCESS", "nosuccess": "no sign of success",
		"campaign": "Campaign", "actions": "Actions", "internal": "home network", "unknown": "unknown owner",
		"low": "low", "medium": "medium", "high": "high",
		"port_scan": "port scan", "ssh_bruteforce": "SSH brute force", "web_login_bruteforce": "web login brute force",
		"web_vuln_scan": "web vulnerability scan", "bot_crawler": "bot/crawler", "internal_device": "internal device", "unclear": "unclear",
	},
}

// RenderAnalysis merges the model's judgments with the facts Go collected
// into the report text: headline, one block per actor in rank order, the
// campaign note and the actions. Judgments about IPs that are not actors
// are dropped; actors the model skipped still get their facts.
func RenderAnalysis(a Analysis, actors []Actor, language string) string {
	l, ok := labels[language]
	if !ok {
		l = labels["en"]
	}
	tr := func(k string) string {
		if v, ok := l[k]; ok {
			return v
		}
		return k
	}
	byIP := map[string]ActorAnalysis{}
	for _, aa := range a.Actors {
		if _, seen := byIP[aa.IP]; !seen {
			byIP[aa.IP] = aa
		}
	}

	var b strings.Builder
	b.WriteString(strings.TrimSpace(a.Headline) + "\n")
	for i, act := range actors {
		who := act.Network
		switch {
		case act.Internal:
			who = tr("internal")
		case who == "":
			who = tr("unknown")
		}
		if act.Country != "" {
			who += ", " + act.Country
		}
		fmt.Fprintf(&b, "\n%d. %s | %s | %d %s", i+1, act.IP, who, act.Events, tr("events"))
		if !act.FirstSeen.IsZero() {
			fmt.Fprintf(&b, ", %s→%s UTC", act.FirstSeen.UTC().Format("15:04"), act.LastSeen.UTC().Format("15:04"))
		}
		b.WriteString("\n")
		if act.Hostname != "" {
			b.WriteString("   rDNS " + act.Hostname + "\n")
		}
		var facts []string
		for _, f := range []struct{ key, label string }{
			{"dst_port", "ports"}, {"app", "apps"}, {"fail2ban_jail", "jails"}, {"http_status", "status"}, {"url", "urls"},
		} {
			if top := topKeys(act.Facets[f.key], 5); top != "" {
				facts = append(facts, tr(f.label)+" "+top)
			}
		}
		if len(facts) > 0 {
			b.WriteString("   " + strings.Join(facts, " · ") + "\n")
		}
		if aa, ok := byIP[act.IP]; ok {
			if s := strings.TrimSpace(aa.Activity); s != "" {
				b.WriteString("   " + s + "\n")
			}
			success := tr("nosuccess")
			if aa.Success {
				success = tr("success")
			}
			fmt.Fprintf(&b, "   %s : %s · %s : %s · %s\n", tr("pattern"), tr(aa.Pattern), tr("threat"), tr(aa.Threat), success)
		}
	}
	if c := strings.TrimSpace(a.Campaign); c != "" {
		b.WriteString("\n" + tr("campaign") + " : " + c + "\n")
	}
	if len(a.Actions) > 0 {
		b.WriteString("\n" + tr("actions") + " :\n")
		for i, act := range a.Actions {
			if i == 3 {
				break
			}
			b.WriteString("- " + strings.TrimSpace(act) + "\n")
		}
	}
	return strings.TrimSpace(b.String())
}

func topKeys(m map[string]int, n int) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if len(keys) > n {
		keys = keys[:n]
	}
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s(%d)", k, m[k])
	}
	return strings.Join(parts, ", ")
}

// duration between first and last activity, for the prompt.
func activeFor(a Actor) time.Duration {
	if a.FirstSeen.IsZero() || a.LastSeen.IsZero() {
		return 0
	}
	return a.LastSeen.Sub(a.FirstSeen)
}
