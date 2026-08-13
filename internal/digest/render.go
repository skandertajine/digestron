package digest

import (
	"fmt"
	"sort"
	"strings"
)

// RenderText is the default rendering used by every sink unless the operator
// configures a template. Output is deterministic: findings arrive sorted from
// the runner and detail breakdowns are ordered by count, then key.
func RenderText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] %s — %s → %s UTC\n",
		strings.ToUpper(r.Verdict.String()), r.Title,
		r.Window.From.UTC().Format("2006-01-02 15:04"),
		r.Window.To.UTC().Format("15:04"))

	if r.Summary != "" {
		b.WriteString("\n" + r.Summary + "\n")
	}

	if len(r.Findings) > 0 {
		b.WriteString("\n")
		for _, f := range r.Findings {
			fmt.Fprintf(&b, "- [%s] %s: %d", f.Severity, f.Title, f.Count)
			if top := topDetails(f.Details, 3); top != "" {
				fmt.Fprintf(&b, " (%s)", top)
			}
			b.WriteString("\n")
		}
	}

	var unreachable []string
	for _, st := range r.Stats {
		if st.Err != "" {
			unreachable = append(unreachable, st.Source+": "+st.Err)
		}
	}
	if len(unreachable) > 0 {
		fmt.Fprintf(&b, "\nUnreachable sources: %s\n", strings.Join(unreachable, "; "))
	}
	return b.String()
}

func topDetails(details map[string]int, n int) string {
	if len(details) == 0 {
		return ""
	}
	type kv struct {
		k string
		v int
	}
	items := make([]kv, 0, len(details))
	for k, v := range details {
		items = append(items, kv{k, v})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].v != items[j].v {
			return items[i].v > items[j].v
		}
		return items[i].k < items[j].k
	})
	if len(items) > n {
		items = items[:n]
	}
	parts := make([]string, len(items))
	for i, it := range items {
		parts[i] = fmt.Sprintf("%s=%d", it.k, it.v)
	}
	return strings.Join(parts, ", ")
}
