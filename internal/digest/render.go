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

	if p := SourceProblems(r); p != "" {
		b.WriteString("\n" + p + "\n")
	}
	return b.String()
}

// SourceProblems names the sources that did not answer in full, on at most
// two lines. A source that returned nothing is "Failed" — the source itself,
// or the network to it, is the thing to look at. A source that returned
// findings *and* an error is "Partial": the counts above it are real but
// short, and the gap is in one query, not in the wire. Conflating the two is
// what sends an operator hunting a network fault when a query body was
// rejected. Empty when every source answered in full.
//
// Exported because the failure has to reach the operator whatever built the
// message. A sink that sends the LLM summary instead of the rendered digest
// never calls RenderText, so it appends this itself; otherwise a run where
// four queries of five never executed arrives looking complete.
func SourceProblems(r Report) string {
	var failed, partial []string
	for _, st := range r.Stats {
		switch {
		case st.Partial():
			partial = append(partial, st.Source+": "+st.Err)
		case st.Err != "":
			failed = append(failed, st.Source+": "+st.Err)
		}
	}
	var lines []string
	if len(failed) > 0 {
		lines = append(lines, "Failed sources: "+strings.Join(failed, "; "))
	}
	if len(partial) > 0 {
		lines = append(lines, "Partial sources: "+strings.Join(partial, "; "))
	}
	// One separator level per nesting level: "; " between sources here,
	// " | " between the queries inside one source (see source.QueryErrors).
	return strings.Join(lines, "\n")
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
