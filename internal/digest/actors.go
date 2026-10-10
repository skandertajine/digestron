package digest

import (
	"context"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// RankActors turns the per-IP breakdowns of every finding into the n most
// active addresses. Detail keys that are not IPs (namespaces, metric labels)
// are ignored. Order is deterministic: events, then IP.
func RankActors(findings []Finding, n int) []Actor {
	byIP := map[string]*Actor{}
	for _, f := range findings {
		for key, count := range f.Details {
			addr, err := netip.ParseAddr(key)
			if err != nil {
				continue
			}
			a := byIP[key]
			if a == nil {
				a = &Actor{
					IP:       key,
					Internal: addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast(),
					Findings: map[string]int{},
				}
				byIP[key] = a
			}
			a.Events += count
			a.Findings[f.Title] += count
		}
	}
	out := make([]Actor, 0, len(byIP))
	for _, a := range byIP {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Events != out[j].Events {
			return out[i].Events > out[j].Events
		}
		return out[i].IP < out[j].IP
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// investigate ranks the top actors and asks every investigating source, then
// the enricher, to fill them in, bounded by InvestigateTimeout.
func (r *Runner) investigate(ctx context.Context, report *Report) {
	if r.TopActors <= 0 {
		return
	}
	report.Actors = RankActors(report.Findings, r.TopActors)
	if len(report.Actors) == 0 {
		return
	}
	r.phase("investigating")

	var investigators []Investigator
	for _, s := range r.Sources {
		if inv, ok := s.Source.(Investigator); ok {
			investigators = append(investigators, inv)
		}
	}

	ictx := ctx
	if r.InvestigateTimeout > 0 {
		var cancel context.CancelFunc
		ictx, cancel = context.WithTimeout(ctx, r.InvestigateTimeout)
		defer cancel()
	}
	start := time.Now()
	// Sources are queried one actor at a time — a small Elasticsearch trips
	// its circuit breaker on parallel aggregations — while the enrichment,
	// which leaves the cluster, runs alongside.
	var wg sync.WaitGroup
	for i := range report.Actors {
		a := &report.Actors[i]
		for _, inv := range investigators {
			if err := inv.Investigate(ictx, report.Window, a); err != nil {
				r.Log.Warn("investigation failed", "ip", a.IP, "error", r.scrub(err.Error()))
			}
		}
		if r.Enrich != nil && !a.Internal {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r.Enrich(ictx, a)
			}()
		}
	}
	wg.Wait()
	r.Log.Debug("actors investigated", "actors", len(report.Actors),
		"investigators", len(investigators), "ms", time.Since(start).Milliseconds())
}
