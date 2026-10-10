package digest

import (
	"strings"
	"testing"
	"time"
)

func TestRankActorsSumsAcrossFindingsAndSkipsNonIPs(t *testing.T) {
	got := RankActors([]Finding{
		{Title: "ssh", Details: map[string]int{"203.0.113.7": 3, "198.51.100.1": 10}},
		{Title: "ufw", Details: map[string]int{"203.0.113.7": 9, "192.168.0.5": 1}},
		{Title: "apps", Details: map[string]int{"immich": 50}},
	}, 2)
	if len(got) != 2 || got[0].IP != "203.0.113.7" || got[0].Events != 12 || got[1].IP != "198.51.100.1" {
		t.Fatalf("ranking = %+v", got)
	}
	if got[0].Findings["ssh"] != 3 || got[0].Findings["ufw"] != 9 {
		t.Errorf("per-finding counts = %v", got[0].Findings)
	}
	if all := RankActors([]Finding{{Details: map[string]int{"192.168.0.5": 1}}}, 5); !all[0].Internal {
		t.Error("private address not flagged internal")
	}
}

func TestParseAnalysisToleratesFences(t *testing.T) {
	a, err := ParseAnalysis("```json\n{\"headline\":\"h\",\"actors\":[],\"campaign\":\"\",\"actions\":[]}\n```")
	if err != nil || a.Headline != "h" {
		t.Fatalf("a=%+v err=%v", a, err)
	}
	if _, err := ParseAnalysis("just prose"); err == nil {
		t.Error("prose accepted as an analysis")
	}
}

func TestRenderAnalysisFactsFromGoJudgmentsFromModel(t *testing.T) {
	t0 := time.Date(2026, 10, 10, 7, 0, 0, 0, time.UTC)
	actors := []Actor{
		{IP: "203.0.113.7", Events: 12, Network: "Example Net", Country: "NL", FirstSeen: t0, LastSeen: t0.Add(30 * time.Minute),
			Facets: map[string]map[string]int{"dst_port": {"22": 12}}},
		{IP: "192.168.0.5", Internal: true, Events: 1},
	}
	out := RenderAnalysis(Analysis{
		Headline: "Brute force SSH.",
		Actors: []ActorAnalysis{
			{IP: "203.0.113.7", Activity: "Tried root.", Pattern: "ssh_bruteforce", Threat: "medium"},
			{IP: "10.9.9.9", Activity: "invented", Pattern: "unclear", Threat: "high"},
		},
		Actions: []string{"a", "b", "c", "d"},
	}, actors, "fr")

	for _, want := range []string{"Brute force SSH.", "1. 203.0.113.7 | Example Net, NL | 12 événements, 07:00→07:30 UTC",
		"ports 22(12)", "Tried root.", "brute force SSH", "Menace : moyenne", "2. 192.168.0.5 | réseau local", "- c"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "invented") || strings.Contains(out, "- d") {
		t.Errorf("judgment on a non-actor or a fourth action leaked:\n%s", out)
	}
}

func TestAnalysisSchemaPinsActors(t *testing.T) {
	s := string(AnalysisSchema([]Actor{{IP: "203.0.113.7"}}))
	if !strings.Contains(s, `"enum":["203.0.113.7"]`) || !strings.Contains(s, `"minItems":1`) {
		t.Errorf("schema not pinned: %s", s)
	}
}
