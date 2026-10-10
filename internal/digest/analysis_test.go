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
	a, err := ParseAnalysis("```json\n{\"headline\":\"h\",\"actors\":[]}\n```")
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
	}, actors, "fr")

	for _, want := range []string{"Brute force SSH.", "1. 203.0.113.7 | Example Net, NL | 12 événements, 07:00→07:30 UTC",
		"ports 22(12)", "Tried root.", "brute force SSH", "Menace : moyenne", "2. 192.168.0.5 | réseau local"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "invented") {
		t.Errorf("judgment on a non-actor leaked:\n%s", out)
	}
}

// T221: the model is asked for no action and no campaign, and when it writes
// them anyway (a provider that does not enforce the schema, an old prompt)
// they never reach the report.
func TestAnalysisCarriesNoFreeTextActions(t *testing.T) {
	schema := string(AnalysisSchema([]Actor{{IP: "203.0.113.7"}}))
	for _, field := range []string{`"actions"`, `"campaign"`} {
		if strings.Contains(schema, field) {
			t.Errorf("schema still asks for %s: %s", field, schema)
		}
	}
	if !strings.Contains(schema, `"additionalProperties":false`) {
		t.Errorf("schema must close the object to fields it does not name: %s", schema)
	}

	req, err := BuildRequest(sampleReport(), "fr", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []string{"actions:", "campaign:"} {
		if strings.Contains(req.System, step) {
			t.Errorf("prompt still asks for %q", step)
		}
	}
	if !strings.Contains(req.System, "never recommend") {
		t.Error("prompt must forbid recommendations in the remaining text fields")
	}

	a, err := ParseAnalysis(`{"headline":"Scan bloqué.","actors":[{"ip":"203.0.113.7","activity":"Scan TCP.","pattern":"port_scan","threat":"low","success":false}],
		"campaign":"Campagne coordonnée depuis 203.0.113.0/24, à bannir.",
		"actions":["Bloquer toutes les connexions entrantes depuis la plage locale"]}`)
	if err != nil {
		t.Fatal(err)
	}
	out := RenderAnalysis(a, []Actor{{IP: "203.0.113.7", Events: 3}}, "fr")
	for _, leak := range []string{"Actions", "Bloquer", "Campagne", "bannir", "203.0.113.0/24"} {
		if strings.Contains(out, leak) {
			t.Errorf("%q leaked into the report:\n%s", leak, out)
		}
	}
}

func TestAnalysisSchemaPinsActors(t *testing.T) {
	s := string(AnalysisSchema([]Actor{{IP: "203.0.113.7"}}))
	if !strings.Contains(s, `"enum":["203.0.113.7"]`) || !strings.Contains(s, `"minItems":1`) {
		t.Errorf("schema not pinned: %s", s)
	}
}
