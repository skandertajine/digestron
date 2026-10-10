package digest

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Replays of the two dev runs whose report told the operator to block the
// k3s node that runs the monitoring (10:05) and then every inbound
// connection from the home network (11:05), on 2026-10-10. Rebuilt with
// documentation addresses and invented owners: the same findings, the same
// shape of investigation, the same kind of reply. T221: whatever the model
// answers, no action and no text that did not pass ParseAnalysis reaches
// Summary, and a reply that does not parse leaves the counters alone.

type replaySource struct {
	findings []Finding
	facets   map[string]map[string]map[string]int
}

func (s replaySource) Name() string { return "es-security" }

func (s replaySource) Collect(context.Context, Window) ([]Finding, error) {
	return append([]Finding(nil), s.findings...), nil
}

func (s replaySource) Investigate(_ context.Context, _ Window, a *Actor) error {
	a.Facets = s.facets[a.IP]
	return nil
}

func quietFindings(blocked Finding) []Finding {
	return []Finding{
		blocked,
		{Source: "es-security", Title: "application login failures"},
		{Source: "es-security", Title: "fail2ban bans"},
		{Source: "es-security", Title: "public edge http errors"},
		{Source: "es-security", Title: "ssh auth failures"},
	}
}

func scanFacets(ports map[string]int) map[string]map[string]int {
	total := 0
	for _, n := range ports {
		total += n
	}
	return map[string]map[string]int{"dst_port": ports, "app": {"kernel": total}}
}

type replayRun struct {
	name     string
	source   replaySource
	counters string // what the raw digest must still show
	reply    string // the model's answer, actions included
}

// The replies are in French, as the dev instance gets them: misspell reads
// their words as English typos.
//
//nolint:misspell
var replayRuns = []replayRun{
	{
		name: "10:05",
		source: replaySource{
			findings: quietFindings(Finding{Source: "es-security", Title: "firewall blocked flows", Count: 533, Severity: SeverityWarning,
				Details: map[string]int{"198.51.100.2": 168, "203.0.113.185": 64, "198.51.100.27": 50, "203.0.113.173": 18, "192.0.2.180": 18}}),
			facets: map[string]map[string]map[string]int{
				"198.51.100.2":  scanFacets(map[string]int{"5000": 168}),
				"203.0.113.185": scanFacets(map[string]int{"119": 1, "1748": 1, "3634": 1}),
				"198.51.100.27": scanFacets(map[string]int{"3423": 68, "41261": 31}),
				"203.0.113.173": scanFacets(map[string]int{"7010": 6, "7070": 4}),
				"192.0.2.180":   scanFacets(map[string]int{"36073": 11, "64627": 7}),
			},
		},
		counters: "firewall blocked flows: 533",
		reply: `{"headline":"Avertissement : scan de ports internes et externes bloqué par UFW avant d'atteindre les services",
"actors":[
 {"ip":"198.51.100.2","activity":"Flux répétés vers le port 5000, tous bloqués.","pattern":"internal_device","threat":"low","success":false},
 {"ip":"203.0.113.185","activity":"Scan TCP de ports aléatoires.","pattern":"port_scan","threat":"medium","success":false},
 {"ip":"198.51.100.27","activity":"Flux UDP vers les ports 3423 et 41261.","pattern":"internal_device","threat":"low","success":false},
 {"ip":"203.0.113.173","activity":"Scan TCP des ports 7010 et 7070.","pattern":"port_scan","threat":"medium","success":false},
 {"ip":"192.0.2.180","activity":"Scan UDP de ports hauts.","pattern":"port_scan","threat":"low","success":false}],
"campaign":"",
"actions":["Bloquer ou réinitialiser les IP 203.0.113.185 et 198.51.100.2 suspectes d'un scan de ports interne agressif",
 "Vérifier l'activité légitime des services UDP provenant du réseau local"]}`,
	},
	{
		name: "11:05",
		source: replaySource{
			findings: quietFindings(Finding{Source: "es-security", Title: "firewall blocked flows", Count: 397, Severity: SeverityWarning,
				Details: map[string]int{"198.51.100.27": 103, "203.0.113.185": 58, "203.0.113.173": 22, "192.0.2.180": 18, "198.51.100.62": 6}}),
			facets: map[string]map[string]map[string]int{
				"198.51.100.27": scanFacets(map[string]int{"3423": 98, "41261": 71}),
				"203.0.113.185": scanFacets(map[string]int{"11959": 1, "13032": 1}),
				"203.0.113.173": scanFacets(map[string]int{"7088": 7, "7100": 6}),
				"192.0.2.180":   scanFacets(map[string]int{"36073": 13, "64627": 5}),
				"198.51.100.62": scanFacets(map[string]int{"9073": 6}),
			},
		},
		counters: "firewall blocked flows: 397",
		reply: `{"headline":"Alerte de sécurité : plus de 50 flux bloqués par UFW, scans de ports externes non coordonnés.",
"actors":[
 {"ip":"198.51.100.27","activity":"Trafic UDP vers les ports 3423 et 41261.","pattern":"internal_device","threat":"low","success":false},
 {"ip":"203.0.113.185","activity":"Scan TCP de ports variés.","pattern":"port_scan","threat":"low","success":false},
 {"ip":"203.0.113.173","activity":"Scan des ports 7088 et 7100.","pattern":"port_scan","threat":"low","success":false},
 {"ip":"192.0.2.180","activity":"Scan UDP de ports hauts.","pattern":"port_scan","threat":"low","success":false},
 {"ip":"198.51.100.62","activity":"Scan TCP du port 9073.","pattern":"port_scan","threat":"low","success":false}],
"campaign":"Campagne coordonnée depuis 203.0.113.0/24, à bannir en bloc.",
"actions":["Ajouter une règle permanente dans UFW pour bloquer toutes les connexions entrantes depuis la plage IPv4 locale (internal) du réseau domestique sur tout port sauf ceux des services autorisés.",
 "Vérifier si le flux UDP provenant de 198.51.100.62 est lié à une activité de scan."]}`,
	},
}

// Words only an action, a campaign or a recommendation would bring.
//
//nolint:misspell
var replayLeaks = []string{"Actions", "action", "Bloquer", "bloquer", "bannir", "Vérifier", "règle permanente", "Campagne", "Recommandation", "203.0.113.0/24"}

func (rr replayRun) runner(reply string, sink *fakeSink) *Runner {
	return &Runner{
		Title: "Security digest [dev]", Window: time.Hour, Language: "fr", MaxChars: 8000,
		Log: quietLogger(), LLMTimeout: time.Second, TopActors: 5,
		Sources: []RunSource{{Source: rr.source}},
		LLM:     fakeLLM{resp: Response{Text: reply, Model: "qwen3.5:9b"}},
		Sinks:   []RunSink{{Sink: sink}},
	}
}

func assertNoLeak(t *testing.T, what, text string) {
	t.Helper()
	for _, leak := range replayLeaks {
		if strings.Contains(text, leak) {
			t.Errorf("%s carries %q:\n%s", what, leak, text)
		}
	}
}

// The reply as the model gave it, and the same wrapped the way small models
// wrap it: the analysis is published, its actions, campaign and trailer are
// not.
func TestReplayValidReplyPublishesNoAction(t *testing.T) {
	for _, rr := range replayRuns {
		for variant, reply := range map[string]string{
			"as answered":      rr.reply,
			"fenced, trailing": "```json\n" + rr.reply + "\n```\nRecommandation : bloquer 203.0.113.0/24 dans UFW.", //nolint:misspell
		} {
			t.Run(rr.name+"/"+variant, func(t *testing.T) {
				sink := &fakeSink{name: "phone"}
				report := rr.runner(reply, sink).Run(context.Background())

				if report.LLM.Err != "" {
					t.Fatalf("a valid analysis was refused: %s", report.LLM.Err)
				}
				top := report.Actors[0].IP
				if !strings.Contains(report.Summary, "1. "+top+" | ") || !strings.Contains(report.Summary, "scan") {
					t.Errorf("the analysis itself is missing:\n%s", report.Summary)
				}
				assertNoLeak(t, "summary", report.Summary)
				assertNoLeak(t, "delivered digest", sink.received[0].Summary)
			})
		}
	}
}

// A reply that is not the analysis — cut short by the token budget, plain
// prose, an object without its headline — is not published at all: the
// digest goes out with its counters, and the report says why.
func TestReplayInvalidReplyDegradesToCounters(t *testing.T) {
	for _, rr := range replayRuns {
		cut := rr.reply[:len(rr.reply)*6/10]
		for variant, reply := range map[string]string{
			"truncated": cut,
			"prose": "Alerte de sécurité : scans externes bloqués.\n\nActions :\n- Ajouter une règle permanente dans UFW pour " +
				"bloquer toutes les connexions entrantes depuis la plage locale.",
			"no headline": `{"headline":"","actors":[],"actions":["Bloquer 198.51.100.2"]}`,
		} {
			t.Run(rr.name+"/"+variant, func(t *testing.T) {
				sink := &fakeSink{name: "phone"}
				report := rr.runner(reply, sink).Run(context.Background())

				if report.Summary != "" {
					t.Errorf("unparsed reply published:\n%s", report.Summary)
				}
				if !strings.HasPrefix(report.LLM.Err, "invalid_reply: ") {
					t.Errorf("llm error = %q, want it to say the reply was invalid", report.LLM.Err)
				}
				if len(sink.received) != 1 || sink.received[0].Summary != "" {
					t.Fatalf("the sink must still get the digest, without the reply: %+v", sink.received)
				}
				digest := RenderText(sink.received[0])
				if !strings.Contains(digest, rr.counters) {
					t.Errorf("degraded digest lost its counters:\n%s", digest)
				}
				assertNoLeak(t, "degraded digest", digest)
				if strings.Contains(digest, "Alerte") || strings.Contains(digest, "Avertissement") {
					t.Errorf("text from the reply reached the degraded digest:\n%s", digest)
				}
			})
		}
	}
}

// pattern and threat are printed as labels; a value outside the schema is
// a sentence the model slipped in, and the judgment goes, not the facts.
func TestReplayOffSchemaJudgmentIsDropped(t *testing.T) {
	rr := replayRuns[0]
	reply := strings.Replace(rr.reply, `"pattern":"internal_device","threat":"low"`,
		`"pattern":"Bloquer 198.51.100.2 immédiatement","threat":"low"`, 1)
	report := rr.runner(reply, &fakeSink{name: "phone"}).Run(context.Background())

	assertNoLeak(t, "summary", report.Summary)
	if !strings.Contains(report.Summary, "1. 198.51.100.2 | ") || !strings.Contains(report.Summary, "ports 5000(168)") {
		t.Errorf("the actor's facts must stay when its judgment goes:\n%s", report.Summary)
	}
	if strings.Contains(report.Summary, "Flux répétés vers le port 5000") {
		t.Errorf("the rest of an off-schema judgment was kept:\n%s", report.Summary)
	}
}

// noop answers nothing, without an error: no summary, and nothing failed.
func TestEmptyReplyIsNoSummaryNotAnError(t *testing.T) {
	report := replayRuns[0].runner("", &fakeSink{name: "phone"}).Run(context.Background())
	if report.Summary != "" || report.LLM.Err != "" {
		t.Errorf("summary = %q, llm error = %q, want both empty", report.Summary, report.LLM.Err)
	}
}
