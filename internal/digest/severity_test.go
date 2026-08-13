package digest

import (
	"encoding/json"
	"testing"
)

func TestScore(t *testing.T) {
	cases := []struct {
		name  string
		count int
		th    Thresholds
		want  Severity
	}{
		{"no thresholds", 1000, Thresholds{}, SeverityInfo},
		{"below warning", 4, Thresholds{Warning: 5, Critical: 50}, SeverityInfo},
		{"at warning", 5, Thresholds{Warning: 5, Critical: 50}, SeverityWarning},
		{"at critical", 50, Thresholds{Warning: 5, Critical: 50}, SeverityCritical},
		{"critical only", 3, Thresholds{Critical: 3}, SeverityCritical},
		{"warning disabled", 10, Thresholds{Critical: 50}, SeverityInfo},
		{"zero count", 0, Thresholds{Warning: 1}, SeverityInfo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Score(tc.count, tc.th); got != tc.want {
				t.Errorf("Score(%d, %+v) = %s, want %s", tc.count, tc.th, got, tc.want)
			}
		})
	}
}

func TestVerdict(t *testing.T) {
	if v := Verdict(nil); v != SeverityInfo {
		t.Errorf("empty findings verdict = %s, want info", v)
	}
	fs := []Finding{
		{Severity: SeverityInfo},
		{Severity: SeverityCritical},
		{Severity: SeverityWarning},
	}
	if v := Verdict(fs); v != SeverityCritical {
		t.Errorf("verdict = %s, want critical", v)
	}
}

func TestSeverityJSONRoundTrip(t *testing.T) {
	for _, s := range []Severity{SeverityInfo, SeverityWarning, SeverityCritical} {
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		var back Severity
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatal(err)
		}
		if back != s {
			t.Errorf("round trip %s -> %s -> %s", s, b, back)
		}
	}
	var s Severity
	if err := json.Unmarshal([]byte(`"apocalyptic"`), &s); err == nil {
		t.Error("unknown severity must fail to unmarshal")
	}
}
