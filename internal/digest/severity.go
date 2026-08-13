package digest

// Thresholds maps a finding count to a severity. A zero value disables that
// level.
type Thresholds struct {
	Warning  int `koanf:"warning" json:"warning,omitempty"`
	Critical int `koanf:"critical" json:"critical,omitempty"`
}

// Score is the single place a severity is decided. The LLM never overrides it.
func Score(count int, t Thresholds) Severity {
	switch {
	case t.Critical > 0 && count >= t.Critical:
		return SeverityCritical
	case t.Warning > 0 && count >= t.Warning:
		return SeverityWarning
	default:
		return SeverityInfo
	}
}

// Verdict is the overall severity of a run: the max across findings.
func Verdict(findings []Finding) Severity {
	v := SeverityInfo
	for _, f := range findings {
		if f.Severity > v {
			v = f.Severity
		}
	}
	return v
}
