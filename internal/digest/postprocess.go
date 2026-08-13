package digest

import (
	"regexp"
	"strings"
)

var (
	thinkRe    = regexp.MustCompile(`(?s)<think>.*?</think>`)
	preambleRe = regexp.MustCompile(`(?i)^((here is|here's|voici)[^:\n]{0,60}:|summary\s*:|r[ée]sum[ée]\s*:)\s*`)
)

// PostProcess cleans an LLM completion into notification-ready text. Models
// disobey format instructions a few percent of the time; this code is the
// actual guarantee: reasoning tags (even with thinking disabled, some
// finetunes emit them inline), code fences and preambles are stripped, and
// the result is capped at maxChars on a word boundary.
func PostProcess(s string, maxChars int) string {
	s = thinkRe.ReplaceAllString(s, "")
	if i := strings.LastIndex(s, "</think>"); i >= 0 {
		s = s[i+len("</think>"):]
	}
	s = strings.TrimSpace(s)

	if strings.HasPrefix(s, "```") {
		s = strings.TrimPrefix(s, "```")
		if i := strings.IndexByte(s, '\n'); i >= 0 && len(strings.Fields(s[:i])) <= 1 {
			s = s[i+1:]
		}
		s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "```"))
	}

	s = preambleRe.ReplaceAllString(s, "")
	s = strings.TrimSpace(s)

	if maxChars > 0 {
		runes := []rune(s)
		if len(runes) > maxChars {
			cut := runes[:maxChars]
			if i := lastSpace(cut); i > maxChars/2 {
				cut = cut[:i]
			}
			s = strings.TrimSpace(string(cut)) + "…"
		}
	}
	return s
}

func lastSpace(runes []rune) int {
	for i := len(runes) - 1; i >= 0; i-- {
		if runes[i] == ' ' || runes[i] == '\n' {
			return i
		}
	}
	return -1
}
