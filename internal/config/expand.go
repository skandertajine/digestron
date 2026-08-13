package config

import (
	"fmt"
	"os"
	"regexp"
)

var varPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// ExpandEnv replaces ${VAR} references with environment values before the
// YAML is parsed. Only the braced form is expanded — a bare $ stays intact
// so query bodies keep their meaning. An unset variable is an error: failing
// at load time beats sending an empty password at 3am.
func ExpandEnv(b []byte) ([]byte, error) {
	var missing []string
	out := varPattern.ReplaceAllFunc(b, func(m []byte) []byte {
		name := string(varPattern.FindSubmatch(m)[1])
		v, ok := os.LookupEnv(name)
		if !ok {
			missing = append(missing, name)
			return m
		}
		return []byte(v)
	})
	if len(missing) > 0 {
		return nil, fmt.Errorf("config: unset environment variables: %v", missing)
	}
	return out, nil
}
