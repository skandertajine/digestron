// Package version holds build metadata injected at link time via -ldflags.
package version

import "fmt"

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

func String() string {
	return fmt.Sprintf("digestron %s (commit %s, built %s)", Version, Commit, Date)
}
