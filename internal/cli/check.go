package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/skandertajine/digestron/internal/digest"
)

func checkCmd(args []string) int {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/digestron/config.yaml", "path to the configuration file")
	timeout := fs.Duration("timeout", 10*time.Second, "probe timeout per module")
	_ = fs.Parse(args)

	app, err := Build(*cfgPath, false)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	failed := 0

	probe := func(kind, name string, mod any) {
		c, ok := mod.(digest.Checker)
		if !ok {
			fmt.Fprintf(w, "%s\t%s\tskipped\tno probe available\n", kind, name)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()
		if err := c.Check(ctx); err != nil {
			failed++
			fmt.Fprintf(w, "%s\t%s\tFAIL\t%v\n", kind, name, err)
			return
		}
		fmt.Fprintf(w, "%s\t%s\tok\t\n", kind, name)
	}

	for _, s := range app.Sources {
		probe("source", s.Name(), s.Source)
	}
	if app.LLM != nil {
		probe("llm", app.LLM.Name(), app.LLM)
	}
	for _, s := range app.Sinks {
		probe("sink", s.Name(), s.Sink)
	}
	_ = w.Flush()

	if failed > 0 {
		fmt.Fprintf(os.Stderr, "\n%d module(s) failed\n", failed)
		return 1
	}
	return 0
}
