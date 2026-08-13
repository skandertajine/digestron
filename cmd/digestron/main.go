package main

import (
	"os"

	"github.com/skandertajine/digestron/internal/cli"

	// Providers register themselves; importing them here decides what ships
	// in the binary.
	_ "github.com/skandertajine/digestron/internal/llm/noop"
	_ "github.com/skandertajine/digestron/internal/llm/ollama"
	_ "github.com/skandertajine/digestron/internal/llm/openai"
	_ "github.com/skandertajine/digestron/internal/sink/email"
	_ "github.com/skandertajine/digestron/internal/sink/homeassistant"
	_ "github.com/skandertajine/digestron/internal/sink/webhook"
	_ "github.com/skandertajine/digestron/internal/source/elasticsearch"
	_ "github.com/skandertajine/digestron/internal/source/prometheus"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
