package main

import (
	"fmt"
	"os"

	"github.com/skandertajine/digestron/internal/version"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println(version.String())
		return
	}
	fmt.Fprintln(os.Stderr, "usage: digestron <run|serve|check|version> [flags]")
	os.Exit(2)
}
