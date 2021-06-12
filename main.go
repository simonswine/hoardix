package main

import (
	"fmt"
	"os"

	"github.com/simonswine/hoardix/pkg/hoardix"
)

func main() {
	app := hoardix.New()
	if err := app.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
