package main

import (
	"encoding/json"
	"flag"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/convert"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/probe"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
	"io"
	"os"
)

// Read through stdin; never put credential-bearing configs in process arguments.
func main() {
	template := flag.Bool("template", false, "prepare final shared-template bytes")
	flag.Parse()
	b, e := io.ReadAll(io.LimitReader(os.Stdin, repair.MaxBytes+1))
	if e != nil {
		os.Exit(1)
	}
	plan := probe.Prepare(b)
	if *template {
		plan = convert.Prepare(b)
	}

	if json.NewEncoder(os.Stdout).Encode(plan) != nil {
		os.Exit(1)
	}
}
