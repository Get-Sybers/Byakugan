package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/get-sybers/byakugan/go/internal/authoring"
	"github.com/get-sybers/byakugan/go/internal/pyjson"
)

// cmdGenIR is the Go-native replacement for `python -m byakugan.export_ir`: it
// serializes the Go-authored IR (authoring.BuildIR) to ir.json byte-identically
// to the old Python output (indent=1, ensure_ascii=False, trailing newline).
//
//	byakugan-parse gen-ir --out go/internal/ir/ir.json        # (re)write the file
//	byakugan-parse gen-ir --check go/internal/ir/ir.json      # CI: fail if the file is stale
//
// --out and --check are alternatives, each taking the ir.json path.
func cmdGenIR(args []string) int {
	fs := flag.NewFlagSet("gen-ir", flag.ExitOnError)
	out := fs.String("out", "", "path to write ir.json (required)")
	check := fs.String("check", "", "path to compare against (fail if it differs); alternative to --out")
	_ = fs.Parse(args)

	s, err := pyjson.DumpsIndent(authoring.BuildIR(), 1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gen-ir: %v\n", err)
		return 1
	}
	data := []byte(s + "\n")

	if *check != "" {
		have, err := os.ReadFile(*check)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gen-ir --check: %v\n", err)
			return 1
		}
		if string(have) != string(data) {
			fmt.Fprintf(os.Stderr, "OUT OF DATE: %s drifted from the Go authoring tables (run: byakugan-parse gen-ir --out %s)\n", *check, *check)
			return 1
		}
		fmt.Printf("OK: %s in sync with the Go authoring tables\n", *check)
		return 0
	}

	if *out == "" {
		fmt.Fprintln(os.Stderr, "gen-ir: --out (or --check) is required")
		return 2
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "gen-ir: %v\n", err)
		return 1
	}
	fmt.Printf("wrote %s\n", *out)
	return 0
}
