// byakugan-parse — the Go parse engine's CLI (go/DESIGN.md CLI contract).
//
//	byakugan-parse parse --in FILE --artefacts k1,k2 [--host H] [--adapter none|winevt|jlecmd]
//	byakugan-parse split-l2t --in RAW.jsonl --out-dir DIR
//	byakugan-parse ir-check [--in ir.json]
//
// Stage A ships the skeleton: flag surfaces are final, `ir-check` works,
// `parse` and `split-l2t` are stage B.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"

	"github.com/get-sybers/byakugan/go/internal/ir"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage:
  byakugan-parse parse --in FILE --artefacts k1,k2 [--host H] [--adapter none|winevt|jlecmd]
  byakugan-parse split-l2t --in RAW.jsonl --out-dir DIR
  byakugan-parse ir-check [--in ir.json]
`)
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "parse":
		return cmdParse(args[1:])
	case "split-l2t":
		return cmdSplitL2t(args[1:])
	case "ir-check":
		return cmdIrCheck(args[1:])
	case "-h", "--help", "help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "byakugan-parse: unknown subcommand %q\n", args[0])
		usage()
		return 2
	}
}

func cmdParse(args []string) int {
	fs := flag.NewFlagSet("parse", flag.ExitOnError)
	in := fs.String("in", "", "input file (required)")
	artefacts := fs.String("artefacts", "", "comma-separated artefact map keys (required)")
	host := fs.String("host", "", "source_host fallback where the map derives none")
	adapter := fs.String("adapter", "none", "input adapter: none | winevt | jlecmd")
	_ = fs.Parse(args)
	_ = host
	if *in == "" || *artefacts == "" {
		fmt.Fprintln(os.Stderr, "byakugan-parse parse: --in and --artefacts are required")
		return 2
	}
	switch *adapter {
	case "none", "winevt", "jlecmd":
	default:
		fmt.Fprintf(os.Stderr, "byakugan-parse parse: unknown adapter %q\n", *adapter)
		return 2
	}
	fmt.Fprintln(os.Stderr, "byakugan-parse parse: not implemented (stage B)")
	return 2
}

func cmdSplitL2t(args []string) int {
	fs := flag.NewFlagSet("split-l2t", flag.ExitOnError)
	in := fs.String("in", "", "raw log2timeline json_line container (required)")
	outDir := fs.String("out-dir", "", "directory for the split per-table files (required)")
	_ = fs.Parse(args)
	if *in == "" || *outDir == "" {
		fmt.Fprintln(os.Stderr, "byakugan-parse split-l2t: --in and --out-dir are required")
		return 2
	}
	fmt.Fprintln(os.Stderr, "byakugan-parse split-l2t: not implemented (stage B)")
	return 2
}

func cmdIrCheck(args []string) int {
	fs := flag.NewFlagSet("ir-check", flag.ExitOnError)
	in := fs.String("in", "", "external ir.json to byte-compare against the embedded one")
	_ = fs.Parse(args)
	if _, err := ir.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "byakugan-parse ir-check: embedded IR invalid: %v\n", err)
		return 1
	}
	if *in != "" {
		data, err := os.ReadFile(*in)
		if err != nil {
			fmt.Fprintf(os.Stderr, "byakugan-parse ir-check: %v\n", err)
			return 1
		}
		if !bytes.Equal(data, ir.Raw()) {
			fmt.Fprintf(os.Stderr, "byakugan-parse ir-check: %s differs from the embedded IR "+
				"(rebuild: python -m byakugan.export_ir && make -C go build)\n", *in)
			return 1
		}
	}
	fmt.Println("OK: embedded IR valid" + map[bool]string{true: " and identical to --in", false: ""}[*in != ""])
	return 0
}
