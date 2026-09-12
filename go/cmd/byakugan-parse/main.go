// byakugan-parse — the Go parse engine's CLI (go/DESIGN.md CLI contract).
//
//	byakugan-parse parse --in FILE --artefacts k1,k2 [--host H] [--adapter none|winevt|jlecmd]
//	byakugan-parse split-l2t --in RAW.jsonl --out-dir DIR
//	byakugan-parse ir-check [--in ir.json]
//
// Stage B ships `parse` (adapter none) — one PyDumps-encoded CAR event per
// stdout line, in input order, byte-identical to the Python reference.
// The winevt/jlecmd adapters and `split-l2t` are stage C.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"

	"github.com/get-sybers/byakugan/go/internal/ir"
	"github.com/get-sybers/byakugan/go/internal/normalize"
	"github.com/get-sybers/byakugan/go/internal/predicates"
	"github.com/get-sybers/byakugan/go/internal/pyjson"
	"github.com/get-sybers/byakugan/go/internal/readers"
	"github.com/get-sybers/byakugan/go/internal/record"
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
	if *in == "" || *artefacts == "" {
		fmt.Fprintln(os.Stderr, "byakugan-parse parse: --in and --artefacts are required")
		return 2
	}
	switch *adapter {
	case "none":
	case "winevt", "jlecmd":
		fmt.Fprintf(os.Stderr, "byakugan-parse parse: adapter %q not implemented (stage C)\n", *adapter)
		return 2
	default:
		fmt.Fprintf(os.Stderr, "byakugan-parse parse: unknown adapter %q\n", *adapter)
		return 2
	}
	// [a.strip() for a in artefacts.split(",") if a.strip()]
	var arts []string
	for _, a := range splitComma(*artefacts) {
		if s := record.Strip(a); s != "" {
			arts = append(arts, s)
		}
	}
	out := bufio.NewWriterSize(os.Stdout, 1<<20)
	err := readers.ForEach(*in, func(v pyjson.Value) error {
		obj, ok := v.(*pyjson.Object)
		if !ok {
			// Python's engine would crash on a non-object record too — the
			// live JSONL lanes only ever carry objects.
			return fmt.Errorf("record is not a JSON object")
		}
		rec := record.New(obj)
		for _, art := range arts {
			ev, err := normalize.Normalize(art, rec)
			if err != nil {
				return err
			}
			if ev == nil {
				continue
			}
			// pipeline fills the caller-supplied default AFTER normalize:
			// `if not ev.get("source_host"): ev["source_host"] = default_host`
			if sh, _ := ev.Get("source_host"); !record.Truthy(sh) {
				if *host != "" {
					ev.Set("source_host", *host)
				} else {
					ev.Set("source_host", nil)
				}
			}
			s, err := pyjson.Dumps(ev)
			if err != nil {
				return err
			}
			out.WriteString(s)
			out.WriteByte('\n')
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "byakugan-parse parse: %v\n", err)
		return 1
	}
	if err := out.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "byakugan-parse parse: %v\n", err)
		return 1
	}
	return 0
}

// splitComma splits on "," (strings.Split, kept tiny and dependency-free
// beside record.Strip's Python whitespace rule).
func splitComma(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return out
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
	doc, err := ir.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "byakugan-parse ir-check: embedded IR invalid: %v\n", err)
		return 1
	}
	// predicate completeness: informational while families are being ported
	// (stage C); the parity harness fails loudly on any family it exercises.
	if names, ok := ir.Get(doc, "predicate_names").([]pyjson.Value); ok {
		var irNames []string
		for _, n := range names {
			if s, ok := n.(string); ok {
				irNames = append(irNames, s)
			}
		}
		if err := predicates.Check(irNames); err != nil {
			fmt.Fprintf(os.Stderr, "byakugan-parse ir-check: note: %v\n", err)
		}
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
