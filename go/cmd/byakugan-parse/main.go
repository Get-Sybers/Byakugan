// byakugan-parse — the Go parse engine's CLI (go/DESIGN.md CLI contract).
//
//	byakugan-parse parse --in FILE --artefacts k1,k2 [--host H] [--adapter none|winevt|jlecmd]
//	byakugan-parse split-l2t --in RAW.jsonl --out-dir DIR
//	byakugan-parse ir-check [--in ir.json]
//
// `parse` emits one PyDumps-encoded CAR event per stdout line, in input order,
// byte-identical to the Python reference — optionally reshaping each record
// through the winevt or jlecmd adapter first. `split-l2t` splits a raw
// log2timeline json_line container into its per-parser table files.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/get-sybers/byakugan/go/internal/adapt"
	"github.com/get-sybers/byakugan/go/internal/ir"
	"github.com/get-sybers/byakugan/go/internal/normalize"
	"github.com/get-sybers/byakugan/go/internal/predicates"
	"github.com/get-sybers/byakugan/go/internal/pyjson"
	"github.com/get-sybers/byakugan/go/internal/readers"
	"github.com/get-sybers/byakugan/go/internal/record"
	"github.com/get-sybers/byakugan/go/internal/split"
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
	case "none", "winevt", "jlecmd":
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
	// pipeline._consume's adapter fan-out, carried by the IR's `adapters`
	// section: a lone ADAPTER ROUTE KEY expands to the maps it feeds
	// (l2t_winevt → every evtx map; jlecmd_dest → itself). A caller that
	// names the maps outright (the parity harness does) is left alone.
	if *adapter != "none" && len(arts) == 1 {
		if maps, err := adapterMaps(arts[0], *adapter); err != nil {
			fmt.Fprintf(os.Stderr, "byakugan-parse parse: %v\n", err)
			return 1
		} else if maps != nil {
			arts = maps
		}
	}

	out := bufio.NewWriterSize(os.Stdout, 1<<20)
	// emit runs every artefact map over ONE (already reshaped) record.
	emit := func(obj *pyjson.Object) error {
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
	}
	err := readers.ForEach(*in, func(v pyjson.Value) error {
		obj, ok := v.(*pyjson.Object)
		if !ok {
			// Python's engine would crash on a non-object record too — the
			// live JSONL lanes only ever carry objects.
			return fmt.Errorf("record is not a JSON object")
		}
		switch *adapter {
		case "winevt":
			// one wrapped Plaso row → at most one EvtxECmd-shaped record;
			// an unmapped (channel, EventId) leaves the row raw (dropped).
			shaped, err := adapt.Winevt(obj)
			if err != nil {
				return err
			}
			if shaped == nil {
				return nil
			}
			return emit(shaped)
		case "jlecmd":
			// one jump-list record → one flat record per DestListEntry.
			flats, err := adapt.Jlecmd(obj)
			if err != nil {
				return err
			}
			for _, flat := range flats {
				if err := emit(flat); err != nil {
					return err
				}
			}
			return nil
		default:
			return emit(obj)
		}
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

// adapterMaps resolves an ADAPTER ROUTE KEY (ir.adapters) to the map keys it
// fans out to, when that entry is driven by `adapter`. nil means `key` is not
// such a route key — the caller keeps what it was given.
func adapterMaps(key, adapter string) ([]string, error) {
	doc, err := ir.Load()
	if err != nil {
		return nil, err
	}
	entry := ir.Get(doc, "adapters", key)
	if entry == nil {
		return nil, nil
	}
	if name, _ := ir.Get(entry, "adapter").(string); name != adapter {
		return nil, nil
	}
	lst, ok := ir.Get(entry, "maps").([]pyjson.Value)
	if !ok {
		return nil, fmt.Errorf("ir: adapters.%s has no maps list", key)
	}
	maps := make([]string, 0, len(lst))
	for _, m := range lst {
		s, ok := m.(string)
		if !ok {
			return nil, fmt.Errorf("ir: adapters.%s.maps holds a non-string", key)
		}
		maps = append(maps, s)
	}
	return maps, nil
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
	// split.SplitL2t is vanish-tolerant (the Python reference returns {} for a
	// container it cannot open); a CLI invocation naming an unreadable file is
	// a user error, so check it here rather than exit 0 on an empty split.
	fh, err := os.Open(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "byakugan-parse split-l2t: %v\n", err)
		return 1
	}
	fh.Close()
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "byakugan-parse split-l2t: %v\n", err)
		return 1
	}
	// pipeline calls split_l2t(f, basename(f), tmp, basename(f)) — the source
	// image label AND the output prefix are the container's file name.
	base := filepath.Base(*in)
	res, err := split.SplitL2t(*in, base, *outDir, base)
	if err != nil {
		fmt.Fprintf(os.Stderr, "byakugan-parse split-l2t: %v\n", err)
		return 1
	}
	tables := pyjson.NewObject()
	for _, t := range res.Tables {
		tables.Set(t.Name, t.Path)
	}
	summary := pyjson.NewObject()
	summary.Set("tables", tables)
	summary.Set("lines", pyjson.Int(int64(res.Lines)))
	s, err := pyjson.Dumps(summary)
	if err != nil {
		fmt.Fprintf(os.Stderr, "byakugan-parse split-l2t: %v\n", err)
		return 1
	}
	fmt.Println(s)
	return 0
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
	// Predicate completeness is a HARD gate now that every mapping family is
	// ported: an IR predicate with no Go registration means some variant of
	// some map would fail at evaluation time, so refuse to certify the build.
	// A missing/ill-typed predicate_names section is itself a broken IR.
	names, ok := ir.Get(doc, "predicate_names").([]pyjson.Value)
	if !ok {
		fmt.Fprintln(os.Stderr, "byakugan-parse ir-check: embedded IR has no "+
			"predicate_names list (rebuild: python -m byakugan.export_ir)")
		return 1
	}
	irNames := make([]string, 0, len(names))
	for _, n := range names {
		s, ok := n.(string)
		if !ok {
			fmt.Fprintln(os.Stderr, "byakugan-parse ir-check: embedded IR "+
				"predicate_names holds a non-string")
			return 1
		}
		irNames = append(irNames, s)
	}
	if err := predicates.Check(irNames); err != nil {
		fmt.Fprintf(os.Stderr, "byakugan-parse ir-check: %v\n"+
			"  (port each in go/internal/predicates/predicates_<family>.go — "+
			"see go/DESIGN.md \"Per-family porting recipe\")\n", err)
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
	fmt.Printf("OK: embedded IR valid%s; all %d IR predicates registered in Go\n",
		map[bool]string{true: " and identical to --in", false: ""}[*in != ""], len(irNames))
	return 0
}
