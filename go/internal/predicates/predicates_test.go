package predicates

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/get-sybers/byakugan/go/internal/ir"
	"github.com/get-sybers/byakugan/go/internal/pyjson"
	"github.com/get-sybers/byakugan/go/internal/record"
)

// vectorFiles lists the per-family vector files. Each mapping family owns
// exactly one testdata/predicate_vectors/<family>.json, written by
// tests/parity/genf/<family>.py — so two agents porting two families never
// touch the same file. Every file found is replayed.
func vectorFiles(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", "predicate_vectors", "*.json"))
	if err != nil {
		t.Fatalf("glob vectors: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("no predicate vector files under testdata/predicate_vectors/ " +
			"(regenerate: python tests/parity/gen_all.py)")
	}
	sort.Strings(paths)
	return paths
}

// TestPredicateVectors replays the Python-recorded (record, verdict,
// post-state) triples of every family — including zeek_conn_has_state's
// record mutation.
func TestPredicateVectors(t *testing.T) {
	total := 0
	for _, path := range vectorFiles(t) {
		family := filepath.Base(path)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", family, err)
		}
		doc, err := pyjson.Decode(raw)
		if err != nil {
			t.Fatalf("decode %s: %v", family, err)
		}
		obj, ok := doc.(*pyjson.Object)
		if !ok {
			t.Fatalf("%s: vector file is not an object", family)
		}
		cases, ok := obj.Get("cases")
		if !ok {
			t.Fatalf("%s: no \"cases\" section", family)
		}
		list, ok := cases.([]pyjson.Value)
		if !ok {
			t.Fatalf("%s: \"cases\" is not a list", family)
		}
		if len(list) == 0 {
			t.Fatalf("%s: no cases — an empty family vector file proves nothing", family)
		}
		total += len(list)
		for i, cv := range list {
			c := cv.(*pyjson.Object)
			namev, _ := c.Get("predicate")
			recv, _ := c.Get("rec")
			wantResult, _ := c.Get("result")
			wantAfter, _ := c.Get("rec_after")
			fn, ok := Lookup(namev.(string))
			if !ok {
				t.Fatalf("%s case %d: predicate %q not registered "+
					"(port it in predicates_<family>.go)", family, i, namev.(string))
			}
			rec := record.New(recv.(*pyjson.Object))
			got := fn(rec)
			if got != wantResult.(bool) {
				t.Errorf("%s case %d (%s): result %v, want %v — rec %s",
					family, i, namev.(string), got, wantResult, mustDumps(t, recv))
			}
			gotAfter := mustDumps(t, rec.Object())
			want := mustDumps(t, wantAfter)
			if gotAfter != want {
				t.Errorf("%s case %d (%s): post-state\n got %s\nwant %s",
					family, i, namev.(string), gotAfter, want)
			}
		}
	}
	// the full registry carries 816 recorded cases across 14 family files; a
	// collapse far below that means vector files went missing, not that a
	// family got smaller. (TestEveryRegisteredPredicateHasAVector is the
	// per-name gate; this is the blunt "did testdata vanish" one.)
	if total < 600 {
		t.Fatalf("suspiciously few predicate vectors in total: %d", total)
	}
}

func mustDumps(t *testing.T, v pyjson.Value) string {
	t.Helper()
	s, err := pyjson.Dumps(v)
	if err != nil {
		t.Fatalf("dumps: %v", err)
	}
	return s
}

// TestRegistryAgainstIR: the registry and the IR's predicate_names must agree
// EXACTLY — every registered predicate exists in the IR (catches typos and
// stale registrations) and every IR predicate is registered in Go. With all
// mapping families ported this is a HARD gate: an unregistered name is a map
// variant that would fail at evaluation time, so it fails the test rather than
// logging (it mirrors `byakugan-parse ir-check`, which exits nonzero on it).
func TestRegistryAgainstIR(t *testing.T) {
	doc, err := ir.Load()
	if err != nil {
		t.Fatalf("ir: %v", err)
	}
	names, _ := ir.Get(doc, "predicate_names").([]pyjson.Value)
	inIR := map[string]bool{}
	var irNames []string
	for _, n := range names {
		s := n.(string)
		inIR[s] = true
		irNames = append(irNames, s)
	}
	for _, reg := range Registered() {
		if !inIR[reg] {
			t.Errorf("predicate %q registered in Go but absent from the IR", reg)
		}
	}
	if len(irNames) == 0 {
		t.Fatal("IR carries no predicate_names — the completeness gate would be vacuous")
	}
	// the completeness gate: every IR predicate name has a Go port
	if missing := Missing(irNames); len(missing) > 0 {
		t.Errorf("%d IR predicate(s) not registered in Go: %v\n"+
			"port each in predicates_<family>.go with vectors "+
			"(go/DESIGN.md → \"Per-family porting recipe\")", len(missing), missing)
	}
	// ...and nothing is registered twice under a different spelling: the two
	// sets must be the same size once both inclusions above hold.
	if len(Registered()) != len(inIR) {
		t.Errorf("registry holds %d predicates, the IR names %d",
			len(Registered()), len(inIR))
	}
}

// TestEveryRegisteredPredicateHasAVector: a port with no recorded Python
// verdict is unproven. Every registered name must appear in at least one
// testdata/predicate_vectors/*.json case.
func TestEveryRegisteredPredicateHasAVector(t *testing.T) {
	seen := map[string]bool{}
	for _, path := range vectorFiles(t) {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		doc, err := pyjson.Decode(raw)
		if err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		cases, _ := doc.(*pyjson.Object).Get("cases")
		list, _ := cases.([]pyjson.Value)
		for _, cv := range list {
			if n, ok := cv.(*pyjson.Object).Get("predicate"); ok {
				seen[n.(string)] = true
			}
		}
	}
	var bare []string
	for _, name := range Registered() {
		if !seen[name] {
			bare = append(bare, name)
		}
	}
	if len(bare) > 0 {
		t.Errorf("%d registered predicate(s) with no recorded vector: %v\n"+
			"add cases in tests/parity/genf/<family>.py and regenerate",
			len(bare), bare)
	}
}
