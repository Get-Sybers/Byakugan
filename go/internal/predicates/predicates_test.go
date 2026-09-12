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
	// the stage-B exemplars alone carry 44 cases; a collapse below that means
	// vector files went missing, not that a family got smaller.
	if total < 40 {
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

// TestRegistryAgainstIR: every REGISTERED predicate must exist in the IR
// (catches typos and stale registrations); the exemplar families must be
// complete; the not-yet-ported remainder is reported, not failed (stage C).
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
	// stage-B exemplar families must be fully registered
	for _, want := range []string{"is_sec_4624", "is_sec_4625", "is_sec_4672",
		"is_http_origin", "is_http_tunnel", "zeek_conn_has_state"} {
		if _, ok := Lookup(want); !ok {
			t.Errorf("exemplar predicate %q not registered", want)
		}
	}
	if missing := Missing(irNames); len(missing) > 0 {
		t.Logf("stage C to port: %d IR predicates not yet registered: %v",
			len(missing), missing)
	}
}
