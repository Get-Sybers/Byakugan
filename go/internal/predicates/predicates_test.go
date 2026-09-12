package predicates

import (
	"os"
	"testing"

	"github.com/get-sybers/byakugan/go/internal/ir"
	"github.com/get-sybers/byakugan/go/internal/pyjson"
	"github.com/get-sybers/byakugan/go/internal/record"
)

// TestPredicateVectors replays the Python-recorded (record, verdict,
// post-state) triples — including zeek_conn_has_state's record mutation.
func TestPredicateVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/predicate_vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	doc, err := pyjson.Decode(raw)
	if err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	cases, _ := doc.(*pyjson.Object).Get("cases")
	list := cases.([]pyjson.Value)
	if len(list) < 40 {
		t.Fatalf("suspiciously few predicate vectors: %d", len(list))
	}
	for i, cv := range list {
		c := cv.(*pyjson.Object)
		namev, _ := c.Get("predicate")
		recv, _ := c.Get("rec")
		wantResult, _ := c.Get("result")
		wantAfter, _ := c.Get("rec_after")
		fn, ok := Lookup(namev.(string))
		if !ok {
			t.Fatalf("case %d: predicate %q not registered", i, namev.(string))
		}
		rec := record.New(recv.(*pyjson.Object))
		got := fn(rec)
		if got != wantResult.(bool) {
			t.Errorf("case %d (%s): result %v, want %v — rec %s",
				i, namev.(string), got, wantResult, mustDumps(t, recv))
		}
		gotAfter := mustDumps(t, rec.Object())
		want := mustDumps(t, wantAfter)
		if gotAfter != want {
			t.Errorf("case %d (%s): post-state\n got %s\nwant %s",
				i, namev.(string), gotAfter, want)
		}
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
