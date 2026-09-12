// Replays the vectors tests/parity/genf/adapters.py records from the FROZEN
// Python adapters (tests/parity/reference/{winevt,jlecmd}.py). A vector file is
// a recording of what the Python side actually did — never a hand-written
// expectation — so a divergence here is a real port bug.
//
//	python tests/parity/genf/adapters.py
package adapt

import (
	"os"
	"testing"

	"github.com/get-sybers/byakugan/go/internal/pyjson"
	"github.com/get-sybers/byakugan/go/internal/record"
)

func loadVectors(t *testing.T, name string) *pyjson.Object {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read %s: %v (regenerate: python tests/parity/genf/adapters.py)", name, err)
	}
	v, err := pyjson.Decode(data)
	if err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	o, ok := v.(*pyjson.Object)
	if !ok {
		t.Fatalf("%s: not a JSON object", name)
	}
	return o
}

// dumps renders a value the way the parity harness compares events — ordered
// keys, Python json.dumps defaults — so the check covers VALUES, TYPES and KEY
// ORDER at once.
func dumps(t *testing.T, v pyjson.Value) string {
	t.Helper()
	s, err := pyjson.Dumps(v)
	if err != nil {
		t.Fatalf("dumps: %v", err)
	}
	return s
}

func TestWinevtVectors(t *testing.T) {
	doc := loadVectors(t, "winevt_vectors.json")
	cases, ok := ir(doc, "cases").([]pyjson.Value)
	if !ok || len(cases) == 0 {
		t.Fatal("winevt_vectors.json: no cases")
	}
	matched := 0
	covered := map[*winevtRule]bool{}
	for i, cv := range cases {
		c := cv.(*pyjson.Object)
		wrapped, _ := c.Get("wrapped")
		want, _ := c.Get("out")
		obj, ok := wrapped.(*pyjson.Object)
		if !ok {
			t.Fatalf("case %d: wrapped is not an object", i)
		}
		got, err := Winevt(obj)
		if err != nil {
			t.Fatalf("case %d: Winevt: %v", i, err)
		}
		if want == nil {
			if got != nil {
				t.Errorf("case %d: adapt returned a record, Python returned None:\n got: %s",
					i, dumps(t, got))
			}
			continue
		}
		matched++
		if got == nil {
			t.Errorf("case %d: adapt returned None, Python returned:\n want: %s",
				i, dumps(t, want))
			continue
		}
		if g, w := dumps(t, got), dumps(t, want); g != w {
			t.Errorf("case %d differs\n want: %s\n  got: %s", i, w, g)
		}
		// Which RULES entry claimed this record? `Channel` is `channel or
		// source` and `Provider` is source, so re-running the lookup over the
		// emitted pair picks the same entry it did inside Winevt.
		ch, _ := got.Get("Channel")
		prov, _ := got.Get("Provider")
		eid, _ := got.Get("EventId")
		if r := winevtRuleFor(record.PyStr(ch), record.PyStr(prov), eid); r != nil {
			covered[r] = true
		}
	}
	if matched == 0 {
		t.Fatal("no vector matched a rule — the RULES table is empty or unreachable")
	}
	// EVERY entry of the RULES table must be exercised: a layout silently
	// dropped or mis-keyed would otherwise sail through.
	for i := range winevtRules {
		r := &winevtRules[i]
		if !covered[r] {
			t.Errorf("RULES entry (%q, %d) is not exercised by any vector", r.kw, r.eid)
		}
	}
}

func TestJlecmdDotnetDateVectors(t *testing.T) {
	doc := loadVectors(t, "jlecmd_vectors.json")
	rows, ok := ir(doc, "dotnet_date").([]pyjson.Value)
	if !ok || len(rows) == 0 {
		t.Fatal("jlecmd_vectors.json: no dotnet_date rows")
	}
	for i, rv := range rows {
		pair := rv.([]pyjson.Value)
		in, want := pair[0], pair[1]
		got := DotnetDate(in)
		if g, w := dumps(t, got), dumps(t, want); g != w {
			t.Errorf("dotnet_date[%d] (%s): want %s, got %s", i, dumps(t, in), w, g)
		}
	}
}

func TestJlecmdFlattenVectors(t *testing.T) {
	doc := loadVectors(t, "jlecmd_vectors.json")
	rows, ok := ir(doc, "flatten").([]pyjson.Value)
	if !ok || len(rows) == 0 {
		t.Fatal("jlecmd_vectors.json: no flatten rows")
	}
	total := 0
	for i, rv := range rows {
		r := rv.(*pyjson.Object)
		recv, _ := r.Get("rec")
		wantv, _ := r.Get("out")
		want, _ := wantv.([]pyjson.Value)
		rec, ok := recv.(*pyjson.Object)
		if !ok {
			t.Fatalf("flatten[%d]: rec is not an object", i)
		}
		got, err := Jlecmd(rec)
		if err != nil {
			t.Fatalf("flatten[%d]: Jlecmd: %v", i, err)
		}
		if len(got) != len(want) {
			t.Errorf("flatten[%d]: Go yielded %d records, Python %d", i, len(got), len(want))
			continue
		}
		for k := range got {
			if g, w := dumps(t, got[k]), dumps(t, want[k]); g != w {
				t.Errorf("flatten[%d][%d] differs\n want: %s\n  got: %s", i, k, w, g)
			}
		}
		total += len(got)
	}
	if total < 5 {
		t.Fatalf("only %d flattened records across all vectors — coverage collapsed", total)
	}
}

// ir is a tiny key lookup (the vector docs are one level deep).
func ir(o *pyjson.Object, key string) pyjson.Value {
	v, _ := o.Get(key)
	return v
}
