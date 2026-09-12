package spindle

import (
	"os"
	"testing"

	"github.com/get-sybers/byakugan/go/internal/pyjson"
	"github.com/get-sybers/byakugan/go/internal/record"
)

// TestResolveVectors replays normalize._spindle over the Python-recorded
// (entry, record, normalized event) cases: intrinsic minting, the positional
// fallback, native.<key> sources and the genuinely-absent case, with the
// exact spindle_key / spindle_scope / spindle_ref natives.
func TestResolveVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/spindle_vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	doc, err := pyjson.Decode(raw)
	if err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	cases, _ := doc.(*pyjson.Object).Get("cases")
	list := cases.([]pyjson.Value)
	if len(list) < 7 {
		t.Fatalf("suspiciously few spindle vectors: %d", len(list))
	}
	sawIntrinsic, sawPositional, sawAbsent := false, false, false
	for i, cv := range list {
		c := cv.(*pyjson.Object)
		namev, _ := c.Get("name")
		objv, _ := c.Get("object")
		recv, _ := c.Get("rec")
		eventv, _ := c.Get("event")
		wantGuid, _ := c.Get("guid")
		wantNatives, _ := c.Get("natives")
		rec := record.New(recv.(*pyjson.Object))
		guid, natives, err := Resolve(namev.(string), objv.(string), rec, eventv.(*pyjson.Object))
		if err != nil {
			t.Errorf("case %d (%s): %v", i, namev.(string), err)
			continue
		}
		if g, w := dumps(t, guid), dumps(t, wantGuid); g != w {
			t.Errorf("case %d (%s): guid %s want %s", i, namev.(string), g, w)
		}
		if g, w := dumps(t, natives), dumps(t, wantNatives); g != w {
			t.Errorf("case %d (%s): natives\n got %s\nwant %s", i, namev.(string), g, w)
		}
		if sv, _ := natives.Get(NativeScope); sv == Intrinsic {
			sawIntrinsic = true
		} else if sv == Positional {
			sawPositional = true
		} else if guid == nil {
			sawAbsent = true
		}
	}
	if !sawIntrinsic || !sawPositional || !sawAbsent {
		t.Errorf("vector coverage gap: intrinsic=%v positional=%v absent=%v",
			sawIntrinsic, sawPositional, sawAbsent)
	}
}

func dumps(t *testing.T, v pyjson.Value) string {
	t.Helper()
	s, err := pyjson.Dumps(v)
	if err != nil {
		t.Fatalf("dumps: %v", err)
	}
	return s
}

// TestObjectMismatchErrors mirrors normalize._spindle's declared-object guard.
func TestObjectMismatchErrors(t *testing.T) {
	rec := record.New(pyjson.NewObject())
	ev := pyjson.NewObject()
	if _, _, err := Resolve("l2t_filestat", "process", rec, ev); err == nil {
		t.Fatal("object mismatch did not error")
	}
	if _, _, err := Resolve("no_such_entry", "file", rec, ev); err == nil {
		t.Fatal("unknown entry did not error")
	}
}
