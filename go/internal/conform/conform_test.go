package conform

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The wire field names must match the Python reference and
// defs.schema.json#/$defs/finding exactly.
func TestFindingWireShape(t *testing.T) {
	b, err := json.Marshal(Finding{ObjectID: "o", Rule: "r", Message: "m", Path: "p"})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"object_id": "o", "rule": "r", "message": "m", "path": "p"}
	if !reflect.DeepEqual(m, want) {
		t.Fatalf("wire shape %v != %v", m, want)
	}
	// path is omitted when empty — the Python as_dict() behaviour
	b, _ = json.Marshal(Finding{ObjectID: "o", Rule: "r", Message: "m"})
	if string(b) != `{"object_id":"o","rule":"r","message":"m"}` {
		t.Fatalf("empty path not omitted: %s", b)
	}
}

func TestTally(t *testing.T) {
	got := Tally([]Finding{{Rule: "a"}, {Rule: "a"}, {Rule: "b"}})
	if got["a"] != 2 || got["b"] != 1 {
		t.Fatalf("tally wrong: %v", got)
	}
}

// The named check-pass table (#136): every engine:"go" entry names a check
// this package declares, and every declared Go check is listed — the table
// and the engine hold each other, from the Go side.
func TestConformanceTableNamesRealGoChecks(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "model", "schema", "conformance.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Checks []struct {
			Name   string `json:"name"`
			Engine string `json:"engine"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, c := range doc.Checks {
		if c.Engine == "go" {
			listed[c.Name] = true
			if !GoChecks[c.Name] {
				t.Errorf("conformance.json claims unknown go check %q", c.Name)
			}
		}
	}
	for name := range GoChecks {
		if !listed[name] {
			t.Errorf("go check %q missing from conformance.json", name)
		}
	}
}
