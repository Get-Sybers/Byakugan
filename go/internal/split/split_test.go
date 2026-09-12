// Replays the vectors tests/parity/genf/adapters.py records from the FROZEN
// Python splitter (tests/parity/reference/l2t_split.py): table names, and the
// exact wrapped-row LINE json.dumps produced for each record.
//
//	python tests/parity/genf/adapters.py
//
// The end-to-end byte compare of every file a split writes lives in
// tests/parity/test_split_parity.py.
package split

import (
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/get-sybers/byakugan/go/internal/pyjson"
)

func loadVectors(t *testing.T) *pyjson.Object {
	t.Helper()
	data, err := os.ReadFile("testdata/split_vectors.json")
	if err != nil {
		t.Fatalf("read split_vectors.json: %v "+
			"(regenerate: python tests/parity/genf/adapters.py)", err)
	}
	v, err := pyjson.Decode(data)
	if err != nil {
		t.Fatalf("decode split_vectors.json: %v", err)
	}
	o, ok := v.(*pyjson.Object)
	if !ok {
		t.Fatal("split_vectors.json: not a JSON object")
	}
	return o
}

func TestTableNameVectors(t *testing.T) {
	doc := loadVectors(t)
	rows, _ := doc.Get("table_name")
	lst, ok := rows.([]pyjson.Value)
	if !ok || len(lst) == 0 {
		t.Fatal("split_vectors.json: no table_name rows")
	}
	for i, rv := range lst {
		pair := rv.([]pyjson.Value)
		in, _ := pair[0].(string)
		want, _ := pair[1].(string)
		if got := TableName(in); got != want {
			t.Errorf("table_name[%d] (%q): want %q, got %q", i, in, want, got)
		}
	}
}

func TestRowVectors(t *testing.T) {
	doc := loadVectors(t)
	rows, _ := doc.Get("rows")
	lst, ok := rows.([]pyjson.Value)
	if !ok || len(lst) == 0 {
		t.Fatal("split_vectors.json: no rows")
	}
	withTs := 0
	for i, rv := range lst {
		r := rv.(*pyjson.Object)
		rec, _ := r.Get("rec")
		source, _ := r.Get("source_rel")
		ridv, _ := r.Get("record_id")
		wantTable, _ := r.Get("table")
		wantLine, _ := r.Get("line")
		rid := -1 // Python's record_id=None → the RecordId key is left out
		if n, ok := ridv.(*big.Int); ok {
			rid = int(n.Int64())
		}
		src, _ := source.(string)
		gotTable, gotLine, err := Row(rec, src, rid)
		if err != nil {
			t.Fatalf("row[%d]: %v", i, err)
		}
		if gotTable != wantTable.(string) {
			t.Errorf("row[%d]: table want %q, got %q", i, wantTable, gotTable)
		}
		if gotLine != wantLine.(string) {
			t.Errorf("row[%d] line differs\n want: %s\n  got: %s", i, wantLine, gotLine)
		}
		if strings.Contains(wantLine.(string), `"Timestamp"`) {
			withTs++
		}
	}
	if withTs < 3 {
		t.Fatalf("only %d vectors carry a Timestamp — the plaso-µs path is untested", withTs)
	}
}

// TestSplitL2tCountsPhysicalLines pins the RecordId contract: blank and
// unparseable lines are SKIPPED but still COUNTED, so a later fix that makes a
// bad line parse never renumbers its neighbours.
func TestSplitL2tCountsPhysicalLines(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "img.jsonl")
	body := strings.Join([]string{
		`{"parser": "usnjrnl", "timestamp": 1600262070462820}`,
		"",          // blank: counted
		"{not json", // bad: counted
		`{"parser": "mft", "timestamp": 1600262070462820}`,       //
		`  {"parser": "usnjrnl", "timestamp": 1600262070462821}`, // padded
	}, "\n") + "\n"
	if err := os.WriteFile(in, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := SplitL2t(in, "img.jsonl", out, "img.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if res.Lines != 5 {
		t.Errorf("lines: want 5 physical lines, got %d", res.Lines)
	}
	if len(res.Tables) != 2 ||
		res.Tables[0].Name != "L2tUsnjrnl" || res.Tables[1].Name != "L2tMft" {
		t.Fatalf("tables: want [L2tUsnjrnl L2tMft] in first-seen order, got %+v", res.Tables)
	}
	got := map[string][]string{}
	for _, tb := range res.Tables {
		data, err := os.ReadFile(tb.Path)
		if err != nil {
			t.Fatal(err)
		}
		got[tb.Name] = strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	}
	if n := len(got["L2tUsnjrnl"]); n != 2 {
		t.Fatalf("L2tUsnjrnl: want 2 rows, got %d", n)
	}
	for _, want := range []struct{ table, needle string }{
		{"L2tUsnjrnl", `"RecordId": 1`},
		{"L2tMft", `"RecordId": 4`},
	} {
		if !strings.Contains(got[want.table][0], want.needle) {
			t.Errorf("%s row 0: want %s in %s", want.table, want.needle, got[want.table][0])
		}
	}
	if !strings.Contains(got["L2tUsnjrnl"][1], `"RecordId": 5`) {
		t.Errorf("L2tUsnjrnl row 1: want RecordId 5, got %s", got["L2tUsnjrnl"][1])
	}
	// file names are "<prefix>.<table>"
	if base := filepath.Base(res.Tables[0].Path); base != "img.jsonl.L2tUsnjrnl" {
		t.Errorf("file name: want img.jsonl.L2tUsnjrnl, got %s", base)
	}
}

// TestSplitL2tMissingFileIsVanishTolerant pins l2t_split's `except OSError:
// return` — the library yields nothing rather than failing (the CLI checks the
// file itself so a typo'd --in is still an error).
func TestSplitL2tMissingFileIsVanishTolerant(t *testing.T) {
	dir := t.TempDir()
	res, err := SplitL2t(filepath.Join(dir, "nope.jsonl"), "nope.jsonl", dir, "nope.jsonl")
	if err != nil {
		t.Fatalf("want no error, got %v", err)
	}
	if len(res.Tables) != 0 || res.Lines != 0 {
		t.Fatalf("want an empty result, got %+v", res)
	}
}
