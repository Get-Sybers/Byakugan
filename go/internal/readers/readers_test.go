package readers

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/get-sybers/byakugan/go/internal/pyjson"
)

// TestIterJSONLVectors replays the Python-recorded byte-level cases:
// utf-8-sig, errors='replace' maximal subparts, universal newlines and the
// line-cleaning rules must yield the exact record stream iter_jsonl does.
func TestIterJSONLVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/reader_vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	doc, err := pyjson.Decode(raw)
	if err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	cases, _ := doc.(*pyjson.Object).Get("cases")
	list := cases.([]pyjson.Value)
	if len(list) < 15 {
		t.Fatalf("suspiciously few reader vectors: %d", len(list))
	}
	dir := t.TempDir()
	for i, cv := range list {
		c := cv.(*pyjson.Object)
		hv, _ := c.Get("hex")
		want, _ := c.Get("records")
		data, err := hex.DecodeString(hv.(string))
		if err != nil {
			t.Fatalf("case %d: bad hex: %v", i, err)
		}
		path := filepath.Join(dir, "in.jsonl")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		var got []pyjson.Value
		if err := ForEach(path, func(v pyjson.Value) error {
			got = append(got, v)
			return nil
		}); err != nil {
			t.Errorf("case %d: ForEach: %v", i, err)
			continue
		}
		wantList := want.([]pyjson.Value)
		if len(got) != len(wantList) {
			t.Errorf("case %d (hex %s): %d records, want %d",
				i, hv.(string), len(got), len(wantList))
			continue
		}
		for j := range got {
			g, err1 := pyjson.Canonical(got[j])
			w, err2 := pyjson.Canonical(wantList[j])
			if err1 != nil || err2 != nil {
				t.Fatalf("case %d rec %d: canonical: %v / %v", i, j, err1, err2)
			}
			if g != w {
				t.Errorf("case %d rec %d:\n got %s\nwant %s", i, j, g, w)
			}
		}
	}
}
