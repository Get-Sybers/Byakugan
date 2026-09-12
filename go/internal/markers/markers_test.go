package markers

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/get-sybers/byakugan/go/internal/pyjson"
	"github.com/get-sybers/byakugan/go/internal/record"
)

// vectorFiles lists the per-family marker vector files. `core.json` carries
// the engine-wide coverage (all 24 kinds, _clean_ts, parse_ts,
// evtx_payload_field); a family adds testdata/marker_vectors/<family>.json
// only when it needs marker coverage core does not already give it — so two
// agents porting two families never touch the same file.
func vectorFiles(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", "marker_vectors", "*.json"))
	if err != nil {
		t.Fatalf("glob vectors: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("no marker vector files under testdata/marker_vectors/ " +
			"(regenerate: python tests/parity/gen_all.py)")
	}
	sort.Strings(paths)
	return paths
}

// section concatenates one named section across every family vector file, in
// file-name order. A family file need not carry every section.
func section(t *testing.T, key string) []pyjson.Value {
	t.Helper()
	var out []pyjson.Value
	for _, path := range vectorFiles(t) {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", filepath.Base(path), err)
		}
		v, err := pyjson.Decode(raw)
		if err != nil {
			t.Fatalf("decode %s: %v", filepath.Base(path), err)
		}
		doc, ok := v.(*pyjson.Object)
		if !ok {
			t.Fatalf("%s: vector file is not an object", filepath.Base(path))
		}
		s, ok := doc.Get(key)
		if !ok {
			continue
		}
		list, ok := s.([]pyjson.Value)
		if !ok {
			t.Fatalf("%s: section %q is not a list", filepath.Base(path), key)
		}
		out = append(out, list...)
	}
	if len(out) == 0 {
		t.Fatalf("no %q vectors in any testdata/marker_vectors/*.json", key)
	}
	return out
}

func canon(t *testing.T, v pyjson.Value) string {
	t.Helper()
	s, err := pyjson.Canonical(v)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	return s
}

func TestResolveVectors(t *testing.T) {
	cases := section(t, "resolve")
	if len(cases) < 150 {
		t.Fatalf("suspiciously few resolve vectors: %d", len(cases))
	}
	for i, cv := range cases {
		c := cv.(*pyjson.Object)
		spec, _ := c.Get("spec")
		recv, _ := c.Get("rec")
		want, _ := c.Get("out")
		rec := record.New(recv.(*pyjson.Object))
		got, err := Resolve(spec, rec)
		if err != nil {
			t.Errorf("vector %d (%s): resolve error: %v", i, canon(t, spec), err)
			continue
		}
		if canon(t, got) != canon(t, want) {
			t.Errorf("vector %d: spec %s rec %s\n got %s\nwant %s",
				i, canon(t, spec), canon(t, recv), canon(t, got), canon(t, want))
		}
	}
}

func TestCleanTsVectors(t *testing.T) {
	for i, cv := range section(t, "clean_ts") {
		pair := cv.([]pyjson.Value)
		got := CleanTs(pair[0])
		if canon(t, got) != canon(t, pair[1]) {
			t.Errorf("clean_ts %d: in %s got %s want %s",
				i, canon(t, pair[0]), canon(t, got), canon(t, pair[1]))
		}
	}
}

func TestParseTsVectors(t *testing.T) {
	for i, cv := range section(t, "parse_ts") {
		pair := cv.([]pyjson.Value)
		sec, us, ok := ParseTs(pair[0])
		var got pyjson.Value
		if ok {
			got = IsoUTC(sec, us) // aware-UTC datetime.isoformat()
		}
		if canon(t, got) != canon(t, pair[1]) {
			t.Errorf("parse_ts %d: in %s got %s want %s",
				i, canon(t, pair[0]), canon(t, got), canon(t, pair[1]))
		}
	}
}

func TestPayloadFieldVectors(t *testing.T) {
	for i, cv := range section(t, "payload_field") {
		c := cv.(*pyjson.Object)
		recv, _ := c.Get("rec")
		namev, _ := c.Get("name")
		wantv, _ := c.Get("out")
		rec := record.New(recv.(*pyjson.Object))
		got := rec.EvtxPayloadField(namev.(string))
		if got != wantv.(string) {
			t.Errorf("payload_field %d (%s): got %q want %q",
				i, namev.(string), got, wantv.(string))
		}
	}
}
