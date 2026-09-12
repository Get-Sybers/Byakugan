package markers

import (
	"os"
	"testing"

	"github.com/get-sybers/byakugan/go/internal/pyjson"
	"github.com/get-sybers/byakugan/go/internal/record"
)

// vectors loads the Python-recorded marker vectors.
func vectors(t *testing.T) *pyjson.Object {
	t.Helper()
	raw, err := os.ReadFile("testdata/marker_vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	v, err := pyjson.Decode(raw)
	if err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	return v.(*pyjson.Object)
}

func canon(t *testing.T, v pyjson.Value) string {
	t.Helper()
	s, err := pyjson.Canonical(v)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	return s
}

func getList(t *testing.T, doc *pyjson.Object, key string) []pyjson.Value {
	t.Helper()
	v, ok := doc.Get(key)
	if !ok {
		t.Fatalf("vectors: no %q section", key)
	}
	return v.([]pyjson.Value)
}

func TestResolveVectors(t *testing.T) {
	doc := vectors(t)
	cases := getList(t, doc, "resolve")
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
	doc := vectors(t)
	for i, cv := range getList(t, doc, "clean_ts") {
		pair := cv.([]pyjson.Value)
		got := CleanTs(pair[0])
		if canon(t, got) != canon(t, pair[1]) {
			t.Errorf("clean_ts %d: in %s got %s want %s",
				i, canon(t, pair[0]), canon(t, got), canon(t, pair[1]))
		}
	}
}

func TestParseTsVectors(t *testing.T) {
	doc := vectors(t)
	for i, cv := range getList(t, doc, "parse_ts") {
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
	doc := vectors(t)
	for i, cv := range getList(t, doc, "payload_field") {
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
