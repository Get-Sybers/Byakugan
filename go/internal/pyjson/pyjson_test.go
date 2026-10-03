package pyjson

import (
	"os"
	"testing"
)

// loadVectors decodes testdata/vectors.json with pyjson itself — decoding
// the vectors file is part of the test surface.
func loadVectors(t *testing.T) *Object {
	t.Helper()
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	v, err := Decode(data)
	if err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	o, ok := v.(*Object)
	if !ok {
		t.Fatalf("vectors: not an object: %T", v)
	}
	return o
}

func vecList(t *testing.T, o *Object, key string) []Value {
	t.Helper()
	v, ok := o.Get(key)
	if !ok {
		t.Fatalf("vectors: no %q section", key)
	}
	arr, ok := v.([]Value)
	if !ok {
		t.Fatalf("vectors: %q is not an array: %T", key, v)
	}
	return arr
}

func vecStr(t *testing.T, rec *Object, key string) string {
	t.Helper()
	v, ok := rec.Get(key)
	if !ok {
		t.Fatalf("vector record: no %q", key)
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("vector record: %q is not a string: %T", key, v)
	}
	return s
}

// TestDumpsVectors round-trips every recorded value byte-identically in both
// encoder styles: decode the Python-emitted token stream, re-encode, compare.
func TestDumpsVectors(t *testing.T) {
	vectors := vecList(t, loadVectors(t), "dumps")
	if len(vectors) == 0 {
		t.Fatal("no dumps vectors")
	}
	for i, rv := range vectors {
		rec := rv.(*Object)
		valueText := vecStr(t, rec, "value")
		wantDefault := vecStr(t, rec, "default")
		wantCanonical := vecStr(t, rec, "canonical")
		v, err := DecodeString(valueText)
		if err != nil {
			t.Errorf("vector %d: decode %q: %v", i, valueText, err)
			continue
		}
		got, err := Dumps(v)
		if err != nil {
			t.Errorf("vector %d: Dumps: %v", i, err)
			continue
		}
		if got != wantDefault {
			t.Errorf("vector %d: Dumps(%s)\n got  %q\n want %q", i, valueText, got, wantDefault)
		}
		got, err = Canonical(v)
		if err != nil {
			t.Errorf("vector %d: Canonical: %v", i, err)
			continue
		}
		if got != wantCanonical {
			t.Errorf("vector %d: Canonical(%s)\n got  %q\n want %q", i, valueText, got, wantCanonical)
		}
		// second round trip: the default encoding must decode back to a value
		// that re-encodes canonically identical
		v2, err := DecodeString(wantDefault)
		if err != nil {
			t.Errorf("vector %d: re-decode %q: %v", i, wantDefault, err)
			continue
		}
		got2, err := Canonical(v2)
		if err == nil && got2 != wantCanonical {
			t.Errorf("vector %d: round-trip Canonical drifted: %q != %q", i, got2, wantCanonical)
		}
	}
}

// TestStrVectors checks Python str() scalar rendering (the fields-guid join).
func TestStrVectors(t *testing.T) {
	vectors := vecList(t, loadVectors(t), "pystr")
	n := 0
	for i, rv := range vectors {
		rec := rv.(*Object)
		want, ok := rec.Get("str")
		if !ok {
			continue // container value: covered by the ids render test
		}
		v, err := DecodeString(vecStr(t, rec, "value"))
		if err != nil {
			t.Errorf("pystr %d: decode: %v", i, err)
			continue
		}
		got, err := Str(v)
		if err != nil {
			t.Errorf("pystr %d: Str: %v", i, err)
			continue
		}
		if got != want.(string) {
			t.Errorf("pystr %d: Str = %q, want %q", i, got, want)
		}
		n++
	}
	if n == 0 {
		t.Fatal("no scalar pystr vectors")
	}
}

// TestDecodeErrors pins the strictness Python json.loads shares.
func TestDecodeErrors(t *testing.T) {
	for _, bad := range []string{
		"", "{", "[1,]", "{\"a\":1,}", "01", "1.", ".5", "+1", "'x'",
		"\"\x01\"", "nul", "tru", "[1 2]", "{\"a\" 1}", "1 2", "--1", "1e",
	} {
		if _, err := DecodeString(bad); err == nil {
			t.Errorf("Decode(%q): expected error, got none", bad)
		}
	}
}

// TestSurrogatePairDecode pins astral handling: a 🎉 pair decodes
// to one code point and re-encodes as the same pair under ensure_ascii (and
// literally under Canonical).
func TestSurrogatePairDecode(t *testing.T) {
	v, err := DecodeString(`"\ud83c\udf89"`)
	if err != nil {
		t.Fatal(err)
	}
	if v.(string) != "\U0001F389" {
		t.Fatalf("got %q", v)
	}
	if out, err := Dumps(v); err != nil || out != `"\ud83c\udf89"` {
		t.Fatalf("Dumps = %q, %v", out, err)
	}
	if out, err := Canonical(v); err != nil || out != "\"\U0001F389\"" {
		t.Fatalf("Canonical = %q, %v", out, err)
	}
}
