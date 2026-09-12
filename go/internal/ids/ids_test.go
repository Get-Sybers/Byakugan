package ids

import (
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/get-sybers/byakugan/go/internal/ir"
	"github.com/get-sybers/byakugan/go/internal/pyjson"
)

func golden(t *testing.T) *pyjson.Object {
	t.Helper()
	doc, err := ir.Load()
	if err != nil {
		t.Fatalf("ir.Load: %v", err)
	}
	g, ok := ir.Get(doc, "golden").(*pyjson.Object)
	if !ok {
		t.Fatal("ir: golden section missing")
	}
	return g
}

func asString(t *testing.T, v pyjson.Value, what string) string {
	t.Helper()
	s, ok := v.(string)
	if !ok {
		t.Fatalf("%s: not a string: %T", what, v)
	}
	return s
}

// TestNamespaces pins the uuid5 chain: NAMESPACE_URL -> CAR_NS -> SPINDLE_NS
// against the golden recipe's literal namespace strings.
func TestNamespaces(t *testing.T) {
	ns, ok := ir.Get(golden(t), "spindle", "recipe", "namespaces").(*pyjson.Object)
	if !ok {
		t.Fatal("golden: no recipe namespaces")
	}
	carNS, _ := ns.Get("CAR_NS")
	if got := CarNS.String(); got != carNS.(string) {
		t.Errorf("CAR_NS = %s, want %s", got, carNS)
	}
	spindleNS, _ := ns.Get("SPINDLE_NS")
	if got := SpindleNS.String(); got != spindleNS.(string) {
		t.Errorf("SPINDLE_NS = %s, want %s", got, spindleNS)
	}
}

// TestRecipeVector pins canonical_json over the fixed recipe input.
func TestRecipeVector(t *testing.T) {
	cj, ok := ir.Get(golden(t), "spindle", "recipe", "canonical_json").(*pyjson.Object)
	if !ok {
		t.Fatal("golden: no recipe canonical_json")
	}
	input, _ := cj.Get("input")
	want, _ := cj.Get("output")
	got, err := CanonicalJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	if got != want.(string) {
		t.Errorf("canonical_json = %q, want %q", got, want)
	}
}

// mintFromKey re-mints a golden key two ways: GuidOf over the key as
// committed, and Mint over the key's identity components (the rendered
// string values re-render identically under RenderStr).
func mintFromKey(t *testing.T, name string, key *pyjson.Object, wantGuid string) {
	t.Helper()
	got, err := GuidOf(key)
	if err != nil {
		t.Errorf("%s: GuidOf: %v", name, err)
		return
	}
	if got != wantGuid {
		t.Errorf("%s: GuidOf = %s, want %s", name, got, wantGuid)
	}
	objV, ok := key.Get(ObjectKey)
	if !ok {
		t.Errorf("%s: key has no %s", name, ObjectKey)
		return
	}
	verV, ok := key.Get(VersionKey)
	if !ok {
		t.Errorf("%s: key has no %s", name, VersionKey)
		return
	}
	var identity []Field
	for _, k := range key.Keys() {
		if k == ObjectKey || k == VersionKey {
			continue
		}
		v, _ := key.Get(k)
		identity = append(identity, Field{Name: k, Value: v})
	}
	guid, mintedKey, err := Mint(objV.(string), identity, int(verV.(*big.Int).Int64()), nil)
	if err != nil {
		t.Errorf("%s: Mint: %v", name, err)
		return
	}
	if guid != wantGuid {
		t.Errorf("%s: Mint = %s, want %s", name, guid, wantGuid)
	}
	wantKey, _ := pyjson.Canonical(key)
	gotKey, _ := pyjson.Canonical(mintedKey)
	if gotKey != wantKey {
		t.Errorf("%s: minted key %s, want %s", name, gotKey, wantKey)
	}
}

// TestGoldenIdentityVectors re-mints every pinned identity vector (all the
// registry entries) plus the positional vector.
func TestGoldenIdentityVectors(t *testing.T) {
	g := golden(t)
	pos, ok := ir.Get(g, "positional").(*pyjson.Object)
	if !ok {
		t.Fatal("golden: no positional vector")
	}
	posKey, _ := pos.Get("key")
	posGuid, _ := pos.Get("guid")
	mintFromKey(t, "positional", posKey.(*pyjson.Object), posGuid.(string))

	idents, ok := ir.Get(g, "identities").([]pyjson.Value)
	if !ok || len(idents) == 0 {
		t.Fatal("golden: no identity vectors")
	}
	for _, ev := range idents {
		e := ev.(*pyjson.Object)
		name, _ := e.Get("name")
		key, _ := e.Get("key")
		guid, _ := e.Get("guid")
		mintFromKey(t, asString(t, name, "identity name"), key.(*pyjson.Object), asString(t, guid, "guid"))
	}
	t.Logf("re-minted %d identity vectors + positional", len(idents))
}

// TestGoldenExternalForms renders every external form's golden sample
// through the same value paths the engine uses (fields join / raw field /
// payload marker string / the producing tool's {hex} form).
func TestGoldenExternalForms(t *testing.T) {
	doc, err := ir.Load()
	if err != nil {
		t.Fatal(err)
	}
	forms, ok := ir.Get(doc, "spindle", "external").(*pyjson.Object)
	if !ok {
		t.Fatal("ir: no spindle external forms")
	}
	exts, ok := ir.Get(golden(t), "external").([]pyjson.Value)
	if !ok || len(exts) == 0 {
		t.Fatal("golden: no external vectors")
	}
	for _, ev := range exts {
		e := ev.(*pyjson.Object)
		nameV, _ := e.Get("name")
		name := asString(t, nameV, "external name")
		objV, _ := e.Get("car_object")
		valuesV, _ := e.Get("values")
		values := valuesV.(*pyjson.Object)
		guidV, _ := e.Get("guid")
		wantGuid := asString(t, guidV, name+" guid")
		form, ok := ir.Get(forms, name, "form").(*pyjson.Object)
		if !ok {
			t.Errorf("%s: no declared form", name)
			continue
		}
		switch {
		case ir.Get(form, "fields") != nil:
			fields := ir.Get(form, "fields").([]pyjson.Value)
			var parts []pyjson.Value
			for _, f := range fields {
				v, _ := values.Get(f.(string))
				parts = append(parts, v)
			}
			got, ok := FieldsGuid(objV.(string), parts)
			if !ok || got != wantGuid {
				t.Errorf("%s: FieldsGuid = %q (%v), want %q", name, got, ok, wantGuid)
			}
		case ir.Get(form, "field") != nil:
			f := ir.Get(form, "field").(string)
			v, _ := values.Get(f)
			got, err := pyjson.Str(v)
			if err != nil || got != wantGuid {
				t.Errorf("%s: field guid = %q (%v), want %q", name, got, err, wantGuid)
			}
		case ir.Get(form, "marker") != nil:
			key := ir.Get(form, "marker", "payload").(string)
			v, _ := values.Get(key)
			got, err := pyjson.Str(v)
			if err != nil || got != wantGuid {
				t.Errorf("%s: payload guid = %q (%v), want %q", name, got, err, wantGuid)
			}
		case ir.Get(form, "form") != nil:
			tmpl := ir.Get(form, "form").(string)
			v, _ := values.Get("offset")
			n, ok := v.(*big.Int)
			if !ok {
				t.Errorf("%s: offset is not an int: %T", name, v)
				continue
			}
			got := strings.Replace(tmpl, "{hex}", fmt.Sprintf("%x", n), 1)
			if got != wantGuid {
				t.Errorf("%s: form guid = %q, want %q", name, got, wantGuid)
			}
		default:
			t.Errorf("%s: unrecognized form shape", name)
		}
	}
	t.Logf("rendered %d external forms", len(exts))
}

// TestRenderVectors replays the pystr vectors' ids.render recordings —
// RENDER_STR (canonical for containers, str() for scalars) and RENDER_JSON.
func TestRenderVectors(t *testing.T) {
	data, err := os.ReadFile("../pyjson/testdata/vectors.json")
	if err != nil {
		t.Fatalf("read pyjson vectors: %v", err)
	}
	v, err := pyjson.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	list, ok := ir.Get(v, "pystr").([]pyjson.Value)
	if !ok || len(list) == 0 {
		t.Fatal("no pystr vectors")
	}
	for i, rv := range list {
		rec := rv.(*pyjson.Object)
		valText, _ := rec.Get("value")
		val, err := pyjson.DecodeString(valText.(string))
		if err != nil {
			t.Errorf("pystr %d: decode: %v", i, err)
			continue
		}
		wantStr, _ := rec.Get("render_str")
		wantJSON, _ := rec.Get("render_json")
		got, err := Render(val, RenderStr)
		if err != nil || got != wantStr.(string) {
			t.Errorf("pystr %d: Render(str) = %q (%v), want %q", i, got, err, wantStr)
		}
		got, err = Render(val, RenderJSON)
		if err != nil || got != wantJSON.(string) {
			t.Errorf("pystr %d: Render(json) = %q (%v), want %q", i, got, err, wantJSON)
		}
	}
}

// TestMintGuards pins the reserved-name and missing-value errors.
func TestMintGuards(t *testing.T) {
	if _, _, err := Mint("file", []Field{{Name: "_obj", Value: "x"}}, 1, nil); err == nil {
		t.Error("reserved identity name accepted")
	}
	if _, _, err := Mint("file", []Field{{Name: "p", Value: nil}}, 1, nil); err == nil {
		t.Error("nil identity value accepted")
	}
	if _, ok := FieldsGuid("file", []pyjson.Value{"a", nil}); ok {
		t.Error("nil fields-guid component accepted")
	}
	if got, ok := FieldsGuid("file", []pyjson.Value{"a", ""}); !ok || got != "file-a-" {
		t.Errorf(`empty-string component: got %q, %v; "" is a legitimate identity value`, got, ok)
	}
}
