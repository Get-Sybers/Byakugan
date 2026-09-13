// Package authoring is the Go-native map-authoring layer that will replace the
// Python byakugan/mappings + byakugan/export_ir tables (DX_DFIR #188, initiative
// 1; docs/go-native-map-authoring.md). Maps are declared here as Go values whose
// Encode() produces the SAME pyjson structure `export_ir.py` emits for the IR
// `mappings` section — so the engine (which already consumes the decoded IR) is
// unchanged, and the migration is proven by semantic equality against the
// committed ir.json (authoring_test.go), then Python is retired.
//
// The builders mirror byakugan/normalize.py's marker DSL and export_ir's
// encoding contract (_VARIADIC/_UNARY/_FIXED, the {"!":[kind,...]} envelope, the
// guid forms, the fixed leaf key order). A field-name source is a bare Go
// string; a marker is an envelope object; a literal action is a bare string.
package authoring

import "github.com/get-sybers/byakugan/go/internal/pyjson"

// Src is a resolver source: a field-name string (Go string) or a marker
// envelope (*pyjson.Object). Matches export_ir.encode_source's two shapes.
type Src = pyjson.Value

// env builds the marker envelope {"!": [kind, arg...]} — export_ir's MARKER_KEY
// form. Sources are placed verbatim (a string field name or a nested envelope);
// fixed-signature literals (patterns, keys, indexes) are placed as-is too, which
// is exactly what encode_source does after recursing sources / _literal-ing the
// rest.
func env(kind string, args ...pyjson.Value) *pyjson.Object {
	arr := make([]pyjson.Value, 0, len(args)+1)
	arr = append(arr, kind)
	arr = append(arr, args...)
	o := pyjson.NewObject()
	o.Set("!", []pyjson.Value(arr))
	return o
}

// --- marker builders (mirror normalize.py; every kind export_ir knows) -------

// variadic
func First(srcs ...Src) Src  { return env("first", srcs...) }
func Concat(srcs ...Src) Src { return env("concat", srcs...) }

// unary (one source)
func Basename(s Src) Src            { return env("basename", s) }
func Ext(s Src) Src                 { return env("ext", s) }
func Lower(s Src) Src               { return env("lower", s) }
func DomainOf(s Src) Src            { return env("domain_of", s) }
func EpochTS(s Src) Src             { return env("epoch_ts", s) }
func ExePath(s Src) Src             { return env("exe_path", s) }
func HostLabel(s Src) Src           { return env("host_label", s) }
func HexInt(s Src) Src              { return env("hex_int", s) }
func UnescapeBackslashes(s Src) Src { return env("unescape_backslashes", s) }
func WinProgramPath(s Src) Src      { return env("win_program_path", s) }
func WinProgramName(s Src) Src      { return env("win_program_name", s) }
func UserCanon(s Src) Src           { return env("user_canon", s) }

// fixed signatures (per-position source-vs-literal, per export_ir._FIXED)
func Regex1(s Src, pattern string) Src  { return env("regex1", s, pattern) }
func Payload(field, key string) Src     { return env("payload", field, key) }
func Userdata(field, key string) Src    { return env("userdata", field, key) }
func Replace(s Src, old, nw string) Src { return env("replace", s, old, nw) }
func At(s Src, index int) Src           { return env("at", s, pyjson.Int(int64(index))) }
func TsBefore(s, other Src) Src         { return env("ts_before", s, other) }

// MapValue: table is a literal string->string lookup; export_ir._literal emits
// it with sorted keys (lookup order is not semantic), so Canonical comparison is
// order-independent — but we build it ordered here for a faithful structure.
func MapValue(s Src, table map[string]string, upper bool) Src {
	t := pyjson.NewObject()
	for _, k := range sortedKeys(table) {
		t.Set(k, table[k])
	}
	return env("map_value", s, t, upper)
}

// Const is a literal the observation itself proves.
func Const(v pyjson.Value) Src { return env("const", v) }

// --- guid forms (export_ir._encode_guid) -------------------------------------

// GuidFields is the positional identity {"fields": [...]} EZ-tool/zeek/evtx maps
// carry (never the Plaso spindle registry — that is plaso-only).
func GuidFields(fields ...string) pyjson.Value {
	arr := make([]pyjson.Value, len(fields))
	for i, f := range fields {
		arr[i] = f
	}
	o := pyjson.NewObject()
	o.Set("fields", arr)
	return o
}

func GuidField(field string) pyjson.Value  { o := pyjson.NewObject(); o.Set("field", field); return o }
func GuidMarker(s Src) pyjson.Value        { o := pyjson.NewObject(); o.Set("marker", s); return o }
func GuidSpindle(name string) pyjson.Value { o := pyjson.NewObject(); o.Set("spindle", name); return o }
func GuidNone() pyjson.Value               { o := pyjson.NewObject(); o.Set("none", true); return o }

// --- leaf + entry ------------------------------------------------------------

// Prop is one CAR column ← source pair (order is semantic: resolve/merge order).
type Prop struct {
	Car  string
	Spec Src
}

// Leaf is one concrete map (a variant submap, a default, or a variant-less
// entry). Nil-able fields encode to JSON null (present, as export_ir does).
type Leaf struct {
	Object        string
	Action        Src          // a literal string (used verbatim) or a marker
	Ts            Src          // nil → null
	Guid          pyjson.Value // nil → null, else a guid form
	Host          Src          // nil → null
	OwningPID     Src
	OwningGuid    Src
	ParentPID     Src
	Props         []Prop
	Keep          []string
	NativeExtract []Prop
}

func pairs(ps []Prop) []pyjson.Value {
	out := make([]pyjson.Value, len(ps))
	for i, p := range ps {
		out[i] = []pyjson.Value{p.Car, p.Spec}
	}
	return out
}

func strList(ss []string) []pyjson.Value {
	out := make([]pyjson.Value, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// Encode produces the pyjson leaf with export_ir._encode_leaf's exact key set
// (all present, nulls included) so a Canonical comparison lines up.
func (l Leaf) Encode() *pyjson.Object {
	o := pyjson.NewObject()
	o.Set("object", l.Object)
	o.Set("action", l.Action)
	o.Set("ts", l.Ts)
	o.Set("guid", l.Guid)
	o.Set("host", l.Host)
	o.Set("owning_pid", l.OwningPID)
	o.Set("owning_guid", l.OwningGuid)
	o.Set("parent_pid", l.ParentPID)
	o.Set("props", pairs(l.Props))
	o.Set("keep", strList(l.Keep))
	o.Set("native_extract", pairs(l.NativeExtract))
	return o
}

func leafOrNull(l *Leaf) pyjson.Value {
	if l == nil {
		return nil
	}
	return l.Encode()
}

// Variant is one (predicate, submap) gate of an entry.
type Variant struct {
	Pred string
	Leaf *Leaf // nil → null (a matched-but-unmapped variant)
}

// Entry is a MAPPINGS entry: ordered variants (first match wins) + a default.
type Entry struct {
	Variants []Variant
	Default  *Leaf
}

// Encode produces the pyjson entry (export_ir._encode_entry, variants form).
func (e Entry) Encode() *pyjson.Object {
	vs := make([]pyjson.Value, len(e.Variants))
	for i, v := range e.Variants {
		vs[i] = []pyjson.Value{v.Pred, leafOrNull(v.Leaf)}
	}
	o := pyjson.NewObject()
	o.Set("variants", vs)
	o.Set("default", leafOrNull(e.Default))
	return o
}
