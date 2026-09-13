package authoring

import (
	"sort"

	"github.com/get-sybers/byakugan/go/internal/predicates"
	"github.com/get-sybers/byakugan/go/internal/pyjson"
)

// IRVersion is the IR document version this authoring layer emits (export_ir's
// IR_VERSION / ir.Version).
const IRVersion = 1

// po builds an insertion-ordered pyjson object from alternating (string key,
// value) pairs — the compact literal form the generated ir_sections.go uses.
func po(kv ...pyjson.Value) *pyjson.Object {
	o := pyjson.NewObject()
	for i := 0; i+1 < len(kv); i += 2 {
		o.Set(kv[i].(string), kv[i+1])
	}
	return o
}

// pa builds a pyjson array.
func pa(vs ...pyjson.Value) []pyjson.Value { return vs }

// mappingsSection assembles the IR `mappings` object from the Go-authored map
// registry (sorted keys, as export_ir emits).
func mappingsSection() *pyjson.Object {
	o := pyjson.NewObject()
	for _, k := range Keys() {
		o.Set(k, Registry[k].Encode())
	}
	return o
}

// predicateNames is the IR `predicate_names` — the LIVE Go predicate registry
// (sorted), so the names the engine can dispatch are the source of truth (not a
// transcribed list).
func predicateNames() []pyjson.Value {
	ns := predicates.Registered()
	sort.Strings(ns)
	out := make([]pyjson.Value, len(ns))
	for i, n := range ns {
		out[i] = n
	}
	return out
}

// BuildIR assembles the full IR document — the Go-native equivalent of
// byakugan/export_ir.py's build_ir(). `mappings` comes from the Go authoring
// registry and `predicate_names` from the live Go predicate registry; the other
// sections are the Go-authored static IR data (ir_sections.go). Insertion order
// here need not match export_ir (the engine reads by key; equality is checked
// via Canonical, which sorts).
func BuildIR() *pyjson.Object {
	o := pyjson.NewObject()
	o.Set("ir_version", pyjson.Int(IRVersion))
	o.Set("marker_kinds", irMarkerKinds())
	o.Set("mappings", mappingsSection())
	o.Set("routes", irRoutes())
	o.Set("evtx_maps", irEvtxMaps())
	o.Set("adapters", irAdapters())
	o.Set("spindle", irSpindle())
	o.Set("canon_user", irCanonUser())
	o.Set("predicate_names", predicateNames())
	o.Set("golden", irGolden())
	return o
}
