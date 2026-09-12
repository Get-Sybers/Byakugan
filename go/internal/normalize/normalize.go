// Package normalize orchestrates one raw record → one CAR event over the
// embedded IR — the Go side of byakugan/normalize.py normalize():
// variant select via predicates → resolve action (nil aborts the row) →
// event built in the EXACT Python key order → _native (keep order, then
// native_extract order, then the spindle natives) → props merged in
// declaration order → guid minted LAST (a spindle id reads the normalized
// event's own values).
package normalize

import (
	"fmt"

	"github.com/get-sybers/byakugan/go/internal/ids"
	"github.com/get-sybers/byakugan/go/internal/ir"
	"github.com/get-sybers/byakugan/go/internal/markers"
	"github.com/get-sybers/byakugan/go/internal/predicates"
	"github.com/get-sybers/byakugan/go/internal/pyjson"
	"github.com/get-sybers/byakugan/go/internal/record"
	"github.com/get-sybers/byakugan/go/internal/spindle"
)

// Normalize maps one raw record to one CAR event; (nil, nil) when the record
// is unmapped or dropped (no matching variant, or a nil action).
func Normalize(artefact string, rec *record.Record) (*pyjson.Object, error) {
	doc, err := ir.Load()
	if err != nil {
		return nil, err
	}
	entry := ir.Get(doc, "mappings", artefact)
	if entry == nil {
		return nil, nil
	}
	leaf, err := selectLeaf(entry, rec)
	if err != nil || leaf == nil {
		return nil, err
	}

	obj, _ := ir.Get(leaf, "object").(string)

	// action: a plain string is the literal action; anything else resolves.
	actionSpec, _ := leaf.Get("action")
	var action pyjson.Value
	if s, ok := actionSpec.(string); ok {
		action = s
	} else {
		action, err = markers.Resolve(actionSpec, rec)
		if err != nil {
			return nil, err
		}
	}
	if action == nil {
		// a matched variant whose action marker resolves to nothing is NOT a
		// CAR event — the row stays raw, never an action-less phantom.
		return nil, nil
	}

	// props are resolved BEFORE the event dict is built (Python evaluation
	// order — visible when a marker parses a payload the header also reads).
	propsSpec, _ := leaf.Get("props")
	propPairs, _ := propsSpec.([]pyjson.Value)
	type kv struct {
		k string
		v pyjson.Value
	}
	props := make([]kv, 0, len(propPairs))
	for _, pv := range propPairs {
		pair, ok := pv.([]pyjson.Value)
		if !ok || len(pair) != 2 {
			return nil, fmt.Errorf("normalize: malformed props pair in %q", artefact)
		}
		car, _ := pair[0].(string)
		v, err := markers.Resolve(pair[1], rec)
		if err != nil {
			return nil, err
		}
		props = append(props, kv{car, v})
	}

	ev := pyjson.NewObject()
	ev.Set("car_object", obj)
	ev.Set("car_action", action)
	if ts, _ := leaf.Get("ts"); ts == nil {
		ev.Set("timestamp", nil)
	} else {
		v, err := markers.Resolve(ts, rec)
		if err != nil {
			return nil, err
		}
		ev.Set("timestamp", markers.CleanTs(v))
	}
	ev.Set("guid", nil) // the row identity — filled LAST (below)
	for _, h := range [...][2]string{
		{"owning_pid", "owning_pid"},
		{"owning_guid_native", "owning_guid"},
		{"parent_pid", "parent_pid"},
	} {
		spec, _ := leaf.Get(h[1])
		if spec == nil { // Python: `if m.get(...)`
			ev.Set(h[0], nil)
			continue
		}
		v, err := markers.Resolve(spec, rec)
		if err != nil {
			return nil, err
		}
		ev.Set(h[0], v)
	}
	ev.Set("owning_guid", nil)
	ev.Set("parent_guid", nil)
	ev.Set("link_confidence", nil)
	ev.Set("source_artefact", artefact)
	if host, _ := leaf.Get("host"); host == nil {
		ev.Set("source_host", nil)
	} else {
		v, err := markers.Resolve(host, rec)
		if err != nil {
			return nil, err
		}
		ev.Set("source_host", v)
	}

	native := pyjson.NewObject()
	if keep, ok := ir.Get(leaf, "keep").([]pyjson.Value); ok {
		for _, kv2 := range keep {
			if k, ok := kv2.(string); ok && rec.Has(k) {
				native.Set(k, rec.Get(k))
			}
		}
	}
	ev.Set("_native", native)

	// parsed values promoted into _native — nil results skipped.
	if ne, ok := ir.Get(leaf, "native_extract").([]pyjson.Value); ok {
		for _, pv := range ne {
			pair, ok := pv.([]pyjson.Value)
			if !ok || len(pair) != 2 {
				return nil, fmt.Errorf("normalize: malformed native_extract pair in %q", artefact)
			}
			name, _ := pair[0].(string)
			v, err := markers.Resolve(pair[1], rec)
			if err != nil {
				return nil, err
			}
			if v != nil {
				native.Set(name, v)
			}
		}
	}

	// event.update(props): new keys append, an existing key keeps its slot.
	for _, p := range props {
		ev.Set(p.k, p.v)
	}

	// the identity — minted LAST, over the finished event.
	guidSpec, _ := leaf.Get("guid")
	guid, idNative, err := identity(guidSpec, obj, rec, ev)
	if err != nil {
		return nil, err
	}
	ev.Set("guid", guid)
	if idNative != nil {
		for _, k := range idNative.Keys() {
			v, _ := idNative.Get(k)
			native.Set(k, v)
		}
	}
	return ev, nil
}

// selectLeaf is normalize._select: the first matching variant, else the
// default; a variant-less entry is its own leaf. Every IR predicate is
// registered (predicates.Check is a hard gate), so an unregistered name here
// means a stale/renamed IR — an error, never a silent non-match.
func selectLeaf(entry pyjson.Value, rec *record.Record) (*pyjson.Object, error) {
	eo, ok := entry.(*pyjson.Object)
	if !ok {
		return nil, fmt.Errorf("normalize: mapping entry is not an object")
	}
	variants, hasVariants := eo.Get("variants")
	if !hasVariants {
		return eo, nil
	}
	vl, ok := variants.([]pyjson.Value)
	if !ok {
		return nil, fmt.Errorf("normalize: variants is not a list")
	}
	for _, vv := range vl {
		pair, ok := vv.([]pyjson.Value)
		if !ok || len(pair) != 2 {
			return nil, fmt.Errorf("normalize: malformed variant pair")
		}
		predName, _ := pair[0].(string)
		fn, ok := predicates.Lookup(predName)
		if !ok {
			return nil, fmt.Errorf("normalize: predicate %q is not registered in Go "+
				"(run `byakugan-parse ir-check`; port it in "+
				"go/internal/predicates/predicates_<family>.go)", predName)
		}
		if fn(rec) {
			leaf, _ := pair[1].(*pyjson.Object) // nil sub → row dropped
			return leaf, nil
		}
	}
	def, _ := eo.Get("default")
	leaf, _ := def.(*pyjson.Object)
	return leaf, nil
}

// identity is normalize._identity: the spindle form mints and describes its
// identity; every other form is _guid, with nothing to add.
func identity(spec pyjson.Value, obj string, rec *record.Record, ev *pyjson.Object) (pyjson.Value, *pyjson.Object, error) {
	so, ok := spec.(*pyjson.Object)
	if ok {
		if sv, has := so.Get("spindle"); has {
			name, _ := sv.(string)
			return spindle.Resolve(name, obj, rec, ev)
		}
	}
	guid, err := guidOf(spec, obj, rec)
	return guid, nil, err
}

// guidOf is normalize._guid: an existing field, a marker,
// "<object>-<fields>" (any nil component voids it), or nil.
func guidOf(spec pyjson.Value, obj string, rec *record.Record) (pyjson.Value, error) {
	so, ok := spec.(*pyjson.Object)
	if !ok { // null spec
		return nil, nil
	}
	if none, _ := so.Get("none"); record.Truthy(none) {
		return nil, nil
	}
	if m, has := so.Get("marker"); has {
		return markers.Resolve(m, rec)
	}
	if f, has := so.Get("field"); has {
		name, _ := f.(string)
		v := rec.Get(name)
		if record.Blank(v) {
			return nil, nil
		}
		return v, nil
	}
	fl, has := so.Get("fields")
	if !has {
		return nil, fmt.Errorf("normalize: unknown guid spec")
	}
	fields, _ := fl.([]pyjson.Value)
	parts := make([]pyjson.Value, 0, len(fields))
	for _, f := range fields {
		name, _ := f.(string)
		parts = append(parts, rec.Get(name))
	}
	if g, ok := ids.FieldsGuid(obj, parts); ok {
		return g, nil
	}
	return nil, nil
}
