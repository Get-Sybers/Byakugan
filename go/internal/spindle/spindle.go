// Package spindle resolves a row's minted identity from the IR's spindle
// registry — the Go side of byakugan/normalize.py _spindle over
// byakugan/spindle.py's registry accessors: identity fields are paths on the
// NORMALIZED event, a blank component falls the row back to its positional
// (SourceImage, RecordId) identity, and every minted row carries
// spindle_key / spindle_scope / spindle_ref in _native.
package spindle

import (
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/get-sybers/byakugan/go/internal/ids"
	"github.com/get-sybers/byakugan/go/internal/ir"
	"github.com/get-sybers/byakugan/go/internal/pyjson"
	"github.com/get-sybers/byakugan/go/internal/record"
)

// The native keys and scope vocabulary (byakugan/spindle.py).
const (
	NativeKey   = "spindle_key"
	NativeScope = "spindle_scope"
	NativeRef   = "spindle_ref"
	Intrinsic   = "intrinsic"
	Positional  = "positional"
)

type identityField struct {
	name   string
	source string
	mode   string // "" = default str rendering
}

type entry struct {
	object   string
	version  int
	identity []identityField
}

type registry struct {
	identities map[string]*entry
	posFields  []string
	posVersion int
}

var (
	regOnce sync.Once
	regErr  error
	reg     *registry
)

func load() (*registry, error) {
	regOnce.Do(func() {
		doc, err := ir.Load()
		if err != nil {
			regErr = err
			return
		}
		r := &registry{identities: map[string]*entry{}}
		pf, ok := ir.Get(doc, "spindle", "positional", "fields").([]pyjson.Value)
		if !ok {
			regErr = fmt.Errorf("spindle: IR positional fields missing")
			return
		}
		for _, f := range pf {
			s, ok := f.(string)
			if !ok {
				regErr = fmt.Errorf("spindle: positional field is not a string")
				return
			}
			r.posFields = append(r.posFields, s)
		}
		pv, ok := ir.Get(doc, "spindle", "positional", "version").(*big.Int)
		if !ok {
			regErr = fmt.Errorf("spindle: IR positional version missing")
			return
		}
		r.posVersion = int(pv.Int64())
		idents, ok := ir.Get(doc, "spindle", "identities").(*pyjson.Object)
		if !ok {
			regErr = fmt.Errorf("spindle: IR identities missing")
			return
		}
		for _, name := range idents.Keys() {
			ev, _ := idents.Get(name)
			eo, ok := ev.(*pyjson.Object)
			if !ok {
				regErr = fmt.Errorf("spindle: identity %q is not an object", name)
				return
			}
			e := &entry{}
			if s, ok := ir.Get(eo, "object").(string); ok {
				e.object = s
			}
			if n, ok := ir.Get(eo, "version").(*big.Int); ok {
				e.version = int(n.Int64())
			} else {
				regErr = fmt.Errorf("spindle: identity %q has no version", name)
				return
			}
			fl, ok := ir.Get(eo, "identity").([]pyjson.Value)
			if !ok {
				regErr = fmt.Errorf("spindle: identity %q has no field list", name)
				return
			}
			for _, triple := range fl {
				t, ok := triple.([]pyjson.Value)
				if !ok || len(t) != 3 {
					regErr = fmt.Errorf("spindle: identity %q malformed triple", name)
					return
				}
				f := identityField{}
				f.name, _ = t[0].(string)
				f.source, _ = t[1].(string)
				if m, ok := t[2].(string); ok {
					f.mode = m
				}
				e.identity = append(e.identity, f)
			}
			r.identities[name] = e
		}
		reg = r
	})
	return reg, regErr
}

// lookup is normalize._lookup — a value off the normalized event by path:
// native.<key> reads _native, anything else is a top-level event key.
func lookup(event *pyjson.Object, path string) pyjson.Value {
	if strings.HasPrefix(path, "native.") {
		nv, _ := event.Get("_native")
		if no, ok := nv.(*pyjson.Object); ok {
			v, _ := no.Get(path[len("native."):])
			return v
		}
		return nil
	}
	v, _ := event.Get(path)
	return v
}

// Resolve is normalize._spindle: (guid, native extras) for a map leaf's
// {"spindle": name} guid spec. guid is nil (with empty natives) when neither
// the intrinsic identity nor the positional fallback is complete.
func Resolve(name, obj string, rec *record.Record, event *pyjson.Object) (pyjson.Value, *pyjson.Object, error) {
	r, err := load()
	if err != nil {
		return nil, nil, err
	}
	e, ok := r.identities[name]
	if !ok {
		return nil, nil, fmt.Errorf("no spindle identity %q in the registry", name)
	}
	if e.object != obj {
		return nil, nil, fmt.Errorf("spindle identity %q is declared for %q, not %q",
			name, e.object, obj)
	}
	ref := pyjson.NewObject()
	for _, f := range r.posFields {
		ref.Set(f, rec.Get(f))
	}
	fields := make([]ids.Field, 0, len(e.identity))
	modes := map[string]string{}
	complete := true
	for _, idf := range e.identity {
		v := lookup(event, idf.source)
		if record.Blank(v) {
			complete = false
			break
		}
		fields = append(fields, ids.Field{Name: idf.name, Value: v})
		if idf.mode != "" {
			modes[idf.name] = idf.mode
		}
	}
	if complete && len(fields) > 0 { // Python: `if identity:`
		guid, key, err := ids.Mint(obj, fields, e.version, modes)
		if err != nil {
			return nil, nil, err
		}
		return guid, natives(key, Intrinsic, ref), nil
	}
	positional := make([]ids.Field, 0, len(r.posFields))
	for _, f := range r.posFields {
		v := rec.Get(f)
		if record.Blank(v) {
			return nil, pyjson.NewObject(), nil // genuinely absent
		}
		positional = append(positional, ids.Field{Name: f, Value: v})
	}
	if len(positional) == 0 {
		return nil, pyjson.NewObject(), nil
	}
	guid, key, err := ids.Mint(obj, positional, r.posVersion, nil)
	if err != nil {
		return nil, nil, err
	}
	return guid, natives(key, Positional, ref), nil
}

func natives(key *pyjson.Object, scope string, ref *pyjson.Object) *pyjson.Object {
	n := pyjson.NewObject()
	n.Set(NativeKey, key)
	n.Set(NativeScope, scope)
	n.Set(NativeRef, ref)
	return n
}
