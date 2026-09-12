// Package record is the input-record type the parse engine resolves markers
// against — an ordered pyjson object plus the EvtxECmd Payload access paths
// (byakugan/normalize.py _parsed_payload, byakugan/mappings/_common.py
// evtx_payload_field) and the Python value semantics (blank rule, str(),
// truthiness, strip) the resolver depends on.
package record

import (
	"github.com/get-sybers/byakugan/go/internal/pyjson"
)

// Record wraps one raw input record. The payload parse cache mirrors
// normalize._parsed_payload's per-(record, field) cache — parsed once, valid
// until the field is replaced (Set invalidates).
type Record struct {
	obj     *pyjson.Object
	payload map[string]payloadParse
}

type payloadParse struct {
	names    *pyjson.Object // EventData.Data indexed by @Name (values pre-stripped)
	hasNames bool
	data     pyjson.Value // the parsed object for the other shapes
}

// New wraps a decoded JSON object as a record.
func New(obj *pyjson.Object) *Record {
	return &Record{obj: obj, payload: map[string]payloadParse{}}
}

// Object returns the underlying ordered object.
func (r *Record) Object() *pyjson.Object { return r.obj }

// Get is rec.get(key) — nil when absent.
func (r *Record) Get(key string) pyjson.Value {
	v, _ := r.obj.Get(key)
	return v
}

// Has is `key in rec`.
func (r *Record) Has(key string) bool {
	_, ok := r.obj.Get(key)
	return ok
}

// Set is rec[key] = v (the zeek_conn predicate's _zc_ stamps). A replaced
// field invalidates its payload parse (the Python cache keys on `is raw`).
func (r *Record) Set(key string, v pyjson.Value) {
	r.obj.Set(key, v)
	delete(r.payload, key)
}

// Blank is normalize._blank: nil, "" and "-" are all blank.
func Blank(v pyjson.Value) bool {
	if v == nil {
		return true
	}
	s, ok := v.(string)
	return ok && (s == "" || s == "-")
}

// ParsedPayload is normalize._parsed_payload — parse-and-index a payload blob
// ONCE per (record, field). names indexes an EventData.Data list by @Name
// (values pre-stripped, blank→nil); data is the parsed object for the other
// shapes. hasNames distinguishes an (even empty) index from no index at all.
func (r *Record) ParsedPayload(field string) (names *pyjson.Object, hasNames bool, data pyjson.Value) {
	if hit, ok := r.payload[field]; ok {
		return hit.names, hit.hasNames, hit.data
	}
	names, hasNames, data = parsePayload(r.Get(field))
	r.payload[field] = payloadParse{names: names, hasNames: hasNames, data: data}
	return names, hasNames, data
}

// parsePayload mirrors the try/except body of _parsed_payload: ANY failure
// (bad JSON, a non-dict where a dict is indexed, a non-string raw) yields
// (nil, false, nil) — Python's `names, data = None, None`.
func parsePayload(raw pyjson.Value) (*pyjson.Object, bool, pyjson.Value) {
	if Blank(raw) {
		return nil, false, nil
	}
	var data pyjson.Value
	switch x := raw.(type) {
	case *pyjson.Object:
		data = x
	case string:
		v, err := pyjson.DecodeString(x)
		if err != nil { // json.JSONDecodeError → (None, None)
			return nil, false, nil
		}
		data = v
	default: // json.loads(non-str) → TypeError → (None, None)
		return nil, false, nil
	}
	var datas pyjson.Value
	if o, ok := data.(*pyjson.Object); ok {
		ed, _ := o.Get("EventData")
		if Truthy(ed) { // `(data.get("EventData") or {})`
			edo, ok := ed.(*pyjson.Object)
			if !ok { // truthy non-dict: .get → AttributeError → (None, None)
				return nil, false, nil
			}
			datas, _ = edo.Get("Data")
		}
	}
	if lst, ok := datas.([]pyjson.Value); ok {
		names := pyjson.NewObject()
		for _, d := range lst {
			do, ok := d.(*pyjson.Object)
			if !ok {
				continue
			}
			nm, ok := do.Get("@Name")
			if !ok {
				continue
			}
			key, ok := nm.(string)
			if !ok {
				// Python stores the value under a non-string key; every
				// engine lookup is by string, so it can never be read back.
				continue
			}
			v, _ := do.Get("#text")
			if s, ok := v.(string); ok {
				v = Strip(s) // MS pads values ('Advapi  ')
			}
			if Blank(v) {
				v = nil
			}
			names.Set(key, v)
		}
		return names, true, data
	}
	return nil, false, data
}

// EvtxPayloadField is mappings._common.evtx_payload_field — the UNSTRIPPED
// gating view: str(d.get('#text') or ”) for the FIRST EventData.Data entry
// whose @Name equals name; "" on any failure. Predicates gate on it; the
// map itself resolves values via the payload() marker (stripped view).
func (r *Record) EvtxPayloadField(name string) string {
	raw := r.Get("Payload")
	if !Truthy(raw) { // `if not raw`
		return ""
	}
	var data pyjson.Value
	switch x := raw.(type) {
	case *pyjson.Object:
		data = x
	case string:
		v, err := pyjson.DecodeString(x)
		if err != nil {
			return ""
		}
		data = v
	default:
		return ""
	}
	o, ok := data.(*pyjson.Object)
	if !ok { // data.get → AttributeError → ""
		return ""
	}
	var datas pyjson.Value
	ed, _ := o.Get("EventData")
	if Truthy(ed) {
		edo, ok := ed.(*pyjson.Object)
		if !ok {
			return ""
		}
		datas, _ = edo.Get("Data")
	}
	lst, ok := datas.([]pyjson.Value) // `... or []`: falsy → no iterations
	if !ok {
		return ""
	}
	for _, d := range lst {
		do, ok := d.(*pyjson.Object)
		if !ok {
			continue
		}
		nm, _ := do.Get("@Name")
		if s, ok := nm.(string); ok && s == name {
			v, _ := do.Get("#text")
			if !Truthy(v) { // `or ''`
				return ""
			}
			return PyStr(v)
		}
	}
	return ""
}
