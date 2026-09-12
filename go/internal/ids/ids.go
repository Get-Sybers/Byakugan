// Package ids is the Go side of byakugan/ids.py — deterministic identity
// minting, THE one recipe every minted id derives from:
//
//	guid = uuid5(SPINDLE_NS, canonical_json({"_obj": <car_object>, "_v": <version>,
//	                                         <name>: <value>, ...}))
//
// Every constant, rendering and seam mirrors the Python module byte for byte;
// model/spindle/golden.yml (embedded in the IR) is the pinned vector table
// both engines must satisfy.
package ids

import (
	"crypto/sha1"
	"fmt"
	"math/big"

	"github.com/get-sybers/byakugan/go/internal/pyjson"
)

// CarNSURL seeds every deterministic id the engine mints.
// Deliberately still the historical PIIAT-MitreCar URL after the byakugan
// rename: this string SEEDS every deterministic id the engine mints — changing
// it would orphan every previously issued id. A seed, not a link.
const CarNSURL = "https://github.com/Get-Sybers/PIIAT-MitreCar/stix"

// SpindleLabel is the CAR row-identity namespace label under CAR_NS.
const SpindleLabel = "spindle"

// UUID is an RFC 4122 UUID as raw bytes.
type UUID [16]byte

// NamespaceURL is uuid.NAMESPACE_URL — 6ba7b811-9dad-11d1-80b4-00c04fd430c8.
var NamespaceURL = UUID{0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1,
	0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}

// CarNS = uuid5(NAMESPACE_URL, CarNSURL) — the project namespace.
var CarNS = UUID5(NamespaceURL, CarNSURL)

// SpindleNS = uuid5(CarNS, "spindle") — the CAR row-identity namespace.
var SpindleNS = UUID5(CarNS, SpindleLabel)

// The reserved keys of an identity key, and the value renderings.
const (
	ObjectKey  = "_obj"
	VersionKey = "_v"
	RenderStr  = "str"
	RenderJSON = "json"
)

// UUID5 mints a version-5 (SHA-1, RFC 4122) UUID — uuid.uuid5(ns, name).
func UUID5(ns UUID, name string) UUID {
	h := sha1.New()
	h.Write(ns[:])
	h.Write([]byte(name))
	sum := h.Sum(nil)
	var u UUID
	copy(u[:], sum[:16])
	u[6] = (u[6] & 0x0F) | 0x50 // version 5
	u[8] = (u[8] & 0x3F) | 0x80 // RFC 4122 variant
	return u
}

// String renders the UUID in its canonical lowercase-hyphenated form.
func (u UUID) String() string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// CanonicalJSON is ids.canonical_json — §2.9 canonical form (sorted keys, no
// whitespace, UTF-8) of the ID-contributing properties.
func CanonicalJSON(props pyjson.Value) (string, error) {
	return pyjson.Canonical(props)
}

// Render is ids.render — a contributing value as it enters the key:
// RenderStr: a scalar in its Python str() form, a structured value as its
// canonical JSON text; RenderJSON: type-faithful canonical JSON text.
func Render(v pyjson.Value, mode string) (string, error) {
	if mode == RenderJSON {
		return pyjson.Canonical(v)
	}
	if mode != RenderStr {
		return "", fmt.Errorf("unknown rendering %q: one of [%s %s]", mode, RenderStr, RenderJSON)
	}
	switch v.(type) {
	case []pyjson.Value, *pyjson.Object:
		return pyjson.Canonical(v)
	}
	return pyjson.Str(v)
}

// GuidOf is ids.guid_of — the guid of an identity key AS RENDERED; the
// invariant every spindle row satisfies.
func GuidOf(key *pyjson.Object) (string, error) {
	cj, err := pyjson.Canonical(key)
	if err != nil {
		return "", err
	}
	return UUID5(SpindleNS, cj).String(), nil
}

// Field is one identity component, by name, in declaration order.
type Field struct {
	Name  string
	Value pyjson.Value
}

// Mint is ids.mint — THE seam: (guid, key) for a CAR object, its raw
// identity values keyed by name, and the identity-key version. `normalize`
// maps a name to a rendering override (RenderJSON); everything else renders
// RenderStr. A nil value is a programming error here — the caller decides
// the positional fallback before minting.
func Mint(obj string, identity []Field, version int, normalize map[string]string) (string, *pyjson.Object, error) {
	key := pyjson.NewObject()
	key.Set(ObjectKey, obj)
	key.Set(VersionKey, big.NewInt(int64(version)))
	for _, f := range identity {
		if f.Name == ObjectKey || f.Name == VersionKey {
			return "", nil, fmt.Errorf("identity name %q is reserved", f.Name)
		}
		if f.Value == nil {
			return "", nil, fmt.Errorf("spindle identity %q is missing for %q", f.Name, obj)
		}
		mode := normalize[f.Name]
		if mode == "" {
			mode = RenderStr
		}
		rendered, err := Render(f.Value, mode)
		if err != nil {
			return "", nil, err
		}
		key.Set(f.Name, rendered)
	}
	guid, err := GuidOf(key)
	if err != nil {
		return "", nil, err
	}
	return guid, key, nil
}

// FieldsGuid is normalize._guid's fields form — "<obj>-" + "-".join(str(p))
// with ANY nil component voiding the whole guid ("" is a legitimate value).
func FieldsGuid(obj string, parts []pyjson.Value) (string, bool) {
	out := obj
	for _, p := range parts {
		if p == nil {
			return "", false
		}
		s, err := pyjson.Str(p)
		if err != nil {
			return "", false
		}
		out += "-" + s
	}
	return out, true
}
