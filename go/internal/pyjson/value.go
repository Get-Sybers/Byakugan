// Package pyjson is the Python-faithful value model and JSON codec the parse
// engine round-trips records through (go/DESIGN.md).
//
// Byte-identical parity with CPython's json module is the contract: what
// Python json.loads distinguishes we distinguish (int vs float by token
// shape, dict order, NaN/Infinity), and Dumps/Canonical re-encode exactly the
// bytes json.dumps would emit (tests/parity/gen_pyjson_vectors.py records the
// reference behavior; pyjson_test.go replays it).
package pyjson

import (
	"fmt"
	"math/big"
	"sort"
	"strings"
)

// Value is one of:
//
//	nil        — Python None / JSON null
//	bool       — True / False
//	string     — str (WTF-8: a decoded lone surrogate keeps its code point)
//	*big.Int   — int (unbounded; a number token with no '.', 'e' or 'E')
//	float64    — float (any other number token; NaN / ±Infinity included)
//	*Object    — dict (insertion-ordered, like Python 3.7+)
//	[]Value    — list
type Value interface{}

// Object is an insertion-ordered string-keyed map — Python's dict.
type Object struct {
	keys []string
	m    map[string]Value
}

// NewObject returns an empty ordered object.
func NewObject() *Object {
	return &Object{m: map[string]Value{}}
}

// Set inserts or replaces k (a replace keeps the original position, exactly
// like assigning to an existing dict key in Python).
func (o *Object) Set(k string, v Value) {
	if _, ok := o.m[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.m[k] = v
}

// Get returns the value for k and whether it is present.
func (o *Object) Get(k string) (Value, bool) {
	v, ok := o.m[k]
	return v, ok
}

// Keys returns the keys in insertion order (the caller must not mutate).
func (o *Object) Keys() []string { return o.keys }

// Len returns the number of entries.
func (o *Object) Len() int { return len(o.keys) }

// sortedKeys returns the keys in Python sort_keys order — code-point order,
// which for our strings equals byte order of their (WT|UT)F-8 encoding.
func (o *Object) sortedKeys() []string {
	ks := make([]string, len(o.keys))
	copy(ks, o.keys)
	sort.Strings(ks)
	return ks
}

// Int builds an int Value from an int64.
func Int(i int64) Value { return big.NewInt(i) }

// Str renders a SCALAR value the way Python str() does — the fields-guid
// join and RENDER_STR rendering (containers go through Canonical instead;
// see the ids package's Render).
func Str(v Value) (string, error) {
	switch x := v.(type) {
	case nil:
		return "None", nil
	case bool:
		if x {
			return "True", nil
		}
		return "False", nil
	case string:
		return x, nil
	case *big.Int:
		return x.Text(10), nil
	case float64:
		return pyFloatStr(x), nil
	default:
		return "", fmt.Errorf("pyjson.Str: not a scalar: %T", v)
	}
}

// --- WTF-8 helpers ----------------------------------------------------------
// Python strings hold arbitrary code points, surrogates included; Go strings
// are bytes. We store any lone surrogate the decoder meets as its 3-byte
// WTF-8 sequence (0xED 0xA0..0xBF 0x80..0xBF), and the encoder walks runes
// with nextRune so those sequences come back out as one code point.

// appendCodePoint appends code point r (surrogates allowed) as (WT|UT)F-8.
func appendCodePoint(b *strings.Builder, r rune) {
	if r >= 0xD800 && r <= 0xDFFF { // lone surrogate: hand-rolled 3-byte form
		b.WriteByte(0xE0 | byte(r>>12))
		b.WriteByte(0x80 | byte((r>>6)&0x3F))
		b.WriteByte(0x80 | byte(r&0x3F))
		return
	}
	b.WriteRune(r)
}

// nextRune decodes the next code point of a WTF-8 string, recognizing the
// surrogate sequences utf8.DecodeRuneInString rejects.
func nextRune(s string, i int) (r rune, size int) {
	c := s[i]
	switch {
	case c < 0x80:
		return rune(c), 1
	case c < 0xC0: // stray continuation byte — pass through as one byte
		return rune(c), 1
	case c < 0xE0:
		if i+1 < len(s) {
			return rune(c&0x1F)<<6 | rune(s[i+1]&0x3F), 2
		}
		return rune(c), 1
	case c < 0xF0:
		if i+2 < len(s) {
			return rune(c&0x0F)<<12 | rune(s[i+1]&0x3F)<<6 | rune(s[i+2]&0x3F), 3
		}
		return rune(c), 1
	default:
		if i+3 < len(s) {
			return rune(c&0x07)<<18 | rune(s[i+1]&0x3F)<<12 |
				rune(s[i+2]&0x3F)<<6 | rune(s[i+3]&0x3F), 4
		}
		return rune(c), 1
	}
}
