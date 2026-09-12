package pyjson

import (
	"fmt"
	"math/big"
	"strings"
)

// Dumps encodes v byte-identically to Python json.dumps(v) DEFAULTS:
// ensure_ascii=True, separators (", ", ": "), document key order.
func Dumps(v Value) (string, error) {
	var b strings.Builder
	if err := encode(&b, v, ", ", ": ", true, false); err != nil {
		return "", err
	}
	return b.String(), nil
}

// Canonical encodes v byte-identically to Python
// json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False) —
// the §2.9 canonical form every deterministic id is minted over.
func Canonical(v Value) (string, error) {
	var b strings.Builder
	if err := encode(&b, v, ",", ":", false, true); err != nil {
		return "", err
	}
	return b.String(), nil
}

func encode(b *strings.Builder, v Value, item, kv string, ascii, sortKeys bool) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		encodeString(b, x, ascii)
	case *big.Int:
		b.WriteString(x.Text(10))
	case float64:
		b.WriteString(pyFloatJSON(x))
	case int: // convenience for hand-built values
		fmt.Fprintf(b, "%d", x)
	case []Value:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteString(item)
			}
			if err := encode(b, e, item, kv, ascii, sortKeys); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case *Object:
		b.WriteByte('{')
		keys := x.keys
		if sortKeys {
			keys = x.sortedKeys()
		}
		for i, k := range keys {
			if i > 0 {
				b.WriteString(item)
			}
			encodeString(b, k, ascii)
			b.WriteString(kv)
			val, _ := x.Get(k)
			if err := encode(b, val, item, kv, ascii, sortKeys); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("pyjson: unencodable type %T", v)
	}
	return nil
}

const hexDigits = "0123456789abcdef"

func writeU16(b *strings.Builder, r rune) {
	b.WriteString("\\u")
	b.WriteByte(hexDigits[(r>>12)&0xF])
	b.WriteByte(hexDigits[(r>>8)&0xF])
	b.WriteByte(hexDigits[(r>>4)&0xF])
	b.WriteByte(hexDigits[r&0xF])
}

// encodeString writes a JSON string exactly as Python's encoder does.
// ascii=true is py_encode_basestring_ascii: everything outside 0x20..0x7e
// (plus " and \) escaped, astral code points as surrogate pairs; ascii=false
// is py_encode_basestring: only ", \ and C0 controls escaped.
func encodeString(b *strings.Builder, s string, ascii bool) {
	b.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := nextRune(s, i)
		i += size
		switch r {
		case '"':
			b.WriteString(`\"`)
			continue
		case '\\':
			b.WriteString(`\\`)
			continue
		case '\b':
			b.WriteString(`\b`)
			continue
		case '\f':
			b.WriteString(`\f`)
			continue
		case '\n':
			b.WriteString(`\n`)
			continue
		case '\r':
			b.WriteString(`\r`)
			continue
		case '\t':
			b.WriteString(`\t`)
			continue
		}
		if r < 0x20 {
			writeU16(b, r)
			continue
		}
		if !ascii || r < 0x7f {
			// ensure_ascii=False leaves everything above C0 literal;
			// ensure_ascii=True keeps printable ASCII 0x20..0x7e literal
			if !ascii || r <= 0x7e {
				appendCodePoint(b, r)
				continue
			}
		}
		// ensure_ascii escapes: BMP as \uxxxx, astral as a surrogate pair
		if r > 0xFFFF {
			r -= 0x10000
			writeU16(b, 0xD800+(r>>10))
			writeU16(b, 0xDC00+(r&0x3FF))
		} else {
			writeU16(b, r)
		}
	}
	b.WriteByte('"')
}
