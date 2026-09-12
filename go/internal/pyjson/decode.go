package pyjson

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// Decode parses one JSON document exactly the way Python json.loads does:
// NaN / Infinity / -Infinity accepted, int-vs-float decided by the token
// shape (no '.', 'e' or 'E' → unbounded int), dict order preserved, strict
// about raw control characters in strings, and no bytes allowed after the
// document (only whitespace).
func Decode(data []byte) (Value, error) {
	d := &decoder{s: string(data)}
	d.ws()
	v, err := d.value()
	if err != nil {
		return nil, err
	}
	d.ws()
	if d.i != len(d.s) {
		return nil, fmt.Errorf("pyjson: extra data at offset %d", d.i)
	}
	return v, nil
}

// DecodeString is Decode over a string.
func DecodeString(s string) (Value, error) { return Decode([]byte(s)) }

type decoder struct {
	s string
	i int
}

func (d *decoder) ws() {
	for d.i < len(d.s) {
		switch d.s[d.i] {
		case ' ', '\t', '\n', '\r':
			d.i++
		default:
			return
		}
	}
}

func (d *decoder) lit(lit string) bool {
	if strings.HasPrefix(d.s[d.i:], lit) {
		d.i += len(lit)
		return true
	}
	return false
}

func (d *decoder) value() (Value, error) {
	if d.i >= len(d.s) {
		return nil, fmt.Errorf("pyjson: unexpected end of input")
	}
	switch c := d.s[d.i]; {
	case c == '{':
		return d.object()
	case c == '[':
		return d.array()
	case c == '"':
		return d.string_()
	case c == 't':
		if d.lit("true") {
			return true, nil
		}
	case c == 'f':
		if d.lit("false") {
			return false, nil
		}
	case c == 'n':
		if d.lit("null") {
			return nil, nil
		}
	case c == 'N':
		if d.lit("NaN") {
			return nan, nil
		}
	case c == 'I':
		if d.lit("Infinity") {
			return posInf, nil
		}
	case c == '-' || (c >= '0' && c <= '9'):
		return d.number()
	}
	return nil, fmt.Errorf("pyjson: invalid token at offset %d", d.i)
}

func (d *decoder) number() (Value, error) {
	if d.lit("-Infinity") {
		return negInf, nil
	}
	start := d.i
	if d.i < len(d.s) && d.s[d.i] == '-' {
		d.i++
	}
	// int part: 0 | [1-9][0-9]*
	if d.i >= len(d.s) || d.s[d.i] < '0' || d.s[d.i] > '9' {
		return nil, fmt.Errorf("pyjson: invalid number at offset %d", start)
	}
	if d.s[d.i] == '0' {
		d.i++
	} else {
		for d.i < len(d.s) && d.s[d.i] >= '0' && d.s[d.i] <= '9' {
			d.i++
		}
	}
	isFloat := false
	if d.i < len(d.s) && d.s[d.i] == '.' {
		isFloat = true
		d.i++
		n := 0
		for d.i < len(d.s) && d.s[d.i] >= '0' && d.s[d.i] <= '9' {
			d.i++
			n++
		}
		if n == 0 {
			return nil, fmt.Errorf("pyjson: invalid number at offset %d", start)
		}
	}
	if d.i < len(d.s) && (d.s[d.i] == 'e' || d.s[d.i] == 'E') {
		isFloat = true
		d.i++
		if d.i < len(d.s) && (d.s[d.i] == '+' || d.s[d.i] == '-') {
			d.i++
		}
		n := 0
		for d.i < len(d.s) && d.s[d.i] >= '0' && d.s[d.i] <= '9' {
			d.i++
			n++
		}
		if n == 0 {
			return nil, fmt.Errorf("pyjson: invalid number at offset %d", start)
		}
	}
	tok := d.s[start:d.i]
	if isFloat {
		f, err := strconv.ParseFloat(tok, 64)
		if err != nil {
			return nil, fmt.Errorf("pyjson: bad float %q: %w", tok, err)
		}
		return f, nil
	}
	n := new(big.Int)
	if _, ok := n.SetString(tok, 10); !ok {
		return nil, fmt.Errorf("pyjson: bad int %q", tok)
	}
	return n, nil
}

func (d *decoder) string_() (string, error) {
	d.i++ // opening quote
	var b strings.Builder
	for {
		if d.i >= len(d.s) {
			return "", fmt.Errorf("pyjson: unterminated string")
		}
		c := d.s[d.i]
		switch {
		case c == '"':
			d.i++
			return b.String(), nil
		case c == '\\':
			d.i++
			if d.i >= len(d.s) {
				return "", fmt.Errorf("pyjson: unterminated escape")
			}
			switch e := d.s[d.i]; e {
			case '"', '\\', '/':
				b.WriteByte(e)
				d.i++
			case 'b':
				b.WriteByte('\b')
				d.i++
			case 'f':
				b.WriteByte('\f')
				d.i++
			case 'n':
				b.WriteByte('\n')
				d.i++
			case 'r':
				b.WriteByte('\r')
				d.i++
			case 't':
				b.WriteByte('\t')
				d.i++
			case 'u':
				r, err := d.uEscape()
				if err != nil {
					return "", err
				}
				// a high surrogate followed by \uDC00-\uDFFF pairs up; a
				// lone surrogate is kept as its own code point (WTF-8),
				// exactly like Python
				if r >= 0xD800 && r <= 0xDBFF && strings.HasPrefix(d.s[d.i:], "\\u") {
					save := d.i
					d.i += 1 // step to 'u'
					lo, err := d.uEscape()
					if err == nil && lo >= 0xDC00 && lo <= 0xDFFF {
						r = 0x10000 + (r-0xD800)<<10 + (lo - 0xDC00)
					} else {
						d.i = save
					}
				}
				appendCodePoint(&b, r)
			default:
				return "", fmt.Errorf("pyjson: invalid escape \\%c at offset %d", e, d.i)
			}
		case c < 0x20:
			// Python json is strict: raw control characters are invalid
			return "", fmt.Errorf("pyjson: invalid control character at offset %d", d.i)
		default:
			// copy one code point verbatim
			_, size := nextRune(d.s, d.i)
			b.WriteString(d.s[d.i : d.i+size])
			d.i += size
		}
	}
}

// uEscape parses the XXXX of a \uXXXX escape; d.i is at 'u' on entry.
func (d *decoder) uEscape() (rune, error) {
	if d.i+5 > len(d.s) {
		return 0, fmt.Errorf("pyjson: truncated \\u escape")
	}
	hex := d.s[d.i+1 : d.i+5]
	n, err := strconv.ParseUint(hex, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("pyjson: bad \\u escape %q", hex)
	}
	d.i += 5
	return rune(n), nil
}

func (d *decoder) object() (Value, error) {
	d.i++ // '{'
	o := NewObject()
	d.ws()
	if d.i < len(d.s) && d.s[d.i] == '}' {
		d.i++
		return o, nil
	}
	for {
		d.ws()
		if d.i >= len(d.s) || d.s[d.i] != '"' {
			return nil, fmt.Errorf("pyjson: expected object key at offset %d", d.i)
		}
		k, err := d.string_()
		if err != nil {
			return nil, err
		}
		d.ws()
		if d.i >= len(d.s) || d.s[d.i] != ':' {
			return nil, fmt.Errorf("pyjson: expected ':' at offset %d", d.i)
		}
		d.i++
		d.ws()
		v, err := d.value()
		if err != nil {
			return nil, err
		}
		o.Set(k, v)
		d.ws()
		if d.i >= len(d.s) {
			return nil, fmt.Errorf("pyjson: unterminated object")
		}
		switch d.s[d.i] {
		case ',':
			d.i++
		case '}':
			d.i++
			return o, nil
		default:
			return nil, fmt.Errorf("pyjson: expected ',' or '}' at offset %d", d.i)
		}
	}
}

func (d *decoder) array() (Value, error) {
	d.i++ // '['
	arr := []Value{}
	d.ws()
	if d.i < len(d.s) && d.s[d.i] == ']' {
		d.i++
		return arr, nil
	}
	for {
		d.ws()
		v, err := d.value()
		if err != nil {
			return nil, err
		}
		arr = append(arr, v)
		d.ws()
		if d.i >= len(d.s) {
			return nil, fmt.Errorf("pyjson: unterminated array")
		}
		switch d.s[d.i] {
		case ',':
			d.i++
		case ']':
			d.i++
			return arr, nil
		default:
			return nil, fmt.Errorf("pyjson: expected ',' or ']' at offset %d", d.i)
		}
	}
}
