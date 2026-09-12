// Python value semantics shared by the resolver, predicates and readers:
// str() (PyStr), truthiness (Truthy), str.strip() whitespace (Strip), and
// int()/float() conversions — each ported from the CPython behavior the
// live engine exercises (parity vectors pin them).
package record

import (
	"math"
	"math/big"
	"strconv"
	"strings"

	"github.com/get-sybers/byakugan/go/internal/pyjson"
)

// PyStr is Python str(v) over pyjson values. Scalars render exactly
// (pyjson.Str); containers render via a Python-repr emulation — the live
// maps only ever str() scalars, so the container path is a safety net whose
// exotic corners (unprintable non-ASCII escapes) are approximated.
func PyStr(v pyjson.Value) string {
	if s, err := pyjson.Str(v); err == nil {
		return s
	}
	return pyRepr(v)
}

func pyRepr(v pyjson.Value) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case string:
		return strRepr(x)
	case []pyjson.Value:
		var b strings.Builder
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(pyRepr(e))
		}
		b.WriteByte(']')
		return b.String()
	case *pyjson.Object:
		var b strings.Builder
		b.WriteByte('{')
		for i, k := range x.Keys() {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(strRepr(k))
			b.WriteString(": ")
			e, _ := x.Get(k)
			b.WriteString(pyRepr(e))
		}
		b.WriteByte('}')
		return b.String()
	default: // scalar: exact
		s, _ := pyjson.Str(v)
		return s
	}
}

// strRepr is Python repr(str): single quotes unless the string contains a
// single quote and no double quote; \\, the quote, \n, \r, \t and other
// C0/DEL escaped.
func strRepr(s string) string {
	quote := byte('\'')
	if strings.ContainsRune(s, '\'') && !strings.ContainsRune(s, '"') {
		quote = '"'
	}
	var b strings.Builder
	b.WriteByte(quote)
	for _, r := range s {
		switch {
		case r == rune(quote) || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			const hex = "0123456789abcdef"
			b.WriteString(`\x`)
			b.WriteByte(hex[r>>4])
			b.WriteByte(hex[r&0xf])
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte(quote)
	return b.String()
}

// Truthy is Python bool(v): None/False/0/0.0/""/[]/{} are false; NaN is true.
func Truthy(v pyjson.Value) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case *big.Int:
		return x.Sign() != 0
	case float64:
		return x != 0 // NaN != 0 → true, like Python
	case []pyjson.Value:
		return len(x) > 0
	case *pyjson.Object:
		return x.Len() > 0
	default:
		return true
	}
}

// isPySpace reports whether r is whitespace for Python str.strip()/isspace().
func isPySpace(r rune) bool {
	switch r {
	case 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
		0x85, 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000:
		return true
	}
	return r >= 0x2000 && r <= 0x200A
}

// Strip is Python str.strip() — Unicode whitespace, both ends.
func Strip(s string) string {
	return strings.TrimFunc(s, isPySpace)
}

// StripLeft / StripRight are lstrip()/rstrip() with no argument.
func StripLeft(s string) string  { return strings.TrimLeftFunc(s, isPySpace) }
func StripRight(s string) string { return strings.TrimRightFunc(s, isPySpace) }

// PyFloat is Python float(v): bool/int/float convert; strings parse with
// whitespace stripped, inf/infinity/nan accepted, underscores between digits,
// hex floats rejected (Python float() has none). ok=false is the
// TypeError/ValueError path.
func PyFloat(v pyjson.Value) (float64, bool) {
	switch x := v.(type) {
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	case *big.Int:
		f, _ := new(big.Float).SetInt(x).Float64()
		return f, true
	case float64:
		return x, true
	case string:
		return pyFloatParse(x)
	default:
		return 0, false
	}
}

func pyFloatParse(s string) (float64, bool) {
	t := Strip(s)
	if t == "" {
		return 0, false
	}
	body := strings.TrimLeft(t, "+-")
	if len(t)-len(body) > 1 { // at most one sign
		return 0, false
	}
	low := strings.ToLower(body)
	if strings.HasPrefix(low, "0x") || strings.HasPrefix(low, "0b") ||
		strings.HasPrefix(low, "0o") || strings.ContainsAny(low, "pxg") {
		return 0, false // Go hex-float syntax Python float() rejects
	}
	if low == "inf" || low == "infinity" || low == "nan" {
		f := math.Inf(1)
		if low == "nan" {
			f = math.NaN()
		}
		if strings.HasPrefix(t, "-") {
			f = -f
		}
		return f, true
	}
	clean, ok := stripUnderscores(t)
	if !ok {
		return 0, false
	}
	var f float64
	var err error
	f, err = parseFloatStrict(clean)
	if err != nil {
		return 0, false
	}
	return f, true
}

// parseFloatStrict is strconv.ParseFloat with Python's overflow behavior:
// a syntactically valid but out-of-range literal is ±inf, not an error.
func parseFloatStrict(s string) (float64, error) {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		if ne, ok := err.(*strconv.NumError); ok && ne.Err == strconv.ErrRange {
			return f, nil
		}
		return 0, err
	}
	return f, nil
}

// PyInt is Python int(v) for the hex_int marker's first attempt: bool/int
// pass, float truncates toward zero, strings parse base 10.
func PyInt(v pyjson.Value) (*big.Int, bool) {
	switch x := v.(type) {
	case bool:
		if x {
			return big.NewInt(1), true
		}
		return big.NewInt(0), true
	case *big.Int:
		return x, true
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return nil, false
		}
		bi, _ := big.NewFloat(math.Trunc(x)).Int(nil)
		return bi, true
	case string:
		return PyIntParse(x, 10)
	default:
		return nil, false
	}
}

// PyIntParse is Python int(s, base) for bases 10 and 16: whitespace
// stripped, one optional sign, an optional 0x/0X prefix for base 16, digits
// with single underscores between them (or right after the prefix).
func PyIntParse(s string, base int) (*big.Int, bool) {
	t := Strip(s)
	neg := false
	if strings.HasPrefix(t, "+") || strings.HasPrefix(t, "-") {
		neg = t[0] == '-'
		t = t[1:]
	}
	if base == 16 && (strings.HasPrefix(t, "0x") || strings.HasPrefix(t, "0X")) {
		t = t[2:]
		t = strings.TrimPrefix(t, "_") // int("0x_10", 16) is legal
	}
	clean, ok := stripUnderscores(t)
	if !ok || clean == "" {
		return nil, false
	}
	for _, c := range clean {
		if !isBaseDigit(byte(c), base) {
			return nil, false
		}
	}
	n, ok2 := new(big.Int).SetString(clean, base)
	if !ok2 {
		return nil, false
	}
	if neg {
		n.Neg(n)
	}
	return n, true
}

func isBaseDigit(c byte, base int) bool {
	switch {
	case c >= '0' && c <= '9':
		return true
	case base == 16 && ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')):
		return true
	}
	return false
}

// stripUnderscores validates Python numeric-literal underscore placement
// (between digits only, never doubled/leading/trailing) and removes them.
func stripUnderscores(s string) (string, bool) {
	if !strings.ContainsRune(s, '_') {
		return s, true
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '_' {
			b.WriteByte(s[i])
			continue
		}
		if i == 0 || i == len(s)-1 || !isAlnum(s[i-1]) || !isAlnum(s[i+1]) {
			return "", false
		}
	}
	return b.String(), true
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}
