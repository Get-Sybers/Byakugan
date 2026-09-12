package pyjson

import (
	"math"
	"strconv"
	"strings"
)

var (
	nan    = math.NaN()
	posInf = math.Inf(1)
	negInf = math.Inf(-1)
)

// pyFloatRepr renders a finite float exactly as Python repr() does — the
// shortest round-trip digits, fixed notation while -4 <= exp < 16, else
// scientific with a sign and an at-least-two-digit exponent (1e+16, 1e-05),
// and ".0" appended to an integral fixed rendering. Python json.dumps uses
// this same rendering for float tokens.
func pyFloatRepr(f float64) string {
	if f == 0 {
		if math.Signbit(f) {
			return "-0.0"
		}
		return "0.0"
	}
	// shortest digits + decimal exponent via strconv's 'e' shortest form
	s := strconv.FormatFloat(f, 'e', -1, 64) // "-d.ddddde±dd" or "de±dd"
	neg := false
	if s[0] == '-' {
		neg = true
		s = s[1:]
	}
	ePos := strings.IndexByte(s, 'e')
	mant := s[:ePos]
	exp, _ := strconv.Atoi(s[ePos+1:])
	digits := strings.Replace(mant, ".", "", 1)

	var out string
	switch {
	case exp < -4 || exp >= 16:
		// scientific: d[.ddd]e±NN with at least two exponent digits
		m := digits[:1]
		if len(digits) > 1 {
			m += "." + digits[1:]
		}
		sign := "+"
		e := exp
		if e < 0 {
			sign = "-"
			e = -e
		}
		es := strconv.Itoa(e)
		if len(es) < 2 {
			es = "0" + es
		}
		out = m + "e" + sign + es
	case exp >= 0:
		if exp+1 >= len(digits) {
			out = digits + strings.Repeat("0", exp+1-len(digits)) + ".0"
		} else {
			out = digits[:exp+1] + "." + digits[exp+1:]
		}
	default:
		out = "0." + strings.Repeat("0", -exp-1) + digits
	}
	if neg {
		return "-" + out
	}
	return out
}

// pyFloatJSON renders a float as a Python json.dumps token: repr() for a
// finite value, and Python's NaN / Infinity / -Infinity constants otherwise.
func pyFloatJSON(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	}
	return pyFloatRepr(f)
}

// pyFloatStr renders a float as Python str(): repr() for a finite value,
// nan / inf / -inf otherwise.
func pyFloatStr(f float64) string {
	switch {
	case math.IsNaN(f):
		return "nan"
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	}
	return pyFloatRepr(f)
}
