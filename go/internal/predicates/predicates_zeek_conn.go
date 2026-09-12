// The byakugan/mappings/zeek_conn.py predicate — zeek_conn_has_state — and
// its record-MUTATING derivation seam (_derive): before the map resolves it
// stamps _zc_end_time (ts + duration as the datetime.isoformat() rendering
// with '+00:00' folded to 'Z') and _zc_packet_count (int(orig_pkts +
// resp_pkts), only when a NUMERIC counter exists), exactly like the Python.
package predicates

import (
	"fmt"
	"math"
	"math/big"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/get-sybers/byakugan/go/internal/markers"
	"github.com/get-sybers/byakugan/go/internal/pyjson"
	"github.com/get-sybers/byakugan/go/internal/record"
)

func init() {
	Register("zeek_conn_has_state", func(r *record.Record) bool {
		zcDerive(r)
		return record.Truthy(r.Get("conn_state")) // bool(rec.get("conn_state"))
	})
}

// zcDerive is zeek_conn._derive.
func zcDerive(r *record.Record) {
	if !r.Has("_zc_end_time") {
		start, ok := zcParseTs(r.Get("ts"))
		if ok {
			if durSec, durUs, numeric := durationParts(r.Get("duration")); numeric {
				end := start.add(durSec, durUs)
				// end.isoformat().replace("+00:00", "Z")
				r.Set("_zc_end_time", strings.ReplaceAll(end.isoformat(), "+00:00", "Z"))
			}
		}
	}
	if !r.Has("_zc_packet_count") {
		counters := make([]pyjson.Value, 0, 2)
		for _, v := range []pyjson.Value{r.Get("orig_pkts"), r.Get("resp_pkts")} {
			if isPyNumber(v) { // isinstance(c, (int, float)) — bool included
				counters = append(counters, v)
			}
		}
		if len(counters) > 0 {
			r.Set("_zc_packet_count", intSum(counters))
		}
	}
}

// isPyNumber is isinstance(v, (int, float)) — Python bools are ints.
func isPyNumber(v pyjson.Value) bool {
	switch v.(type) {
	case *big.Int, float64, bool:
		return true
	}
	return false
}

// durationParts is `isinstance(dur, (int, float))` + timedelta(seconds=dur)'s
// split into whole seconds and HALF-EVEN-rounded microseconds.
func durationParts(v pyjson.Value) (sec int64, us int, numeric bool) {
	switch x := v.(type) {
	case bool:
		if x {
			return 1, 0, true
		}
		return 0, 0, true
	case *big.Int:
		if !x.IsInt64() {
			return 0, 0, false // beyond any real duration; avoid overflow
		}
		return x.Int64(), 0, true
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) || math.Abs(x) > 1e15 {
			return 0, 0, false
		}
		whole, frac := math.Modf(x)            // Go Modf: (int, frac) — reversed vs Python
		u := int(math.RoundToEven(frac * 1e6)) // CPython round() is half-even
		return int64(whole), u, true
	}
	return 0, 0, false
}

// intSum is `int(sum(counters))` — an int sum stays exact; any float makes
// the sum float and int() truncates toward zero.
func intSum(counters []pyjson.Value) *big.Int {
	anyFloat := false
	for _, c := range counters {
		if _, ok := c.(float64); ok {
			anyFloat = true
		}
	}
	if anyFloat {
		f := 0.0
		for _, c := range counters {
			g, _ := record.PyFloat(c)
			f += g
		}
		bi, _ := big.NewFloat(math.Trunc(f)).Int(nil)
		return bi
	}
	sum := big.NewInt(0)
	for _, c := range counters {
		switch x := c.(type) {
		case *big.Int:
			sum.Add(sum, x)
		case bool:
			if x {
				sum.Add(sum, big.NewInt(1))
			}
		}
	}
	return sum
}

// --- the zeek lane's own _parse_ts + datetime arithmetic ---------------------

// zcTime is a Python datetime: civil fields (as epoch seconds of those
// fields read as UTC) + µs + optional utcoffset. Arithmetic is on the civil
// fields; the offset only renders.
type zcTime struct {
	sec    int64 // civil fields as UTC epoch seconds
	us     int
	hasTZ  bool
	offSec int // utcoffset in seconds (0 for the fromtimestamp/utc path)
}

func (t zcTime) add(sec int64, us int) zcTime {
	nus := t.us + us
	t.sec += sec + int64(floorDiv(nus, 1000000))
	t.us = mod(nus, 1000000)
	return t
}

func floorDiv(a, b int) int {
	q := a / b
	if a%b != 0 && (a < 0) != (b < 0) {
		q--
	}
	return q
}

func mod(a, b int) int {
	m := a % b
	if m != 0 && (m < 0) != (b < 0) {
		m += b
	}
	return m
}

// isoformat is datetime.isoformat(): fields, optional 6-digit fraction,
// offset suffix only for an aware datetime (±HH:MM, :SS when needed).
func (t zcTime) isoformat() string {
	g := time.Unix(t.sec, 0).UTC()
	s := fmt.Sprintf("%04d-%02d-%02dT%02d:%02d:%02d",
		g.Year(), int(g.Month()), g.Day(), g.Hour(), g.Minute(), g.Second())
	if t.us != 0 {
		s += fmt.Sprintf(".%06d", t.us)
	}
	if t.hasTZ {
		off := t.offSec
		sign := "+"
		if off < 0 {
			sign = "-"
			off = -off
		}
		s += fmt.Sprintf("%s%02d:%02d", sign, off/3600, (off%3600)/60)
		if off%60 != 0 {
			s += fmt.Sprintf(":%02d", off%60)
		}
	}
	return s
}

// zcParseTs is zeek_conn._parse_ts: epoch float first (fromtimestamp, utc),
// else fromisoformat(str(v).replace('Z', '+00:00')) — the Python 3.10
// grammar; ok=false is its `return None`.
func zcParseTs(v pyjson.Value) (zcTime, bool) {
	if v == nil || v == "" { // `if v is None or v == ""`
		return zcTime{}, false
	}
	if f, ok := record.PyFloat(v); ok {
		if sec, us, ok2 := markers.FromTimestamp(f); ok2 {
			return zcTime{sec: sec, us: us, hasTZ: true, offSec: 0}, true
		}
		// fromtimestamp raised → fall through to the isoformat path
	}
	return parseIso(strings.ReplaceAll(record.PyStr(v), "Z", "+00:00"))
}

// parseIso is datetime.fromisoformat as the live runtime (Python 3.11+)
// implements it, for the shapes reaching the zeek lane: YYYY-MM-DD or
// YYYYMMDD; optional (any single char) separator + HH[[:]MM[[:]SS]] with an
// optional '.'/',' fraction of ANY width (first 6 digits used, the rest
// dropped); optional 'Z' or ±HH[[:]MM[[:]SS]] offset. 3.11's ISO week and
// ordinal dates are not ported (never in the data) → false, not a mis-parse.
func parseIso(s string) (zcTime, bool) {
	var y, mo, d int
	var rest string
	switch {
	case len(s) >= 10 && s[4] == '-' && s[7] == '-' &&
		digits(s[0:4]) && digits(s[5:7]) && digits(s[8:10]):
		y, mo, d = num(s[0:4]), num(s[5:7]), num(s[8:10])
		rest = s[10:]
	case len(s) >= 8 && digits(s[0:8]):
		y, mo, d = num(s[0:4]), num(s[4:6]), num(s[6:8])
		rest = s[8:]
	default:
		return zcTime{}, false
	}
	hh, mm, ss, us := 0, 0, 0, 0
	hasTZ, offSec := false, 0
	if rest != "" {
		_, sepLen := utf8.DecodeRuneInString(rest) // any single separator char
		tstr := rest[sepLen:]
		if tstr == "" {
			return zcTime{}, false
		}
		// tzinfo starts at 'Z', '+' or '-'
		tzPos := strings.IndexAny(tstr, "Z+-")
		timestr := tstr
		var tzstr string
		if tzPos >= 0 {
			timestr, tzstr = tstr[:tzPos], tstr[tzPos:]
		}
		var ok bool
		hh, mm, ss, us, ok = parseTimePart(timestr, true)
		if !ok {
			return zcTime{}, false
		}
		if tzstr != "" {
			if tzstr == "Z" {
				hasTZ = true
			} else {
				th, tm, ts2, _, ok := parseTimePart(tzstr[1:], false)
				if !ok {
					return zcTime{}, false
				}
				offSec = th*3600 + tm*60 + ts2
				if tzstr[0] == '-' {
					offSec = -offSec
				}
				if offSec <= -24*3600 || offSec >= 24*3600 {
					return zcTime{}, false // timezone() raises outside ±24h
				}
				hasTZ = true
			}
		}
	}
	if y < 1 || y > 9999 || mo < 1 || mo > 12 || d < 1 || hh > 23 || mm > 59 || ss > 59 {
		return zcTime{}, false
	}
	t := time.Date(y, time.Month(mo), d, hh, mm, ss, 0, time.UTC)
	if t.Day() != d || int(t.Month()) != mo { // day out of range for month
		return zcTime{}, false
	}
	return zcTime{sec: t.Unix(), us: us, hasTZ: hasTZ, offSec: offSec}, true
}

// parseTimePart parses HH[[:]MM[[:]SS]] (+ optional fraction when allowFrac)
// with 3.11's tolerance for both ':'-separated and compact forms; the whole
// string must be consumed.
func parseTimePart(t string, allowFrac bool) (hh, mm, ss, us int, ok bool) {
	comps := [3]int{}
	pos := 0
	for comp := 0; comp < 3; comp++ {
		if len(t)-pos < 2 || !digits(t[pos:pos+2]) {
			return 0, 0, 0, 0, false
		}
		comps[comp] = num(t[pos : pos+2])
		pos += 2
		if pos >= len(t) {
			break
		}
		if t[pos] == ':' {
			pos++
			continue
		}
		if t[pos] >= '0' && t[pos] <= '9' { // compact HHMMSS
			continue
		}
		break // fraction (or garbage — caught below)
	}
	if pos < len(t) {
		if !allowFrac || (t[pos] != '.' && t[pos] != ',') {
			return 0, 0, 0, 0, false
		}
		pos++
		fs := t[pos:]
		if !digits(fs) && fs != "" {
			return 0, 0, 0, 0, false
		}
		if len(fs) > 6 {
			fs = fs[:6] // extra digits dropped, never rounded
		}
		for len(fs) < 6 {
			fs += "0"
		}
		us = num(fs)
	}
	return comps[0], comps[1], comps[2], us, true
}

func digits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

func num(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}
