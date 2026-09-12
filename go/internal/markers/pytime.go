// Timestamp semantics ported from byakugan/normalize.py (parse_ts, the
// epoch_ts marker's datetime.fromtimestamp path, _clean_ts).
package markers

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/get-sybers/byakugan/go/internal/pyjson"
	"github.com/get-sybers/byakugan/go/internal/record"
)

// datetime.MINYEAR..MAXYEAR as UTC epoch seconds — fromtimestamp raises
// (and epoch_ts falls back) outside this window.
const (
	minEpochSec = -62135596800 // 0001-01-01T00:00:00
	maxEpochSec = 253402300799 // 9999-12-31T23:59:59
)

// FromTimestamp is datetime.fromtimestamp(f, timezone.utc)'s epoch → (sec,
// µs) split: frac*1e6 rounded HALF-EVEN (CPython round()), carry applied.
// ok=false is the ValueError/OverflowError path (NaN/Inf/out-of-range year).
func FromTimestamp(f float64) (sec int64, us int, ok bool) {
	if math.IsNaN(f) || math.IsInf(f, 0) || math.Abs(f) > 1e18 {
		return 0, 0, false
	}
	whole, frac := math.Modf(f) // Go Modf: (int part, frac part) — NB reversed vs Python
	u := int(math.RoundToEven(frac * 1e6))
	t := int64(whole)
	if u >= 1000000 {
		t++
		u -= 1000000
	} else if u < 0 {
		t--
		u += 1000000
	}
	if t < minEpochSec || t > maxEpochSec {
		return 0, 0, false
	}
	return t, u, true
}

// IsoUTC renders (sec, µs) the way an aware-UTC datetime.isoformat() does:
// microseconds omitted when 0, else 6 digits; '+00:00' suffix.
func IsoUTC(sec int64, us int) string {
	return isoFields(sec, us) + "+00:00"
}

// isoFields renders the civil fields of sec (treated as UTC) + fraction.
func isoFields(sec int64, us int) string {
	t := time.Unix(sec, 0).UTC()
	s := fmt.Sprintf("%04d-%02d-%02dT%02d:%02d:%02d",
		t.Year(), int(t.Month()), t.Day(), t.Hour(), t.Minute(), t.Second())
	if us != 0 {
		s += fmt.Sprintf(".%06d", us)
	}
	return s
}

// EpochTs is the epoch_ts marker's core: numeric epoch → aware-UTC
// isoformat; a float()-unconvertible value falls back to the ISO-passthrough
// gate (s[:4].isdigit() and '-' in s); nil otherwise.
func EpochTs(v pyjson.Value) pyjson.Value {
	if record.Blank(v) {
		return nil
	}
	if f, ok := record.PyFloat(v); ok {
		if sec, us, ok2 := FromTimestamp(f); ok2 {
			return IsoUTC(sec, us)
		}
	}
	s := record.PyStr(v)
	head := s
	if len(head) > 4 {
		head = head[:4]
	}
	if head != "" && allDigits(head) && strings.Contains(s, "-") {
		return s
	}
	return nil
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// _TS_RE from normalize.py — YYYY-MM-DD, T or space, HH:MM:SS, optional
// .fraction, optional Z or ±HH[:]MM. re.match, so start-anchored; the
// pattern's own $ is moot because parse_ts strips first.
var tsRe = regexp.MustCompile(
	`^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?` +
		`(?:(Z)|([+-])(\d{2}):?(\d{2}))?(?:\n)?\z`)

// ParseTs is normalize.parse_ts — the true UTC instant of an ISO-8601-ish
// timestamp as (epoch sec, µs), ok=false when blank or unparseable.
func ParseTs(v pyjson.Value) (sec int64, us int, ok bool) {
	if !record.Truthy(v) { // `if not value`
		return 0, 0, false
	}
	m := tsRe.FindStringSubmatch(record.Strip(record.PyStr(v)))
	if m == nil {
		return 0, 0, false
	}
	y, mo, d := atoi(m[1]), atoi(m[2]), atoi(m[3])
	hh, mm, ss := atoi(m[4]), atoi(m[5]), atoi(m[6])
	frac := m[7]
	if len(frac) > 6 {
		frac = frac[:6] // ljust(6,'0')[:6] — truncate, never round
	}
	for len(frac) < 6 {
		frac += "0"
	}
	us = atoi(frac)
	if !validCivil(y, mo, d, hh, mm, ss) { // datetime() ValueError
		return 0, 0, false
	}
	sec = civilSec(y, mo, d, hh, mm, ss)
	if m[9] != "" { // ±HH[:]MM offset → normalize to UTC
		off := int64(atoi(m[10])*3600 + atoi(m[11])*60)
		if m[9] == "-" {
			off = -off
		}
		sec -= off
	}
	return sec, us, true
}

func atoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}

func validCivil(y, mo, d, hh, mm, ss int) bool {
	if y < 1 || y > 9999 || mo < 1 || mo > 12 || hh > 23 || mm > 59 || ss > 59 {
		return false
	}
	return d >= 1 && d <= daysInMonth(y, mo)
}

func daysInMonth(y, mo int) int {
	switch mo {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	}
	if y%4 == 0 && (y%100 != 0 || y%400 == 0) {
		return 29
	}
	return 28
}

// civilSec converts civil UTC fields to epoch seconds.
func civilSec(y, mo, d, hh, mm, ss int) int64 {
	return time.Date(y, time.Month(mo), d, hh, mm, ss, 0, time.UTC).Unix()
}

// CleanTs is normalize._clean_ts: blank → nil; the epoch-zero renderings
// (1601-01-01 / 1970-01-01 / 0001-01-01 / 1600-12-) → nil; else str(v).
func CleanTs(v pyjson.Value) pyjson.Value {
	if record.Blank(v) {
		return nil
	}
	s := record.PyStr(v)
	for _, p := range [...]string{"1601-01-01", "1970-01-01", "0001-01-01", "1600-12-"} {
		if strings.HasPrefix(s, p) {
			return nil
		}
	}
	return s
}
