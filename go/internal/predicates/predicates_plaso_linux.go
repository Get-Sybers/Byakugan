// Variant predicates of byakugan/mappings/plaso_linux.py — the Plaso
// filesystem (l2t_filestat / l2t_mft / l2t_usnjrnl) and Linux session
// (l2t_utmp / l2t_utmpx / l2t_text) families, ported clause by clause.
//
// Every gate reads the WRAPPED l2t row that adapters/l2t_split emits
// ({SourceImage, RecordId, Parser, Record, Timestamp}); the flat plaso event
// lives under "Record". The module's own reader is
//
//	def _record(rec):
//	    r = rec.get("Record")
//	    return r if isinstance(r, dict) else {}
//
// — an isinstance gate, NOT `or {}`: a truthy non-dict Record (a string, a
// list) yields {} here rather than raising, unlike mappings/plaso_exec.py.
// The three value readers on top of it:
//
//	_td(rec)         = str(_record(rec).get("timestamp_desc") or "")
//	_usn_flags(rec)  = int(_record(rec).get("update_reason_flags") or 0)
//	                   with (TypeError, ValueError) -> 0
//	_login_type(rec) = int(_record(rec).get("login_type"))     # NO `or 0`
//	                   with (TypeError, ValueError) -> None
package predicates

import (
	"math/big"
	"regexp"
	"strings"

	"github.com/get-sybers/byakugan/go/internal/pyjson"
	"github.com/get-sybers/byakugan/go/internal/record"
)

func init() {
	Register("l2t_td_create", func(r *record.Record) bool {
		return plasoLinuxTDCreate.MatchString(plasoLinuxTD(r))
	})
	Register("l2t_td_modify", func(r *record.Record) bool {
		return plasoLinuxTDModify.MatchString(plasoLinuxTD(r))
	})
	Register("l2t_td_read", func(r *record.Record) bool {
		return plasoLinuxTDRead.MatchString(plasoLinuxTD(r))
	})
	Register("l2t_td_delete", func(r *record.Record) bool {
		return plasoLinuxTDDelete.MatchString(plasoLinuxTD(r))
	})
	Register("l2t_usn_create", func(r *record.Record) bool {
		return plasoLinuxUsnBit(r, 0x100) // USN_REASON_FILE_CREATE
	})
	Register("l2t_usn_delete", func(r *record.Record) bool {
		return plasoLinuxUsnBit(r, 0x200) // USN_REASON_FILE_DELETE
	})
	Register("l2t_utmp_login", func(r *record.Record) bool {
		// `_login_type(rec) in (6, 7)` — LOGIN_PROCESS / USER_PROCESS
		n, ok := plasoLinuxLoginType(r)
		return ok && n.IsInt64() && (n.Int64() == 6 || n.Int64() == 7)
	})
	Register("l2t_utmp_logout", func(r *record.Record) bool {
		// `_login_type(rec) == 8` — DEAD_PROCESS
		n, ok := plasoLinuxLoginType(r)
		return ok && n.IsInt64() && n.Int64() == 8
	})
	Register("l2t_text_ssh_login", func(r *record.Record) bool {
		// str(_record(rec).get("data_type") or "") == "syslog:ssh:login"
		return plasoLinuxRecStr(r, "data_type") == "syslog:ssh:login"
	})
}

// The plaso timestamp_desc → CAR file action patterns, verbatim from
// plaso_linux.py. Unanchored re.search over the description string; `create`
// is tested first by the map so overlapping descriptions resolve to it.
var (
	plasoLinuxTDCreate = regexp.MustCompile(`(?i)creation|crtime|birth`)
	plasoLinuxTDModify = regexp.MustCompile(`(?i)modification|mtime`)
	plasoLinuxTDRead   = regexp.MustCompile(`(?i)last access|atime`)
	plasoLinuxTDDelete = regexp.MustCompile(`(?i)deletion|deleted`)
)

// plasoLinuxRec is _record(rec): the wrapped row's flat plaso event, or an
// empty mapping when "Record" is absent or is not a dict (isinstance gate).
func plasoLinuxRec(r *record.Record) *pyjson.Object {
	o, _ := r.Get("Record").(*pyjson.Object)
	return o // nil reads as the empty dict
}

// plasoLinuxRecField is _record(rec).get(key).
func plasoLinuxRecField(r *record.Record, key string) pyjson.Value {
	o := plasoLinuxRec(r)
	if o == nil {
		return nil
	}
	v, _ := o.Get(key)
	return v
}

// plasoLinuxRecStr is str(_record(rec).get(key) or "") — `or ""`, so a
// present-but-falsy value (None, "", 0, False) renders as "" rather than
// Python's str() of it.
func plasoLinuxRecStr(r *record.Record, key string) string {
	v := plasoLinuxRecField(r, key)
	if !record.Truthy(v) {
		return ""
	}
	return record.PyStr(v)
}

// plasoLinuxTD is _td, pre-folded for the ONE case-insensitivity difference
// between CPython's `re` and RE2 that these patterns can reach.
//
// Enumerated over all of Unicode, letter by letter, the two engines' (?i)
// fold sets for the pattern letters are identical (both fold 'ſ' onto 's')
// EXCEPT for 'i': CPython's sre also matches U+0130 'İ' and U+0131 'ı'
// against an ASCII 'i', while Go's SimpleFold orbits do not. Every pattern
// letter is ASCII, so mapping those two runes to 'i' in the SUBJECT before
// matching reproduces CPython exactly — it can only create matches CPython
// also makes, and never suppresses one. (No plaso timestamp_desc carries
// them; the predicate vectors pin the behavior anyway.)
func plasoLinuxTD(r *record.Record) string {
	return plasoLinuxDottedI.Replace(plasoLinuxRecStr(r, "timestamp_desc"))
}

var plasoLinuxDottedI = strings.NewReplacer("İ", "i", "ı", "i")

// plasoLinuxUsnFlags is _usn_flags: int(<flags> or 0), with int()'s
// TypeError/ValueError caught and answered with 0. A float truncates toward
// zero, a decimal string parses, a hex string ("0x100") does NOT (Python
// int(s) is base 10) and lands on the 0 fallback.
func plasoLinuxUsnFlags(r *record.Record) *big.Int {
	v := plasoLinuxRecField(r, "update_reason_flags")
	if !record.Truthy(v) { // `or 0`
		return big.NewInt(0)
	}
	n, ok := record.PyInt(v)
	if !ok { // TypeError / ValueError
		return big.NewInt(0)
	}
	return n
}

// plasoLinuxUsnBit is `_usn_flags(rec) & <mask> != 0` — Python binds `&`
// tighter than `!=`, and its AND is two's-complement over arbitrary
// precision, which math/big matches for negative flag values too.
func plasoLinuxUsnBit(r *record.Record, mask int64) bool {
	return new(big.Int).And(plasoLinuxUsnFlags(r), big.NewInt(mask)).Sign() != 0
}

// plasoLinuxLoginType is _login_type: int(<login_type>) with NO `or 0`, so a
// missing/None field is a TypeError → None (ok=false), never 0. A float
// truncates (7.9 → 7), a bool is an int (True → 1), "7.5" is a ValueError.
func plasoLinuxLoginType(r *record.Record) (*big.Int, bool) {
	return record.PyInt(plasoLinuxRecField(r, "login_type"))
}
