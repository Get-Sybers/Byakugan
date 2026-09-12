// Variant predicates of byakugan/mappings/plaso_fs_extra.py — the filesystem/
// file family (plaso_fseventsd / plaso_pecoff / plaso_olecf), ported clause by
// clause.
//
// This module reads the wrapped l2t row through _common.plaso_rec, which is
// `r if isinstance(r, dict) else {}` — a NON-dict Record is an empty dict here
// (no AttributeError, unlike plaso_web's `(r or {})` reader) — and then:
//
//	_dt(rec, name) = _rec(rec).get("data_type") == name   # str EQUALITY, no str()
//	_td(rec)       = str(_rec(rec).get("timestamp_desc") or "")
package predicates

import (
	"regexp"

	"github.com/get-sybers/byakugan/go/internal/pyjson"
	"github.com/get-sybers/byakugan/go/internal/record"
)

func init() {
	Register("fse_is_record", plasofsIsFseventsRecord)
	Register("pe_is_compile_stamp", plasofsPEIsCompileStamp)
	Register("pe_is_table_stamp", plasofsPEIsTableStamp)
	Register("pe_is_file", plasofsPEIsFile)
	Register("ole_is_create", plasofsOLEIsCreate)
	Register("ole_is_modify", plasofsOLEIsModify)
}

// The three timestamp_desc classifiers of plaso_fs_extra. Unanchored
// re.search, case-insensitive. _TD_READ is declared by the module but unused
// by any live gate, so it is not ported.
var (
	plasofsTDCreate = regexp.MustCompile(`(?i)creation|crtime|birth`)
	plasofsTDModify = regexp.MustCompile(`(?i)modification|mtime|last written|content`)
)

// plasofsIsFseventsRecord: every macOS FSEvents journal record (the map never
// drops one — the generic file/modify action).
func plasofsIsFseventsRecord(r *record.Record) bool {
	return plasofsDataTypeIs(r, "macos:fseventsd:record")
}

// plasofsPEIsCompileStamp: the pe_coff:file row whose stamp is the header
// TimeDateStamp (plaso's 'Creation Time' = the compile/link time).
func plasofsPEIsCompileStamp(r *record.Record) bool {
	return plasofsDataTypeIs(r, "pe_coff:file") &&
		plasofsTDCreate.MatchString(plasofsTimestampDesc(r))
}

// plasofsPEIsTableStamp: an export / load-configuration table stamp
// ('Content Modification Time').
func plasofsPEIsTableStamp(r *record.Record) bool {
	return plasofsDataTypeIs(r, "pe_coff:file") &&
		plasofsTDModify.MatchString(plasofsTimestampDesc(r))
}

// plasofsPEIsFile: any pe_coff:file row — the undated placeholder fallback
// ('Not a time'). pe_coff:dll_import / pe_coff:resource stay raw.
func plasofsPEIsFile(r *record.Record) bool {
	return plasofsDataTypeIs(r, "pe_coff:file")
}

func plasofsOLEIsCreate(r *record.Record) bool {
	return plasofsDataTypeIs(r, "olecf:summary_info") &&
		plasofsTDCreate.MatchString(plasofsTimestampDesc(r))
}

func plasofsOLEIsModify(r *record.Record) bool {
	return plasofsDataTypeIs(r, "olecf:summary_info") &&
		!plasofsTDCreate.MatchString(plasofsTimestampDesc(r))
}

// --- the wrapped-row readers -------------------------------------------------

// plasofsRecField is `_rec(rec).get(key)` — _common.plaso_rec's isinstance
// check means a non-dict Record is simply an empty dict.
func plasofsRecField(r *record.Record, key string) pyjson.Value {
	o, ok := r.Get("Record").(*pyjson.Object)
	if !ok {
		return nil
	}
	v, _ := o.Get(key)
	return v
}

// plasofsDataTypeIs is `_rec(rec).get("data_type") == "<literal>"`: a string
// comparison, so a non-string data_type never matches.
func plasofsDataTypeIs(r *record.Record, want string) bool {
	s, ok := plasofsRecField(r, "data_type").(string)
	return ok && s == want
}

// plasofsTimestampDesc is _td: str(_rec(rec).get("timestamp_desc") or "").
func plasofsTimestampDesc(r *record.Record) string {
	v := plasofsRecField(r, "timestamp_desc")
	if !record.Truthy(v) {
		return ""
	}
	return record.PyStr(v)
}
