// Variant predicates of byakugan/mappings/plaso_web.py — the browser/download
// evidence family (l2t_msiecf / l2t_firefox_cache / l2t_firefox_places /
// l2t_javaidx), ported clause by clause.
//
// Every gate reads the WRAPPED l2t row (the flat plaso event lives under
// "Record") through the module's two readers, both of which coerce with
// `or ""` — a present-but-FALSY value (0, False, "", []) renders as "", never
// as Python's str() of it:
//
//	_dt(rec) = str((rec.get("Record") or {}).get("data_type") or "")
//	_td(rec) = str((rec.get("Record") or {}).get("timestamp_desc") or "")
package predicates

import (
	"strings"

	"github.com/get-sybers/byakugan/go/internal/pyjson"
	"github.com/get-sybers/byakugan/go/internal/record"
)

func init() {
	Register("plasoweb_is_ie_visit", plasowebIsIEVisit)
	Register("plasoweb_is_ff_cache", plasowebIsFFCache)
	Register("plasoweb_is_ff_visit", plasowebIsFFVisit)
	Register("plasoweb_is_javaidx", plasowebIsJavaIdx)
}

// plasowebHistoryDTs is plaso_web._HISTORY_VISIT_DTS: the browser-history
// visit/download rows inside the generic sqlite table — Firefox places plus
// Chrome/Edge history (Edge is Chromium, same chrome:history:* data_types).
var plasowebHistoryDTs = map[string]bool{
	"firefox:places:page_visited":    true,
	"chrome:history:page_visited":    true,
	"chrome:history:file_downloaded": true,
}

// plasowebIsIEVisit: an msiecf:url row at its Last Visited Time — the visit
// event. Expiration rows and the url-less msiecf:leak / cached-object rows
// stay raw.
func plasowebIsIEVisit(r *record.Record) bool {
	return plasowebDataType(r) == "msiecf:url" &&
		strings.Contains(plasowebTimestampDesc(r), "Last Visited")
}

func plasowebIsFFCache(r *record.Record) bool {
	return plasowebDataType(r) == "firefox:cache:record"
}

// plasowebIsFFVisit: a browser-history visit/download row → http/get, gated
// strictly by data_type (bookmarks/annotations and the other sqlite plugins
// stay raw).
func plasowebIsFFVisit(r *record.Record) bool {
	return plasowebHistoryDTs[plasowebDataType(r)]
}

func plasowebIsJavaIdx(r *record.Record) bool {
	return plasowebDataType(r) == "java:download:idx"
}

// --- the wrapped-row readers -------------------------------------------------

// plasowebRecField is `(rec.get("Record") or {}).get(key)`. A Record that is
// not a dict yields nil here; Python raises AttributeError on a TRUTHY
// non-dict Record (a shape the plaso lane never emits — see the port report).
func plasowebRecField(r *record.Record, key string) pyjson.Value {
	o, ok := r.Get("Record").(*pyjson.Object)
	if !ok {
		return nil
	}
	v, _ := o.Get(key)
	return v
}

// plasowebRecStr is `str((rec.get("Record") or {}).get(key) or "")`.
func plasowebRecStr(r *record.Record, key string) string {
	v := plasowebRecField(r, key)
	if !record.Truthy(v) { // `or ""` — None/""/0/False/[] all become ""
		return ""
	}
	return record.PyStr(v)
}

// plasowebDataType is plaso_web._dt.
func plasowebDataType(r *record.Record) string {
	return plasowebRecStr(r, "data_type")
}

// plasowebTimestampDesc is plaso_web._td.
func plasowebTimestampDesc(r *record.Record) string {
	return plasowebRecStr(r, "timestamp_desc")
}
