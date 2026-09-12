// Variant predicates of byakugan/mappings/evtx_windows.py — the
// evtx_security_sessions (Security 4624/4634/4647/4778/4779 → user_session),
// evtx_services (System 7045 / Security 4697 → service) and evtx_process
// (Security 4688 → process) families, ported clause by clause.
//
// Every gate in that module has the same shape:
//
//	rec.get("EventId") == <id> and "<Channel>" in str(rec.get("Channel", ""))
//
// so the EventId comparison is Python `==` against an int literal (numEq: an
// int or a float value compares numerically, True/False count as 1/0, a STRING
// never equals an int) and the channel guard is a plain substring test over
// `str(rec.get("Channel", ""))` (getStr: "" when the key is absent, "None" when
// the value is None — Python's str(), not a blank).
//
// FILE NAME: the per-family convention is predicates_<family>.go, but this
// family is called evtx_windows and a Go source file whose name ends in
// `_windows.go` carries an IMPLICIT GOOS=windows build constraint — the
// toolchain would drop this file from the linux build without a word (it lands
// in IgnoredGoFiles, so every gate here reads as "not registered"). The `_family`
// suffix defeats the GOOS pattern; nothing else about the layout changes.
package predicates

import (
	"strings"

	"github.com/get-sybers/byakugan/go/internal/record"
)

func init() {
	Register("evtxwin_is_sec_4624", func(r *record.Record) bool {
		return evtxwinIsChannelEvent(r, "Security", 4624)
	})
	// `rec.get("EventId") in (4634, 4647, 4779)` — tuple membership is a
	// left-to-right `==` scan, so the same numeric equality applies per element.
	Register("evtxwin_is_sec_logoff", func(r *record.Record) bool {
		return evtxwinIsChannelEvent(r, "Security", 4634, 4647, 4779)
	})
	Register("evtxwin_is_sec_4778", func(r *record.Record) bool {
		return evtxwinIsChannelEvent(r, "Security", 4778)
	})
	Register("evtxwin_is_sys_7045", func(r *record.Record) bool {
		return evtxwinIsChannelEvent(r, "System", 7045)
	})
	Register("evtxwin_is_sec_4697", func(r *record.Record) bool {
		return evtxwinIsChannelEvent(r, "Security", 4697)
	})
	Register("evtxwin_is_sec_4688", func(r *record.Record) bool {
		return evtxwinIsChannelEvent(r, "Security", 4688)
	})
}

// evtxwinIsChannelEvent is the module's single gate shape: the record's
// EventId equals one of ids AND the channel string CONTAINS channel. The
// EventId test runs first, exactly like the Python `and` (no short-circuit
// difference is observable here — neither half has side effects — but the
// order is kept for readability against the source).
func evtxwinIsChannelEvent(r *record.Record, channel string, ids ...int64) bool {
	v := r.Get("EventId")
	hit := false
	for _, id := range ids {
		if numEq(v, id) {
			hit = true
			break
		}
	}
	return hit && strings.Contains(getStr(r, "Channel"), channel)
}
