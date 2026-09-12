// Variant predicates of byakugan/mappings/evtx_extra.py (evtx_bits, evtx_rdp)
// and byakugan/mappings/evtx_more.py (evtx_more), ported clause by clause.
//
// The two modules gate their EventId DIFFERENTLY, and the difference is
// observable, so it is reproduced exactly:
//
//   - evtx_extra:  `rec.get("EventId") in (59, 60)` — Python `==` against int
//     literals. A STRING "59" is never equal to 59; 59.0 is; True is 1.
//     (same shape as core.py's gates → the shared numEq helper).
//   - evtx_more:   `int(rec.get("EventId"))` inside try/except (TypeError,
//     ValueError) → None. So "4907" DOES match, 4907.9 truncates to 4907, and
//     None/absent/"0x4907"/"" are simply no-match.
package predicates

import (
	"strings"

	"github.com/get-sybers/byakugan/go/internal/record"
)

func init() {
	// --- byakugan/mappings/evtx_extra.py ---------------------------------
	Register("evtxx_is_bits_transfer", func(r *record.Record) bool {
		return (numEq(r.Get("EventId"), 59) || numEq(r.Get("EventId"), 60)) &&
			strings.Contains(getStr(r, "Channel"), "Bits-Client")
	})
	Register("evtxx_is_ts_session", func(r *record.Record) bool {
		id := r.Get("EventId")
		return (numEq(id, 21) || numEq(id, 24) || numEq(id, 25)) &&
			strings.Contains(getStr(r, "Channel"),
				"TerminalServices-LocalSessionManager")
	})

	// --- byakugan/mappings/evtx_more.py ----------------------------------
	Register("em_is_4907_file", func(r *record.Record) bool {
		return emEIDIs(r, 4907) && emChannelHas(r, "Security") &&
			r.EvtxPayloadField("ObjectType") == "File"
	})
	Register("em_is_wmi_5857", func(r *record.Record) bool {
		return emEIDIs(r, 5857) && emChannelHas(r, "WMI-Activity")
	})
	Register("em_is_pnp_20003", func(r *record.Record) bool {
		return emEIDIs(r, 20003) && emChannelHas(r, "System")
	})
	Register("em_is_smb_30803", func(r *record.Record) bool {
		return emEIDIs(r, 30803) && emChannelHas(r, "SmbClient")
	})
	Register("em_is_winlogon_7001", func(r *record.Record) bool {
		return emEIDIs(r, 7001) && emChannelHas(r, "System")
	})
	Register("em_is_winlogon_7002", func(r *record.Record) bool {
		return emEIDIs(r, 7002) && emChannelHas(r, "System")
	})
	Register("em_is_scm_7034", func(r *record.Record) bool {
		return emEIDIs(r, 7034) && emChannelHas(r, "System")
	})
}

// emEIDIs is evtx_more._eid(rec) == id:
//
//	try: return int(rec.get("EventId"))
//	except (TypeError, ValueError): return None
//
// record.PyInt is int() itself (bool→0/1, float truncated toward zero, a
// decimal string parsed with Python's whitespace/sign/underscore rules), and
// its false return covers exactly the two caught exception classes.
// DEVIATION (noted, harmless): int(±inf) raises OverflowError, which the
// Python except clause does NOT catch — Python crashes there where Go reports
// no-match. No live EventId is an infinity, and json.dumps cannot even write
// one that round-trips through a real EvtxECmd export.
func emEIDIs(r *record.Record, id int64) bool {
	n, ok := record.PyInt(r.Get("EventId"))
	if !ok {
		return false
	}
	return n.IsInt64() && n.Int64() == id
}

// emChannelHas is evtx_more._ch: `needle in str(rec.get("Channel", ""))`.
func emChannelHas(r *record.Record, needle string) bool {
	return strings.Contains(getStr(r, "Channel"), needle)
}
