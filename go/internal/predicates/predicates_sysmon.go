// Variant predicates of byakugan/mappings/sysmon.py — the thirteen per-EID
// gates of the single `evtx_sysmon` artefact key, ported clause by clause.
//
// Every gate is `_is_sysmon(rec) and _eid(rec) == <EID>`; the three registry
// EIDs additionally read the Payload's EventType (the action authority) with
// a case-SENSITIVE substring test, exactly like the Python.
package predicates

import (
	"math/big"
	"strings"

	"github.com/get-sybers/byakugan/go/internal/record"
)

func init() {
	Register("sysmon_proc_create", func(r *record.Record) bool { return sysmonEIDIs(r, 1) })
	Register("sysmon_flow_start", func(r *record.Record) bool { return sysmonEIDIs(r, 3) })
	Register("sysmon_proc_terminate", func(r *record.Record) bool { return sysmonEIDIs(r, 5) })
	Register("sysmon_driver_load", func(r *record.Record) bool { return sysmonEIDIs(r, 6) })
	Register("sysmon_module_load", func(r *record.Record) bool { return sysmonEIDIs(r, 7) })
	Register("sysmon_thread_remote", func(r *record.Record) bool { return sysmonEIDIs(r, 8) })
	Register("sysmon_proc_access", func(r *record.Record) bool { return sysmonEIDIs(r, 10) })
	Register("sysmon_file_create", func(r *record.Record) bool { return sysmonEIDIs(r, 11) })
	Register("sysmon_file_delete", func(r *record.Record) bool { return sysmonEIDIs(r, 23) })

	// EID 12 is 'RegistryEvent (Object create and delete)': EventType
	// Create*→add, Delete*→remove; any other EventType falls through to the
	// map's default (None) and the row stays raw.
	Register("sysmon_reg_add", func(r *record.Record) bool {
		return sysmonEIDIs(r, 12) && strings.Contains(sysmonEventType(r), "Create")
	})
	Register("sysmon_reg_remove", func(r *record.Record) bool {
		return sysmonEIDIs(r, 12) && strings.Contains(sysmonEventType(r), "Delete")
	})
	// EID 13 'RegistryEvent (Value Set)' — EventType SetValue and only that.
	Register("sysmon_reg_value_set", func(r *record.Record) bool {
		return sysmonEIDIs(r, 13) && strings.Contains(sysmonEventType(r), "Set")
	})
	// EID 14 'RegistryEvent (Key and Value Rename)'.
	Register("sysmon_reg_rename", func(r *record.Record) bool {
		return sysmonEIDIs(r, 14) && strings.Contains(sysmonEventType(r), "Rename")
	})
}

// sysmonIsProvider is sysmon._is_sysmon:
// `"sysmon" in str(rec.get("Provider", "")).lower()` — a SUBSTRING test on the
// lowercased provider (absent → "", None → "None"), not an equality.
func sysmonIsProvider(r *record.Record) bool {
	return strings.Contains(strings.ToLower(getStr(r, "Provider")), "sysmon")
}

// sysmonEID is sysmon._eid: `int(rec.get("EventId"))` with TypeError and
// ValueError swallowed → None. NOTE this is NOT core's numEq pattern: int()
// COERCES, so "1", 1.9 (truncation) and True all yield 1, while "0x1", "1.0",
// "" and None yield None.
func sysmonEID(r *record.Record) (*big.Int, bool) {
	return record.PyInt(r.Get("EventId"))
}

// sysmonEIDIs is the gate every variant shares: `_is_sysmon(rec) and
// _eid(rec) == <id>` (Python's `and` short-circuits; neither half mutates).
func sysmonEIDIs(r *record.Record, id int64) bool {
	if !sysmonIsProvider(r) {
		return false
	}
	n, ok := sysmonEID(r)
	return ok && n.IsInt64() && n.Int64() == id
}

// sysmonEventType is sysmon._payload_event_type — evtx_payload_field(rec,
// "EventType"), the UNSTRIPPED gating view of the EvtxECmd Payload blob
// ("" whenever the blob is absent, unparseable or carries no such @Name).
func sysmonEventType(r *record.Record) string {
	return r.EvtxPayloadField("EventType")
}
