// The variant gates of the three per-tool mapping modules that share one
// family here — each owns exactly one artefact key and one map:
//
//	byakugan/mappings/plaso_srum.py  → srum_is_network_usage,
//	                                   srum_is_application_usage   (l2t_srum)
//	byakugan/mappings/recmd.py       → recmd_is_value_record       (recmd_batch)
//	byakugan/mappings/jlecmd.py      → jl_is_dest_entry            (jlecmd_dest)
//
// The two SRUM gates read the WRAPPED plaso row's nested `Record` dict (an
// `or {}` fold, not mappings._common.plaso_rec's isinstance check); the RECmd
// and JLECmd gates read their tool's own UNWRAPPED record directly.
package predicates

import (
	"github.com/get-sybers/byakugan/go/internal/pyjson"
	"github.com/get-sybers/byakugan/go/internal/record"
)

// The two SRUM data_types that carry an honest CAR object. A third,
// windows:srum:network_connectivity, is SRUM-internal indexes only and is
// deliberately claimed by neither gate (it stays raw).
const (
	srjNetworkUsage     = "windows:srum:network_usage"
	srjApplicationUsage = "windows:srum:application_usage"
)

func init() {
	Register("srum_is_network_usage", func(r *record.Record) bool {
		return srjDataType(r) == srjNetworkUsage
	})
	Register("srum_is_application_usage", func(r *record.Record) bool {
		return srjDataType(r) == srjApplicationUsage
	})
	Register("recmd_is_value_record", srjRecmdIsValueRecord)
	Register("jl_is_dest_entry", func(r *record.Record) bool {
		return record.Truthy(r.Get("Path")) // bool(rec.get("Path"))
	})
}

// srjDataType is plaso_srum._dt:
//
//	r = rec.get("Record")
//	return str((r or {}).get("data_type") or "")
//
// Both `or` folds are Python truthiness, not the engine's blank rule: a FALSY
// non-dict Record (None, {}, [], "", 0, False) reads as the empty dict, and a
// falsy data_type (None, "", 0, False) reads as "". A TRUTHY non-dict Record
// makes Python raise AttributeError — Go returns "" (so: no match) instead of
// panicking. That shape cannot reach the gate on the live lane (the L2tSrum
// route always carries a dict Record), so no vector pins it: Python cannot
// survive it to be recorded.
func srjDataType(r *record.Record) string {
	var dtv pyjson.Value
	if rv := r.Get("Record"); record.Truthy(rv) {
		o, ok := rv.(*pyjson.Object)
		if !ok {
			return ""
		}
		dtv, _ = o.Get("data_type")
	}
	if !record.Truthy(dtv) { // `... or ""`
		return ""
	}
	return record.PyStr(dtv)
}

// srjRecmdIsValueRecord is recmd.recmd_is_value_record:
//
//	return bool(rec.get("KeyPath")) and rec.get("Deleted") is not True
//
// `is not True` is an IDENTITY test against the True singleton, not
// truthiness: only a real JSON `true` declines the record. A Deleted of 1,
// "true", "True" or any other truthy non-bool is NOT the True object, so the
// record is still claimed — reproduced exactly (the vectors pin it).
func srjRecmdIsValueRecord(r *record.Record) bool {
	if !record.Truthy(r.Get("KeyPath")) {
		return false
	}
	deleted, isBool := r.Get("Deleted").(bool)
	return !(isBool && deleted)
}
