// The variant gates of the Get-Sybers Go parsers — the Linux-native
// SRUM and Prefetch parsers (Get-Sybers/GoDFIR-toolz), each its own artefact
// key / map:
//
//	byakugan/mappings/esedump_srum.py   → esedump_srum_is_network_usage,
//	                                      esedump_srum_is_application_usage  (esedump_srum)
//	byakugan/mappings/prefetch_dump.py  → prefetch_dump_is_execution        (prefetch_dump)
//
// These read the tool's OWN UNWRAPPED record directly (like the RECmd/JLECmd
// gates), not a wrapped plaso Record: ese_dump tags each row with `TableAlias`
// (the friendly SRUM provider name), prefetch_dump names the `Executable`.
package predicates

import (
	"github.com/get-sybers/byakugan/go/internal/record"
)

// The two SRUM provider tables that carry an honest CAR object. The rest
// (NetworkConnectivityUsage, EnergyUsage, AppTimelineProvider, …) are claimed by
// neither gate and stay raw.
const (
	esdNetworkUsage     = "NetworkDataUsage"
	esdApplicationUsage = "ApplicationResourceUsage"
)

func init() {
	// esedump_srum_is_network_usage:  rec.get("TableAlias") == "NetworkDataUsage"
	Register("esedump_srum_is_network_usage", func(r *record.Record) bool {
		return record.PyStr(r.Get("TableAlias")) == esdNetworkUsage
	})
	// esedump_srum_is_application_usage:  rec.get("TableAlias") == "ApplicationResourceUsage"
	Register("esedump_srum_is_application_usage", func(r *record.Record) bool {
		return record.PyStr(r.Get("TableAlias")) == esdApplicationUsage
	})
	// prefetch_dump_is_execution:  bool(rec.get("Executable"))
	Register("prefetch_dump_is_execution", func(r *record.Record) bool {
		return record.Truthy(r.Get("Executable"))
	})
}
