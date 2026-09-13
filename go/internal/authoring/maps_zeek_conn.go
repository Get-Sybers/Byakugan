package authoring

// zeek_conn — Zeek conn.log → CAR flow (Go-native port of
// byakugan/mappings/zeek_conn.py, epic #86). One flow variant, gated on a
// non-empty conn_state. The predicate zeek_conn_has_state (which also stamps the
// _zc_end_time / _zc_packet_count derivations) is already in go/internal/predicates;
// this module only references its name.

// the view's case(): terminal states → end, pure attempt → start, any other
// observed state falls through to the const("message") second source.
var zeekConnActions = map[string]string{
	"SF":   "end",
	"REJ":  "end",
	"RSTO": "end",
	"RSTR": "end",
	"S0":   "start",
}

func init() {
	register("zeek_conn", Entry{
		Variants: []Variant{
			{Pred: "zeek_conn_has_state", Leaf: &Leaf{
				Object: "flow",
				// unmapped-but-present states fall through to "message"
				Action: First(MapValue("conn_state", zeekConnActions, false), Const("message")),
				Ts:     EpochTS("ts"),
				// the sensor-minted connection identity — run-scoped, shared with http/files
				Guid: GuidField("uid"),
				Props: []Prop{
					{"src_ip", "id.orig_h"},
					{"src_port", "id.orig_p"},
					{"dest_ip", "id.resp_h"},
					{"dest_port", "id.resp_p"},
					{"transport_protocol", "proto"},
					{"application_protocol", "service"},
					{"tcp_flags", "history"},
					{"out_bytes", "orig_bytes"},
					{"in_bytes", "resp_bytes"},
					{"start_time", EpochTS("ts")},
					{"end_time", "_zc_end_time"},
					{"packet_count", "_zc_packet_count"},
				},
				Keep: []string{"uid", "service", "conn_state", "missed_bytes"},
			}},
		},
	})
}
