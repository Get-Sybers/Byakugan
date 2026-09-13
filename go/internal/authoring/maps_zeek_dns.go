package authoring

// zeek_dns — Zeek dns.log → CAR flow (Go-native port of
// byakugan/mappings/zeek_dns.py, B2). A DNS record is a granular view of the
// connection it rode; guid = uid + trans_id, because one UDP :53 connection
// carries many queries. Predicate zeek_dns_is_query is already in go/internal/predicates.

func init() {
	register("zeek_dns", Entry{
		Variants: []Variant{
			{Pred: "zeek_dns_is_query", Leaf: &Leaf{
				Object: "flow",
				Action: Const("message"),
				Ts:     EpochTS("ts"),
				Guid:   GuidFields("uid", "trans_id"),
				Props: []Prop{
					{"src_ip", "id.orig_h"},
					{"src_port", "id.orig_p"},
					{"dest_ip", "id.resp_h"},
					{"dest_port", "id.resp_p"},
					{"transport_protocol", "proto"},
					{"application_protocol", Const("dns")},
					{"fqdn", "query"},
					{"start_time", EpochTS("ts")},
				},
				Keep: []string{"uid", "query", "qtype_name", "rcode_name", "answers", "trans_id"},
			}},
		},
	})
}
