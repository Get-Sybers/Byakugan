package authoring

// zeek_ssl — Zeek ssl.log → CAR flow (Go-native port of
// byakugan/mappings/zeek_ssl.py, B2). One record per TLS connection, sharing the
// conn uid (so guid = uid alone, unlike dns). The SNI lands in dest_fqdn.
// Predicate zeek_ssl_is_tls is already in go/internal/predicates.

func init() {
	register("zeek_ssl", Entry{
		Variants: []Variant{
			{Pred: "zeek_ssl_is_tls", Leaf: &Leaf{
				Object: "flow",
				Action: Const("message"),
				Ts:     EpochTS("ts"),
				Guid:   GuidField("uid"),
				Props: []Prop{
					{"src_ip", "id.orig_h"},
					{"src_port", "id.orig_p"},
					{"dest_ip", "id.resp_h"},
					{"dest_port", "id.resp_p"},
					// ssl.log carries no proto (TLS is TCP); prefer the sensor's value else assert tcp
					{"transport_protocol", First("proto", Const("tcp"))},
					{"application_protocol", Const("tls")},
					{"dest_fqdn", "server_name"},
					{"start_time", EpochTS("ts")},
				},
				Keep: []string{
					"uid", "server_name", "version", "cipher", "curve",
					"next_protocol", "resumed", "established", "ssl_history",
					"cert_chain_fps", "cert_chain_fuids",
					"client_cert_chain_fps", "sni_matches_cert",
					"ja3", "ja3s", "validation_status",
				},
			}},
		},
	})
}
