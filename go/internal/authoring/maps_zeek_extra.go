package authoring

// zeek_extra — the Zeek logs beyond conn/http/dns/ssl/x509 that carry a CAR
// object (Go-native port of byakugan/mappings/zeek_extra.py, epic #86):
// smtp → email (only when message content is present) and files → file (a
// network-observed file object). Predicates zeek_is_smtp_message / zeek_is_file
// are already in go/internal/predicates.

func init() {
	// ---- smtp.log → email (only when message content is present) ----------
	register("zeek_smtp", Entry{
		Variants: []Variant{
			{Pred: "zeek_is_smtp_message", Leaf: &Leaf{
				Object: "email",
				Action: Const("deliver"),
				Ts:     EpochTS("ts"),
				Guid:   GuidFields("uid", "trans_depth"),
				Props: []Prop{
					{"src_ip", "id.orig_h"},
					{"src_port", "id.orig_p"},
					{"dest_ip", "id.resp_h"},
					{"dest_port", "id.resp_p"},
					// envelope (MAIL FROM / RCPT TO) is the real sender/recipient;
					// from/to are the forgeable header display values
					{"src_address", First("mailfrom", "from")},
					{"dest_address", First("rcptto", "to")},
					{"src_domain", DomainOf(First("mailfrom", "from"))},
					{"from", "from"},
					{"to", "to"},
					{"subject", "subject"},
					{"date", "date"},
				},
				Keep: []string{
					"uid", "trans_depth", "helo", "path", "tls", "fuids",
					"last_reply", "id.orig_p", "id.resp_p",
				},
			}},
		},
	})

	// ---- files.log → file (a network-observed file object) ----------------
	register("zeek_files", Entry{
		Variants: []Variant{
			{Pred: "zeek_is_file", Leaf: &Leaf{
				Object: "file",
				Action: Const("create"),
				Ts:     EpochTS("ts"),
				Guid:   GuidFields("fuid"),
				Props: []Prop{
					{"file_name", "filename"},
					{"extension", Ext("filename")},
					{"mime_type", "mime_type"},
					// canonicalised to LOWERCASE (one hash format across sources)
					{"md5_hash", Lower("md5")},
					{"sha1_hash", Lower("sha1")},
					{"sha256_hash", Lower("sha256")},
				},
				Keep: []string{
					"fuid", "uid", "source", "seen_bytes", "total_bytes",
					"is_orig", "analyzers", "id.orig_h", "id.resp_h", "mime_type",
				},
			}},
		},
	})
}
