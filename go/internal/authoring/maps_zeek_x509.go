package authoring

// zeek_x509 — Zeek x509.log → CAR file (Go-native port of
// byakugan/mappings/zeek_x509.py, B2). A TLS certificate is content; its Zeek
// fingerprint IS a SHA-256 of the DER cert, promoted (lowercased) to sha256_hash.
// guid = the fingerprint. Predicate zeek_x509_has_fingerprint is already in
// go/internal/predicates.

func init() {
	register("zeek_x509", Entry{
		Variants: []Variant{
			{Pred: "zeek_x509_has_fingerprint", Leaf: &Leaf{
				Object: "file",
				Action: "create",
				Ts:     EpochTS("ts"),
				Guid:   GuidField("fingerprint"),
				Props: []Prop{
					// LOWERCASE: one hash format across sources
					{"sha256_hash", Lower("fingerprint")},
				},
				Keep: []string{
					"fingerprint", "certificate.subject", "certificate.issuer",
					"certificate.serial", "certificate.version",
					"certificate.not_valid_before", "certificate.not_valid_after",
					"certificate.key_alg", "certificate.sig_alg",
					"certificate.key_type", "certificate.key_length",
					"san.dns", "basic_constraints.ca", "host_cert", "client_cert",
				},
			}},
		},
	})
}
