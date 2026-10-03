package authoring

// evtx_extra — additional Windows operational-channel grabs (Go-native port of
// byakugan/mappings/evtx_extra.py):
//   - evtx_bits : BITS-Client 59/60 → http/get (a download is an HTTP GET)
//   - evtx_rdp  : TerminalServices-LocalSessionManager 21/24/25 → user_session
//
// Predicates evtxx_is_bits_transfer / evtxx_is_ts_session are already in
// go/internal/predicates.

func init() {
	register("evtx_bits", Entry{
		Variants: []Variant{
			{Pred: "evtxx_is_bits_transfer", Leaf: &Leaf{
				Object: "http", Action: Const("get"), Ts: "TimeCreated",
				Guid: GuidFields("Computer", "Channel", "EventRecordId"),
				Host: HostLabel("Computer"),
				Props: []Prop{
					{"url_full", evP("url")},
					{"url_domain", Regex1(evP("url"), `^https?://([^/?#]+)`)},
					{"url_scheme", Regex1(evP("url"), `^(https?)`)},
					{"url_remainder", Regex1(evP("url"), `^https?://[^/]+(/[^\s]*)`)},
					{"response_body_bytes", evP("bytesTransferred")},
					{"hostname", HostLabel("Computer")},
				},
				Keep: []string{"EventId", "EventRecordId", "Channel", "Computer",
					"Payload", "SourceFile", "MapDescription"},
				NativeExtract: []Prop{
					{"transferId", evP("transferId")},
					{"name", evP("name")},
					{"bytesTotal", evP("bytesTotal")},
					{"fileTime", evP("fileTime")},
					{"peer", evP("peer")},
				},
			}},
		},
	})

	register("evtx_rdp", Entry{
		Variants: []Variant{
			{Pred: "evtxx_is_ts_session", Leaf: &Leaf{
				Object: "user_session",
				Action: MapValue("EventId", map[string]string{
					"21": "login", "24": "logout", "25": "reconnect"}, false),
				Ts:   "TimeCreated",
				Guid: GuidFields("Computer", "Channel", "EventRecordId"),
				Host: HostLabel("Computer"),
				Props: []Prop{
					{"user", UserCanon(evU("User"))},
					{"src_ip", Regex1(evU("Address"), `^(?!LOCAL$)(.+)$`)},
					{"hostname", HostLabel("Computer")},
				},
				Keep: []string{"EventId", "EventRecordId", "Channel", "Computer",
					"Payload", "SourceFile", "MapDescription", "UserName"},
				NativeExtract: []Prop{
					{"SessionID", evU("SessionID")},
					{"Address", evU("Address")},
				},
			}},
		},
	})
}
