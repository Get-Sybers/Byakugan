package authoring

// core — the DX_DFIR per-artefact core maps (Go-native port of
// byakugan/mappings/core.py). Two keys live here:
//   - evtx_security : EvtxECmd Security channel 4624/4625/4672 → authentication
//   - zeek_http     : Zeek http.log → http (origin request / CONNECT tunnel)
//
// Predicates is_sec_4624/_4625/_4672 and is_http_origin/_tunnel are already in
// go/internal/predicates.

// evP is the EvtxECmd Payload-blob field marker (normalize.payload(key) with the
// default field="Payload"): {"!":["payload","Payload",<field>]}. Shared by every
// evtx map in this package.
func evP(field string) Src { return Payload("Payload", field) }

// evU is the EvtxECmd UserData-shape field marker (normalize.userdata(key) with
// the default field="Payload"): {"!":["userdata","Payload",<field>]}.
func evU(field string) Src { return Userdata("Payload", field) }

// --- authentication (Security 4624/4625/4672) --------------------------------

// authProps is the shared _auth_props() block, in resolve order.
func authProps() []Prop {
	return []Prop{
		{"target_user", evP("TargetUserName")},
		{"target_uid", evP("TargetUserSid")},
		{"target_ad_domain", evP("TargetDomainName")},
		{"user", UserCanon(evP("SubjectUserName"))},
		{"uid", evP("SubjectUserSid")},
		{"ad_domain", evP("SubjectDomainName")},
		{"hostname", evP("WorkstationName")},
		{"auth_target", "Computer"},
		{"method", evP("AuthenticationPackageName")},
		{"auth_service", evP("LogonProcessName")},
		{"app_name", Basename(evP("ProcessName"))},
	}
}

var authKeep = []string{
	"EventId", "EventRecordId", "Channel", "Computer", "Payload",
	"SourceFile", "RemoteHost", "MapDescription",
}

func authNative() []Prop {
	return []Prop{
		{"TargetLogonId", evP("TargetLogonId")},
		{"SubjectLogonId", evP("SubjectLogonId")},
		{"LogonType", evP("LogonType")},
		{"IpAddress", evP("IpAddress")},
	}
}

// --- http (Zeek http.log) ----------------------------------------------------

// httpProps is the shared _HTTP_PROPS block, in resolve order.
func httpProps() []Prop {
	return []Prop{
		{"url_domain", DomainOf("host")},
		{"url_remainder", "uri"},
		{"http_version", "version"},
		{"requester_ip_address", "id.orig_h"},
		{"request_body_bytes", "request_body_len"},
		{"response_body_bytes", "response_body_len"},
		{"response_status_code", "status_code"},
		{"request_referrer", "referrer"},
		{"user_agent_full", "user_agent"},
	}
}

var httpKeep = []string{
	"uid", "id.orig_p", "id.resp_h", "id.resp_p", "method",
	"status_msg", "trans_depth", "tags", "resp_fuids", "orig_fuids",
	"resp_mime_types", "orig_mime_types", "resp_filenames",
	"origin", "username",
}

func init() {
	register("evtx_security", Entry{
		Variants: []Variant{
			{Pred: "is_sec_4624", Leaf: &Leaf{
				Object: "authentication", Action: "success", Ts: "TimeCreated",
				Guid: GuidFields("Computer", "Channel", "EventRecordId"),
				Host: HostLabel("Computer"),
				// R6: the caller process that requested the logon.
				OwningPID: evP("ProcessId"),
				Props:     authProps(),
				Keep:      authKeep, NativeExtract: authNative(),
			}},
			{Pred: "is_sec_4625", Leaf: &Leaf{
				Object: "authentication", Action: "failure", Ts: "TimeCreated",
				Guid:      GuidFields("Computer", "Channel", "EventRecordId"),
				Host:      HostLabel("Computer"),
				OwningPID: evP("ProcessId"),
				Props: append(authProps(), Prop{"decision_reason",
					First(evP("SubStatus"), evP("Status"), evP("FailureReason"))}),
				Keep: authKeep, NativeExtract: authNative(),
			}},
			{Pred: "is_sec_4672", Leaf: &Leaf{
				Object: "authentication", Action: "success", Ts: "TimeCreated",
				Guid: GuidFields("Computer", "Channel", "EventRecordId"),
				Host: HostLabel("Computer"),
				Props: []Prop{
					{"user", UserCanon(evP("SubjectUserName"))},
					{"uid", evP("SubjectUserSid")},
					{"ad_domain", evP("SubjectDomainName")},
					{"auth_target", "Computer"},
					{"user_role", Const("administrator")},
				},
				Keep: authKeep,
				NativeExtract: []Prop{
					{"SubjectLogonId", evP("SubjectLogonId")},
					{"PrivilegeList", evP("PrivilegeList")},
				},
			}},
		},
	})

	register("zeek_http", Entry{
		Variants: []Variant{
			{Pred: "is_http_origin", Leaf: &Leaf{
				Object: "http",
				Action: MapValue("method", map[string]string{
					"GET": "get", "POST": "post", "PUT": "put"}, true),
				Ts:   EpochTS("ts"),
				Guid: GuidFields("uid", "trans_depth"),
				Props: append(httpProps(),
					Prop{"url_scheme", Const("http")},
					Prop{"url_full", Concat(Const("http://"), "host", "uri")}),
				Keep: httpKeep,
			}},
			{Pred: "is_http_tunnel", Leaf: &Leaf{
				Object: "http", Action: "tunnel", Ts: EpochTS("ts"),
				Guid:  GuidFields("uid", "trans_depth"),
				Props: httpProps(),
				Keep:  httpKeep,
			}},
		},
	})
}
