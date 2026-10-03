package authoring

// evtx_windows — Windows event logs beyond Sysmon → user_session / service /
// process (Go-native port of byakugan/mappings/evtx_windows.py):
//   - evtx_security_sessions : Security 4624/4634/4647/4779/4778 → user_session
//   - evtx_services          : System 7045 / Security 4697 → service/create
//   - evtx_process           : Security 4688 → process/create
//
// Predicates evtxwin_is_* are already in go/internal/predicates.
//
// NOTE: this is the port of evtx_windows.py, but the file is NOT named
// maps_evtx_windows.go: Go reads a trailing "_windows" as a GOOS build
// constraint and would drop the file on every non-Windows build. maps_evtxwin.go
// avoids that (the suffix is no longer a recognised GOOS token).

// loginTypeTable ← LogonType, per the vetted view's case logic.
var loginTypeTable = map[string]string{
	"2": "interactive", "3": "remote", "10": "rdp",
}

// integrityTable: S-1-16-<RID> mandatory-label SID → CAR integrity_level.
var integrityTable = map[string]string{
	"S-1-16-0": "untrusted", "S-1-16-4096": "low", "S-1-16-8192": "medium",
	"S-1-16-8448": "medium", "S-1-16-12288": "high", "S-1-16-16384": "system",
}

// ltAction: 4624 action — LogonType 7 = unlock, else login.
func ltAction() Src {
	return First(MapValue(evP("LogonType"), map[string]string{"7": "unlock"}, false),
		Const("login"))
}

// sessionProps is the shared _session_props() block, in resolve order.
func sessionProps() []Prop {
	return []Prop{
		{"user", UserCanon(First(evP("TargetUserName"), evP("AccountName"), "UserName"))},
		{"uid", evP("TargetUserSid")},
		{"login_id", First(evP("TargetLogonId"), evP("LogonID"))},
		{"login_type", MapValue(evP("LogonType"), loginTypeTable, false)},
		{"hostname", HostLabel("Computer")},
		{"src_ip", Regex1(First(evP("IpAddress"), evP("ClientAddress")),
			`^(?!(?:::1|127\.0\.0\.1|LOCAL)$)(.+)$`)},
		{"src_port", Regex1(evP("IpPort"), `^(?!0$)(\d+)$`)},
	}
}

var sessionKeep = []string{
	"EventId", "EventRecordId", "Channel", "Computer", "Payload",
	"SourceFile", "RemoteHost", "MapDescription",
}

func sessionNative() []Prop {
	return []Prop{
		{"LogonType", evP("LogonType")},
		{"SubjectLogonId", evP("SubjectLogonId")},
		{"WorkstationName", evP("WorkstationName")},
		{"ClientName", evP("ClientName")},
		{"SessionName", evP("SessionName")},
	}
}

// svcRaw / svcImg: 7045 ImagePath / 4697 ServiceFileName, coalesced.
func svcRaw() Src { return First(evP("ImagePath"), evP("ServiceFileName")) }
func svcImg() Src { return ExePath(svcRaw()) }

// svcProps is the shared _SVC_PROPS block, in resolve order.
func svcProps() []Prop {
	return []Prop{
		{"name", evP("ServiceName")},
		{"image_path", svcImg()},
		{"exe", Basename(svcImg())},
		{"command_line", svcRaw()},
		{"user", UserCanon(First(evP("AccountName"), evP("ServiceAccount"), "UserName"))},
		{"hostname", HostLabel("Computer")},
		{"fqdn", Regex1("Computer", `^(.+\..+)$`)},
	}
}

var svcKeep = []string{
	"EventId", "EventRecordId", "Channel", "Computer", "Payload",
	"SourceFile", "MapDescription", "UserId",
}

func svcNative() []Prop {
	return []Prop{
		{"StartType", First(evP("StartType"), evP("ServiceStartType"))},
		{"ServiceType", evP("ServiceType")},
		{"SubjectLogonId", evP("SubjectLogonId")},
	}
}

func svcLeaf(pred string) Variant {
	return Variant{Pred: pred, Leaf: &Leaf{
		Object: "service", Action: "create", Ts: "TimeCreated",
		Guid:  GuidFields("Computer", "Channel", "EventRecordId"),
		Host:  HostLabel("Computer"),
		Props: svcProps(),
		Keep:  svcKeep, NativeExtract: svcNative(),
	}}
}

func init() {
	register("evtx_security_sessions", Entry{
		Variants: []Variant{
			{Pred: "evtxwin_is_sec_4624", Leaf: &Leaf{
				Object: "user_session", Action: ltAction(), Ts: "TimeCreated",
				Guid:      GuidFields("Computer", "Channel", "EventRecordId"),
				Host:      HostLabel("Computer"),
				OwningPID: evP("ProcessId"),
				Props:     append(sessionProps(), Prop{"login_successful", Const(true)}),
				Keep:      sessionKeep, NativeExtract: sessionNative(),
			}},
			{Pred: "evtxwin_is_sec_logoff", Leaf: &Leaf{
				Object: "user_session", Action: "logout", Ts: "TimeCreated",
				Guid:  GuidFields("Computer", "Channel", "EventRecordId"),
				Host:  HostLabel("Computer"),
				Props: sessionProps(),
				Keep:  sessionKeep, NativeExtract: sessionNative(),
			}},
			{Pred: "evtxwin_is_sec_4778", Leaf: &Leaf{
				Object: "user_session", Action: "reconnect", Ts: "TimeCreated",
				Guid:  GuidFields("Computer", "Channel", "EventRecordId"),
				Host:  HostLabel("Computer"),
				Props: sessionProps(),
				Keep:  sessionKeep, NativeExtract: sessionNative(),
			}},
		},
	})

	register("evtx_services", Entry{
		Variants: []Variant{
			svcLeaf("evtxwin_is_sys_7045"),
			svcLeaf("evtxwin_is_sec_4697"),
		},
	})

	register("evtx_process", Entry{
		Variants: []Variant{
			{Pred: "evtxwin_is_sec_4688", Leaf: &Leaf{
				Object: "process", Action: "create", Ts: "TimeCreated",
				Guid:      GuidFields("Computer", "Channel", "EventRecordId"),
				Host:      HostLabel("Computer"),
				ParentPID: evP("ProcessId"),
				Props: []Prop{
					{"pid", HexInt(evP("NewProcessId"))},
					{"ppid", HexInt(evP("ProcessId"))},
					{"image_path", evP("NewProcessName")},
					{"exe", Basename(evP("NewProcessName"))},
					{"parent_image_path", evP("ParentProcessName")},
					{"parent_exe", Basename(evP("ParentProcessName"))},
					{"command_line", evP("CommandLine")},
					{"user", UserCanon(First(evP("TargetUserName"), evP("SubjectUserName")))},
					{"sid", First(Regex1(evP("TargetUserSid"), `^(?!S-1-0-0$)(S-.+)$`),
						evP("SubjectUserSid"))},
					{"integrity_level", MapValue(evP("MandatoryLabel"), integrityTable, false)},
					{"hostname", HostLabel("Computer")},
				},
				Keep: []string{"EventId", "EventRecordId", "Channel", "Computer",
					"Payload", "SourceFile", "MapDescription"},
				NativeExtract: []Prop{
					{"SubjectLogonId", evP("SubjectLogonId")},
					{"TokenElevationType", evP("TokenElevationType")},
					{"MandatoryLabel", evP("MandatoryLabel")},
					{"SubjectDomainName", evP("SubjectDomainName")},
				},
			}},
		},
	})
}
