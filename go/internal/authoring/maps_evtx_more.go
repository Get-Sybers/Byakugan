package authoring

// evtx_more — additional Windows event-log → CAR maps (Go-native port of
// byakugan/mappings/evtx_more.py). One key, evtx_more, with seven variants:
//   4907(File)→file/acl_modify, WMI 5857→module/load, PnP 20003→service/create,
//   SMB 30803→flow/start, Winlogon 7001/7002→user_session login/logout,
//   SCM 7034→service/stop.
//
// Predicates em_is_* are already in go/internal/predicates. EVTX_HOST /
// EVTX_FQDN / EVTX_KEEP mirror byakugan/mappings/_common.py.

var evtxMoreKeep = []string{
	"EventId", "EventRecordId", "Channel", "Computer", "Provider",
	"Payload", "SourceFile", "MapDescription", "UserName",
}

// evtxFqdn is EVTX_FQDN: the Computer value only when it is a real FQDN.
func evtxFqdn() Src { return Regex1("Computer", `^([^.]+\..+)$`) }

func init() {
	register("evtx_more", Entry{
		Variants: []Variant{
			{Pred: "em_is_4907_file", Leaf: &Leaf{
				Object: "file", Action: "acl_modify", Ts: "TimeCreated",
				Guid:      GuidFields("Computer", "Channel", "EventRecordId"),
				Host:      HostLabel("Computer"),
				OwningPID: evP("ProcessId"),
				Props: []Prop{
					{"file_path", evP("ObjectName")},
					{"file_name", Basename(evP("ObjectName"))},
					{"extension", Ext(evP("ObjectName"))},
					{"image_path", evP("ProcessName")},
					{"pid", HexInt(evP("ProcessId"))},
					{"user", UserCanon(evP("SubjectUserName"))},
					{"hostname", HostLabel("Computer")},
					{"fqdn", evtxFqdn()},
				},
				Keep: evtxMoreKeep,
				NativeExtract: []Prop{
					{"OldSd", evP("OldSd")},
					{"NewSd", evP("NewSd")},
					{"HandleId", evP("HandleId")},
					{"ObjectServer", evP("ObjectServer")},
					{"SubjectLogonId", evP("SubjectLogonId")},
				},
			}},
			{Pred: "em_is_wmi_5857", Leaf: &Leaf{
				Object: "module", Action: "load", Ts: "TimeCreated",
				Guid:      GuidFields("Computer", "Channel", "EventRecordId"),
				Host:      HostLabel("Computer"),
				OwningPID: evU("ProcessID"),
				Props: []Prop{
					{"module_path", evU("ProviderPath")},
					{"module_name", Basename(evU("ProviderPath"))},
					{"image_path", evU("HostProcess")},
					{"pid", evU("ProcessID")},
					{"hostname", HostLabel("Computer")},
					{"fqdn", evtxFqdn()},
				},
				Keep: evtxMoreKeep,
				NativeExtract: []Prop{
					{"ProviderName", evU("ProviderName")},
					{"Code", evU("Code")},
				},
			}},
			{Pred: "em_is_pnp_20003", Leaf: &Leaf{
				Object: "service", Action: "create", Ts: "TimeCreated",
				Guid: GuidFields("Computer", "Channel", "EventRecordId"),
				Host: HostLabel("Computer"),
				Props: []Prop{
					{"name", evU("ServiceName")},
					{"image_path", evU("DriverFileName")},
					{"exe", Basename(evU("DriverFileName"))},
					{"hostname", HostLabel("Computer")},
					{"fqdn", evtxFqdn()},
				},
				Keep: evtxMoreKeep,
				NativeExtract: []Prop{
					{"DeviceInstanceID", evU("DeviceInstanceID")},
					{"PrimaryService", evU("PrimaryService")},
					{"AddServiceStatus", evU("AddServiceStatus")},
				},
			}},
			{Pred: "em_is_smb_30803", Leaf: &Leaf{
				Object: "flow", Action: "start", Ts: "TimeCreated",
				Guid: GuidFields("Computer", "Channel", "EventRecordId"),
				Host: HostLabel("Computer"),
				Props: []Prop{
					{"dest_fqdn", evP("ServerName")},
					{"start_time", "TimeCreated"},
					{"hostname", HostLabel("Computer")},
					{"fqdn", evtxFqdn()},
				},
				Keep: evtxMoreKeep,
				NativeExtract: []Prop{
					{"RemoteAddress", evP("RemoteAddress")},
					{"LocalAddress", evP("LocalAddress")},
					{"Status", evP("Status")},
					{"Reason", evP("Reason")},
				},
			}},
			{Pred: "em_is_winlogon_7001", Leaf: &Leaf{
				Object: "user_session", Action: "login", Ts: "TimeCreated",
				Guid: GuidFields("Computer", "Channel", "EventRecordId"),
				Host: HostLabel("Computer"),
				Props: []Prop{
					{"uid", evP("UserSid")},
					{"login_successful", Const(true)},
					{"hostname", HostLabel("Computer")},
				},
				Keep:          evtxMoreKeep,
				NativeExtract: []Prop{{"TSId", evP("TSId")}},
			}},
			{Pred: "em_is_winlogon_7002", Leaf: &Leaf{
				Object: "user_session", Action: "logout", Ts: "TimeCreated",
				Guid: GuidFields("Computer", "Channel", "EventRecordId"),
				Host: HostLabel("Computer"),
				Props: []Prop{
					{"uid", evP("UserSid")},
					{"hostname", HostLabel("Computer")},
				},
				Keep:          evtxMoreKeep,
				NativeExtract: []Prop{{"TSId", evP("TSId")}},
			}},
			{Pred: "em_is_scm_7034", Leaf: &Leaf{
				Object: "service", Action: "stop", Ts: "TimeCreated",
				Guid: GuidFields("Computer", "Channel", "EventRecordId"),
				Host: HostLabel("Computer"),
				Props: []Prop{
					{"name", evP("param1")},
					{"hostname", HostLabel("Computer")},
					{"fqdn", evtxFqdn()},
				},
				Keep:          evtxMoreKeep,
				NativeExtract: []Prop{{"param2", evP("param2")}},
			}},
		},
	})
}
