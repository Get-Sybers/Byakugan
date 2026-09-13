package authoring

// evtx_sysmon — the Sysmon EVTX data source (Go-native port of
// byakugan/mappings/sysmon.py + _common.py). The biggest single map: 13
// variants across process/flow/file/registry/module/driver/thread objects.
// EID1/EID5 (process create/terminate) carry a record identity from the
// ProcessGuid marker; every other variant uses the shared record-guid
// (Computer, Channel, EventRecordId). Predicates sysmon_* are already in
// go/internal/predicates.

import "github.com/get-sybers/byakugan/go/internal/pyjson"

// pl is a Payload-field source: {"!":["payload","Payload",<key>]}.
func sysPl(key string) Src { return Payload("Payload", key) }

// shared host / fqdn / user / hash leaves (fresh envelopes per call).
func sysHost() Src         { return HostLabel("Computer") }
func sysFqdn() Src         { return Regex1("Computer", `^([^.]+\..+)$`) }
func sysUser(f string) Src { return UserCanon(sysPl(f)) }
func sysHash(algo string) Src {
	return Lower(Regex1(sysPl("Hashes"), `(?i)\b`+algo+`=([0-9A-Fa-f]+)`))
}

// signature_valid: map_value with a boolean-valued table {"Valid": true}.
func sysSigValid() Src {
	t := pyjson.NewObject()
	t.Set("Valid", true)
	return env("map_value", sysPl("SignatureStatus"), t, false)
}

var sysmonKeep = []string{
	"EventId", "EventRecordId", "Channel", "Computer", "Provider",
	"Payload", "SourceFile", "MapDescription", "UserName", "ExecutableInfo",
}

func init() {
	register("evtx_sysmon", Entry{
		Variants: []Variant{
			// 1: process create (EID 1) — ProcessGuid record identity.
			{Pred: "sysmon_proc_create", Leaf: &Leaf{
				Object: "process", Action: "create", Ts: "TimeCreated",
				Guid:       GuidMarker(sysPl("ProcessGuid")),
				Host:       sysHost(),
				OwningPID:  sysPl("ProcessId"),
				OwningGuid: sysPl("ProcessGuid"),
				ParentPID:  sysPl("ParentProcessId"),
				Props: []Prop{
					{"exe", sysPl("Image")},
					{"image_path", sysPl("Image")},
					{"parent_exe", sysPl("ParentImage")},
					{"parent_image_path", sysPl("ParentImage")},
					{"command_line", sysPl("CommandLine")},
					{"parent_command_line", sysPl("ParentCommandLine")},
					{"current_working_directory", sysPl("CurrentDirectory")},
					{"integrity_level", sysPl("IntegrityLevel")},
					{"pid", sysPl("ProcessId")},
					{"ppid", sysPl("ParentProcessId")},
					{"user", sysUser("User")},
					{"md5_hash", sysHash("MD5")},
					{"sha1_hash", sysHash("SHA1")},
					{"sha256_hash", sysHash("SHA256")},
					{"hostname", sysHost()},
					{"fqdn", sysFqdn()},
				},
				Keep: sysmonKeep,
				NativeExtract: []Prop{
					{"UtcTime", sysPl("UtcTime")},
					{"ParentProcessGuid", sysPl("ParentProcessGuid")},
					{"LogonId", sysPl("LogonId")},
					{"LogonGuid", sysPl("LogonGuid")},
					{"OriginalFileName", sysPl("OriginalFileName")},
					{"Company", sysPl("Company")},
					{"Product", sysPl("Product")},
					{"Description", sysPl("Description")},
					{"FileVersion", sysPl("FileVersion")},
					{"ParentUser", sysPl("ParentUser")},
					{"Imphash", sysHash("IMPHASH")},
				},
			}},
			// 2: process terminate (EID 5) — ProcessGuid record identity.
			{Pred: "sysmon_proc_terminate", Leaf: &Leaf{
				Object: "process", Action: "terminate", Ts: "TimeCreated",
				Guid:       GuidMarker(sysPl("ProcessGuid")),
				Host:       sysHost(),
				OwningPID:  sysPl("ProcessId"),
				OwningGuid: sysPl("ProcessGuid"),
				Props: []Prop{
					{"exe", sysPl("Image")},
					{"image_path", sysPl("Image")},
					{"pid", sysPl("ProcessId")},
					{"user", sysUser("User")},
					{"hostname", sysHost()},
					{"fqdn", sysFqdn()},
				},
				Keep: sysmonKeep,
				NativeExtract: []Prop{
					{"UtcTime", sysPl("UtcTime")},
				},
			}},
			// 3: network connect (EID 3) — flow start.
			{Pred: "sysmon_flow_start", Leaf: &Leaf{
				Object: "flow", Action: "start", Ts: "TimeCreated",
				Guid:       GuidFields("Computer", "Channel", "EventRecordId"),
				Host:       sysHost(),
				OwningPID:  sysPl("ProcessId"),
				OwningGuid: sysPl("ProcessGuid"),
				Props: []Prop{
					{"src_ip", sysPl("SourceIp")},
					{"src_port", sysPl("SourcePort")},
					{"src_hostname", sysPl("SourceHostname")},
					{"dest_ip", sysPl("DestinationIp")},
					{"dest_port", sysPl("DestinationPort")},
					{"dest_hostname", sysPl("DestinationHostname")},
					{"transport_protocol", sysPl("Protocol")},
					{"network_direction", MapValue(sysPl("Initiated"),
						map[string]string{"FALSE": "inbound", "TRUE": "outbound"}, true)},
					{"exe", sysPl("Image")},
					{"image_path", sysPl("Image")},
					{"pid", sysPl("ProcessId")},
					{"user", sysUser("User")},
					{"start_time", "TimeCreated"},
					{"hostname", sysHost()},
					{"fqdn", sysFqdn()},
				},
				Keep: sysmonKeep,
				NativeExtract: []Prop{
					{"UtcTime", sysPl("UtcTime")},
				},
			}},
			// 4: file create (EID 11).
			{Pred: "sysmon_file_create", Leaf: &Leaf{
				Object: "file", Action: "create", Ts: "TimeCreated",
				Guid:       GuidFields("Computer", "Channel", "EventRecordId"),
				Host:       sysHost(),
				OwningPID:  sysPl("ProcessId"),
				OwningGuid: sysPl("ProcessGuid"),
				Props: []Prop{
					{"file_path", sysPl("TargetFilename")},
					{"file_name", Basename(sysPl("TargetFilename"))},
					{"extension", Ext(sysPl("TargetFilename"))},
					{"image_path", sysPl("Image")},
					{"pid", sysPl("ProcessId")},
					{"user", sysUser("User")},
					{"hostname", sysHost()},
					{"fqdn", sysFqdn()},
					{"creation_time", Replace(sysPl("CreationUtcTime"), " ", "T")},
				},
				Keep: sysmonKeep,
				NativeExtract: []Prop{
					{"UtcTime", sysPl("UtcTime")},
					{"CreationUtcTime", sysPl("CreationUtcTime")},
					{"overwrite", TsBefore(sysPl("CreationUtcTime"), sysPl("UtcTime"))},
				},
			}},
			// 5: file delete (EID 23/26).
			{Pred: "sysmon_file_delete", Leaf: &Leaf{
				Object: "file", Action: "delete", Ts: "TimeCreated",
				Guid:       GuidFields("Computer", "Channel", "EventRecordId"),
				Host:       sysHost(),
				OwningPID:  sysPl("ProcessId"),
				OwningGuid: sysPl("ProcessGuid"),
				Props: []Prop{
					{"file_path", sysPl("TargetFilename")},
					{"file_name", Basename(sysPl("TargetFilename"))},
					{"extension", Ext(sysPl("TargetFilename"))},
					{"image_path", sysPl("Image")},
					{"pid", sysPl("ProcessId")},
					{"user", sysUser("User")},
					{"hostname", sysHost()},
					{"fqdn", sysFqdn()},
					{"md5_hash", sysHash("MD5")},
					{"sha1_hash", sysHash("SHA1")},
					{"sha256_hash", sysHash("SHA256")},
				},
				Keep: sysmonKeep,
				NativeExtract: []Prop{
					{"UtcTime", sysPl("UtcTime")},
				},
			}},
			// 6: registry key create (EID 12, add).
			{Pred: "sysmon_reg_add", Leaf: &Leaf{
				Object: "registry", Action: "add", Ts: "TimeCreated",
				Guid:       GuidFields("Computer", "Channel", "EventRecordId"),
				Host:       sysHost(),
				OwningPID:  sysPl("ProcessId"),
				OwningGuid: sysPl("ProcessGuid"),
				Props: []Prop{
					{"key", sysPl("TargetObject")},
					{"image_path", sysPl("Image")},
					{"pid", sysPl("ProcessId")},
					{"user", sysUser("User")},
					{"hostname", sysHost()},
					{"fqdn", sysFqdn()},
				},
				Keep: sysmonKeep,
				NativeExtract: []Prop{
					{"UtcTime", sysPl("UtcTime")},
					{"EventType", sysPl("EventType")},
				},
			}},
			// 7: registry key delete (EID 12, remove).
			{Pred: "sysmon_reg_remove", Leaf: &Leaf{
				Object: "registry", Action: "remove", Ts: "TimeCreated",
				Guid:       GuidFields("Computer", "Channel", "EventRecordId"),
				Host:       sysHost(),
				OwningPID:  sysPl("ProcessId"),
				OwningGuid: sysPl("ProcessGuid"),
				Props: []Prop{
					{"key", sysPl("TargetObject")},
					{"image_path", sysPl("Image")},
					{"pid", sysPl("ProcessId")},
					{"user", sysUser("User")},
					{"hostname", sysHost()},
					{"fqdn", sysFqdn()},
				},
				Keep: sysmonKeep,
				NativeExtract: []Prop{
					{"UtcTime", sysPl("UtcTime")},
					{"EventType", sysPl("EventType")},
				},
			}},
			// 8: registry value set (EID 13, value_edit).
			{Pred: "sysmon_reg_value_set", Leaf: &Leaf{
				Object: "registry", Action: "value_edit", Ts: "TimeCreated",
				Guid:       GuidFields("Computer", "Channel", "EventRecordId"),
				Host:       sysHost(),
				OwningPID:  sysPl("ProcessId"),
				OwningGuid: sysPl("ProcessGuid"),
				Props: []Prop{
					{"key", sysPl("TargetObject")},
					{"image_path", sysPl("Image")},
					{"pid", sysPl("ProcessId")},
					{"user", sysUser("User")},
					{"hostname", sysHost()},
					{"fqdn", sysFqdn()},
					{"value", Basename(sysPl("TargetObject"))},
					{"data", sysPl("Details")},
					{"new_content", sysPl("Details")},
				},
				Keep: sysmonKeep,
				NativeExtract: []Prop{
					{"UtcTime", sysPl("UtcTime")},
					{"EventType", sysPl("EventType")},
				},
			}},
			// 9: registry key/value rename (EID 14, key_edit).
			{Pred: "sysmon_reg_rename", Leaf: &Leaf{
				Object: "registry", Action: "key_edit", Ts: "TimeCreated",
				Guid:       GuidFields("Computer", "Channel", "EventRecordId"),
				Host:       sysHost(),
				OwningPID:  sysPl("ProcessId"),
				OwningGuid: sysPl("ProcessGuid"),
				Props: []Prop{
					{"key", sysPl("TargetObject")},
					{"image_path", sysPl("Image")},
					{"pid", sysPl("ProcessId")},
					{"user", sysUser("User")},
					{"hostname", sysHost()},
					{"fqdn", sysFqdn()},
				},
				Keep: sysmonKeep,
				NativeExtract: []Prop{
					{"UtcTime", sysPl("UtcTime")},
					{"EventType", sysPl("EventType")},
					{"NewName", sysPl("NewName")},
				},
			}},
			// 10: image/module load (EID 7).
			{Pred: "sysmon_module_load", Leaf: &Leaf{
				Object: "module", Action: "load", Ts: "TimeCreated",
				Guid:       GuidFields("Computer", "Channel", "EventRecordId"),
				Host:       sysHost(),
				OwningPID:  sysPl("ProcessId"),
				OwningGuid: sysPl("ProcessGuid"),
				Props: []Prop{
					{"module_path", sysPl("ImageLoaded")},
					{"module_name", Basename(sysPl("ImageLoaded"))},
					{"image_path", sysPl("Image")},
					{"pid", sysPl("ProcessId")},
					{"md5_hash", sysHash("MD5")},
					{"sha1_hash", sysHash("SHA1")},
					{"sha256_hash", sysHash("SHA256")},
					{"signer", sysPl("Signature")},
					{"signature_valid", sysSigValid()},
					{"hostname", sysHost()},
					{"fqdn", sysFqdn()},
				},
				Keep: sysmonKeep,
				NativeExtract: []Prop{
					{"UtcTime", sysPl("UtcTime")},
					{"Signed", sysPl("Signed")},
					{"Imphash", sysHash("IMPHASH")},
					{"OriginalFileName", sysPl("OriginalFileName")},
					{"Company", sysPl("Company")},
					{"Product", sysPl("Product")},
					{"Description", sysPl("Description")},
					{"FileVersion", sysPl("FileVersion")},
				},
			}},
			// 11: process access (EID 10).
			{Pred: "sysmon_proc_access", Leaf: &Leaf{
				Object: "process", Action: "access", Ts: "TimeCreated",
				Guid:       GuidFields("Computer", "Channel", "EventRecordId"),
				Host:       sysHost(),
				OwningPID:  sysPl("SourceProcessId"),
				OwningGuid: sysPl("SourceProcessGUID"),
				Props: []Prop{
					{"pid", sysPl("SourceProcessId")},
					{"image_path", sysPl("SourceImage")},
					{"exe", Basename(sysPl("SourceImage"))},
					{"target_pid", sysPl("TargetProcessId")},
					{"target_guid", sysPl("TargetProcessGUID")},
					{"target_name", Basename(sysPl("TargetImage"))},
					{"access_level", sysPl("GrantedAccess")},
					{"call_trace", sysPl("CallTrace")},
					{"user", sysUser("SourceUser")},
					{"hostname", sysHost()},
					{"fqdn", sysFqdn()},
				},
				Keep: sysmonKeep,
				NativeExtract: []Prop{
					{"UtcTime", sysPl("UtcTime")},
					{"TargetProcessGUID", sysPl("TargetProcessGUID")},
					{"TargetImage", sysPl("TargetImage")},
				},
			}},
			// 12: driver load (EID 6) — no owning process.
			{Pred: "sysmon_driver_load", Leaf: &Leaf{
				Object: "driver", Action: "load", Ts: "TimeCreated",
				Guid: GuidFields("Computer", "Channel", "EventRecordId"),
				Host: sysHost(),
				Props: []Prop{
					{"module_name", Basename(sysPl("ImageLoaded"))},
					{"image_path", sysPl("ImageLoaded")},
					{"md5_hash", sysHash("MD5")},
					{"sha1_hash", sysHash("SHA1")},
					{"sha256_hash", sysHash("SHA256")},
					{"signer", sysPl("Signature")},
					{"signature_valid", sysSigValid()},
					{"hostname", sysHost()},
					{"fqdn", sysFqdn()},
				},
				Keep: sysmonKeep,
				NativeExtract: []Prop{
					{"UtcTime", sysPl("UtcTime")},
					{"Signed", sysPl("Signed")},
					{"Imphash", sysHash("IMPHASH")},
				},
			}},
			// 13: create remote thread (EID 8).
			{Pred: "sysmon_thread_remote", Leaf: &Leaf{
				Object: "thread", Action: "remote_create", Ts: "TimeCreated",
				Guid:       GuidFields("Computer", "Channel", "EventRecordId"),
				Host:       sysHost(),
				OwningPID:  sysPl("SourceProcessId"),
				OwningGuid: sysPl("SourceProcessGuid"),
				Props: []Prop{
					{"src_pid", sysPl("SourceProcessId")},
					{"tgt_pid", sysPl("TargetProcessId")},
					{"tgt_tid", sysPl("NewThreadId")},
					{"start_address", sysPl("StartAddress")},
					{"start_module", sysPl("StartModule")},
					{"start_module_name", Basename(sysPl("StartModule"))},
					{"start_function", sysPl("StartFunction")},
					{"hostname", sysHost()},
				},
				Keep: sysmonKeep,
				NativeExtract: []Prop{
					{"UtcTime", sysPl("UtcTime")},
					{"TargetProcessGuid", sysPl("TargetProcessGuid")},
				},
			}},
		},
		Default: nil,
	})
}
