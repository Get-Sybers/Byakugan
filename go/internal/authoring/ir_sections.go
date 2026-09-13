// Code generated from ir.json (phase-3 bootstrap of the non-map IR sections).
// The static IR data byakugan/{spindle.yml,pipeline.py,normalize.py} used to
// source, now authored in Go. Regenerate with scripts/gen_ir_sections.py (bootstrap
// only — hand-maintained thereafter). DO NOT edit the Python sources for these.

package authoring

import "github.com/get-sybers/byakugan/go/internal/pyjson"

func irMarkerKinds() pyjson.Value {
	return pa(
		"at",
		"basename",
		"concat",
		"const",
		"domain_of",
		"epoch_ts",
		"exe_path",
		"ext",
		"first",
		"hex_int",
		"host_label",
		"lower",
		"map_value",
		"payload",
		"regex1",
		"replace",
		"ts_before",
		"unescape_backslashes",
		"user_canon",
		"userdata",
		"win_program_name",
		"win_program_path",
	)
}

func irRoutes() pyjson.Value {
	return pa(
		pa(
			"_EvtxECmd_Output",
			pa(
				"evtx_security",
				"evtx_security_sessions",
				"evtx_process",
				"evtx_services",
				"evtx_sysmon",
				"evtx_bits",
				"evtx_rdp",
				"evtx_more",
			),
		),
		pa(
			"conn.json",
			pa(
				"zeek_conn",
			),
		),
		pa(
			"dns.json",
			pa(
				"zeek_dns",
			),
		),
		pa(
			"http.json",
			pa(
				"zeek_http",
			),
		),
		pa(
			"smtp.json",
			pa(
				"zeek_smtp",
			),
		),
		pa(
			"files.json",
			pa(
				"zeek_files",
			),
		),
		pa(
			"ssl.json",
			pa(
				"zeek_ssl",
			),
		),
		pa(
			"x509.json",
			pa(
				"zeek_x509",
			),
		),
		pa(
			"dhcp.json",
			[]pyjson.Value{},
		),
		pa(
			"ntp.json",
			[]pyjson.Value{},
		),
		pa(
			"snmp.json",
			[]pyjson.Value{},
		),
		pa(
			"ocsp.json",
			[]pyjson.Value{},
		),
		pa(
			"weird.json",
			[]pyjson.Value{},
		),
		pa(
			"pe.json",
			[]pyjson.Value{},
		),
		pa(
			"packet_filter.json",
			[]pyjson.Value{},
		),
		pa(
			".L2tPrefetch",
			pa(
				"plaso_exec_prefetch",
			),
		),
		pa(
			".L2tWinreg",
			pa(
				"plaso_exec_winreg",
				"plaso_registry",
				"plaso_shellitem",
			),
		),
		pa(
			".L2tSyslog",
			pa(
				"plaso_exec_cron",
				"l2t_text",
			),
		),
		pa(
			".L2tCron",
			pa(
				"plaso_exec_cron",
			),
		),
		pa(
			".L2tFilestat",
			pa(
				"l2t_filestat",
			),
		),
		pa(
			".L2tMft",
			pa(
				"l2t_mft",
			),
		),
		pa(
			".L2tUsnjrnl",
			pa(
				"l2t_usnjrnl",
			),
		),
		pa(
			".L2tWinevt",
			pa(
				"l2t_winevt",
			),
		),
		pa(
			".L2tWinevtx",
			pa(
				"l2t_winevt",
			),
		),
		pa(
			".L2tMsiecf",
			pa(
				"l2t_msiecf",
			),
		),
		pa(
			".L2tFirefoxCache",
			pa(
				"l2t_firefox_cache",
			),
		),
		pa(
			".L2tSqlite",
			pa(
				"l2t_firefox_places",
			),
		),
		pa(
			".L2tJavaIdx",
			pa(
				"l2t_javaidx",
			),
		),
		pa(
			".L2tLnk",
			pa(
				"l2t_lnk",
				"plaso_shellitem",
			),
		),
		pa(
			".L2tRecycleBinInfo2",
			pa(
				"l2t_recyclebin",
			),
		),
		pa(
			".L2tRecycleBin",
			pa(
				"l2t_recyclebin",
			),
		),
		pa(
			".L2tPe",
			pa(
				"plaso_pecoff",
			),
		),
		pa(
			".L2tOlecf",
			pa(
				"plaso_olecf",
			),
		),
		pa(
			".L2tRplog",
			[]pyjson.Value{},
		),
		pa(
			".L2tFseventsd",
			pa(
				"plaso_fseventsd",
			),
		),
		pa(
			".L2tEsedb",
			pa(
				"l2t_srum",
			),
		),
		pa(
			"_RECmd_Batch_",
			pa(
				"recmd_batch",
			),
		),
		pa(
			"jlecmd_AutomaticDestinations",
			pa(
				"jlecmd_dest",
			),
		),
		pa(
			"jlecmd_CustomDestinations",
			[]pyjson.Value{},
		),
		pa(
			"_LECmd_Output",
			[]pyjson.Value{},
		),
		pa(
			"recmd_batch.json",
			pa(
				"recmd_batch",
			),
		),
		pa(
			"NetworkDataUsage",
			pa(
				"esedump_srum",
			),
		),
		pa(
			"ApplicationResourceUsage",
			pa(
				"esedump_srum",
			),
		),
		pa(
			"PrefetchDump_Output",
			pa(
				"prefetch_dump",
			),
		),
		pa(
			".L2tUtmp",
			pa(
				"l2t_utmp",
			),
		),
		pa(
			".L2tUtmpx",
			pa(
				"l2t_utmpx",
			),
		),
		pa(
			".L2tText",
			pa(
				"l2t_text",
			),
		),
	)
}

func irEvtxMaps() pyjson.Value {
	return pa(
		"evtx_security",
		"evtx_security_sessions",
		"evtx_process",
		"evtx_services",
		"evtx_sysmon",
		"evtx_bits",
		"evtx_rdp",
		"evtx_more",
	)
}

func irAdapters() pyjson.Value {
	return po(
		"jlecmd_dest", po(
			"adapter", "jlecmd",
			"maps", pa(
				"jlecmd_dest",
			),
		),
		"l2t_winevt", po(
			"adapter", "winevt",
			"maps", pa(
				"evtx_security",
				"evtx_security_sessions",
				"evtx_process",
				"evtx_services",
				"evtx_sysmon",
				"evtx_bits",
				"evtx_rdp",
				"evtx_more",
			),
		),
	)
}

func irCanonUser() pyjson.Value {
	return po(
		"wellknown_sids", po(
			"S-1-0-0", "NULL SID",
			"S-1-1-0", "EVERYONE",
			"S-1-2-0", "LOCAL",
			"S-1-3-0", "CREATOR OWNER",
			"S-1-3-1", "CREATOR GROUP",
			"S-1-5-11", "AUTHENTICATED USERS",
			"S-1-5-18", "SYSTEM",
			"S-1-5-19", "LOCAL SERVICE",
			"S-1-5-20", "NETWORK SERVICE",
			"S-1-5-32-544", "ADMINISTRATORS",
			"S-1-5-32-545", "USERS",
			"S-1-5-32-546", "GUESTS",
			"S-1-5-32-547", "POWER USERS",
			"S-1-5-32-551", "BACKUP OPERATORS",
			"S-1-5-32-555", "REMOTE DESKTOP USERS",
			"S-1-5-7", "ANONYMOUS LOGON",
		),
		"wellknown_names", po(
			"ADMINISTRATORS", "ADMINISTRATORS",
			"ANONYMOUS LOGON", "ANONYMOUS LOGON",
			"AUTHENTICATED USERS", "AUTHENTICATED USERS",
			"EVERYONE", "EVERYONE",
			"LOCAL SERVICE", "LOCAL SERVICE",
			"LOCAL SYSTEM", "SYSTEM",
			"LOCALSERVICE", "LOCAL SERVICE",
			"LOCALSYSTEM", "SYSTEM",
			"NETWORK SERVICE", "NETWORK SERVICE",
			"NETWORKSERVICE", "NETWORK SERVICE",
			"SYSTEM", "SYSTEM",
			"SYSTEMPROFILE", "SYSTEM",
		),
		"wellknown_authorities", pa(
			"BUILTIN",
			"NT AUTHORITY",
		),
	)
}

func irSpindle() pyjson.Value {
	return po(
		"namespace", po(
			"CAR_NS_URL", "https://github.com/Get-Sybers/PIIAT-MitreCar/stix",
			"SPINDLE_LABEL", "spindle",
			"CAR_NS", "c59b6244-0ed6-57c9-9248-03376f66270d",
			"SPINDLE_NS", "dd668a4a-3945-5171-b031-7eb064307058",
		),
		"object_key", "_obj",
		"version_key", "_v",
		"renderings", pa(
			"str",
			"json",
		),
		"positional", po(
			"fields", pa(
				"SourceImage",
				"RecordId",
			),
			"version", pyjson.Int(1),
		),
		"identities", po(
			"l2t_filestat", po(
				"object", "file",
				"kind", "entity",
				"scope", "intrinsic",
				"version", pyjson.Int(1),
				"identity", pa(
					pa(
						"file_path",
						"file_path",
						nil,
					),
					pa(
						"event_time",
						"timestamp",
						nil,
					),
				),
			),
			"l2t_firefox_cache", po(
				"object", "http",
				"kind", "entity",
				"scope", "intrinsic",
				"version", pyjson.Int(1),
				"identity", pa(
					pa(
						"db_path",
						"native.artefact_file",
						nil,
					),
					pa(
						"url",
						"url_full",
						nil,
					),
					pa(
						"visit_time",
						"timestamp",
						nil,
					),
				),
			),
			"l2t_firefox_places", po(
				"object", "http",
				"kind", "entity",
				"scope", "intrinsic",
				"version", pyjson.Int(1),
				"identity", pa(
					pa(
						"db_path",
						"native.artefact_file",
						nil,
					),
					pa(
						"url",
						"url_full",
						nil,
					),
					pa(
						"visit_time",
						"timestamp",
						nil,
					),
				),
			),
			"l2t_javaidx", po(
				"object", "http",
				"kind", "entity",
				"scope", "intrinsic",
				"version", pyjson.Int(1),
				"identity", pa(
					pa(
						"db_path",
						"native.artefact_file",
						nil,
					),
					pa(
						"url",
						"url_full",
						nil,
					),
					pa(
						"visit_time",
						"timestamp",
						nil,
					),
				),
			),
			"l2t_lnk", po(
				"object", "file",
				"kind", "entity",
				"scope", "intrinsic",
				"version", pyjson.Int(1),
				"identity", pa(
					pa(
						"lnk_file",
						"native.lnk_file",
						nil,
					),
					pa(
						"file_path",
						"file_path",
						nil,
					),
					pa(
						"event_time",
						"timestamp",
						nil,
					),
				),
			),
			"l2t_mft", po(
				"object", "file",
				"kind", "record",
				"scope", "intrinsic",
				"version", pyjson.Int(1),
				"identity", pa(
					pa(
						"file_reference",
						"native.file_reference",
						nil,
					),
					pa(
						"event_time",
						"timestamp",
						nil,
					),
				),
			),
			"l2t_msiecf", po(
				"object", "http",
				"kind", "entity",
				"scope", "intrinsic",
				"version", pyjson.Int(1),
				"identity", pa(
					pa(
						"db_path",
						"native.artefact_file",
						nil,
					),
					pa(
						"url",
						"url_full",
						nil,
					),
					pa(
						"visit_time",
						"timestamp",
						nil,
					),
				),
			),
			"l2t_recyclebin", po(
				"object", "file",
				"kind", "entity",
				"scope", "intrinsic",
				"version", pyjson.Int(1),
				"identity", pa(
					pa(
						"artefact_file",
						"native.artefact_file",
						nil,
					),
					pa(
						"file_path",
						"file_path",
						nil,
					),
					pa(
						"event_time",
						"timestamp",
						nil,
					),
				),
			),
			"l2t_srum/application_usage", po(
				"object", "process",
				"kind", "entity",
				"scope", "intrinsic",
				"version", pyjson.Int(1),
				"identity", pa(
					pa(
						"application",
						"native.application",
						nil,
					),
					pa(
						"user_identifier",
						"native.user_identifier",
						nil,
					),
					pa(
						"recorded_time",
						"timestamp",
						nil,
					),
				),
			),
			"l2t_srum/network_usage", po(
				"object", "flow",
				"kind", "entity",
				"scope", "intrinsic",
				"version", pyjson.Int(1),
				"identity", pa(
					pa(
						"application",
						"native.application",
						nil,
					),
					pa(
						"user_identifier",
						"native.user_identifier",
						nil,
					),
					pa(
						"interface_luid",
						"native.interface_luid",
						nil,
					),
					pa(
						"recorded_time",
						"timestamp",
						nil,
					),
				),
			),
			"l2t_text", po(
				"object", "user_session",
				"kind", "entity",
				"scope", "intrinsic",
				"version", pyjson.Int(1),
				"identity", pa(
					pa(
						"pid",
						"owning_pid",
						nil,
					),
					pa(
						"user",
						"user",
						nil,
					),
					pa(
						"event_time",
						"timestamp",
						nil,
					),
				),
			),
			"l2t_usnjrnl", po(
				"object", "file",
				"kind", "record",
				"scope", "intrinsic",
				"version", pyjson.Int(1),
				"identity", pa(
					pa(
						"usn",
						"native.update_sequence_number",
						nil,
					),
					pa(
						"file_reference",
						"native.file_reference",
						nil,
					),
				),
			),
			"l2t_utmp", po(
				"object", "user_session",
				"kind", "entity",
				"scope", "intrinsic",
				"version", pyjson.Int(1),
				"identity", pa(
					pa(
						"pid",
						"owning_pid",
						nil,
					),
					pa(
						"terminal",
						"native.terminal",
						nil,
					),
					pa(
						"event_time",
						"timestamp",
						nil,
					),
				),
			),
			"l2t_utmpx", po(
				"object", "user_session",
				"kind", "entity",
				"scope", "intrinsic",
				"version", pyjson.Int(1),
				"identity", pa(
					pa(
						"pid",
						"owning_pid",
						nil,
					),
					pa(
						"terminal",
						"native.terminal",
						nil,
					),
					pa(
						"event_time",
						"timestamp",
						nil,
					),
				),
			),
			"plaso_exec_cron", po(
				"object", "process",
				"kind", "entity",
				"scope", "intrinsic",
				"version", pyjson.Int(1),
				"identity", pa(
					pa(
						"command",
						"command_line",
						nil,
					),
					pa(
						"pid",
						"pid",
						nil,
					),
					pa(
						"event_time",
						"timestamp",
						nil,
					),
				),
			),
			"plaso_exec_prefetch", po(
				"object", "process",
				"kind", "entity",
				"scope", "intrinsic",
				"version", pyjson.Int(1),
				"identity", pa(
					pa(
						"exe",
						"exe",
						nil,
					),
					pa(
						"prefetch_hash",
						"native.prefetch_hash",
						nil,
					),
					pa(
						"run_time",
						"timestamp",
						nil,
					),
				),
			),
			"plaso_exec_winreg/amcache", po(
				"object", "process",
				"kind", "entity",
				"scope", "intrinsic",
				"version", pyjson.Int(1),
				"identity", pa(
					pa(
						"image_path",
						"image_path",
						nil,
					),
					pa(
						"recorded_time",
						"timestamp",
						nil,
					),
				),
			),
			"plaso_exec_winreg/amcache_link_time", po(
				"object", "file",
				"kind", "entity",
				"scope", "intrinsic",
				"version", pyjson.Int(1),
				"identity", pa(
					pa(
						"file_path",
						"file_path",
						nil,
					),
					pa(
						"sha1",
						"sha1_hash",
						nil,
					),
				),
			),
			"plaso_exec_winreg/appcompatcache", po(
				"object", "process",
				"kind", "entity",
				"scope", "intrinsic",
				"version", pyjson.Int(1),
				"identity", pa(
					pa(
						"image_path",
						"image_path",
						nil,
					),
					pa(
						"recorded_time",
						"timestamp",
						nil,
					),
				),
			),
			"plaso_exec_winreg/bam", po(
				"object", "process",
				"kind", "entity",
				"scope", "intrinsic",
				"version", pyjson.Int(1),
				"identity", pa(
					pa(
						"key_path",
						"native.key_path",
						nil,
					),
					pa(
						"image_path",
						"image_path",
						nil,
					),
					pa(
						"event_time",
						"timestamp",
						nil,
					),
				),
			),
			"plaso_exec_winreg/userassist", po(
				"object", "process",
				"kind", "entity",
				"scope", "intrinsic",
				"version", pyjson.Int(1),
				"identity", pa(
					pa(
						"key_path",
						"native.key_path",
						nil,
					),
					pa(
						"value_name",
						"native.value_name",
						nil,
					),
					pa(
						"event_time",
						"timestamp",
						nil,
					),
				),
			),
			"plaso_fseventsd", po(
				"object", "file",
				"kind", "record",
				"scope", "intrinsic",
				"version", pyjson.Int(1),
				"identity", pa(
					pa(
						"event_identifier",
						"native.event_identifier",
						nil,
					),
					pa(
						"file_path",
						"file_path",
						nil,
					),
				),
			),
			"plaso_olecf", po(
				"object", "file",
				"kind", "entity",
				"scope", "intrinsic",
				"version", pyjson.Int(1),
				"identity", pa(
					pa(
						"file_path",
						"file_path",
						nil,
					),
					pa(
						"event_time",
						"timestamp",
						nil,
					),
				),
			),
			"plaso_pecoff", po(
				"object", "file",
				"kind", "entity",
				"scope", "intrinsic",
				"version", pyjson.Int(1),
				"identity", pa(
					pa(
						"file_path",
						"file_path",
						nil,
					),
					pa(
						"sha256",
						"sha256_hash",
						nil,
					),
				),
			),
			"plaso_registry", po(
				"object", "registry",
				"kind", "entity",
				"scope", "intrinsic",
				"version", pyjson.Int(1),
				"identity", pa(
					pa(
						"hive",
						"hive",
						nil,
					),
					pa(
						"key_path",
						"key",
						nil,
					),
					pa(
						"last_write",
						"timestamp",
						nil,
					),
				),
			),
			"plaso_shellitem", po(
				"object", "file",
				"kind", "entity",
				"scope", "intrinsic",
				"version", pyjson.Int(1),
				"identity", pa(
					pa(
						"origin",
						"native.origin",
						nil,
					),
					pa(
						"file_path",
						"file_path",
						nil,
					),
					pa(
						"event_time",
						"timestamp",
						nil,
					),
				),
			),
		),
		"external", po(
			"esedump_srum_application", po(
				"object", "process",
				"form", po(
					"fields", pa(
						"AppId",
						"UserId",
						"TimeStamp",
					),
				),
			),
			"esedump_srum_network", po(
				"object", "flow",
				"form", po(
					"fields", pa(
						"AppId",
						"UserId",
						"InterfaceLuid",
						"TimeStamp",
						"BytesSent",
						"BytesRecvd",
					),
				),
			),
			"evtx_record", po(
				"object", "process",
				"form", po(
					"fields", pa(
						"Computer",
						"Channel",
						"EventRecordId",
					),
				),
			),
			"jlecmd_entry", po(
				"object", "file",
				"form", po(
					"fields", pa(
						"SourceFile",
						"EntryNumber",
					),
				),
			),
			"memory_proc_offset", po(
				"object", "process",
				"form", po(
					"form", "proc-{hex}",
				),
			),
			"prefetch_dump_pf", po(
				"object", "process",
				"form", po(
					"fields", pa(
						"Executable",
						"Hash",
					),
				),
			),
			"recmd_value", po(
				"object", "registry",
				"form", po(
					"fields", pa(
						"HivePath",
						"KeyPath",
						"ValueName",
					),
				),
			),
			"sysmon_process_guid", po(
				"object", "process",
				"form", po(
					"marker", po(
						"payload", "ProcessGuid",
					),
				),
			),
			"zeek_cert_fp", po(
				"object", "file",
				"form", po(
					"field", "fingerprint",
				),
			),
			"zeek_fuid", po(
				"object", "file",
				"form", po(
					"fields", pa(
						"fuid",
					),
				),
			),
			"zeek_uid", po(
				"object", "flow",
				"form", po(
					"field", "uid",
				),
			),
			"zeek_uid_trans_depth", po(
				"object", "http",
				"form", po(
					"fields", pa(
						"uid",
						"trans_depth",
					),
				),
			),
			"zeek_uid_trans_id", po(
				"object", "flow",
				"form", po(
					"fields", pa(
						"uid",
						"trans_id",
					),
				),
			),
		),
	)
}

func irGolden() pyjson.Value {
	return po(
		"spindle", po(
			"version", pyjson.Int(1),
			"recipe", po(
				"canonical_json", po(
					"input", po(
						"b", pyjson.Int(1),
						"a", "é",
					),
					"output", "{\"a\":\"é\",\"b\":1}",
				),
				"namespaces", po(
					"STIX_NS", "00abedb4-aa42-466c-9c01-fed23315a9b7",
					"CAR_NS", "c59b6244-0ed6-57c9-9248-03376f66270d",
					"SPINDLE_NS", "dd668a4a-3945-5171-b031-7eb064307058",
				),
				"mint", "guid = uuid5(SPINDLE_NS, canonical_json(key))",
			),
		),
		"positional", po(
			"version", pyjson.Int(1),
			"fields", pa(
				"SourceImage",
				"RecordId",
			),
			"source", "synthetic",
			"key", po(
				"_obj", "file",
				"_v", pyjson.Int(1),
				"SourceImage", "M57-JO.jsonl",
				"RecordId", "42",
			),
			"guid", "b04cd5e3-8531-5596-a584-85f82067a885",
		),
		"identities", pa(
			po(
				"name", "l2t_filestat",
				"kind", "entity",
				"version", pyjson.Int(1),
				"source", "real",
				"key", po(
					"_obj", "file",
					"_v", pyjson.Int(1),
					"file_path", "\\Program Files\\app\\FPEXT.MSG",
					"event_time", "2020-09-16T13:14:30.462820Z",
				),
				"guid", "445da026-0327-550f-8ca8-f3e7e41725c2",
			),
			po(
				"name", "l2t_firefox_cache",
				"kind", "entity",
				"version", pyjson.Int(1),
				"source", "synthetic",
				"key", po(
					"_obj", "http",
					"_v", pyjson.Int(1),
					"db_path", "NTFS:\\Documents and Settings\\Jo\\Local Settings\\Application Data\\Mozilla\\Firefox\\Profiles\\x.default\\Cache\\_CACHE_001_",
					"url", "http://windowsupdate.microsoft.com/",
					"visit_time", "2009-11-20T19:13:29.625000Z",
				),
				"guid", "5a07b777-ec7a-5992-953d-0dab657162a8",
			),
			po(
				"name", "l2t_firefox_places",
				"kind", "entity",
				"version", pyjson.Int(1),
				"source", "synthetic",
				"key", po(
					"_obj", "http",
					"_v", pyjson.Int(1),
					"db_path", "NTFS:\\Documents and Settings\\Jo\\Application Data\\Mozilla\\Firefox\\Profiles\\x.default\\places.sqlite",
					"url", "http://windowsupdate.microsoft.com/",
					"visit_time", "2009-11-20T19:13:29.625000Z",
				),
				"guid", "36cc0018-5671-5965-953c-2d84e3b35019",
			),
			po(
				"name", "l2t_javaidx",
				"kind", "entity",
				"version", pyjson.Int(1),
				"source", "synthetic",
				"key", po(
					"_obj", "http",
					"_v", pyjson.Int(1),
					"db_path", "NTFS:\\Documents and Settings\\Jo\\Application Data\\Sun\\Java\\Deployment\\cache\\6.0\\12\\1e0d05cc-6a7b1b6d.idx",
					"url", "http://dl.javafx.com/jogl.jar",
					"visit_time", "2009-11-20T19:13:29.625000Z",
				),
				"guid", "9aa795b3-141c-578b-b5c5-c388728a9af5",
			),
			po(
				"name", "l2t_lnk",
				"kind", "entity",
				"version", pyjson.Int(1),
				"source", "synthetic",
				"key", po(
					"_obj", "file",
					"_v", pyjson.Int(1),
					"lnk_file", "NTFS:\\Documents and Settings\\Jo\\Desktop\\OpenOffice.org.lnk",
					"file_path", "C:\\Program Files\\OO3\\soffice.exe",
					"event_time", "2009-11-20T19:13:29.625000Z",
				),
				"guid", "990e99d8-f356-5869-aca4-7560c253692a",
			),
			po(
				"name", "l2t_mft",
				"kind", "record",
				"version", pyjson.Int(1),
				"source", "synthetic",
				"key", po(
					"_obj", "file",
					"_v", pyjson.Int(1),
					"file_reference", "843",
					"event_time", "2020-09-16T13:14:30.462820Z",
				),
				"guid", "8750caa0-0755-5d4f-b487-850d6047eaf7",
			),
			po(
				"name", "l2t_msiecf",
				"kind", "entity",
				"version", pyjson.Int(1),
				"source", "synthetic",
				"key", po(
					"_obj", "http",
					"_v", pyjson.Int(1),
					"db_path", "NTFS:\\Documents and Settings\\Jo\\Local Settings\\Temporary Internet Files\\Content.IE5\\index.dat",
					"url", "http://windowsupdate.microsoft.com/x",
					"visit_time", "2009-11-20T19:13:29.625000Z",
				),
				"guid", "14f16528-69d8-58ab-998f-c20fe74b0363",
			),
			po(
				"name", "l2t_recyclebin",
				"kind", "entity",
				"version", pyjson.Int(1),
				"source", "synthetic",
				"key", po(
					"_obj", "file",
					"_v", pyjson.Int(1),
					"artefact_file", "NTFS:\\RECYCLER\\S-1-5-21-606747145-1547161642-1644491937-500\\INFO2",
					"file_path", "C:\\Documents and Settings\\Jo\\secret.xls",
					"event_time", "2009-11-20T19:13:29.625000Z",
				),
				"guid", "6dff9f7e-ae52-52a4-957d-fd69919ff658",
			),
			po(
				"name", "l2t_srum/application_usage",
				"kind", "entity",
				"version", pyjson.Int(1),
				"source", "synthetic",
				"key", po(
					"_obj", "process",
					"_v", pyjson.Int(1),
					"application", "\\Device\\HarddiskVolume4\\Windows\\System32\\LogonUI.exe",
					"user_identifier", "S-1-5-18",
					"recorded_time", "2018-03-27T12:19:00Z",
				),
				"guid", "f5306754-3e3f-583b-80a6-850e75be574b",
			),
			po(
				"name", "l2t_srum/network_usage",
				"kind", "entity",
				"version", pyjson.Int(1),
				"source", "synthetic",
				"key", po(
					"_obj", "flow",
					"_v", pyjson.Int(1),
					"application", "DiagTrack",
					"user_identifier", "S-1-5-21-1-2-3-1001",
					"interface_luid", "19985273102270464",
					"recorded_time", "2018-03-27T12:19:00Z",
				),
				"guid", "e5505e75-40ae-5abd-b68e-ad6ac69c930b",
			),
			po(
				"name", "l2t_text",
				"kind", "entity",
				"version", pyjson.Int(1),
				"source", "real",
				"key", po(
					"_obj", "user_session",
					"_v", pyjson.Int(1),
					"pid", "3756",
					"user", "insec",
					"event_time", "2020-09-16T13:14:30.462820Z",
				),
				"guid", "a2ea3c6e-dca4-5d6f-904b-c18d69556148",
			),
			po(
				"name", "l2t_usnjrnl",
				"kind", "record",
				"version", pyjson.Int(1),
				"source", "real",
				"key", po(
					"_obj", "file",
					"_v", pyjson.Int(1),
					"usn", "1048576",
					"file_reference", "281474976727294",
				),
				"guid", "3a2ab643-e362-5270-b2ce-ff0dd75812e7",
			),
			po(
				"name", "l2t_utmp",
				"kind", "entity",
				"version", pyjson.Int(1),
				"source", "real",
				"key", po(
					"_obj", "user_session",
					"_v", pyjson.Int(1),
					"pid", "3401",
					"terminal", "tty7",
					"event_time", "2020-09-16T13:14:30.462820Z",
				),
				"guid", "66bccfff-8d8f-5f11-a5fd-06c16a14d7c2",
			),
			po(
				"name", "l2t_utmpx",
				"kind", "entity",
				"version", pyjson.Int(1),
				"source", "synthetic",
				"key", po(
					"_obj", "user_session",
					"_v", pyjson.Int(1),
					"pid", "501",
					"terminal", "ttys000",
					"event_time", "2020-09-16T13:14:30.462820Z",
				),
				"guid", "a4f7f4d0-7bc5-5f2c-a9dc-c9bfd21b2b6f",
			),
			po(
				"name", "plaso_exec_cron",
				"kind", "entity",
				"version", pyjson.Int(1),
				"source", "real",
				"key", po(
					"_obj", "process",
					"_v", pyjson.Int(1),
					"command", "test -x /etc/cron.daily/popularity-contest && /etc/cron.daily/popularity-contest --crond",
					"pid", "2534",
					"event_time", "2020-08-26T11:46:13.000000Z",
				),
				"guid", "1028f1ec-0585-59ba-b3f9-a297b0767848",
			),
			po(
				"name", "plaso_exec_prefetch",
				"kind", "entity",
				"version", pyjson.Int(1),
				"source", "real",
				"key", po(
					"_obj", "process",
					"_v", pyjson.Int(1),
					"exe", "SVCHOST.EXE",
					"prefetch_hash", "892401266",
					"run_time", "2009-11-20T09:31:29.671875Z",
				),
				"guid", "4c294458-58b8-53f8-a08e-5e061deeb6a6",
			),
			po(
				"name", "plaso_exec_winreg/amcache",
				"kind", "entity",
				"version", pyjson.Int(1),
				"source", "synthetic",
				"key", po(
					"_obj", "process",
					"_v", pyjson.Int(1),
					"image_path", "c:\\users\\bob\\downloads\\evil.exe",
					"recorded_time", "2023-05-01T10:00:00.000000Z",
				),
				"guid", "76356f08-7ebe-57f4-a18f-dae52ef93374",
			),
			po(
				"name", "plaso_exec_winreg/amcache_link_time",
				"kind", "entity",
				"version", pyjson.Int(1),
				"source", "synthetic",
				"key", po(
					"_obj", "file",
					"_v", pyjson.Int(1),
					"file_path", "c:\\users\\bob\\downloads\\evil.exe",
					"sha1", "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
				),
				"guid", "af665d74-c954-5517-a1e4-577adeea633d",
			),
			po(
				"name", "plaso_exec_winreg/appcompatcache",
				"kind", "entity",
				"version", pyjson.Int(1),
				"source", "real",
				"key", po(
					"_obj", "process",
					"_v", pyjson.Int(1),
					"image_path", "\\??\\C:\\WINDOWS\\system32\\hkcmd.exe",
					"recorded_time", "2004-02-10T18:31:30.000000Z",
				),
				"guid", "9f7d9174-75ac-5efd-b38e-ec4be58357f1",
			),
			po(
				"name", "plaso_exec_winreg/bam",
				"kind", "entity",
				"version", pyjson.Int(1),
				"source", "synthetic",
				"key", po(
					"_obj", "process",
					"_v", pyjson.Int(1),
					"key_path", "HKEY_LOCAL_MACHINE\\System\\ControlSet001\\Services\\bam\\State\\UserSettings\\S-1-5-21-1-2-3-1001",
					"image_path", "\\Device\\HarddiskVolume2\\Windows\\System32\\notepad.exe",
					"event_time", "2023-05-01T11:00:00.000000Z",
				),
				"guid", "7e4df065-f8cb-5635-bc3d-49b7534d8163",
			),
			po(
				"name", "plaso_exec_winreg/userassist",
				"kind", "entity",
				"version", pyjson.Int(1),
				"source", "real",
				"key", po(
					"_obj", "process",
					"_v", pyjson.Int(1),
					"key_path", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{75048700-EF1F-11D0-9888-006097DEACF9}\\Count",
					"value_name", "UEME_RUNPATH:E:\\R54402.EXE",
					"event_time", "2009-11-20T01:23:45.000000Z",
				),
				"guid", "c227a3e4-2cdd-5f87-bd30-f6555633cd69",
			),
			po(
				"name", "plaso_fseventsd",
				"kind", "record",
				"version", pyjson.Int(1),
				"source", "synthetic",
				"key", po(
					"_obj", "file",
					"_v", pyjson.Int(1),
					"event_identifier", "226530",
					"file_path", "/Users/jo/Documents/notes.txt",
				),
				"guid", "4632d78d-e5d0-508d-8fe7-a18781b019da",
			),
			po(
				"name", "plaso_olecf",
				"kind", "entity",
				"version", pyjson.Int(1),
				"source", "synthetic",
				"key", po(
					"_obj", "file",
					"_v", pyjson.Int(1),
					"file_path", "\\Documents and Settings\\Jo\\My Documents\\budget.xls",
					"event_time", "2009-11-20T19:13:29.625000Z",
				),
				"guid", "139b87de-7a0a-5dd3-809e-72d0c7945d28",
			),
			po(
				"name", "plaso_pecoff",
				"kind", "entity",
				"version", pyjson.Int(1),
				"source", "synthetic",
				"key", po(
					"_obj", "file",
					"_v", pyjson.Int(1),
					"file_path", "\\Windows\\System32\\evil.dll",
					"sha256", "b5de10a000000000000000000000000000000000000000000000000000000000",
				),
				"guid", "dd7a8086-618e-560c-8687-1b56d01b75e0",
			),
			po(
				"name", "plaso_registry",
				"kind", "entity",
				"version", pyjson.Int(1),
				"source", "synthetic",
				"key", po(
					"_obj", "registry",
					"_v", pyjson.Int(1),
					"hive", "NTFS:\\WINDOWS\\system32\\config\\software",
					"key_path", "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
					"last_write", "2020-09-16T13:14:30.462820Z",
				),
				"guid", "f42566b3-3742-5364-8bf8-c90d8aa76e53",
			),
			po(
				"name", "plaso_shellitem",
				"kind", "entity",
				"version", pyjson.Int(1),
				"source", "synthetic",
				"key", po(
					"_obj", "file",
					"_v", pyjson.Int(1),
					"origin", "NTFS:\\Documents and Settings\\Jo\\Desktop\\OpenOffice.org.lnk",
					"file_path", "C:\\Program Files\\OO3\\soffice.exe",
					"event_time", "2009-11-20T19:13:29.625000Z",
				),
				"guid", "d465d1af-2c1e-5f27-b158-fab9a18cfa20",
			),
		),
		"external", pa(
			po(
				"name", "esedump_srum_application",
				"kind", "record",
				"source", "real",
				"car_object", "process",
				"values", po(
					"AppId", pyjson.Int(388),
					"UserId", pyjson.Int(951),
					"TimeStamp", "2024-02-20T07:50:59Z",
				),
				"guid", "process-388-951-2024-02-20T07:50:59Z",
			),
			po(
				"name", "esedump_srum_network",
				"kind", "record",
				"source", "real",
				"car_object", "flow",
				"values", po(
					"AppId", pyjson.Int(102),
					"UserId", pyjson.Int(8),
					"InterfaceLuid", pyjson.Int(1689399632855040),
					"TimeStamp", "2024-02-20T07:50:00Z",
					"BytesSent", pyjson.Int(2100),
					"BytesRecvd", pyjson.Int(1440),
				),
				"guid", "flow-102-8-1689399632855040-2024-02-20T07:50:00Z-2100-1440",
			),
			po(
				"name", "evtx_record",
				"kind", "record",
				"source", "real",
				"car_object", "process",
				"values", po(
					"Computer", "WIN-1M3263ACE5D",
					"Channel", "Security",
					"EventRecordId", pyjson.Int(2623),
				),
				"guid", "process-WIN-1M3263ACE5D-Security-2623",
			),
			po(
				"name", "jlecmd_entry",
				"kind", "record",
				"source", "synthetic",
				"car_object", "file",
				"values", po(
					"SourceFile", "/in/fb3b.automaticDestinations-ms",
					"EntryNumber", pyjson.Int(1),
				),
				"guid", "file-/in/fb3b.automaticDestinations-ms-1",
			),
			po(
				"name", "memory_proc_offset",
				"kind", "entity",
				"source", "synthetic",
				"car_object", "process",
				"values", po(
					"offset", pyjson.Int(6699),
				),
				"guid", "proc-1a2b",
			),
			po(
				"name", "prefetch_dump_pf",
				"kind", "entity",
				"source", "real",
				"car_object", "process",
				"values", po(
					"Executable", "ADDINUTIL.EXE",
					"Hash", "0x4E6085D4",
				),
				"guid", "process-ADDINUTIL.EXE-0x4E6085D4",
			),
			po(
				"name", "recmd_value",
				"kind", "record",
				"source", "synthetic",
				"car_object", "registry",
				"values", po(
					"HivePath", "/in/UsrClass.dat",
					"KeyPath", "S-1-5-21-1_Classes\\X",
					"ValueName", "LangID",
				),
				"guid", "registry-/in/UsrClass.dat-S-1-5-21-1_Classes\\X-LangID",
			),
			po(
				"name", "sysmon_process_guid",
				"kind", "entity",
				"source", "real",
				"car_object", "process",
				"values", po(
					"ProcessGuid", "{DFAE8213-70EB-5CDD-0000-0010F66D0A00}",
				),
				"guid", "{DFAE8213-70EB-5CDD-0000-0010F66D0A00}",
			),
			po(
				"name", "zeek_cert_fp",
				"kind", "entity",
				"source", "synthetic",
				"car_object", "file",
				"values", po(
					"fingerprint", "bac9e9e2d4e38c7716fc17dcd701dd45e226cd9b623f21e9a145921fb5b6dc4d",
				),
				"guid", "bac9e9e2d4e38c7716fc17dcd701dd45e226cd9b623f21e9a145921fb5b6dc4d",
			),
			po(
				"name", "zeek_fuid",
				"kind", "entity",
				"source", "synthetic",
				"car_object", "file",
				"values", po(
					"fuid", "FdEQ",
				),
				"guid", "file-FdEQ",
			),
			po(
				"name", "zeek_uid",
				"kind", "entity",
				"source", "synthetic",
				"car_object", "flow",
				"values", po(
					"uid", "CtEReq24zLXEGt4V67",
				),
				"guid", "CtEReq24zLXEGt4V67",
			),
			po(
				"name", "zeek_uid_trans_depth",
				"kind", "record",
				"source", "synthetic",
				"car_object", "http",
				"values", po(
					"uid", "Cno6",
					"trans_depth", pyjson.Int(1),
				),
				"guid", "http-Cno6-1",
			),
			po(
				"name", "zeek_uid_trans_id",
				"kind", "record",
				"source", "synthetic",
				"car_object", "flow",
				"values", po(
					"uid", "CEVU",
					"trans_id", pyjson.Int(23150),
				),
				"guid", "flow-CEVU-23150",
			),
		),
	)
}
