package authoring

// plaso_exec — Plaso execution evidence → CAR process (Go-native port of
// byakugan/mappings/plaso_exec.py). Three per-parser keys:
//   - plaso_exec_prefetch : windows:prefetch:execution → process/create
//   - plaso_exec_winreg   : amcache(link-time entity)/amcache/userassist/bam/
//                           appcompatcache → file or process
//   - plaso_exec_cron     : syslog:cron:task_run → process/create
// plr = payload scoped to "Record"; guids are minted spindle ids (sub-keyed for
// the winreg variants). Predicates plaso_is_* are already in Go.

// hostname / enrich scope: the image identity the lane stamps (bare, no label).
func execImgHost() Src { return plr("image_hostname") }

// amcache stores the PROGRAM's SHA-1 in file_identifier as "0000"+40hex; extract
// the 40-hex honestly, LOWERcased.
func execAmcacheSha1() Src {
	return Lower(Regex1(plr("file_identifier"), `(?i)^0000([0-9a-f]{40})$`))
}

// provenance: the ARTEFACT file (never exe/image_path) + its own hash + event.
func execProv() []Prop {
	return []Prop{
		{"data_type", plr("data_type")},
		{"timestamp_desc", plr("timestamp_desc")},
		{"artefact_file", plr("display_name")},
		{"artefact_sha256", plr("sha256_hash")},
	}
}

// common process props for the Windows execution artefacts.
func execWinProps(imagePath Src) []Prop {
	return []Prop{
		{"exe", WinProgramName(imagePath)},
		{"image_path", WinProgramPath(imagePath)},
		{"user", UserCanon(plr("username"))},
		{"hostname", execImgHost()},
	}
}

// userassist: the program is provable only from the value name.
func execUaProg() Src {
	return First(
		Regex1(plr("value_name"), `^UEME_RUNPATH:(.+)$`),
		Regex1(plr("value_name"), `^(?!UEME_)(.+)$`))
}

// shimcache: what the row's timestamp MEANS — none is a proven run time.
func execShimcacheTimeMeaning() Src {
	return First(
		MapValue(plr("timestamp_desc"), map[string]string{
			"File Last Modification Time": "file mtime, not run time",
			"Registry Last Written Time":  "registry key write time, not run time",
			"Last Time Executed":          "XP-era cache last-update time (plaso labels it last run)",
		}, false),
		Const("cache entry timestamp (see timestamp_desc), not run time"))
}

func init() {
	register("plaso_exec_prefetch", Entry{
		Variants: []Variant{
			{Pred: "plaso_is_prefetch_execution", Leaf: &Leaf{
				Object: "process", Action: "create", Ts: "Timestamp",
				Guid: GuidSpindle("plaso_exec_prefetch"), Host: execImgHost(),
				Props: []Prop{
					{"exe", plr("executable")},
					{"user", UserCanon(plr("username"))},
					{"hostname", execImgHost()},
				},
				Keep: plasoLinuxKeep,
				NativeExtract: append(execProv(),
					Prop{"path_hints", plr("path_hints")},
					Prop{"run_count", plr("run_count")},
					Prop{"prefetch_hash", plr("prefetch_hash")},
					Prop{"mapped_files", plr("mapped_files")},
					Prop{"volume_device_paths", plr("volume_device_paths")},
					Prop{"volume_serial_numbers", plr("volume_serial_numbers")},
					Prop{"number_of_volumes", plr("number_of_volumes")},
					Prop{"version", plr("version")},
				),
			}},
		},
	})

	register("plaso_exec_winreg", Entry{
		Variants: []Variant{
			// amcache "Link Time": the PE compile stamp → a time-free file ENTITY.
			{Pred: "plaso_is_amcache_link_time", Leaf: &Leaf{
				Object: "file", Action: "create", Ts: nil,
				Guid: GuidSpindle("plaso_exec_winreg/amcache_link_time"), Host: execImgHost(),
				Props: []Prop{
					{"file_path", plr("full_path")},
					{"file_name", Basename(plr("full_path"))},
					{"extension", Ext(plr("full_path"))},
					{"sha1_hash", execAmcacheSha1()},
					{"company", plr("company_name")},
					{"hostname", execImgHost()},
				},
				Keep: plasoLinuxKeep,
				NativeExtract: append(execProv(),
					Prop{"compile_time", "Timestamp"},
					Prop{"key_path", plr("key_path")},
					Prop{"program_identifier", plr("program_identifier")},
					Prop{"file_reference", plr("file_reference")},
				),
			}},
			// every OTHER dated amcache row: presence-implies-execution.
			{Pred: "plaso_is_amcache", Leaf: &Leaf{
				Object: "process", Action: "create", Ts: "Timestamp",
				Guid: GuidSpindle("plaso_exec_winreg/amcache"), Host: execImgHost(),
				Props: append(execWinProps(plr("full_path")),
					Prop{"sha1_hash", execAmcacheSha1()}),
				Keep: plasoLinuxKeep,
				NativeExtract: append(execProv(),
					Prop{"key_path", plr("key_path")},
					Prop{"program_identifier", plr("program_identifier")},
					Prop{"file_reference", plr("file_reference")},
				),
			}},
			{Pred: "plaso_is_userassist_run", Leaf: &Leaf{
				Object: "process", Action: "create", Ts: "Timestamp",
				Guid: GuidSpindle("plaso_exec_winreg/userassist"), Host: execImgHost(),
				Props: []Prop{
					{"exe", Basename(execUaProg())},
					{"image_path", Regex1(execUaProg(), `^(.*[\\/].*)$`)},
					{"user", UserCanon(First(
						plr("username"),
						userFromPath(plr("display_name"))))},
					{"hostname", execImgHost()},
				},
				Keep: plasoLinuxKeep,
				NativeExtract: append(execProv(),
					Prop{"key_path", plr("key_path")},
					Prop{"value_name", plr("value_name")},
					Prop{"number_of_executions", plr("number_of_executions")},
				),
			}},
			{Pred: "plaso_is_bam", Leaf: &Leaf{
				Object: "process", Action: "create", Ts: "Timestamp",
				Guid: GuidSpindle("plaso_exec_winreg/bam"), Host: execImgHost(),
				Props: append(execWinProps(plr("path")),
					Prop{"sid", plr("user_identifier")}),
				Keep: plasoLinuxKeep,
				NativeExtract: append(execProv(),
					Prop{"key_path", plr("key_path")}),
			}},
			{Pred: "plaso_is_appcompatcache", Leaf: &Leaf{
				Object: "process", Action: "create", Ts: "Timestamp",
				Guid: GuidSpindle("plaso_exec_winreg/appcompatcache"), Host: execImgHost(),
				Props: execWinProps(plr("path")),
				Keep:  plasoLinuxKeep,
				NativeExtract: append(execProv(),
					Prop{"key_path", plr("key_path")},
					Prop{"entry_index", plr("entry_index")},
					Prop{"control_set", plr("control_set")},
					Prop{"execution_inferred", Const(true)},
					Prop{"time_meaning", execShimcacheTimeMeaning()},
				),
			}},
		},
	})

	register("plaso_exec_cron", Entry{
		Variants: []Variant{
			{Pred: "plaso_is_cron_task_run", Leaf: &Leaf{
				Object: "process", Action: "create", Ts: "Timestamp",
				Guid: GuidSpindle("plaso_exec_cron"),
				Host: First(execImgHost(), plr("hostname")),
				Props: []Prop{
					{"exe", Basename(Regex1(plr("command"), `^(\S+)`))},
					{"image_path", Regex1(plr("command"), `^(/\S+)`)},
					{"command_line", plr("command")},
					{"pid", plr("pid")},
					{"user", plr("username")},
					{"hostname", First(execImgHost(), plr("hostname"))},
				},
				Keep: plasoLinuxKeep,
				NativeExtract: append(execProv(),
					Prop{"reporter", plr("reporter")},
					Prop{"syslog_hostname", plr("hostname")},
					Prop{"message_body", plr("message_body")},
				),
			}},
		},
	})
}
