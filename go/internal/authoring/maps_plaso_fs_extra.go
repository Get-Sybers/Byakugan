package authoring

// plaso_fs_extra — Plaso filesystem/file artefacts → CAR file (Go-native port of
// byakugan/mappings/plaso_fs_extra.py). Three keys:
//   - plaso_fseventsd : macos:fseventsd:record → file/modify
//   - plaso_pecoff    : pe_coff:file → time-free file ENTITY (every PE stamp is
//                       internal to the binary); up to three variants per PE
//   - plaso_olecf     : olecf:summary_info → file, action by timestamp_desc
// plr = payload scoped to "Record"; guids are minted spindle ids. Predicates
// fse_is_*/pe_is_*/ole_is_* are already in Go.

// strip a Plaso display_name volume prefix ("NTFS:\path" → "\path").
func fsxPath() Src {
	return First(Regex1(plr("display_name"), `^[^:]+:(.+)$`), plr("display_name"))
}

func fsxHost() Src { return HostLabel(plr("image_hostname")) }

// _pe_map: `stamp` names the native slot the row's own PE-internal timestamp is
// kept under ("" for the undated placeholder row). The record carries NO ts.
func fsxPeMap(stamp string) *Leaf {
	native := []Prop{
		{"data_type", plr("data_type")},
		{"timestamp_desc", plr("timestamp_desc")},
		{"imphash", Lower(plr("imphash"))},
		{"pe_type", plr("pe_type")},
		{"export_dll_name", plr("export_dll_name")},
		{"section_names", plr("section_names")},
	}
	native = append(native, plasoProv()...)
	if stamp != "" {
		native = append(native, Prop{stamp, "Timestamp"})
	}
	return &Leaf{
		Object: "file", Action: "create", Ts: nil,
		Guid: GuidSpindle("plaso_pecoff"), Host: fsxHost(),
		Props: []Prop{
			{"file_path", fsxPath()},
			{"file_name", Basename(fsxPath())},
			{"extension", Ext(fsxPath())},
			{"sha256_hash", Lower(plr("sha256_hash"))},
			{"hostname", plr("image_hostname")},
		},
		NativeExtract: native,
	}
}

func fsxOleMap(action string) *Leaf {
	return &Leaf{
		Object: "file", Action: action, Ts: "Timestamp",
		Guid: GuidSpindle("plaso_olecf"), Host: fsxHost(),
		Props: []Prop{
			{"file_path", fsxPath()},
			{"file_name", Basename(fsxPath())},
			{"extension", Ext(fsxPath())},
			{"sha256_hash", Lower(plr("sha256_hash"))},
			{"owner", plr("author")},
			{"hostname", plr("image_hostname")},
		},
		NativeExtract: append([]Prop{
			{"data_type", plr("data_type")},
			{"timestamp_desc", plr("timestamp_desc")},
			{"title", plr("title")},
			{"author", plr("author")},
			{"last_saved_by", plr("last_saved_by")},
			{"application", plr("application")},
			{"revision_number", plr("revision_number")},
			{"subject", plr("subject")},
			{"keywords", plr("keywords")},
			{"comments", plr("comments")},
			{"template", plr("template")},
			{"number_of_pages", plr("number_of_pages")},
			{"number_of_words", plr("number_of_words")},
			{"number_of_characters", plr("number_of_characters")},
			{"security_flags", plr("security")},
			{"codepage", plr("codepage")},
		}, plasoProv()...),
	}
}

func init() {
	register("plaso_fseventsd", Entry{
		Variants: []Variant{
			{Pred: "fse_is_record", Leaf: &Leaf{
				Object: "file", Action: "modify", Ts: "Timestamp",
				Guid: GuidSpindle("plaso_fseventsd"), Host: fsxHost(),
				Props: []Prop{
					{"file_path", plr("path")},
					{"file_name", Basename(plr("path"))},
					{"extension", Ext(plr("path"))},
					{"hostname", plr("image_hostname")},
				},
				NativeExtract: []Prop{
					{"data_type", plr("data_type")},
					{"flags", plr("flags")},
					{"event_identifier", plr("event_identifier")},
					{"node_identifier", plr("node_identifier")},
					{"timestamp_desc", plr("timestamp_desc")},
					{"artefact_sha256", plr("sha256_hash")},
					{"disk_id", plr("disk_id")},
					{"volume_id", plr("volume_id")},
				},
			}},
		},
	})

	register("plaso_pecoff", Entry{
		Variants: []Variant{
			{Pred: "pe_is_compile_stamp", Leaf: fsxPeMap("compile_time")},
			{Pred: "pe_is_table_stamp", Leaf: fsxPeMap("pe_table_time")},
			{Pred: "pe_is_file", Leaf: fsxPeMap("")},
		},
	})

	register("plaso_olecf", Entry{
		Variants: []Variant{
			{Pred: "ole_is_create", Leaf: fsxOleMap("create")},
			{Pred: "ole_is_modify", Leaf: fsxOleMap("modify")},
		},
	})
}
