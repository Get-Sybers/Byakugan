package authoring

// plaso_artifacts — Plaso Windows file-artefact evidence → CAR file (Go-native
// port of byakugan/mappings/plaso_artifacts.py). Two keys:
//   - l2t_lnk        : windows:lnk:link → file, MAC times by timestamp_desc
//   - l2t_recyclebin : windows:metadata:deleted_item → file/delete
// Both consume the wrapped l2t row (plr = payload scoped to "Record"); the guid
// is the minted spindle id. Predicates plasoart_* are already in Go.

// the recorded target: local_path → network_path → link_target with the
// "<My Computer> " style shell-item prefix stripped.
func artLnkPath() Src {
	return UnescapeBackslashes(First(
		plr("local_path"), plr("network_path"),
		Regex1(plr("link_target"), `^(?:<[^>]+>\s*)?(.+)$`)))
}

func artHost() Src { return HostLabel(plr("image_hostname")) }

// the rich LNK metadata block (order is semantic).
func artLnkNative() []Prop {
	return []Prop{
		{"data_type", plr("data_type")},
		{"lnk_file", plr("display_name")},
		{"description", plr("description")},
		{"working_directory", plr("working_directory")},
		{"relative_path", plr("relative_path")},
		{"file_size", plr("file_size")},
		{"command_line_arguments", plr("command_line_arguments")},
		{"env_var_location", plr("env_var_location")},
		{"icon_location", plr("icon_location")},
		{"file_attribute_flags", plr("file_attribute_flags")},
		{"drive_type", plr("drive_type")},
		{"drive_serial_number", plr("drive_serial_number")},
		{"volume_label", plr("volume_label")},
		{"link_target_raw", plr("link_target")},
		{"droid_file_identifier", plr("droid_file_identifier")},
		{"droid_volume_identifier", plr("droid_volume_identifier")},
		{"birth_droid_file_identifier", plr("birth_droid_file_identifier")},
		{"birth_droid_volume_identifier", plr("birth_droid_volume_identifier")},
	}
}

func artLnkMap(action string) *Leaf {
	return &Leaf{
		Object: "file", Action: action, Ts: "Timestamp",
		Guid: GuidSpindle("l2t_lnk"), Host: artHost(),
		Props: []Prop{
			{"file_path", artLnkPath()},
			{"file_name", Basename(artLnkPath())},
			{"extension", Ext(artLnkPath())},
			{"link_target", plr("link_target")},
			{"hostname", plr("image_hostname")},
			{"user", UserCanon(First(
				plr("username"),
				userFromPath(plr("display_name")),
				userFromPath(artLnkPath())))},
		},
		NativeExtract: artLnkNative(),
	}
}

func init() {
	register("l2t_lnk", Entry{
		Variants: []Variant{
			{Pred: "plasoart_lnk_create", Leaf: artLnkMap("create")},
			{Pred: "plasoart_lnk_modify", Leaf: artLnkMap("modify")},
			{Pred: "plasoart_lnk_read", Leaf: artLnkMap("read")},
		},
	})

	register("l2t_recyclebin", Entry{
		Variants: []Variant{
			{Pred: "plasoart_recycle_delete", Leaf: &Leaf{
				Object: "file", Action: "delete", Ts: "Timestamp",
				Guid: GuidSpindle("l2t_recyclebin"), Host: artHost(),
				Props: []Prop{
					{"file_path", plr("original_filename")},
					{"file_name", Basename(plr("original_filename"))},
					{"extension", Ext(plr("original_filename"))},
					{"hostname", plr("image_hostname")},
					{"user", UserCanon(First(
						plr("username"),
						userFromPath(plr("original_filename"))))},
					{"uid", Regex1(plr("display_name"),
						`(?i)\$Recycle\.Bin[/\\](S-1-[0-9-]+)`)},
				},
				NativeExtract: []Prop{
					{"data_type", plr("data_type")},
					{"file_size", plr("file_size")},
					{"record_index", plr("record_index")},
					{"drive_number", plr("drive_number")},
					{"artefact_file", plr("display_name")},
					{"artefact_sha256", plr("sha256_hash")},
					{"disk_id", plr("disk_id")},
					{"volume_id", plr("volume_id")},
					{"volume_offset", plr("volume_offset")},
				},
			}},
		},
	})
}
