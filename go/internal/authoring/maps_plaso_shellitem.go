package authoring

// plaso_shellitem — Plaso shell items → CAR file (Go-native port of
// byakugan/mappings/plaso_shellitem.py). windows:shell_item:file_entry rows
// (embedded in LNK targets, shellbags, MRU lists) → file, action by
// timestamp_desc (create/modify/read). plr = payload scoped to "Record"; guid is
// the minted spindle id. Predicates plasoshell_* are already in Go.

// the navigated target: shell_item_path ("<My Computer> " prefix stripped) then
// long_name / name.
func shPath() Src {
	return UnescapeBackslashes(First(
		Regex1(plr("shell_item_path"), `^(?:<[^>]+>\s*)?(.+)$`),
		plr("long_name"), plr("name")))
}

func shHost() Src { return HostLabel(plr("image_hostname")) }

func shMap(action string) *Leaf {
	props := []Prop{
		{"file_path", shPath()},
		{"file_name", Basename(shPath())},
		{"extension", Ext(shPath())},
		{"hostname", plr("image_hostname")},
		{"user", UserCanon(First(
			userFromPath(plr("display_name")),
			userFromPath(shPath())))},
	}
	if action == "create" {
		props = append(props, Prop{"creation_time", "Timestamp"})
	}
	return &Leaf{
		Object: "file", Action: action, Ts: "Timestamp",
		Guid: GuidSpindle("plaso_shellitem"), Host: shHost(),
		Props: props,
		NativeExtract: []Prop{
			{"data_type", plr("data_type")},
			{"origin", plr("origin")},
			{"shell_item_path", plr("shell_item_path")},
			{"long_name", plr("long_name")},
			{"name", plr("name")},
			{"localized_name", plr("localized_name")},
			{"artefact_path", plr("display_name")},
			{"disk_id", plr("disk_id")},
			{"volume_id", plr("volume_id")},
			{"volume_offset", plr("volume_offset")},
			{"artefact_sha256", plr("sha256_hash")},
		},
	}
}

func init() {
	register("plaso_shellitem", Entry{
		Variants: []Variant{
			{Pred: "plasoshell_create", Leaf: shMap("create")},
			{Pred: "plasoshell_modify", Leaf: shMap("modify")},
			{Pred: "plasoshell_read", Leaf: shMap("read")},
		},
	})
}
