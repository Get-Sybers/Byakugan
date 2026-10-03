package authoring

// plaso_linux — Plaso filesystem + Linux session data sources (Go-native port of
// byakugan/mappings/plaso_linux.py). The wrapped l2t row: payload(<field>,
// "Record") reads the raw Plaso event under "Record". Predicates l2t_td_* /
// l2t_usn_* / l2t_utmp_* / l2t_text_ssh_login are already in go/internal/predicates.

// plr reads a field out of the wrapped row's flat plaso Record dict — the
// Python _common.R(k) = payload(k, "Record") marker ({"!":["payload","Record",k]}).
func plr(k string) Src { return Payload("Record", k) }

// filestat/usnjrnl file_path: filename, else display_name with its "TYPE:"
// prefix stripped, else display_name as-is.
func fnDnPath() Src {
	return First(plr("filename"),
		Regex1(plr("display_name"), `\A[A-Z0-9]+:(.*)\Z`),
		plr("display_name"))
}

// mft: the file the entry describes — Record.name, else Record.filename.
func mftPath() Src { return First(plr("name"), plr("filename")) }

// unset/loopback source is NOT a remote origin — src_ip stays null.
func srcIP() Src {
	return Regex1(plr("ip_address"), `\A(?!(?:0\.0\.0\.0|127\.0\.0\.1|::1)\Z)(.+)\Z`)
}

var plasoLinuxKeep = []string{"SourceImage", "Parser"}

// EWF/partition provenance appended to every disk-image native block.
func plasoProv() []Prop {
	return []Prop{
		{"disk_id", plr("disk_id")},
		{"volume_id", plr("volume_id")},
		{"volume_offset", plr("volume_offset")},
	}
}

func filestatNative() []Prop {
	return append([]Prop{
		{"timestamp_desc", plr("timestamp_desc")},
		{"data_type", plr("data_type")},
		{"file_entry_type", plr("file_entry_type")},
		{"file_size", plr("file_size")},
		{"file_system_type", plr("file_system_type")},
		{"is_allocated", plr("is_allocated")},
		{"inode", plr("inode")},
		{"number_of_links", plr("number_of_links")},
		{"display_name", plr("display_name")},
	}, plasoProv()...)
}

func mftNative() []Prop {
	return append([]Prop{
		{"timestamp_desc", plr("timestamp_desc")},
		{"data_type", plr("data_type")},
		{"path_hints", plr("path_hints")},
		{"file_reference", plr("file_reference")},
		{"parent_file_reference", plr("parent_file_reference")},
		{"is_allocated", plr("is_allocated")},
		{"file_attribute_flags", plr("file_attribute_flags")},
		{"display_name", plr("display_name")},
	}, plasoProv()...)
}

func usnNative() []Prop {
	return append([]Prop{
		{"timestamp_desc", plr("timestamp_desc")},
		{"data_type", plr("data_type")},
		{"update_reason_flags", plr("update_reason_flags")},
		{"update_source_flags", plr("update_source_flags")},
		{"update_sequence_number", plr("update_sequence_number")},
		{"file_reference", plr("file_reference")},
		{"parent_file_reference", plr("parent_file_reference")},
		{"file_attribute_flags", plr("file_attribute_flags")},
		{"display_name", plr("display_name")},
		{"offset", plr("offset")},
	}, plasoProv()...)
}

func utmpNative() []Prop {
	return []Prop{
		{"data_type", plr("data_type")},
		{"login_type", plr("login_type")},
		{"hostname", plr("hostname")},
		{"terminal", plr("terminal")},
		{"terminal_identifier", plr("terminal_identifier")},
		{"exit_status", plr("exit_status")},
	}
}

func sshNative() []Prop {
	return []Prop{
		{"data_type", plr("data_type")},
		{"authentication_method", plr("authentication_method")},
		{"protocol", plr("protocol")},
		{"reporter", plr("reporter")},
		{"hostname", plr("hostname")},
	}
}

// fileMap builds one CAR file variant. creation_time is asserted only on
// action=create (any other MACB row's time is provably not the creation time).
func fileMap(action, spindleName string, pathMarker Src, hashes, posix bool, native []Prop) *Leaf {
	props := []Prop{
		{"file_path", pathMarker},
		{"extension", Ext(pathMarker)},
		{"file_name", Basename(pathMarker)},
		{"hostname", plr("image_hostname")},
		{"user", plr("username")},
	}
	if hashes {
		props = append(props,
			Prop{"md5_hash", Lower(plr("md5_hash"))},
			Prop{"sha1_hash", Lower(plr("sha1_hash"))},
			Prop{"sha256_hash", Lower(plr("sha256_hash"))})
	}
	if posix {
		props = append(props,
			Prop{"mode", plr("mode")},
			Prop{"owner_uid", plr("owner_identifier")},
			Prop{"gid", plr("group_identifier")})
	}
	if action == "create" {
		props = append(props, Prop{"creation_time", "Timestamp"})
	}
	return &Leaf{
		Object: "file", Action: action, Ts: "Timestamp",
		Guid:          GuidSpindle(spindleName),
		Host:          HostLabel(plr("image_hostname")),
		Props:         props,
		Keep:          plasoLinuxKeep,
		NativeExtract: native,
	}
}

// macbEntry: filestat/mft — the four MACB actions, create tested first.
func macbEntry(spindleName string, pathMarker Src, hashes, posix bool, native func() []Prop) Entry {
	return Entry{
		Variants: []Variant{
			{Pred: "l2t_td_create", Leaf: fileMap("create", spindleName, pathMarker, hashes, posix, native())},
			{Pred: "l2t_td_modify", Leaf: fileMap("modify", spindleName, pathMarker, hashes, posix, native())},
			{Pred: "l2t_td_read", Leaf: fileMap("read", spindleName, pathMarker, hashes, posix, native())},
			{Pred: "l2t_td_delete", Leaf: fileMap("delete", spindleName, pathMarker, hashes, posix, native())},
		},
	}
}

// sessionMap builds one user_session variant (utmp/utmpx/ssh).
func sessionMap(action, spindleName string, extra []Prop, native []Prop) *Leaf {
	props := []Prop{
		{"user", plr("username")},
		{"hostname", plr("image_hostname")},
		{"src_ip", srcIP()},
	}
	props = append(props, extra...)
	return &Leaf{
		Object: "user_session", Action: action, Ts: "Timestamp",
		Guid:          GuidSpindle(spindleName),
		Host:          HostLabel(plr("image_hostname")),
		OwningPID:     plr("pid"),
		Props:         props,
		Keep:          plasoLinuxKeep,
		NativeExtract: native,
	}
}

func utmpEntry(spindleName string) Entry {
	return Entry{
		Variants: []Variant{
			{Pred: "l2t_utmp_login", Leaf: sessionMap("login", spindleName, nil, utmpNative())},
			{Pred: "l2t_utmp_logout", Leaf: sessionMap("logout", spindleName, nil, utmpNative())},
		},
	}
}

func init() {
	register("l2t_filestat", macbEntry("l2t_filestat", fnDnPath(), true, true, filestatNative))
	register("l2t_mft", macbEntry("l2t_mft", mftPath(), false, false, mftNative))
	register("l2t_usnjrnl", Entry{
		Variants: []Variant{
			{Pred: "l2t_usn_create", Leaf: fileMap("create", "l2t_usnjrnl", fnDnPath(), false, false, usnNative())},
			{Pred: "l2t_usn_delete", Leaf: fileMap("delete", "l2t_usnjrnl", fnDnPath(), false, false, usnNative())},
		},
		Default: fileMap("modify", "l2t_usnjrnl", fnDnPath(), false, false, usnNative()),
	})
	register("l2t_utmp", utmpEntry("l2t_utmp"))
	register("l2t_utmpx", utmpEntry("l2t_utmpx"))
	register("l2t_text", Entry{
		Variants: []Variant{
			{Pred: "l2t_text_ssh_login", Leaf: sessionMap("login", "l2t_text",
				[]Prop{{"src_port", plr("port")}}, sshNative())},
		},
	})
}
