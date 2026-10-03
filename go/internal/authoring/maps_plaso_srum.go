package authoring

// plaso_srum — Plaso-parsed SRUM (System Resource Usage Monitor) data source
// (Go-native port of byakugan/mappings/plaso_srum.py). Two sub-keyed spindle
// variants: network_usage → flow/message, application_usage → process/create.
// Predicates srum_is_network_usage / srum_is_application_usage are already in
// go/internal/predicates. (plr is defined in maps_plasolinux.go.)

// a real SID, never an SRUM-internal numeric index.
func srumSid() Src { return Regex1(plr("user_identifier"), `^(S-1-[0-9-]+)$`) }

// a device path carries the executable; a bare name is only the exe.
func srumPlasoImage() Src { return Regex1(plr("application"), `^(\\Device\\.+)$`) }
func srumPlasoExe() Src   { return First(Basename(srumPlasoImage()), plr("application")) }

func srumKeepNative() []Prop {
	return []Prop{
		{"data_type", plr("data_type")},
		{"identifier", plr("identifier")},
		{"interface_luid", plr("interface_luid")},
		{"user_identifier", plr("user_identifier")},
		{"application", plr("application")},
	}
}

func init() {
	register("l2t_srum", Entry{
		Variants: []Variant{
			{Pred: "srum_is_network_usage", Leaf: &Leaf{
				Object: "flow", Action: "message", Ts: "Timestamp",
				Guid: GuidSpindle("l2t_srum/network_usage"),
				Props: []Prop{
					{"exe", srumPlasoExe()},
					{"image_path", srumPlasoImage()},
					{"in_bytes", plr("bytes_received")},
					{"out_bytes", plr("bytes_sent")},
					{"uid", srumSid()},
				},
				NativeExtract: srumKeepNative(),
			}},
			{Pred: "srum_is_application_usage", Leaf: &Leaf{
				Object: "process", Action: "create", Ts: "Timestamp",
				Guid: GuidSpindle("l2t_srum/application_usage"),
				Props: []Prop{
					{"exe", srumPlasoExe()},
					{"image_path", srumPlasoImage()},
					{"sid", srumSid()},
				},
				NativeExtract: append(srumKeepNative(),
					Prop{"foreground_cycle_time", plr("foreground_cycle_time")},
					Prop{"foreground_bytes_read", plr("foreground_bytes_read")},
					Prop{"foreground_bytes_written", plr("foreground_bytes_written")},
					Prop{"face_time", plr("face_time")}),
			}},
		},
	})
}
