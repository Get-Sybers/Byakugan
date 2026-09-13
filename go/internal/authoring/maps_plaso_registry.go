package authoring

// plaso_registry — Plaso registry artefacts → CAR registry (Go-native port of
// byakugan/mappings/plaso_registry.py). Every windows:registry:* data_type is
// claimed as a registry/key_edit event; the values LIST and every join key ride
// in native_extract. Predicate plaso_is_registry is already in
// go/internal/predicates. (plr is defined in maps_plaso_linux.go.)

// the owning account named by a Vista+ per-user hive path (\Users\<name>\).
func userFromPath(s Src) Src { return Regex1(s, `(?i)[/\\]Users[/\\]([^/\\]+)[/\\]`) }

func init() {
	register("plaso_registry", Entry{
		Variants: []Variant{
			{Pred: "plaso_is_registry", Leaf: &Leaf{
				Object: "registry", Action: "key_edit", Ts: "Timestamp",
				Guid: GuidSpindle("plaso_registry"), Host: HostLabel(plr("image_hostname")),
				Props: []Prop{
					{"key", plr("key_path")},
					{"hive", plr("display_name")},
					{"image_path", plr("image_path")},
					{"hostname", plr("image_hostname")},
					{"user", UserCanon(First(plr("username"), userFromPath(plr("display_name"))))},
				},
				NativeExtract: []Prop{
					{"data_type", plr("data_type")},
					{"values", plr("values")},
					{"name", plr("name")},
					{"object_name", plr("object_name")},
					{"start_type", plr("start_type")},
					{"service_type", plr("service_type")},
					{"service_dll", plr("service_dll")},
					{"error_control", plr("error_control")},
					{"command", plr("command")},
					{"application", plr("application")},
					{"handler", plr("handler")},
					{"trigger", plr("trigger")},
					{"entries", plr("entries")},
					{"username", plr("username")},
					{"fullname", plr("fullname")},
					{"comments", plr("comments")},
					{"account_rid", plr("account_rid")},
					{"login_count", plr("login_count")},
					{"serial", plr("serial")},
					{"vendor", plr("vendor")},
					{"product", plr("product")},
					{"subkey_name", plr("subkey_name")},
					{"device_display_name", plr("device_display_name")},
					{"device_type", plr("device_type")},
					{"revision", plr("revision")},
					{"server_name", plr("server_name")},
					{"share_name", plr("share_name")},
					{"source_type", plr("source_type")},
					{"drive_letter", plr("drive_letter")},
					{"product_name", plr("product_name")},
					{"build_number", plr("build_number")},
					{"service_pack", plr("service_pack")},
					{"version", plr("version")},
					{"owner", plr("owner")},
					{"configuration", plr("configuration")},
					{"settings", plr("settings")},
				},
			}},
		},
	})
}
