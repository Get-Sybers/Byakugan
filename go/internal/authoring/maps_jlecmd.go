package authoring

// jlecmd_dest — JLECmd jump-list destination entries (Go-native port of
// byakugan/mappings/jlecmd.py). Each destination entry → file/read, timed at
// the entry's LastModified, hosted by the jump list's Hostname. Predicate
// jl_is_dest_entry is already in go/internal/predicates.

func init() {
	register("jlecmd_dest", Entry{
		Variants: []Variant{
			{Pred: "jl_is_dest_entry", Leaf: &Leaf{
				Object: "file", Action: "read", Ts: "LastModified",
				Guid: GuidFields("SourceFile", "EntryNumber"),
				Host: "Hostname",
				Props: []Prop{
					{"file_path", "Path"},
					{"file_name", Basename("Path")},
					{"extension", Ext("Path")},
					{"hostname", "Hostname"},
				},
				Keep: []string{
					"AppId", "AppDescription", "InteractionCount",
					"CreatedOn", "EntryNumber", "MRUPosition", "Pinned",
					"MacAddress", "VolumeDroid", "SourceFile",
				},
			}},
		},
	})
}
