package authoring

// recmd_batch — the RECmd batch (Kroll) registry data source (Go-native port of
// byakugan/mappings/recmd.py). Each live value record → registry/value_edit,
// timestamped by its key's LastWriteTimestamp (normalised to ISO 'T' form).
// Deleted records stay raw (default null). Predicate recmd_is_value_record is
// already in go/internal/predicates.

// per-user hive path names the user (Users/<name>/...); raw string keeps the
// two literal backslashes (matches r"(?i)[/\\]Users[/\\]([^/\\]+)[/\\]").
const recmdUserPathRe = `(?i)[/\\]Users[/\\]([^/\\]+)[/\\]`

// for a value snapshot the current content IS its content (data + new_content).
func recmdData() Src { return First("ValueData", "ValueData2", "ValueData3") }

func init() {
	register("recmd_batch", Entry{
		Variants: []Variant{
			{Pred: "recmd_is_value_record", Leaf: &Leaf{
				Object: "registry", Action: "value_edit",
				Ts:   Replace("LastWriteTimestamp", " ", "T"),
				Guid: GuidFields("HivePath", "KeyPath", "ValueName"),
				Props: []Prop{
					{"hive", "HiveType"},
					{"key", "KeyPath"},
					{"value", "ValueName"},
					{"data", recmdData()},
					{"type", "ValueType"},
					{"new_content", recmdData()},
					{"user", UserCanon(Regex1("HivePath", recmdUserPathRe))},
				},
				Keep: []string{
					"HivePath", "HiveType", "Category", "Description",
					"Comment", "ValueType", "Deleted", "Recursive",
				},
			}},
		},
	})
}
