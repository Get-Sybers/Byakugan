package authoring

// prefetch_dump — the Get-Sybers prefetch_dump data source (Go-native port of
// byakugan/mappings/prefetch_dump.py). Prefetch → process/create, own positional
// identity. Predicate prefetch_dump_is_execution is already in go/internal/predicates.

func init() {
	register("prefetch_dump", Entry{
		Variants: []Variant{
			{Pred: "prefetch_dump_is_execution", Leaf: &Leaf{
				Object: "process", Action: "create", Ts: "LastRun",
				Guid: GuidFields("Executable", "Hash"),
				Props: []Prop{
					// full path where the .pf records it; a bare name leaves image_path null
					{"exe", First(WinProgramName("Path"), "Executable")},
					{"image_path", WinProgramPath("Path")},
				},
				Keep: []string{
					"SourceFilename", "SourceModified", "Executable", "Path", "Hash",
					"Version", "FileSize", "RunCount", "LastRun", "PreviousRuns", "FilesAccessed",
				},
			}},
		},
	})
}
