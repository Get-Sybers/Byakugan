# Go-native map authoring — status

Tracked under DX_DFIR #188 (all-Go migration, initiative 1). Goal: **remove the
Python map-authoring layer** so byakugan is authored *and* run in Go. The
runtime has been 100% Go since the parse engine landed (`go/internal/…`: the
marker resolver, 80 predicates, the identity mint, the adapters, the splitter);
this page records where the *authoring* side stands.

## Done

- **Authoring is Go.** The map tables live in `go/internal/authoring/maps_<family>.go`,
  the predicates in `go/internal/predicates/predicates_<family>.go`, the static
  sections (marker kinds, routes, evtx_maps, adapters, canon_user, spindle,
  golden) in `go/internal/authoring/ir_sections.go`. `byakugan-parse gen-ir`
  serialises them to the embedded `go/internal/ir/ir.json`; `gen-ir --check`
  and `ir-check` gate drift and completeness in CI.
- **Python reads the IR.** `byakugan/mappings/` is `_from_ir.py` (decodes
  `MAPPINGS` from `ir.json` for `sources_model`, `spindle`, `sigma` and the
  tests) plus `_common.py` (helpers the spindle tests use). Nothing on the
  Python side runs a map.
- **Retired:** `byakugan/export_ir.py` (replaced by `gen-ir`); `tests/parity/`
  and `tests/reference_plumbing.py` (the CAR tests drive the Go engine directly
  through `tests/go_engine.py`); `scripts/bench-parse.py` (it drove the deleted
  Python path) and `scripts/gen_ir_sections.py` (a one-time bootstrap); and the
  22 per-family `byakugan/mappings/*.py` modules that mirrored the Go
  predicates — nothing consumed them once the parity harness went.

## Still Python — what remains, and why

| what | where | status |
|---|---|---|
| routing | `byakugan/pipeline.py` `ROUTES` / `EVTX_MAPS` | the pipeline routes files to the engine from here. The IR carries the same table (`irRoutes` / `irEvtxMaps`), `model/schema/mappings/routes.yaml` is generated from the IR, and `tests/test_routes_ir_sync.py` holds the two statements together. A **second hand-maintained copy** until the pipeline reads routing from the IR. |
| the row-identity registry | `byakugan/spindle.yml` + `byakugan/spindle.py` | `spindle --check`, the snapshot generator (`model/spindle/`) and the drift guards read the YAML. The IR's `spindle` section carries the same 26 identities and the 13 engine-minted external forms (the YAML also declares the 12 `memory_*` forms the Anamnesis passthrough carries, which the engine never mints); `tests/test_spindle_ir_sync.py` holds the shared part together. A **second hand-maintained copy** of that shared part. |
| the source manifests | `byakugan/sources_model.py` (`DERIVATIONS` — tool / parser / URL provenance) + `gen_sources.py` → `sources/` | provenance the IR does not carry; `byakugan.schema_gen` reads `sources/` as the reviewed lane surface. |
| the marker DSL constructors + value normalisers | `byakugan/normalize.py` | the introspection substrate for `sources_model`, `spindle` and `sigma`; the resolver that runs the markers is `go/internal/markers`. |
| the schema generators and gates | `byakugan/schema_gen.py`, `conform.py`, `wirecheck.py` | Python owns the JSON Schema side by decision (the Go engine stays stdlib-only). |

The honest next step for the first two rows is the move the maps already made:
have the pipeline and the spindle tooling read the IR, then delete the Python
copies.

## Open items carried over from the port

- `_SID` is mapped to the **`uid`** column for SRUM network usage but **`sid`**
  for application usage, in both `maps_plaso_srum.go` and `maps_esedump_srum.go`
  — ported as found. Decide the canonical column (verify against the CAR model
  and the existing tests first; it changes CAR output).
