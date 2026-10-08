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
  `MAPPINGS`, the routing table and the EVTX family from `ir.json` for the
  pipeline, `sources_model`, `spindle`, `sigma` and the tests) plus
  `_common.py` (helpers the spindle tests use). Nothing on the Python side
  runs a map, and `pipeline.ROUTES` / `EVTX_MAPS` are read from the IR's
  `routes` / `evtx_maps` — the Python literals are gone.
- **The spindle registry is read from the IR.** The identity rules (entries,
  positional fallback, engine-minted external forms, golden vectors) have one
  home, the `spindle` and `golden` sections of `ir_sections.go`;
  `byakugan.spindle` assembles its registry from `ir.json` plus the notes that
  stay in `byakugan/spindle.yml` (prose, the equality rule, the passthrough's
  forms) and re-mints every pinned golden vector as a guard.
- **Retired:** `byakugan/export_ir.py` (replaced by `gen-ir`); `tests/parity/`
  and `tests/reference_plumbing.py` (the CAR tests drive the Go engine directly
  through `tests/go_engine.py`); `scripts/bench-parse.py` (it drove the deleted
  Python path) and `scripts/gen_ir_sections.py` (a one-time bootstrap); and the
  22 per-family `byakugan/mappings/*.py` modules that mirrored the Go
  predicates — nothing consumed them once the parity harness went.

## Still Python — what remains, and why

| what | where | status |
|---|---|---|
| the source manifests | `byakugan/sources_model.py` (`DERIVATIONS` — tool / parser / URL provenance; `gen_sources.py` exports what it builds) | provenance the IR does not carry. Nothing is committed: every build writes its own `sources.yaml` and `byakugan.schema_gen` reads the manifests in memory. |
| the marker DSL constructors + value normalisers | `byakugan/normalize.py` | the introspection substrate for `sources_model`, `spindle` and `sigma`; the resolver that runs the markers is `go/internal/markers`. |
| the schema generators and gates | `byakugan/schema_gen.py`, `conform.py`, `wirecheck.py` | Python owns the JSON Schema side by decision (the Go engine stays stdlib-only). |

What remains in Python is by decision: provenance the IR has no reason to
carry, and the JSON Schema side.

## Open items carried over from the port

- `_SID` is mapped to the **`uid`** column for SRUM network usage but **`sid`**
  for application usage, in both `maps_plaso_srum.go` and `maps_esedump_srum.go`
  — ported as found. Decide the canonical column (verify against the CAR model
  and the existing tests first; it changes CAR output).
