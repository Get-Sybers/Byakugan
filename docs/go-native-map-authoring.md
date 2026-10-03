# Go-native map authoring — design & migration plan

Tracked under DX_DFIR #188 (all-Go migration, initiative 1). Goal: **remove the Python map-authoring layer** so byakugan is authored *and* run in Go. Byakugan's **runtime is already 100% Go** (parse engine, 22 markers, 80 predicates, identity mint, routing, adapters — all in `go/internal/…`, zero gaps). What is still Python is only the **authoring + generation** layer that produces the embedded `go/internal/ir/ir.json` the engine loads.

## What's Python today (to remove)
- `byakugan/mappings/*.py` — 40 map keys / 87 variant leaves across 22 modules (the `MAPPINGS`/`PREDICATES` data).
- `byakugan/sources_model.py` — `Derivation` + `DERIVATIONS` (40) + coverage introspection → `sources/*.yaml`; `verify_registry`, `validate_against_car_model`, `verify_coverage`.
- `byakugan/spindle.py` + `spindle.yml` — 26 identities + 13 external forms + the drift guards + `model/spindle/` snapshot generation (`registry_doc`/`golden_doc`/`record_doc`).
- `byakugan/export_ir.py` (→ `ir.json`) and `byakugan/gen_sources.py` (→ `sources/*.yaml`) — the generators, byte-parity-gated in CI.
- `tests/parity/` — the Python↔Go byte-parity harness (its whole purpose dies once Python is gone; the committed Go vectors it produced remain the spec).

## Already Go (reuse, don't touch)
`go/internal/markers` (22 kinds incl. `regex1` via pyre), `go/internal/predicates` (80 `Register`, `Check()` completeness gate), `go/internal/ids` (mint recipe — `canonical_json`, `mint`, frozen `CAR_NS`/`SPINDLE_NS`), `go/internal/normalize` (walks the IR), routing/adapters. `byakugan-parse ir-check` + `TestRegistryAgainstIR` + `TestEveryRegisteredPredicateHasAVector` are the completeness invariants to keep.

## ir.json schema (what a Go generator must reproduce — `export_ir.build_ir`)
Top-level keys: `ir_version`, `marker_kinds` (sorted 22), `mappings`, `routes`, `evtx_maps`, `adapters` (`jlecmd_dest`/`l2t_winevt`), `spindle`, `canon_user`, `predicate_names` (sorted 80), `golden`. Rendered `json.dumps(..., ensure_ascii=False, indent=1) + "\n"`.
- **entry** = `{variants:[[pred, leaf|null], …], default: leaf|null}` (or a bare leaf).
- **leaf** = `object, action(src), ts(src|null), guid, host(src|null), owning_pid, owning_guid, parent_pid, props:[[car,src]], keep:[…], native_extract:[[name,src]]`.
- **guid** = `null | {none} | {field} | {fields:[…]} | {marker:src} | {spindle:name}`.
- **marker src** = a field-name string, or the envelope `{"!":["kind", arg…]}`. Kinds: variadic `first`/`concat`; unary `basename ext lower domain_of epoch_ts exe_path host_label hex_int unescape_backslashes win_program_path win_program_name user_canon`; fixed-sig `regex1 payload userdata map_value replace at ts_before`; plus `const`. (Per-arg src-vs-literal signature from `export_ir._VARIADIC/_UNARY/_FIXED`.)
- **spindle section**: namespace (`CAR_NS`/`SPINDLE_NS`/`CAR_NS_URL`/labels from `ids.py`), `object_key`/`version_key`, `renderings`, `positional {fields,version}`, `identities {name:{object,kind,scope,version,identity:[[iname,source,mode]]}}` (26), `external {name:{object,form}}` (13).
- **canon_user**: `_WELLKNOWN_SIDS/_NAMES/_AUTHORITIES` from `normalize.py`.
- **golden**: `spindle.golden_doc()` — per-entry MINTED uuid5 key+guid vectors (Go has `ids.mint`, so reproducible), positional + external + recipe vectors.

## Migration plan (lowest-risk: engine unchanged; prove byte-equality)
1. **Foundation PR** — Go authoring types (marker builders mirroring the DSL, guid, leaf, entry) + a Go IR encoder reproducing `export_ir`'s `marker_kinds`+`mappings` encoding byte-for-byte; hand-port `esedump_srum`+`prefetch_dump` as the pilot; test: the Go-encoded fragment for those two == the committed `ir.json` fragment. Python stays authoritative.
2. **Map translation PRs** — port the remaining 38 maps to Go data (parallelizable across agents), each proven by fragment byte-match. Also port `DERIVATIONS`, spindle identities/externals, `canon_user`.
3. **Generators PR** — Go `gen-ir`/`gen-sources`/`gen-spindle-snapshot` reproducing all three artifacts byte-for-byte (full-file equality gate).
4. **Flip + delete** — switch source-of-truth to Go, delete `mappings/`, `sources_model.py`, `export_ir.py`, `gen_sources.py`, the Python spindle-authoring bits, and `tests/parity/`; re-anchor the introspection tests (`test_car_sources`, `sigma`) and swap the four Python `--check` CI gates for Go equivalents.

## Fidelity traps (must reproduce exactly)
- `zeek_conn_has_state` is a **side-effecting predicate** (stamps `_zc_end_time` ISO-Z µs-rounded + `_zc_packet_count`) and runs BEFORE resolve.
- Extra leaf fields beyond the common set: **`parent_pid`** (evtx_process, sysmon proc_create) and **`owning_guid`** (sysmon, 12/13 variants).
- **`l2t_usnjrnl` is the only map with a non-None `default`.**
- **`ts: None`** entity records (amcache_link_time, all pecoff variants).
- **`<map>/<variant>` sub-keyed** spindle names (`l2t_srum/network_usage`, `plaso_exec_winreg/…`).
- Spindle rule: **plaso maps MUST mint from the registry; EVTX-family maps MUST stay raw external** (`spindle.verify_registry`), and an entry is **named by its map key**.
- `action`/`ts` are often markers (`const`, `map_value`, `first(map_value…,const…)`, `epoch_ts`, `replace`) — `sources_model.resolve_actions` only accepts const/map_value/first.

## Known bug to reconcile during the port
`_SID` is mapped to the **`uid`** column for SRUM network_usage but **`sid`** for application_usage — in BOTH `plaso_srum.py` and `esedump_srum.py`. Likely an inconsistency; decide the canonical column when porting (don't silently change CAR output — verify against the CAR model + existing tests first).

## Stale doc note
`go/DESIGN.md` predates the last additions: says "24-marker"/"77 predicates"/"10 external forms" — actual is **22 / 80 / 13**. Fix when touching it.
