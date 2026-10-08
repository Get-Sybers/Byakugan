# Contributing

## Setup

The object model is reconstructed live from the pinned **CAR submodule** (the
ATT&CK data-sources model is a vendored, frozen file — upstream is archived), so
initialise that submodule, then install and build:

```
git clone https://github.com/Get-Sybers/Byakugan
cd Byakugan
git submodule update --init third_party/car    # the CAR model — the one submodule the engine reads
pip install -e '.[dev]'                        # loose install, from pyproject's extras
make -C go build                               # the Go parse engine — REQUIRED to run the pipeline
```

For the EXACT versions this repo is proven against (what CI ran on), install the
pinned inventory instead:

```
pip install -r requirements-dev.txt    # pulls in requirements.txt too
pip install -e .                       # the package itself, no extras
```

The model sources, and when each is read:

- `third_party/car` (submodule) — the MITRE CAR data model (the 13 CAR objects)
  and the CAR analytics. **Read at run time.**
- `model/sources/attack-datasources/attack_data_sources_objects.yaml` (vendored,
  frozen; its pin rides in the file's own header) — the ATT&CK data-sources model
  (the superset objects + the relationship catalogue). **Read at run time.**
- `model/sources/forensicartifacts` (submodule) — the ForensicArtifacts catalogue
  that seeds the Artefact Class layer. **Refresh-time only:** nothing reads it at
  run time, CI does not need it, and only
  `pipeline/ingest/forensicartifacts/ingest.py` wants it checked out.

**Go >= 1.27 is a prerequisite.** The parse stage (raw file → pre-enrichment CAR
events) is the Go engine in `go/`; `python -m byakugan` shells out to
`go/bin/byakugan-parse` for every file source and fails with a build hint if it
is absent. Point `$BYAKUGAN_PARSE_BIN` at a binary to use one from elsewhere.
See [go/README.md](go/README.md).

A model refresh is a **submodule-pin bump** (or, for the vendored ATT&CK file, a
refresh with its header pin) followed by `python model/generate.py` — never a
hand edit of anything under `model/` (see [docs/DataModel.md](docs/DataModel.md)).

## Where things are authored

Every static declaration has ONE authoring home; everything else is generated
from it and drift-gated in CI (the README's "Repository layout" table says what
each directory is):

| you want to change | edit | then regenerate |
|---|---|---|
| a map (the object / action / props / guid of an artefact family), or one of its predicates | `go/internal/authoring/maps_<family>.go`, `go/internal/predicates/predicates_<family>.go` | `make -C go gen-ir` → `python -m byakugan.gen_sources` → `python -m byakugan.schema_gen` |
| which file names route to which maps | `byakugan/pipeline.py` (`ROUTES` / `EVTX_MAPS`) **and** `go/internal/authoring/ir_sections.go` (`irRoutes` / `irEvtxMaps`), same entries in the same order — `tests/test_routes_ir_sync.py` holds the two together | as above |
| a row identity (the fields a disk-image row's guid is minted from) | `byakugan/spindle.yml` **and** the `spindle` section of `ir_sections.go` — `tests/test_spindle_ir_sync.py` holds the shared entries together | `make -C go gen-ir` → `python model/generate.py` (→ `model/spindle/`) → `gen_sources` → `schema_gen` |
| the cascade rules, the relationship-verb bridge | `byakugan/relationships.yml`, `byakugan/cascade_relationships.yml` | `python model/generate.py` (→ `model/relationships/`) |
| the Artefact Class / Parser Profile seeds | `model/schema/classes-seed.yaml`, `model/schema/profiles-seed.yaml` | `python -m byakugan.schema_gen` |
| a source's provenance (tool, parser, URL, what it is derived from) | `DERIVATIONS` in `byakugan/sources_model.py` | `python -m byakugan.gen_sources` (→ `sources/`) |
| the CAR → ECS projection | `elastic/projection/*.yml` (hand-authored) | `python elastic/projection/render_elastic.py` |
| the CAR → STIX projection | `model/stix/*.yml` (hand-authored) | `python model/stix/validate.py` |
| a detection rule | `rules/<id>.yml` (+ `PINNED_IDS` in `rules/validate.py`) | `python rules/validate.py` |

Generated — never hand-edited, always committed: `go/internal/ir/ir.json`,
`sources/`, `model/car/`, `model/superset/`, `model/relationships/`,
`model/spindle/`, `model/schema/{classes,mappings,profiles,vocab,wire}/`,
`model/schema/conformance.json`, `model/schema/constants.yaml` and
`elastic/projection/rendered/`.

## Dependencies

Every module Byakugan depends on is declared in one of three traced files, so an
upgrade is a diff in a known place rather than an archaeology exercise:

| file | what | upgrade |
|---|---|---|
| [`requirements.txt`](requirements.txt) | runtime (`pyyaml` + `jsonschema` — everything else is the stdlib) | edit the range here **and** in `pyproject.toml` `[project] dependencies`, then `pip install -r requirements.txt` |
| [`requirements-dev.txt`](requirements-dev.txt) | the exact `pytest` / `yamale` / `yamllint` versions this repo is proven against (`pyproject`'s `dev` extra keeps the loose floors) | bump the pin, then `pip install -r requirements-dev.txt` |
| [`go/go.mod`](go/go.mod) | the parse engine — **stdlib-only**, no `require` block and no `go.sum` | bump the `go` directive (+ the CI toolchain version), then `make -C go build test` |

After ANY dependency change, re-prove the repo:

```
python -m pytest -q
python elastic/projection/validate.py && python model/stix/validate.py
python -m byakugan.gen_sources --check && python -m byakugan.spindle --check
python -m byakugan.schema_gen --check && python -m byakugan.conform --strict
make -C go build test && ./go/bin/byakugan-parse gen-ir --check go/internal/ir/ir.json
```

`tests/test_requirements_sync.py` keeps the files honest: it fails if
`requirements.txt` and `pyproject.toml` disagree on a package or a range, if the
dev pins drift from the `dev` extra or fall below its floors, or if the Go module
ever gains a third-party dependency.

## Everyday commands

```
python -m byakugan --in <file-or-dir> --out <dir>   # run one source
python -m byakugan --batch <processed_dir>          # every source
python -m byakugan.timeline <car-dir>               # the unified CAR timeline over a materialised tree
python -m byakugan.verify <car-dir>                 # the CAR run-through over a materialised tree
python -m byakugan build|timeline|verify|car-vocab|load   # the env-driven sub-tools (cli.py; BYAKUGAN_<SUBTOOL>_*)
python -m byakugan.build_data_model --write out/    # export the models for inspection
make -C go build test                               # build the parse engine + go vet/test
make -C go gen-ir                                   # re-serialise ir.json after a map / route / identity change
python -m byakugan.gen_sources                      # regenerate sources/ after a map or route change
python -m byakugan.schema_gen                       # regenerate model/schema/{classes,mappings,profiles,vocab,wire}
python model/generate.py                            # regenerate model/{car,superset,relationships,spindle}
pytest -q                                           # the suite (the CAR map tests drive the Go engine)
```

The import package is `byakugan` — write all code against it.

CI (`.github/workflows/lint.yml`) runs `gen_sources --check`, `spindle --check`
(the identity registry, its snapshot and the golden vectors), `yamale` over
`sources/`, `yamllint` over `sources/` and `docs/to-be-validated/`, `gofmt`,
`make -C go build test`, `ir-check` (every IR predicate is ported) and
`gen-ir --check` (ir.json is in step with the authoring tables), then `pytest`
— with the submodules checked out and a Go toolchain installed. The
`elastic-e2e` workflow (path-filtered, or by hand) brings up the standalone
Elastic stack and runs `scripts/e2e_elastic.py` against it.

## Code style — [module-best-practices](https://github.com/mattdesl/module-best-practices)

- **Small, focused, separate files** — one artefact family per file in
  `go/internal/authoring/` and `go/internal/predicates/`. Prefer another small
  file over a big one; the layout stays flat.
- **Don't duplicate** — the marker builders (`Const`, `First`, `EpochTS`,
  `Regex1`, `MapValue`, …) and the guid forms (`GuidFields`, `GuidSpindle`, …)
  live in `go/internal/authoring/authoring.go`; the one id recipe (namespaces +
  canonical JSON, shared by the STIX projection and the spindle row guid) in
  `byakugan/ids.py` and `go/internal/ids`. Import them rather than re-defining.
- **Data, not code** — the cascade rules (`relationships.yml`), the
  relationship-verb bridge (`cascade_relationships.yml`), the spindle
  row-identity registry (`spindle.yml`; snapshot `model/spindle/`), the source
  manifests (`sources/`, generated) and the schema layers (`model/schema/`) are
  data; the engines implement mechanics.
- **Honest mapping** — map a record only when it fits a canonical CAR
  object + action; nulls/duplicates are fine, near-misses are not (see
  [docs/CAR-Relations.md](docs/CAR-Relations.md)). Unvalidated inferences go in
  `docs/to-be-validated/`.
- Naming: `readers.py` = the memory-passthrough reader (the mapped-artefact
  readers are the Go engine); `sources_model.py` = the source-manifest
  generator; `sources/` = its generated output. Keep those distinct.

## Adding a map

1. Author the family in `go/internal/authoring/maps_<family>.go`
   (`register("<key>", Entry{...})` over the marker builders) and its gate
   functions in `go/internal/predicates/predicates_<family>.go`
   (`Register(name, fn)`), with replay vectors under
   `go/internal/predicates/testdata/predicate_vectors/<family>.json` (and
   `go/internal/markers/testdata/marker_vectors/<family>.json` when the family
   needs marker coverage `core.json` does not already give).
2. Route it: `byakugan/pipeline.py` (`ROUTES` / `EVTX_MAPS`) **and** `irRoutes` /
   `irEvtxMaps` in `go/internal/authoring/ir_sections.go`, same entries in the
   same order.
3. A disk-image (l2t/Plaso) map names its row identity: add the entry to
   `byakugan/spindle.yml` — `object`, `kind` (`record` | `entity`),
   `scope: intrinsic`, `version: 1`, `validated_against: [plaso]`,
   `stable_across`, the `identity` fields and a `golden` sample — and the same
   entry to the `spindle` section of `ir_sections.go`; reference it from the map
   with `Guid: GuidSpindle("<entry>")`. Any other map's raw guid form must be
   one of the registry's `external:` forms. **The P7 rule:** a leaf that emits
   no timestamp (`Ts: nil` — a PE's compile stamp, an amcache Link Time) MUST
   name a time-free `kind: entity` entry; `spindle --check` refuses a Plaso leaf
   without an entry and a timed identity on an untimed leaf.
4. Add the source's provenance (`DERIVATIONS` in `byakugan/sources_model.py`)
   and, for a new artefact class, its seed rows in
   `model/schema/classes-seed.yaml` / `profiles-seed.yaml`.
5. Regenerate, in this order, and commit the outputs: `make -C go gen-ir`,
   `python -m byakugan.gen_sources`, `python -m byakugan.schema_gen`,
   `python model/generate.py`.
6. Add a test under `tests/` (the map tests drive the engine through
   `tests/go_engine.py`); run `pytest -q` and `make -C go build test`.

## Changing a row identity (the change protocol)

An entry's identity fields, names, rendering or golden sample change **only
with a `version` bump** — the version is hashed into every guid as `_v`:

1. edit the entry in `spindle.yml` and bump its `version`; mirror the change in
   the `spindle` section of `go/internal/authoring/ir_sections.go` and
   `make -C go gen-ir`;
2. `python model/generate.py` — regenerates `model/spindle/` (the golden vector
   moves with the version; the generator refuses a guid that moved without it);
3. commit the snapshot, `golden.yml` included, and the regenerated `sources/`
   and `model/schema/mappings/` (each manifest states its identity entries and
   versions);
4. rebuild the stores (`--batch --force`) — every guid of that entry re-mints
   (a remint / audit tool is a follow-up). The id recipe itself (namespaces,
   canonical JSON) never changes under a version bump: that would move every
   guid at once and is a new spindle.

## Branch / release flow

- Work on a **feature branch**; open a **pull request to `main`**; CI must be
  green. Maintainers merge — open the PR and leave it.
- Follow **SemVer** for `version` in `pyproject.toml`. The
  [GoDFIR-toolz](https://github.com/Get-Sybers/GoDFIR-toolz/tree/main/byakugan)
  image pins this repository by commit (`BYAKUGAN_REF`), so a release is a tag
  here plus a pin bump there.
