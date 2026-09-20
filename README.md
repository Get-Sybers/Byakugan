# Byakugan

**Turn raw DFIR evidence into one MITRE-aligned timeline — normalise every
artefact into MITRE CAR, relate the objects through proven relationships, and
(roadmap) flag adversary TTP behaviours — automatically.**

An analyst points it at what their forensic tooling already produces and gets
back a timeline that is **CAR-normalised**, **relationship-enriched**, and
heading toward **TTP-flagged** — the complete, faithful model of what happened,
not just the events a single detection cares about.

## What it does

- **Normalises** processor output — goevtx event logs, log2timeline (Plaso),
  Zeek, gore registry batches, ese_dump SRUM,
  [anamnesis](https://github.com/Get-Sybers/Anamnesis) memory — into
  finished [MITRE CAR](https://car.mitre.org/) objects. Every record carrying a
  valid CAR object + canonical action is mapped; honest nulls, nothing faked.
- **Relates** those objects — owning process, parent, auth↔session (LUID),
  file→process, thread injection — as a granular relationship timeline, typed
  against the MITRE ATT&CK data-sources relationship vocabulary.
- **Flags TTPs** (roadmap, [#12](https://github.com/Get-Sybers/byakugan/issues/12)):
  CAR/ATT&CK analytics over the objects and relationships surface adversary
  behaviours on the same timeline.

## Quickstart

```
git submodule update --init --recursive          # the model comes from pinned submodules
make -C go build                                 # the Go parse engine (Go >= 1.24)
python -m byakugan --in <file-or-dir> --out <dir>   # one source
python -m byakugan --batch <processed_dir>          # every source, isolated
python -m byakugan.timeline <car-dir>               # one property-rich, time-ordered timeline
python -m byakugan.verify <car-dir>                 # the CAR run-through (correctness gate)
byakugan build|timeline|verify|car-vocab            # env-driven (BYAKUGAN_<SUBTOOL>_*): one JSON summary line
```

`byakugan <sub-tool>` with nothing else is the container entry point
(`byakugan/cli.py`): each sub-tool reads its own `BYAKUGAN_<SUBTOOL>_INPUT_DIR`
/ `_OUT_DIR` / `_FORCE` / `_LOG_LEVEL` block, prints exactly one JSON summary
line on stdout and exits by the uniform table (0 ok, 1 nothing — or the verify
gate failed, 2 config error, 3 partial). A sub-tool followed by arguments is
the pass-through to that module's own CLI.

`--batch` discovers the processed tree's sources: `windows_logs/<item>/goevtx.jsonl`
(and `*_EvtxECmd_Output.json` directories), `zeek/<capture>/`,
`log2timeline/jsonl/<source>/timeline.jsonl` (and raw `<image>.jsonl`
containers), `godfir-toolz/<tool>/<item>/<tool>.jsonl` (and `godfir-toolz/<host>/`
trees) and `memory/<image>/car.db` — one isolated store each.

**The parse stage is Go-accelerated.** Everything from a raw processor file to
the pre-enrichment CAR event stream — line reading, raw-l2t container splitting,
the format adapters, the marker resolver, the spindle identity — runs in
`go/bin/byakugan-parse`, built by `make -C go build` (**prerequisite: Go >=
1.24**) and byte-for-byte identical to the Python path it replaced
([go/README.md](go/README.md)). The CLI is unchanged: `python -m byakugan` is
still the pipeline, and routing, enrichment, the relationship cascade, STIX and
every mapping table stay Python. The pipeline finds the binary via
`$BYAKUGAN_PARSE_BIN`, then `go/bin/byakugan-parse`, then `PATH`, and says so
if it is missing.

Each evidence **source** becomes two self-contained SQLite stores:

- **`car.db`** — the CAR object events (one table per object) + `car_<object>.jsonl`.
- **`superset.db`** — the CAR + ATT&CK superset model and the relationship-instance
  timeline linking the car.db rows (`car_relationships.jsonl`).

## Documentation

| doc | what |
|---|---|
| [docs/Architecture.md](docs/Architecture.md) | principles, components, coverage, the two-store model |
| [docs/DataModel.md](docs/DataModel.md) | CAR (13) + the CAR+ATT&CK superset (38), reconstructed live from pinned submodules |
| [docs/CAR-Pipeline.md](docs/CAR-Pipeline.md) | how the pipeline works end to end |
| [docs/CAR-Relations.md](docs/CAR-Relations.md) | per-object rules and the enrichment-cascade reasoning |
| [docs/CAR-Extraction-Rules.md](docs/CAR-Extraction-Rules.md) | the four extraction principles every CAR object is built by |
| [docs/CAR-CrossSource.md](docs/CAR-CrossSource.md) | the deferred cross-source aggregate stage (correlating across per-source stores) |
| [docs/Elastic-Store-Plan.md](docs/Elastic-Store-Plan.md) | the served-store decision (SQLite → Elasticsearch, not a graph DB) and the cross-repo migration plan |
| [docs/car-provenance/](docs/car-provenance/README.md) | the property-provenance catalogue: every CAR field → every artefact that can supply it |
| [docs/research/cross-source-linkage/](docs/research/cross-source-linkage/README.md) | the research arc — resolving entities across sources and lining detections up against them |

The north-star goal (evidence → CAR → superset relationships → flagged MITRE
TTPs) and its workstreams are tracked in
[#12](https://github.com/Get-Sybers/byakugan/issues/12).

## Contributing

Setup (submodules + dev install), commands, code style, and the branch/release
flow are in [CONTRIBUTING.md](CONTRIBUTING.md).

Dependencies are traced in three files, each carrying its own upgrade path:
[`requirements.txt`](requirements.txt) (runtime — the same list as
`pyproject.toml`, held to it by a test), [`requirements-dev.txt`](requirements-dev.txt)
(the exact test/lint versions the repo is proven against) and
[`go/go.mod`](go/go.mod) for the parse engine, which is stdlib-only.

## Standalone tooling

Standalone public tooling, consumed by pipelines via the CLI:
[anamnesis](https://github.com/Get-Sybers/Anamnesis) (memory → CAR) and
Byakugan (processor output → CAR).
