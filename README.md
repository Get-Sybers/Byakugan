# Byakugan
<p align="center">
  <img src="https://github.com/user-attachments/assets/2b524ed3-0bb0-48a1-a28e-a887b6124e8c" alt="Project Banner" width="85%">
</p>

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

## How it runs

Byakugan is a **hybrid**. `go/bin/byakugan-parse` is the parse engine — build
it once (`make -C go build`; prerequisite: **Go >= 1.24**) — and everything
else — routing, enrichment, the relationship cascade, the CAR→ECS projection,
the CLI itself — is the **Python package** you actually run, as
`python -m byakugan`, `python -m byakugan.<module>`, or the `byakugan` console
script. Building the binary is a one-time setup step, not a second program to
operate day to day: every real invocation below is Python, and the pipeline
finds the binary itself (`$BYAKUGAN_PARSE_BIN`, then `go/bin/byakugan-parse`,
then `PATH`) — see [go/README.md](go/README.md) for the engine.

## Three ways to run it

Byakugan works as an individual component in three shapes:

- **Standalone.** Point it at whatever your forensic tooling already produces
  (the Quickstart below) — `car_<object>.jsonl` + `car_relationships.jsonl` is
  a complete, self-contained result on its own. For a queryable tier, stand up
  Byakugan's own Elasticsearch + Kibana: [elastic/README.md](elastic/README.md).
- **Fed by Anamnesis alone.** `memory/<image>/car.db` — Anamnesis's own
  finished CAR — is a first-class input on its own, no other evidence
  required: passthrough, links preserved. The exact translation, and what the
  enrichment cascade does and does not do to it:
  [docs/Anamnesis-Interchange.md](docs/Anamnesis-Interchange.md).
- **Inside DX_DFIR.** The
  [GoDFIR-toolz](https://github.com/Get-Sybers/GoDFIR-toolz/tree/main/byakugan)
  image wraps this engine as one container in DX_DFIR's wider pipeline;
  DX_DFIR's own Ansible/compose own the orchestration, scheduling and its
  Elastic stack. Nothing here changes to be embedded — the same
  `byakugan <sub-tool>` env contract this README documents is exactly what
  DX_DFIR drives.

## Quickstart

```
git submodule update --init --recursive          # the model comes from pinned submodules
make -C go build                                 # the Go parse engine (Go >= 1.24)

python -m byakugan --in <file-or-dir> --out <dir>   # build: one source
python -m byakugan --batch <processed_dir>          # build: every source, isolated

python -m byakugan.timeline <car-dir>               # timeline: from the local materialised JSONL tree
python -m byakugan.timeline <car-dir> --elastic <es-url> --namespace <ns>   # timeline: from logs-car.* instead

python -m byakugan.verify <car-dir>                 # verify: the CAR run-through (correctness gate)

python -m byakugan.elastic.load <car-dir>                   # load: bundle mode — offline _bulk NDJSON, no network
python -m byakugan.elastic.load <car-dir> --es-url <url> --es-user <u> --es-password <p>   # load: push mode — also POSTs it

byakugan car-vocab                                  # the canonical car_action vocabulary, one JSON line
byakugan build|timeline|verify|car-vocab|load       # env-driven (BYAKUGAN_<SUBTOOL>_*): one JSON summary line
```

`byakugan <sub-tool>` with nothing else is the container entry point
(`byakugan/cli.py`): `build`, `timeline`, `verify` and `load` each read their
own `BYAKUGAN_<SUBTOOL>_INPUT_DIR` / `_OUT_DIR` / `_FORCE` / `_LOG_LEVEL`
block, print exactly one JSON summary line on stdout and exit by the uniform
table (0 ok, 1 nothing — or the verify gate failed, 2 config error, 3
partial); `car-vocab` takes no env block — it just prints the vocabulary and
exits. A sub-tool followed by arguments is instead the pass-through to that
module's own CLI, exactly as in the Quickstart above (`byakugan timeline
<car_dir> [flags]`, `byakugan load <car_dir> [flags]`, ...).

`--batch` discovers the processed tree's sources: `windows_logs/<item>/goevtx.jsonl`
(and `*_EvtxECmd_Output.json` directories), `zeek/<capture>/`,
`log2timeline/jsonl/<source>/timeline.jsonl` (and raw `<image>.jsonl`
containers), `godfir-toolz/<tool>/<item>/<tool>.jsonl` (and `godfir-toolz/<host>/`
trees) and `memory/<image>/car.db` — one isolated store each.

**The parse stage is Go-accelerated.** Everything from a raw processor file to
the pre-enrichment CAR event stream — line reading, raw-l2t container splitting,
the format adapters, the marker resolver, the spindle identity — runs in
`go/bin/byakugan-parse`, byte-for-byte identical to the Python path it replaced
([go/README.md](go/README.md)). Routing, enrichment, the relationship cascade,
STIX, the CAR→ECS projection and every mapping table stay Python.

## The materialised CAR tree

Byakugan is an **elastic engine**: for the duration of one source's build it
holds that source's finished CAR events and relationship edges **in memory**
(`store.CarStore`, `superset.SupersetStore`) and writes only the
**materialised CAR tree** — `car_<object>.jsonl` (13 CAR objects) +
`car_relationships.jsonl` (the granular relationship-instance timeline,
always written, even empty — the build's done-marker), plus
`car_inferred.jsonl` with `--derive` — no SQLite anywhere. That JSONL tree is
**the interchange every consumer reads**: downstream ingestion,
`byakugan.timeline`, `byakugan.verify`, `byakugan.crosssource`, `byakugan.stix`,
`byakugan.exchange` and `byakugan.elastic.load` all read it, never the in-memory stores behind it
(the one exception: `byakugan/readers.py` reads an Anamnesis `car.db` — that
file is Anamnesis's own output format, a component boundary, not Byakugan's
store).

`byakugan load` projects that same materialised tree, through the CAR→ECS
projection contract (`elastic/projection/`), into `logs-car.*` Elasticsearch
data streams — the **served, queryable tier**: bundle mode renders the
`_bulk` NDJSON offline (the air-gap path); push mode also POSTs it, to
DX_DFIR's integrated stack, Byakugan's own standalone one
([elastic/](elastic/README.md)), or any other Elasticsearch that serves the
same contract. `byakugan.timeline --elastic` reads that served tier back into
the exact same `timeline.jsonl` shape a local JSONL-backed run produces.

**The STIX/CTI exchange is the engine's too** (`byakugan.exchange`, sub-tools
`stix-export` / `stix-behaviour` / `cti-pull` / `cti-sightings`): detections
out as STIX 2.1 sightings + indicators with the projection's bundles merged
through, the detection lanes joined to CAR entities as behaviour sightings
over spindle-keyed observations, and OpenCTI as the wire in both directions —
[docs/STIX-Exchange.md](docs/STIX-Exchange.md).

## Documentation

| doc | what |
|---|---|
| [docs/Architecture.md](docs/Architecture.md) | principles, components, coverage, the two-store model |
| [docs/DataModel.md](docs/DataModel.md) | CAR (13) + the CAR+ATT&CK superset (38), reconstructed live from pinned submodules |
| [docs/CAR-Pipeline.md](docs/CAR-Pipeline.md) | how the pipeline works end to end |
| [docs/CAR-Relations.md](docs/CAR-Relations.md) | per-object rules and the enrichment-cascade reasoning |
| [docs/Anamnesis-Interchange.md](docs/Anamnesis-Interchange.md) | the Anamnesis car.db contract: schema, the translation, what the second enrich pass does (and does not) do to it |
| [docs/CAR-Extraction-Rules.md](docs/CAR-Extraction-Rules.md) | the four extraction principles every CAR object is built by |
| [docs/CAR-CrossSource.md](docs/CAR-CrossSource.md) | the deferred cross-source aggregate stage (correlating across per-source stores) |
| [docs/Elastic-Store-Plan.md](docs/Elastic-Store-Plan.md) | the served-store decision (SQLite → Elasticsearch, not a graph DB) and the cross-repo migration plan |
| [docs/STIX-Exchange.md](docs/STIX-Exchange.md) | the STIX 2.1 / OpenCTI exchange: what a hit becomes, ids and versioning, the property extension, the CTI round-trip |
| [rules/README.md](rules/README.md) | the Elastic detection rules-as-code: the pinned set, the tagged-evidence-line contract, the car-detections lookup contract and the cti indicator-match rule — baked into the image at `/rules` |
| [elastic/README.md](elastic/README.md) | Byakugan's own standalone Elastic stack: bring-up, the one-command load, coexisting with DX_DFIR |
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
