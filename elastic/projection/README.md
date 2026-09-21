# `elastic/projection/` — the CAR → ECS boundary contract

**Hand-authored. Validated by `validate.py`. Owned by Byakugan.**

This directory is the one place that decides *how a finished MITRE CAR event
lands in Elastic*: the mapping of every CAR object and every CAR field onto
**Elastic Common Schema 8.x** (`ecs.version: 8.11.0`). It is the boundary
contract the **DX_DFIR loader consumes** to write CAR events into Elastic as
`logs-car.<object>-*` data streams — one data stream per CAR object, one ECS
document per CAR event row, no envelope.

Unlike the generated model data under `model/`, nothing here is generated: a
projection is a *decision* (which ECS field is the honest home for
`thread.start_address`? none — so it stays native), and decisions are
authored, reviewed and versioned by hand. What *is* mechanical is keeping
those decisions in step with the generated CAR model (`model/car/objects/`)
— that is `validate.py`'s job, and it fails the build on drift.

## Layout

```
elastic/projection/
├── README.md                      this file
├── conventions.yml                cross-cutting rules: the common header, data-stream shape,
│                                  the car.* custom namespace, precedence/coercion rules
├── objects/<object>.yml           one file per CAR object (13): every object_field -> ECS, or native
├── relationships.yml              relationship-timeline row (REL_COLUMNS) -> logs-car.rel-* (the edge timeline)
├── inferred.yml                   inferred-node row (INFERRED_COLUMNS) -> logs-car.inferred-*
├── ecs_types.yml                  mapping-type overrides (date/long/ip/float/boolean) for the
│                                  non-keyword `ecs:`/`also:`/`derived:` targets objects/*.yml uses
├── validate.py                    the drift check (pyyaml only) — exit 1 on any problem
├── render_elastic.py              renders rendered/ from the contract (pyyaml only) — --check for drift
├── rendered/                      GENERATED, committed: component templates, index templates, Kibana views
├── test_projection_contract.py    thin pytest wrapper around validate.py + render_elastic.py --check
└── test_kibana_assets.py          structural checks on rendered/kibana/*.ndjson
```

## The shape of the contract

### `conventions.yml`

- **Identity.** `timestamp → @timestamp`, `car_action → event.action` (the CAR
  verb, verbatim), `guid → event.id` (and, for `process`, `process.entity_id`),
  `owning_guid → process.entity_id` (the owning/acting process — in ECS the
  `process.*` block on a file/registry/module/… event *is* the process that
  acted), `parent_guid → process.parent.entity_id` (a MITRE `process` field, in
  `objects/process.yml`).
- **Provenance / scope.** `source_artefact → event.provider`,
  `source_host → host.name`; `event.dataset` / `data_stream.dataset` are the
  constant `car.<object>`.
- **Confidence.** `link_confidence → car.link_confidence` (float:
  `definitive = 1.0`, `heuristic = 0.5`) plus the verbatim word in
  `labels.link_confidence`. Deliberately *not* `event.risk_score` — it measures
  the owner/parent join, not event risk, and the Detection Engine's
  `risk_score_mapping` would otherwise read it as such.
- **Native.** `native → car.native` (ECS `flattened`): the source-evidence bag,
  keys verbatim. CAR *object* fields ECS cannot home land at
  `car.<object>.<field>` with a declared type. **Nothing homeless is dropped.**
- **Rules** the object files rely on: `one_home`, `fallback` (explicit
  precedence when two CAR fields share an ECS target), `coercion` (an
  unparseable value for a typed ECS field is kept verbatim under `car.*`),
  `verbatim` (only ECS-demanded normalisations, each called out on its entry),
  `nulls`, `event_action`.
- The **data-stream shape** (`logs-car.<object>-<namespace>`, the constants
  stamped on every document, a recommended deterministic `_id`) and the default
  `event.category` per object.

### `objects/<object>.yml`

```yaml
object: process
data_stream: logs-car.process-*
event_defaults:
  category: [process]              # ECS event.category for the object
  type_by_action: {create: [start], terminate: [end], ...}   # every car_action, no more
fields:
  - car: command_line              # a CAR object_field (must exist in model/car/objects/process.yml)
    ecs: process.command_line      # its ONE primary ECS home ...
    also: [related.user]           # ... plus optional unconditional copies
  - car: uid
    ecs: user.id
    fallback: true                 # shares user.id with `sid`: fills it only when sid is null
  - car: integrity_level
    native: true                   # ECS has no honest home -> car.process.integrity_level
    type: keyword                  # its mapping type there
    rationale: ECS has no process integrity-level field ...
```

An entry is **mapped** (`ecs:`) or **native** (`native: true` + `rationale` +
`type`) — never both, never neither. `derived:` entries name ECS fields the
loader builds from CAR data that is not a field of its own (e.g.
`http.request.method` from `car_action`).

### Namespace decisions, per object

| object | ECS home | native (`car.<object>.*`) |
|---|---|---|
| authentication | `user.*` = the account **being authenticated**, `source.user.*` = the initiating account, `related.user`, `event.outcome`, `source.domain`, `destination.domain` | `method`, `user_type`, `target_user_type` |
| driver | `file.*` (the driver image; ECS has no driver object), `file.code_signature.*`, `process.pid` | `base_address` |
| email | `email.*` (sender = envelope, from = header, to = envelope recipient), `source/destination.*` | `dest`-vs-`to` overflow, `server_relay`, `message_links`, `src_domain`, `message_body` |
| file | `file.*`, `file.hash.*` (the file's own hash), `process.*` (the acting process) | `previous_creation_time`, `content` |
| flow | `network.*`, `source.*` (initiator), `destination.*` (responder), `event.start/end`, `process.*` | `content`, `proto_info`, `tcp_flags` |
| http | `url.*`, `http.*`, `user_agent.*`, `source.ip` | — |
| module | `dll.*` (+ `file.*` copies, as Elastic's Sysmon 7 does), `process.*` | `base_address` |
| process | `process.*`, `process.parent.*`, `process.hash.*`, `process.code_signature.*`, `user.*` | `integrity_level`, `access_level`, `call_trace`, `target_guid/pid/address/name` (ECS has no target-process block) |
| registry | `registry.*` (key verbatim; hive abbreviated per ECS), `process.*` | `new_content` |
| service | `service.name`, `process.*`, `user.*`; Windows-service specifics arrive via `car.native` | — |
| socket | `source.*` = local end, `destination.*` = remote end, `network.transport/type`, `event.outcome` | — |
| thread | `process.*` = the **acting** process/thread, `dll.*` for the start module | `tgt_pid`, `tgt_tid`, every stack/start address, `start_function` |
| user_session | `user.*`, `related.user`, `source/destination.*`, `event.outcome` | `login_id` (the LUID join key), `login_type` |

Recording where ECS *lacks* a field is the point of a hand-authored contract:
a bad mapping is worse than an honest `native`.

## Validating

```sh
python elastic/projection/validate.py    # exit 1 + a problem list on drift; one-line summary on success
pytest -q elastic/projection             # the same, as a test
```

`validate.py` asserts: every CAR object has a file and there is no orphan
file; every `object_field` has exactly one entry and no entry names a field the
object does not have; every common-header field is projected; `ecs:` paths are
ECS-shaped (a known ECS 8.x top-level field set — `car.*` homes must be
`native: true`, never an `ecs:` path); shared targets declare `fallback: true`;
`event_defaults` cover every `car_action` and only those; `derived:` sources
exist. The same run also checks `relationships.yml` / `inferred.yml`: their
`fields:` cover exactly the exported `relationship` / `inferred_node`
column lists (no dup, no unknown key), every entry's `type:` (or an
`ecs_types.yml` match) is explicit, the `document_id.recipe` names real source
columns, and `constants:` carries the data_stream identity — and it checks
`ecs_types.yml` itself: every path is ECS- or `car.*`-shaped, and every
non-keyword override is actually used somewhere in the contract (no dead
overrides).

## Rendered assets

`render_elastic.py` (pyyaml only, like `validate.py`) renders the contract —
`conventions.yml` + `objects/*.yml` + `relationships.yml` + `inferred.yml` +
`ecs_types.yml` — into the Elasticsearch/Kibana assets DX_DFIR's loader
composes at index-template time, under `rendered/` (committed output, like
`model/sql/*.sql`: a point-in-time record kept for inspection and easy
diffing, not a live artifact in its own right):

- `rendered/component_templates/logs-car-header.json` — the common-header
  mapping every stream shares (composed first everywhere): the eleven
  `byakugan/store.py` HEADER fields at their ECS/custom homes, plus the
  CAR-name aliases (`car.guid → event.id`, `car.owning_guid → process.entity_id`, ...)
  a query can use either name through.
- `rendered/component_templates/logs-car-<object>.json` (13) /
  `logs-car-rel.json` / `logs-car-inferred.json` — one stream's own mapped
  fields (typed via `ecs_types.yml`, keyword by default), its `native: true`
  fields as concrete `car.<object>.<field>`, and (objects only) a CAR-name
  alias for every mapped field — deduplicated against the header, which
  already supplies `@timestamp`, `host.name`, `process.entity_id`, ...
- `rendered/index_templates/logs-car-<object>.json` (13) + `logs-car-rel.json`
  + `logs-car-inferred.json` — `index_patterns`, `data_stream: {}`,
  `composed_of: [logs-car-header, the stream's own component, logs-car@custom]`,
  with `ignore_missing_component_templates` so the template applies before
  DX_DFIR creates its own `@custom` customization component.
- `rendered/kibana/logs-car-views.ndjson` — one data view (`logs-car.*`) and
  one saved search, minimal and hand-editable, its saved-object shapes
  modelled on the uSaid Kibana bundle conventions.

```sh
python elastic/projection/render_elastic.py           # write rendered/
python elastic/projection/render_elastic.py --check    # verify rendered/ is in sync; write nothing
```

`--check` is the drift guard (the same idea as `byakugan.gen_sources --check`):
it re-renders to memory and byte-compares against the files on disk, exiting 1
with a missing/drifted/orphan-file list on any mismatch — so `rendered/` going
stale after a contract edit is caught exactly like an un-regenerated `sources/`
manifest is. `test_projection_contract.py` runs `--check` in CI;
`test_kibana_assets.py` separately checks the Kibana bundle's own internal
consistency (every column/sort/timeField resolves against the rendered
mappings of the streams its data view matches, references resolve, ids are
unique); `tests/test_projection_rel_drift.py` (repo root) checks
`relationships.yml`/`inferred.yml` against the *live* superset.py row shapes, not
just their own declared coverage.

## Changing it

- **A CAR model refresh** (submodule-pin bump + `python model/generate.py`)
  that adds or renames a field makes `validate.py` fail until the new field has
  a decision here. That is the intended coupling.
- **A mapping decision** changes in `objects/<object>.yml` (or, for the header,
  `conventions.yml`); bump `contract.version` in `conventions.yml` when a target
  field *path* changes — the loader and any rule written against the old path
  need to know.
- Do not add a `car.*` path as an `ecs:` target; mark the field `native: true`
  and let the namespace rule place it.

## What this is not

- Not runtime code: no loader, no ingest pipeline, nothing that talks to a
  live cluster. Elasticsearch component/index templates now ARE rendered here
  (`render_elastic.py`, `rendered/` — see above); *putting* them
  (`_component_template` / `_index_template`), the ingest pipeline, and the
  loader that writes CAR events into the resulting streams are still built in
  DX_DFIR *from* this contract.
- Not the Sigma/detection layer: rules are authored against the ECS fields this
  contract produces (and the `car-detections` lookup joins on `event.id`), in a
  later phase.
- Not a replacement for the existing per-object JSONL export
  (`store.export_jsonl()`) — this is additive.
