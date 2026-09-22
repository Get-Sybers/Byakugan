# `model/` — the materialized data model

A **human-navigable, human-readable** snapshot of the two models this project
runs on, materialized as static YAML (plus the SQL schema snapshots) so the shape
of the model is reviewable without checking out the submodules or running the
pipeline. Everything here is **generated from the project's own model code** at
the pinned submodules — never hand-written — and is fully regenerable. (The
hand-authored CAR → ECS boundary contract that used to live alongside it here,
`projection/`, has since moved to [`elastic/projection/`](../elastic/projection/)
— the Elastic home; see below.)

This implements the intent of issue #33: keep the static relationship/data-source
model as YAML, co-located with a generator and this README.

## Source of truth

The live source of truth is **not** this directory — it is the pinned submodules
and the code that reconstructs the models from them:

| Submodule | Pinned commit |
|-----------|---------------|
| [`third_party/car`](../third_party/car) (MITRE CAR data model) | `1b922fe1527d956e222a99473472e594f10f610b` |
| [`third_party/attack-datasources`](../third_party/attack-datasources) (ATT&CK data sources) | `5d50f731de441eb09078623a2c29cc3420a01949` |

The files under `model/` are a **materialized snapshot of that pinned model**
(materialized 2026-09-02). A model refresh is a **submodule-pin bump** followed by
re-running the generator — never a hand edit here. This is consistent with the
repo's guiding principle: *everything is data, reconstructed from source* (the
CAR/superset models are otherwise built on demand and nothing generated is
normally committed; see [`docs/DataModel.md`](../docs/DataModel.md)).

## Layout

```
model/
├── generate.py                      the ONE generator — reproduces everything below
├── car/
│   └── objects/<object>.yml         one file per CAR object (13)
├── superset/
│   ├── model-objects.yml            the CAR + ATT&CK object catalogue (38)
│   ├── relationship-types.yml       the ATT&CK relationship vocabulary (243 edge-types)
│   └── relationship-schema.yml      the relationship-instance row shape
├── relationships/
│   ├── declared.yml                 the DECLARED relationship model: per object the owner-edge
│   │                                verb per action, the special edges, the association
│   │                                properties each edge carries — typing-tiered (exact |
│   │                                extension) against the pinned ATT&CK catalogue
│   └── derived.yml                  the DERIVED relationship model: strong identities, 1:1
│                                    links, reconstruction rules
└── spindle/
    ├── identity.yml                 the spindle row-identity registry, resolved against the maps
    ├── record.yml                   the shape of a spindle — a minted-identity CAR row
    └── golden.yml                   the golden vectors: the guid the engine mints per entry's sample
```

### `relationships/` — the declared + derived relationship model, readable

The hand-authored relationship sources (`byakugan/cascade_relationships.yml`,
`byakugan/relationships.yml` `derived:`) rendered for the reader — one place to
see every edge the engine can materialize: the owner-edge verb per (object,
action) with its association properties (facts *of* the edge, the #108
pattern), the special edges with their triggers, and the derived
links/reconstructs with their identities. Every edge carries a **typing
tier**: `exact` (the triple exists in the pinned ATT&CK catalogue under the
element aliasing in `generate.py`) or `extension` (a catalogue verb applied
where Byakugan's evidence is finer-grained than ATT&CK's elements). The gap
register behind the declarations is
[`docs/research/relationship-model-gaps.md`](../docs/research/relationship-model-gaps.md).

(`projection/` — the hand-authored CAR -> ECS boundary contract — used to be
here too; it now lives at [`elastic/projection/`](../elastic/projection/).)

### `car/objects/<object>.yml` — the 13 CAR objects

One file per canonical MITRE CAR object (`authentication`, `driver`, `email`,
`file`, `flow`, `http`, `module`, `process`, `registry`, `service`, `socket`,
`thread`, `user_session`). Each file carries the object's name and description,
its `car_action` list (from the superset `model_object.actions`), and its
`properties`, **clearly separated** into:

- **`common_header`** — the eight fields every CAR event row shares
  (`timestamp`, `car_action`, `guid`, `owning_guid`, `link_confidence`,
  `source_artefact`, `source_host`, `native`), defined by
  [`byakugan/store.py`](../byakugan/store.py) (`HEADER`); and
- **`object_fields`** — the object's MITRE CAR fields, with the description and
  example the CAR data model provides for each.

> **Descriptions and examples are copied verbatim from the upstream MITRE CAR
> data model** (the pinned `third_party/car` submodule). They are intentionally
> *not* edited here — this directory is a faithful snapshot — so they may carry
> upstream typos or imperfect example values (e.g. a `flow.dest_port` example
> that shows an IP address). Corrections belong upstream in the car data model,
> not in this snapshot; a submodule-pin bump + regenerate then brings them in.

### `superset/` — the CAR + ATT&CK superset

- **`model-objects.yml`** — the 38-object catalogue: each object's `name`,
  `source` (`car` | `attack` | `car+attack`), `actions`, and `definition`
  (the ATT&CK data-source definition, `null` for CAR-only objects).
- **`relationship-types.yml`** — the 243 identified ATT&CK relationships, each a
  `source --relationship--> target` edge, grouped by source element for
  navigability. This is the cascade *vocabulary*.
- **`relationship-schema.yml`** — the row shape of `SupersetStore.relationships`
  (`timestamp`, `source_host`, `relationship`, `source_object`, `source_guid`,
  `target_object`, `target_guid`, `confidence`, `method`, `class`,
  `identity_key`, `inferred_end`, `corroborated_by` — `superset.REL_COLUMNS`).

> **Identifier note.** `relationship-types.yml` uses the upstream ATT&CK
> *data-element labels* (spaced, lower-case — e.g. `application log`), whereas
> `model-objects.yml` and the object filenames use the normalized object *keys*
> (underscored — e.g. `application_log`). They correspond one-to-one but are
> **not string-identical**, so don't join the two files on the raw label.

`relationship-schema.yml` is the row shape of `SupersetStore.relationships`
(`byakugan/superset.py`'s `REL_COLUMNS`) — the engine holds this collection in
memory for the duration of a build and writes only `car_relationships.jsonl`;
there is no SQLite schema to snapshot any more (the `sql/` directory that used
to hold `car.sql`/`superset.sql` dumps of the old per-source SQLite stores is
gone — Byakugan is an elastic engine now, and the materialised JSONL tree is
its only on-disk product; see [docs/Architecture.md](../docs/Architecture.md)).

### `spindle/` — the spindle row identity

A disk-image row (log2timeline / Plaso) carries no sensor-minted id, so its
`guid` is **minted**: `uuid5(SPINDLE_NS, canonical_json({"_obj": <object>,
"_v": <version>, <name>: <value>, …}))` over the record's own stable-identity
fields — the same recipe the STIX projection mints §2.9 ids with
([`byakugan/ids.py`](../byakugan/ids.py); `ids.mint` is the one
seam). *Which* fields identify each artefact's row is a rule, declared as data
in [`byakugan/spindle.yml`](../byakugan/spindle.yml) (a map only
names its entry): per entry the CAR object, the `kind` (`record` — a
record-numbered / journal key asserting the *same record*; `entity` — a
content-like key asserting records that *coincide*), the `scope` (`intrinsic`;
`positional` is the per-record fallback), the identity-key `version` (hashed
as `_v`), what it is `validated_against` (`[plaso]` — cross-run within the
tool — until a second tool's map renders the same key on a real record), what
it is `stable_across`, the ordered `identity` and a `golden` sample. The
registry also declares the **external forms** every other map carries
verbatim (a sensor's or tool's own id) and the cross-source **equality** rule
(#41). This directory is that registry's materialized snapshot:

- **`identity.yml`** — every registry entry resolved against the live maps:
  `name`, `map`, `variants`, `car_object`, `car_action`, `kind`, `scope`,
  `version`, `validated_against`, `stable_across`, the ordered `identity`
  (`name ← source path on the event`), the positional `fallback`
  (`SourceImage`, `RecordId`) — plus the external forms with the maps that
  carry them, the equality rule, the literal namespaces (`STIX_NS`, `CAR_NS`,
  `SPINDLE_NS`), the mint rule and the scope / kind vocabularies.
- **`record.yml`** — the shape of a spindle: what a minted-identity CAR row
  *is* (the common header, `native.spindle_key`, `native.spindle_scope`,
  `native.spindle_ref` — the record's provenance, outside the key — the
  linkage back to its artefact) and its invariants, in the `car/objects`
  convention.
- **`golden.yml`** — the golden vectors: per entry the key and the guid the
  engine mints for its sample at the entry's version, the positional vector,
  one vector per external form, and the recipe vector. It is the **change
  protocol's evidence**: an entry's guid may move only together with its
  version; the recipe vector never moves.

All three are generated by `python model/generate.py` (or
`python -m byakugan.spindle`) from
[`byakugan/spindle.py`](../byakugan/spindle.py) — the code the
engine mints with — and drift is caught by `python -m byakugan.spindle
--check` (CI) and `tests/test_spindle_model.py`: registry ↔ maps ↔ engine,
committed snapshot ↔ fresh rendering, and the golden gate. **Changing an
identity** follows the protocol in `spindle.yml`: edit the entry → bump its
`version` → `python model/generate.py` → commit `model/spindle/` (golden.yml
included) → rebuild the stores (`--batch --force`; a remint tool follows). The
check — and the generator itself — refuse an identity whose guid moved without
its version. See `docs/CAR-Pipeline.md` §7.1.

### `projection/` — moved to `elastic/projection/` — the Elastic home

The hand-authored CAR → ECS boundary contract (the static YAML that decides
how each CAR object and field lands in ECS 8.x, plus the rendered Elastic/
Kibana assets) used to live here as `model/projection/`. It is still
**validated against** `car/objects/*.yml` (a CAR field without a decision
fails the same way it always did), but the contract itself is Elastic's, not
a materialized snapshot of the submodule models this directory otherwise
holds — so it now lives at [`elastic/projection/`](../elastic/projection/),
alongside the rest of Byakugan's Elastic story. See
[`elastic/projection/README.md`](../elastic/projection/README.md).

## Regenerating

One command, from the repo root, after the submodules are checked out and the
package is installed:

```sh
git submodule update --init --recursive third_party/car third_party/attack-datasources
pip install -e .
python model/generate.py
```

[`model/generate.py`](generate.py) reproduces **every** file above — the
per-object YAML and the superset YAML — deterministically from the pinned
submodules. It re-uses the project's own model code rather than
re-implementing anything:

- [`byakugan/carmodel.py`](../byakugan/carmodel.py) — loads the 13
  CAR objects (fields + actions) from the pinned car submodule.
- [`byakugan/build_data_model.py`](../byakugan/build_data_model.py) —
  builds the CAR + ATT&CK superset (objects) and the relationship catalogue.
- [`byakugan/store.py`](../byakugan/store.py) — the `CarStore`
  header (`HEADER`, common to every CAR object).
- [`byakugan/superset.py`](../byakugan/superset.py) — the
  `SupersetStore` row shapes (`REL_COLUMNS`/`INFERRED_COLUMNS`).
- [`byakugan/spindle.py`](../byakugan/spindle.py) — the spindle
  registry resolved against the maps, and the spindle record shape (`spindle/`).

## Inputs that feed the model

Three **hand-authored** input files (kept under `byakugan/`, not here) drive
the relationship and identity layers and are *not* regenerated by this directory
— they are the inputs the materialized models are built against:

- [`byakugan/relationships.yml`](../byakugan/relationships.yml) — the
  CAR inheritance / dedupe / identity / join rules the enrichment cascade applies.
- [`byakugan/cascade_relationships.yml`](../byakugan/cascade_relationships.yml)
  — maps each cascade edge (owning-process, parent, auth↔session, file→process,
  thread injection) to a verb in the ATT&CK relationship vocabulary materialized
  in `superset/relationship-types.yml`.
- [`byakugan/spindle.yml`](../byakugan/spindle.yml) — the spindle
  row-identity registry: per artefact, the fields a disk-image row's guid is
  minted from, materialized in `spindle/identity.yml`.
