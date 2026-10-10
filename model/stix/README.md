# `model/stix/` — the CAR → STIX 2.1 projection contract

**Hand-authored. Validated by `validate.py`. Engine: `byakugan/stix.py`.**

This directory is the one place that decides *how the materialised CAR
becomes STIX 2.1 at export*. The projection is **derived from CAR** — the
object events (`car_<object>.jsonl`), the relationship timeline
(`car_relationships.jsonl`, both classes), the reconstructed nodes
(`car_inferred.jsonl`), the content-keyed attribution layer (recomputed from
the same events) and the `native` bag — and from
nothing else. There is no parser-side STIX and no second extraction path: a
re-export of the same stores reproduces the same bundle, byte for byte. OpenCTI
(or any STIX consumer) is an **exchange interface only**; the stores stay the
truth.

Like `model/projection/` (CAR → ECS), nothing here is generated: a projection
is a *decision* (is a Windows service a `process` with `windows-service-ext`,
or nothing? — a process), and decisions are authored, reviewed and versioned by
hand. What is mechanical is keeping them in step with the generated CAR model
and with the engine — that is `validate.py` plus `tests/test_stix.py`.

## Layout

```
model/stix/
├── README.md          this file — the model, stated as fact
├── conventions.yml    the id-derivation rules (global vs case-scoped), the identity conventions
│                      mirrored from CAR -> ECS, observation / relationship / inferred-node shape,
│                      and the three engine declarations; `contract.version` is the ONE version marker
├── objects.yml        one entry per CAR object (13): its SCO, its SRO end, its hash subject, its
│                      acting-process columns, and every object_field's home
├── changelog/         one file per contract version (`v<N>.md`): the delta record — decisions,
│                      defect register, migration rules. Rationale lives there, never here
└── validate.py        the drift check (pyyaml only) — exit 1 on any problem
```

## The two extension-definitions

Every property and object outside the STIX core rides one of two §7.3
extension-definitions; each bundle carries the definitions its objects use,
and both carry `created_by_ref` → their producer identity.

- **`dxdfir`** — the detection-exchange extension (`extension_type:
  property-extension`): `detection_id`, `severity`, `status`, `case_id`,
  `run_id`, `car_guid`, `car_object`, `technique`, `signature`, `source`,
  `feed`, `alert_ids`, `matched`, `indicator`, `relationship_class` on
  indicator / sighting / relationship — the closed set in
  `exchange/extension/dxdfir-extension.schema.json`.
  Its id is `extension-definition--uuid5(DX_NAMESPACE,
  'extension-definition|dxdfir')`; its `$id` URL and `DX_NAMESPACE` are wire
  constants.
- **`dxdfir-evidence`** — the CAR evidence extension (`extension_types:
  ["toplevel-property-extension", "new-sco", "new-sdo"]`). Its
  `extension_properties` list declares every `x_car_*` top-level property —
  the list is closed and generated from the emitted surface
  (`byakugan/stix.py` plus the contract files; 47 names). Its objects are
  `x-car-thread` and `x-car-record` (new-SCO) and `x-car-inferred-node`
  (new-SDO). Its id is `extension-definition--uuid5(DX_NAMESPACE,
  'extension-definition|dxdfir-evidence')`; its definition carries a
  description and an external reference to this contract; its `schema` URL
  is the raw `github.com/Get-Sybers` path of
  `model/schema/extensions/dxdfir-evidence.schema.json`.

Where the spec predefines an SCO extension, the predefined extension is the
home: `http` rides `network-traffic` + `http-request-ext`, `socket` rides
`network-traffic` + `socket-ext`, `service` rides `process` +
`windows-service-ext`. The dxdfir extensions carry only what no core or
predefined property home already covers.

## What a bundle holds

| STIX object | from | one per |
|---|---|---|
| SCOs (`process`, `file`, `directory`, `windows-registry-key`, `network-traffic`, `user-account`, `ipv4-addr`/`ipv6-addr`, `domain-name`, `url`, `email-addr`, `email-message`, `x-car-thread`, `x-car-record`) | object event rows | entity a row observes (superset-filled across rows); `x-car-record` anchors a row that projects no entity |
| content SCOs (`file` by hash, `user-account` by real SID) | superset `content_node` (derive's content pass over the same events) | content |
| `observed-data` | object event rows | row with an identity and a time — the observation, `x_car_*` extension properties, `x_car_native` verbatim, `x_car_fields` for what no SCO property homed (a guid-less row keys nothing off itself: its content/path SCOs stand, no observation — `observations_skipped_no_identity`) |
| `relationship` | superset `relationship` | row, both classes, labelled `car:declared` / `car:derived` + `car:<method>`; `relationship_type` is drawn from the closed, generated evidence vocabulary |
| `x-car-inferred-node` | superset `inferred_node` | reconstructed node — an extension-defined SDO, flagged, `confidence: 20`, never an SCO, never inside an observation |
| `indicator` | runnable CAR analytic | analytic (the detection, `pattern_type: car`) — **global**, catalogue-keyed |
| `relationship` (`indicates`) | analytic coverage | `indicator → attack-pattern`, one per technique an analytic covers — **global**, catalogue-keyed; the target is MITRE's authoritative `attack-pattern--<uuid>` |
| `sighting` | `analytics` over the object events | behaviour hit — a Sighting of the indicator over the row's observed-data — **case-scoped** |
| `identity` | — | the producer (with `contact_information`); plus one per host (`identity_class: system`) where a behaviour was sighted |
| `extension-definition` | — | bundle — the `dxdfir-evidence` definition; the exchange's own `dxdfir` definition rides the exchange bundles that use it |

Not bundle members: MITRE's `attack-pattern` objects — techniques
are referenced by their MITRE-authoritative ids, resolved through the pinned
exchange attack index (revoked ids substituted by their successors) — and the
four TLP `marking-definition` singletons, which are referenced, never emitted.

## Ids — the scopes

- **Content-keyed → global, spec-deterministic.** A file by hash, an account by
  real SID, an IP, a domain, a URL, an e-mail address get the STIX 2.1 §2.9 id:
  UUIDv5 over the STIX namespace and the canonical JSON of the ID-contributing
  properties. The STIX namespace mints SCO ids only. For a file *one* hash
  contributes (MD5, SHA-1, SHA-256, SHA-512 — the first present), and the hash
  nodes one record co-references are unioned first so the file carries all its
  hashes. The content file carries its hashes and nothing else — no `name`,
  no extension entry; names, paths, signers and reference counts ride on the
  case-scoped instance objects and observations. The same content is the same
  object in every case, for every consumer.
- **Instance / observation → case-scoped.** A process, a file at a path, a key,
  a connection, every `observed-data`, every `sighting`, every evidence SRO,
  every `x-car-*` object, the host identities and the bundle id get UUIDv5
  under the per-case namespace
  `case_ns = uuid5(CAR_NS, "case|<case>")` (`--case`, default the car
  directory's name). A re-export of the same case is idempotent; two cases
  never collide; the same path on two hosts never collapses into one object.
  This deviates from the spec's SHOULDs — UUIDv4 for SDOs/SROs, and the §2.9
  contributing-property UUIDv5 for `directory` / `windows-registry-key` /
  `network-traffic` / `email-message` — see
  `conventions.yml id_derivation.case_scoped.deviation`.
- **Catalogue → global, producer-deterministic.** `indicator` and the
  `indicates` SRO get UUIDv5 under
  `catalogue_ns = uuid5(CAR_NS, "catalogue")` — the same detection is the same
  object in every case.
- **SMOs.** Each extension-definition id is
  `uuid5(DX_NAMESPACE, "extension-definition|<name>")`.
- **The spindle guid is row identity, never an object id.** It rides in
  `x_car_event_id` / `native.spindle_key` only; `SPINDLE_NS` sits under
  `CAR_NS` so row guids and object ids cannot collide.

## Markings

TLP is a deployment-level export setting (`exchange` config: `tlp:
white|green|amber|red|none`, default `amber`; env `BYAKUGAN_STIX_TLP`, CLI
`--tlp`) — evidence sensitivity is a property of case handling, not of the
artefact. `object_marking_refs` is attached to SDOs, SROs and `observed-data`;
SCOs, marking-definitions, extension-definitions and the bundle carry none.
The four TLP marking-definitions are the spec's fixed singletons —
`white: marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9`,
`green: marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da`,
`amber: marking-definition--f88d31f6-486f-44da-b317-01333bde0b82`,
`red: marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed` — referenced,
never emitted, never bundle members. Byakugan-produced objects reference only
these four ids; third-party marking refs on merged content are tallied, never
rejected.

## Identity conventions (mirrored from CAR → ECS)

`guid → x_car_event_id` (event.id) and, on a process row without `owning_guid`,
the process SCO key; `owning_guid → x_car_process_entity_id` (process.entity_id)
and the acting process the observation references; `parent_guid → parent_ref`;
`native → x_car_native` (car.native), verbatim; `link_confidence` verbatim on the
observation and as STIX `confidence` (100 / 50 / 20) on the SRO.

## Embedded references and SROs

Embedded `_ref`/`_refs` properties carry the spec-defined structural links:
`created_by_ref`, `object_marking_refs`, `observed-data.object_refs` (the
row's SCOs and their connecting SROs — each observation references a
connected graph), the
sighting triple (`sighting_of_ref` / `observed_data_refs` /
`where_sighted_refs`), `source_ref`/`target_ref`, `process.parent_ref`,
`process.image_ref`, `file.parent_directory_ref`,
`network-traffic.src_ref`/`dst_ref`, `email-message.from_ref`/`to_refs`.
Every analyst- or derivation-level link is an SRO from the relationship
timeline: the evidence vocabulary (closed, generated — hyphenated verbs with
pair-wise source/target constraints from `model/superset/`), `indicates`, and
`sighting`. Extension-carried ids (`x_car_corroborated_by`,
`x_car_corroborating_refs`, `x_car_event_id`, `car_guid`) are provenance
pointers — data, never resolved as graph edges. The generic verbs
(`related-to`, `duplicate-of`, `derived-from`) are not in the evidence
vocabulary; the exchange admits them on inbound third-party content only. An
edge either carries a declared verb with method and confidence, or its
unresolvable end is counted (`relationships_unresolved`) — doubt is tallied,
not modeled.

## The three engine declarations

1. **`hash_subject` per leaf** — what a row's `md5/sha1/sha256_hash` hash:
   `process → image_path`, `file → file_path`, `module → module_path`,
   `driver → image_path`. The hashes land on that file instance and bind it to
   the global content file (`x_car_content_ref`).
2. **The inheritance trace is kept in native.** The cascade's null-only
   inheritance writes into the spoke's columns with no marker; the only trace of
   what the cascade / derived pass did is the keys they wrote into `native`
   (`executed_as_process_guid`, `flow_guid`, `target_session_guid`,
   `target_process_guid`, `coalesced_sources`, `coalesced_conflicts`, …). The
   projection carries them verbatim and never re-derives an SRO or a `_ref` from
   them — every SRO comes from the relationship timeline. A spoke never mints its owner: its
   acting-process columns fill the owning process SCO only when the cascade
   resolved `owning_guid`; an unresolved owner is derive's inferred node.
3. **The two native-only join keys** — `http.native.resp_fuids` (→ `file.guid`,
   the Zeek fuid; rule `http_file_transfer`) and `thread.native.TargetProcessGuid`
   (→ `process.guid`, the Sysmon 8 target; rule `injection_target`). They have no
   CAR column, live in native only, and the projection reads them from nowhere:
   the derived SROs they yield come from the relationship timeline.

## The behaviour layer — Sightings of ATT&CK techniques

The third pillar (*normalise → relate → **flag TTPs***). After the SCOs,
observations and SROs are projected, the finished object events are read back
through the **runnable MITRE CAR analytics** (`byakugan/analytics.py` — the events
only, so the "derived from the stores" contract holds) and each hit becomes STIX:

- one **`indicator`** per runnable analytic (the detection; `pattern_type: car`,
  the analytic's pseudocode the pattern; `indicator_types` and
  `kill_chain_phases` from the coverage pin; `external_references` →
  car.mitre.org);
- an **`indicates`** SRO `indicator → attack-pattern` per covered technique —
  the target id is MITRE's authoritative `attack-pattern--<uuid>`, resolved
  through the pinned exchange attack index; kill-chain and tactic vocabulary
  are generated from the same pin;
- one **`sighting`** per hit — `sighting_of_ref` the indicator,
  `observed_data_refs` the matched row's observed-data (by the spindle guid — the
  same `self.obs` map the observations built; omitted when the row produced none,
  the sighting still stands), `where_sighted_refs` the host identity,
  `first_seen`/`last_seen` the row's instant.

The catalogue (indicator, `indicates`) is **global content** — the same
detection is the same object in every case; its `modified` timestamp derives
from the pinned corpus version, and a retired analytic emits a
`revoked: true` tombstone for one contract version — and the sightings are
**case-scoped evidence**, minted like the observations. It is
**evidence-driven** — an analytic that did not fire in the case adds nothing —
and **additive**: a missing analytics corpus leaves the rest of the bundle
untouched. See `conventions.yml` `behaviour`.

## Inferred ends are flagged, never asserted

A derived relationship may end on a node no source observed (antiforensics,
partial recovery). That end is an `x-car-inferred-node` — an extension-defined
SDO with `x_car_inferred: true`, `x_car_asserted: false`, `confidence: 20`,
`labels: [car:inferred, car:reconstructed]`, carrying what the observed
records said about it and the `observed-data` that corroborate it. It is never
a `process` SCO, never in an `observed-data.object_refs`, never a
`car_<object>` row.

## Validation and running

Each object type validates against a composed schema: the vendored OASIS core
schema, byte-verbatim, under `allOf` with the byakugan overlay (the two
`extensions` entries and the `x_car_*` properties), closed by
`unevaluatedProperties: false`. The bundle schema is the minimal envelope
(`id`, `type`, `objects: [≥1]`); each member dispatches on its `type` field to
its per-type schema. Failures and unknown types are count-and-carry findings
`{object_id, rule, path, message}` — nothing is dropped for being unfamiliar —
and strict mode fails `--check` on a nonzero tally.

```sh
python model/stix/validate.py                         # the drift check
pytest -q tests/test_stix.py                          # + the engine/contract lock-step and the smoke export
python -m byakugan.stix export <car-dir> [--out FILE] [--case ID] [--as-of ISO]
python -m byakugan --in <src> --out <dir> --derive --stix   # export as a pipeline step
```

## Changing it

- A CAR model refresh that adds or renames a field makes `validate.py` fail
  until the field has a decision in `objects.yml` — the intended coupling.
- A mapping decision changes in `objects.yml` **and** in the matching
  `_b_<object>` builder of `stix.py`; `tests/test_stix.py` fails when the
  `OBJECTS` table and `objects.yml` disagree on `sco`, `sro_end`, `hash_subject`
  or `acting`. Bump `contract.version` when an id recipe or a target property
  changes — ids are what consumers keep.
- Every contract version gets its delta record in `changelog/v<N>.md` —
  decisions, defect register, migration rules live there;
  `conventions.yml contract.version` is the one version marker; this README
  states the resulting model only.
- Do not add a native key as an SRO source, and do not project an inferred node
  as its would-be SCO type.

## What this is not

- Not an OpenCTI connector or data model — the bundle is the interface.
- Not the CAR → ECS loader contract (`model/projection/`) — the two mirror the
  same identity conventions and are otherwise independent.
- Not a replacement for the JSONL exports; additive.
