# The layered schema: one static source of truth

**Status: approved mission — tracked by issue #123.** Scope: byakugan
only. Authoritative references, vendored in this repo:
[STIX 2.1 (Errata 01)](../standards/stix-v2.1-errata01-csd01-complete.md) and
[STIX Best Practices 1.0](../standards/stix-bp-v1.0.0-cn01.docx). Prior
art: MITRE's attack-data-model — used **as the specification, not the
library** (see [the alignment study](../research/attack-data-model-alignment.md)).

## Problem

The object/relationship model lives in three places that agree only by
discipline: the Go IR (authored as Go literals, `ir.json` generated FROM
code), the CAR model (reconstructed at runtime from the `model/sources/car`
submodule), and per-consumer copies (anamnesis embeds its own
`car_data_model.json`, enrich data and normalize mappings; the elastic
projection commits its own rendered artifacts). Nothing gates the engines
against a common declaration, and the submodule chains tests and image
builds to GitHub.

## Goal

One versioned JSON Schema set at **`model/schema/`** is the single source
of truth. The Go modules and the Python graph engine (byakugan's own
Elasticsearch deployment) consume the same schema files — Go via
`go:embed`, Python as package data — and each carries a conformance gate
proving it implements exactly the declared model. Drift between the
engines becomes a CI failure, not a review catch. Types and behaviour
stay in code; every static declaration lives as data
([go-standards §5, "Static declarations are data, not code"](https://github.com/Get-Sybers/DX_DFIR/blob/main/docs/reference/go-standards.md),
restored to its intended direction).

## The layers

Named for their abstraction, two words each. Walking down from "a value
lands in a CAR data object": the value arrives in the **Object Model**,
wired there by the **Model Mapping** for its artefact class, from a
`dfir_fields` key fixed by its **Artefact Class**, filled by the field
one **Parser Profile** bound to it — prefetch is prefetch regardless of
which parser read it. **Identity Rules**, **Enrichment Rules** and the
**Schema Envelope** cut across all of them.

The shape is an hourglass: **many Parser Profiles feed one Artefact
Class; one Model Mapping per artefact class feeds the Object Model.**

### Artefact Class — what the evidence is (parser-independent)

One declaration per artefact class:

- `object`: the STIX SCO type it grounds to (spec §6: `file`, `process`,
  `network-traffic`, `user-account`, `windows-registry-key`, …).
- `domain`: acquisition domain — `filesystem | memory | network | cloud`
  (the brief's `type` facet, renamed to avoid colliding with the STIX
  `type` property; `family` added as the parser-binding facet).
- `family`: the artefact family (`prefetch`, `mft`, `evtx`, `journal`,
  `wtmp`, `srum`, `pcap-flow`, `process-list`, …). Domain and family are
  orthogonal facets; parsers bind to families.
- `dfir_fields`: the key-values this artefact ALWAYS yields — regardless
  of parser — each typed, each mapped to either a core SCO property or a
  property of the dxdfir extension (STIX §7.3 Extension Definition;
  `byakugan/exchange/extension/dxdfir-extension.schema.json` is the seed).
- `absence`: what a conforming producer emits when a guaranteed field
  cannot be produced. Declared once is the shared *vocabulary* of absence
  markers and their semantics (`not-applicable` on this OS/version,
  `collection-failed`, `unsupported` by the producing parser, `unknown`)
  — each `dfir_fields` entry then declares which markers it can carry, so
  genuinely different absence semantics stay distinguishable without
  per-consumer conventions.
- `platform`: an ARRAY over the closed generated enum (`windows`, `linux`,
  `macos`) — orthogonal to `domain` and `family`. A platform value enters
  the enum only when a class carrying it has an in-house Parser Profile or
  collection surface (ESXi is deferred by exactly this rule). Class-layer
  metadata only: no wire object carries it.
- `references`: citations in the shared external-reference shape
  (`defs.schema.json#/$defs/external-reference` — the STIX §2.5 form plus a
  `coverage: leaf | container | none` qualifier). Each seed cites its
  ForensicArtifacts definitions and format references; upstream pins live
  once in the envelope, never per reference. A class with no upstream
  authority states it by having none.
- `aliases`: prior byakugan class names only — rename compatibility,
  lowercased and collision-checked within the class namespace
  (cross-namespace collisions are a CI lint, not schema validity).
  Citations are never aliases.
- `evidences`: the DFIR-context matrix — what events this artefact
  evidences, the event-level counterpart of `dfir_fields`' field-level
  yields. Rows `{object, action, evidence, time, basis, when}`: the
  (object, action) pair validates against the CAR objects' generated
  action enums; `evidence` reuses the `definitive | heuristic | inferred`
  tier vocabulary; `time` is `event-time | bounded | none`; `when` selects
  over the class's OWN `dfir_fields` keys, never parser field names. The
  canonical set per family is the ir.json bootstrap closure UNION the
  source-grounded overlay (`model/schema/matched-evidences.yaml`,
  whose `constraints:` block is the normative layer — backbones, the
  MAY class with absence-not-evidence, tier ceilings, pair bans, and the
  SRO derivation rules). Emitted pairs outside the declared set are
  count-and-carry findings; declared-but-unreached rows tally as
  warnings — coverage debt, deliberately representable.

An admission rule keeps the hourglass honest: a family earns a class only
when at least one Parser Profile or one collection surface exists in-house
— an upstream catalogue alone never creates a class.

Seeded by triangulation: gomount's `materialise-sets.yml` (the collection
surface — 17 materialise sets including the OS-surface sets), byakugan's
the lane manifests `byakugan.sources_model` builds (the parsing surface), and the ForensicArtifacts
index (naming, scope and citations only).

### Parser Profile — what one parser literally emits

Many per artefact class; the normalisation and automated-ingestion
wiring. One declaration per (parser, artefact class):

- `parser`: tool + version range (gowindowlicker, godaemonhunter,
  gopinfo, anamnesis, …).
- `artefact_class`: the Artefact Class ref it feeds.
- `fields`: the literal field names and datatypes this parser emits —
  the record struct, as data — with each field bound to a `dfir_fields`
  key of the artefact class (or declared parser-specific surplus).
- `datatypes` matter here: this is where normalisation is pinned, so two
  parsers of the same artefact converge before mapping, and ingestion is
  wired without duplicated effort.

The parser binding and routing already exist as data
(`byakugan/car_source_schema.yaml` + the lane manifests `byakugan.sources_model` builds); what has no
as-data source anywhere is the field/datatype surface — the record
struct — which is authored fresh, mined from the Go record structs
(read-only grounding from the toolz repos and anamnesis).

### Model Mapping — artefact fields to object properties

One per artefact class; the hourglass waist. The IR, flipped from
code-authored to declared:

- input: an Artefact Class ref (not a parser — profiles have already
  normalised).
- output: Object Model class(es).
- field mappings, and predicates **by name only**. Implementations live
  in code registries (Go: `internal/predicates`; Python: the engine
  registry); a conformance test in each engine asserts
  declared-names ⊆ registered-names and vice versa. The mapping is data;
  the transform is code.

Bootstrapped from today's `ir.json` mappings/routes/adapters and
anamnesis's `internal/normalize/mappings.yaml` resolver grammar
(read-only grounding).

### Object Model — objects and relationships (STIX-native)

- Objects: STIX SDOs/SCOs (spec §4/§6) carrying the CAR semantics through
  the dxdfir extension; detections ground to Sighting (§5.2).
- Relationships: first-class SRO records (§5.1) —
  `{relationship_type, source_ref, target_ref}` with declared direction
  and cardinality. In Elasticsearch, edges are documents; this is what
  makes the Python side a graph engine rather than a document dump.
- Relationship typing has schema-level teeth: allowed source/target
  pairs are **generated** per relationship type as `if/then` constraints
  whose `then` is an `anyOf` over the declared (source-pattern,
  target-pattern) pairs — pair-wise, because for 11 of the edge names the
  allowed pairs are not a cross-product of their sources and targets —
  with `relationship_type` itself closed by a generated enum so
  undeclared types cannot pass vacuously; STIX ids carry their type
  prefix, so each leg stays a pattern check
  (`model/superset/relationship-types.yml`, 243 edges, plus
  `model/relationships/`). Same-type rules (ATT&CK's `revoked-by`,
  handled today in `exchange/attack_index.py`) stay code checks.
- The OASIS JSON schemas for the core types are vendored under
  `model/schema/vendor/oasis/` (informative per STIX §1.2.12); our
  schemas compose them, never fork them.
- The CAR upstream (`model/sources/car`) becomes a REFRESH-TIME input: a
  maintenance task regenerates Object Model declarations from it, humans
  review the diff, and the committed files are canonical. Engines and
  tests never read the submodule again. Staleness is gated, not trusted:
  CI compares the pinned submodule commit against the `generated_from`
  pin in the derived declarations' envelopes and fails on mismatch, so a
  routine pin bump cannot silently strand the committed model.

### Identity Rules — deterministic ID minting

Already data: `byakugan/spindle.yml` is a versioned registry of GUID
recipes with golden vectors; `ids.py` holds the CAR/spindle namespaces
(`CAR_NS`/`SPINDLE_NS`) and `exchange/objects.py` the dxdfir tree
(`DX_NAMESPACE`/`EXTENSION_ID`). This layer formalises them:

- the uuid5 roots as schema constants — **both** trees: `CAR_NS`/
  `SPINDLE_NS` and `DX_NAMESPACE`/`EXTENSION_ID` are wire format, never
  to be edited (STIX §2.9: UUIDv5 over the SCO namespace with JCS
  canonicalisation is the native analogue). Mechanics: `constants.yaml`
  ships inside the embedded/packaged schema dir, so it is bundled at
  build time, not discovered at runtime; each engine loads it once at
  init, validates it against the envelope schema and fails fast — no
  fallback values exist to fall back to. Any drift a silent fallback
  could have hidden is also caught downstream by the golden vectors.
- one recipe per identified thing: inputs, canonicalisation, namespace,
  recipe version.
- golden vectors are part of the declaration and become shared
  conformance fixtures for BOTH engines — the spindle change protocol
  (bump recipe version, add vectors, never mutate) is the layer's edit
  rule.

### Enrichment Rules — self-enrichment first

One declaration per rule:

- `applies_to`: Object Model selector (object class + property).
- `method`: registered function name (code), `inputs`, `emits`.
- `scope`: `self` (closed over the same host/collection's records — the
  SID→username, GUID-translation class of rule; deterministic, no
  external lookups) or, later, `external` with its source declared.
- provenance: enriched properties are attributable to the rule that set
  them.

Bootstrapped from `byakugan/relationships.yml` (inheritance / dedupe /
derived sections), the `canon_user` table currently baked into `ir.json`,
and anamnesis's `internal/enrich/data.yaml` (read-only grounding).

### Schema Envelope — version and provenance

Every file in every layer carries the envelope: `schema_version` (ONE
formal version for the whole schema set, replacing today's four ad hoc
markers), `generated_from` (upstream pins, when derived) and `source`
(hand-authored vs generator) — the provenance triple. Instance documents
emitted by the engines carry the same triple. Vocabularies and enums are
**generated from pinned sources, never hand-typed** (hand-typed tactic
lists rotted in both attack-data-model and our own `stix.py` — same bug
class, twice); genuinely open vocabularies are modelled
`anyOf: [enum, pattern]` so unknown-but-well-formed values validate
instead of failing; the loader separately checks enum membership and tallies misses
as count-and-carry warnings. Retirements use native `deprecated: true`
with loader-surfaced counts; removals ride the schema version.

## Layout

```
model/schema/
  envelope.schema.json               the version/provenance envelope
  defs.schema.json                   shared $defs property library
  artefact-class.schema.json         + classes/*.yaml
  parser-profile.schema.json         + profiles/*.yaml
  model-mapping.schema.json          + mappings/*.yaml
  object-class.schema.json
  relationship.schema.json           + objects/*.yaml, relationships/*.yaml
  identity-rules.schema.json         + identity/*.yaml
  enrichment-rule.schema.json        + enrichment/*.yaml
  vendor/oasis/                      published STIX 2.1 JSON schemas, verbatim
  constants.yaml                     uuid5 roots, extension ids, spec version
```

All meta-schemas are JSON Schema **2020-12**; closed shapes use
`unevaluatedProperties: false` under composition (never
`additionalProperties: false`, which breaks `allOf`).

## Consumption and gates

- Go: `go:embed` the schema dir; validate declarations at load and own
  emissions in tests (santhosh-tekuri/jsonschema); registry-coverage
  tests; `gen-ir` validates against Model Mapping + Object Model instead
  of owning them.
- Python: package the same dir; `jsonschema` validation of graph-engine
  input/output; the ES index templates and ECS projection are drift-gated
  against the Object Model — regeneration must reproduce the committed
  rendered artifacts (`model/projection/` → `elastic/`), and changing the projection
  output stays a separate, explicit decision (wire format rule).
- Validation policy is **count-and-carry**: every object validates, every
  failure tallies into a neutral finding record
  `{object_id, rule, path, message}` — identical in both engines. Strict
  mode = nonzero tally fails `--check`. No silent relaxed mode: nothing
  unvalidated enters the graph unmarked.
- Shared golden vectors (including the spindle identity vectors) and a
  named check-pass conformance table prove Go and Python run the same
  rule set.
- CI: schema validation + registry coverage + generation drift in both
  engines' gates. A declaration change either engine cannot honour fails
  that engine's pipeline — drift is caught at the MR, not in production.

## Decisions (divergences this schema settles)

1. **One common header.** The Object Model declares a single common
   header, seeded from byakugan's `common_header`. Anamnesis's store
   header is recorded as a known variant; converging it is that repo's
   future mission, not a byakugan change.
2. **One tstamp rule.** Timestamp requiredness is declared per artefact
   class in `dfir_fields`, with the `absence` convention covering the
   cannot-produce case — no per-consumer opinions.
3. **One artefact catalogue.** Artefact Class instances are seeded by the
   declared triangulation — gomount's `materialise-sets.yml` (collection
   surface), byakugan's lane manifests (parsing surface), and the
   ForensicArtifacts index (naming/scope/citations only) — under the
   admission rule; the dx_dfir evidence taxonomy is a directory
   *projection* of these classes, not a second catalogue, and upstream
   group graphs (ForensicArtifacts `members`) are seeding signals consumed
   at crosswalk time, never a stored taxonomy.

## Bootstrap plan (schema mined from existing logic — accepted as the start)

1. Vendor the OASIS schemas; write envelope + the seven meta-schemas +
   the shared `$defs` library; `constants.yaml` with both uuid5 root
   trees.
2. Generate instances (generators extend `go/internal/authoring` and the
   model tooling) from what already exists as data: Model Mapping
   from `ir.json`; Object Model from `model/car` + `model/superset` +
   `model/relationships`; Identity Rules from `spindle.yml` + `ids.py`;
   Enrichment Rules from `relationships.yml` + `canon_user`; Artefact
   Class from gomount's sets. Parser Profiles authored fresh from the Go
   record structs.
3. Gates on: both engines validate against the schema dir; `gen-ir`
   flips from owner to consumer behind its drift check; count-and-carry
   findings wired into `--check`.
4. Only then: retire runtime submodule use; `model/sources/` stays for the
   refresh task alone.

## Non-goals (this mission)

Anything outside byakugan: gomount, anamnesis, godfir-toolz and dx_dfir
*adopting* the schema are future missions — their files are read-only
grounding here. Also out: renaming CAR concepts, changing wire formats or
uuid5 identities (formalise, don't mutate — changing what is emitted is a
separate, explicit decision), STIX-patterning (§1.2.6), and moving the
schema to its own repo before it has two external consumers.
