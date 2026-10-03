# ATT&CK data-model alignment — research & course of action

**Status:** research (issue-grade COA; nothing here is implemented yet).
**Ground truth:** ATT&CK v19.2 (enterprise, 2026-08-05, spec 3.3.0), read from
`mitre-attack/attack-stix-data@6cda5ad`; the pinned submodules at their current
pins; the `attack-data-model`, `mitreattack-python` and
`attack-workbench-taxii-server` repositories at HEAD (2026-09).

The question set this answers (from the alignment request):

1. How much work are we from aligning to the `attack-data-model`?
2. What else can we extract from it?
3. Can we enhance, directly use, or must we modify the model we have built?
4. A plan for scripts that feed Byakugan from `attack-stix-data` — from the
   data-model level through to mapping our detections to TTPs, campaigns,
   collections and more.

## TL;DR

- **The premise holds, and has moved one step further.** Data components did
  become the reusable hub — but since ATT&CK v18 (Oct 2025) they are no longer
  the *detection* link. The live chain is now
  `technique ←detects← detection strategy → analytics → data components →
  log sources (name+channel)`. Data **sources** are deprecated (all 38 of
  them); data **components** survive as the telemetry hub (106 live), each now
  carrying concrete `x_mitre_log_sources` — `WinEventLog:Sysmon` /
  `EventCode=1`-grade detail that joins **directly** onto Byakugan's per-map
  routing.
- **Byakugan's evidence model is not what ADM models — no collision.** The
  attack-data-model is the schema of the *knowledge base* (techniques,
  strategies, analytics, campaigns…). It has **no observable/evidence layer**:
  nothing upstream replaces CAR's scalar fields, the spindle, or the
  relationship timeline. Alignment means **joining** our model to theirs at
  three seams (log sources, components, techniques), not migrating ours onto
  theirs.
- **Distance to aligned: small-to-medium, and sharply bounded.** One wrong id
  scheme to fix (`stix.py` mints its own `attack-pattern`s — DX_DFIR already
  does it right; its hardcoded tactics table is *already stale*: v19 renamed
  TA0005 to `stealth` and added TA0112 `defense-impairment`), one superset
  input to rebase (archived `attack-datasources`
  YAML → live components; 97 of our 116 component names survive verbatim in
  v19.2), one new pinned input (the bundle) and one new hand-authored mapping
  (sources → log sources/components). The 243-edge relationship vocabulary has
  **no successor upstream** — we keep its pin and own it.
- **Directly use ADM the library? No — use it as the specification.** ADM is
  TypeScript/Zod; Byakugan is stdlib-Python by design. We mirror its schemas
  and navigation semantics in a thin stdlib loader over the pinned bundle
  (mitreattack-python's relationship maps show the recipe), and optionally run
  ADM as a dev-time validator. Nothing of Byakugan's runtime dependency
  posture changes.
- **The extractable surplus is large**: 699 detection strategies covering
  697/697 live techniques, 1,758 platform-tagged analytics with tuning knobs,
  a 344-name log-source vocabulary (with per-EventCode channels), campaigns
  (56, with `attributed-to` → groups and `first_seen`/`last_seen`),
  groups/software `uses` edges (~17k), mitigations, tactics, and the
  per-release `x-mitre-collection` manifest for provenance-grade pinning.

---

## Part I — ground truth

### 1. Where ATT&CK's data model actually is (v19.2, spec 3.3.0)

Enterprise v19.2 bundle contents (counts, `enterprise-attack-19.2.json`):

| type | count | state |
|---|---:|---|
| `relationship` | 21,262 | `uses` 18,457 · `mitigates` 1,448 · `detects` 697 · `subtechnique-of` 477 · `revoked-by` 157 · `attributed-to` 26 |
| `x-mitre-analytic` | 1,758 | live (0 deprecated) — **new in v18** |
| `attack-pattern` | 858 | 697 live techniques |
| `malware` / `tool` | 733 / 95 | software |
| `x-mitre-detection-strategy` | 699 | live — **new in v18**; `detects` → technique |
| `course-of-action` | 268 | mitigations |
| `intrusion-set` | 191 | groups |
| `x-mitre-data-component` | 109 | **106 live** — the reusable hub, now carrying `x_mitre_log_sources` |
| `campaign` | 56 | `attributed-to` → intrusion-set; `first_seen`/`last_seen` |
| `x-mitre-data-source` | 38 | **all 38 deprecated** (kept for compatibility) |
| `x-mitre-tactic` / `x-mitre-matrix` / `x-mitre-collection` | 15 / 1 / 1 | collection = the release manifest (26,084 `x_mitre_contents` entries) |

The detection meta-model, as it exists in the live data:

```
attack-pattern (T1234)  ←── detects ───  x-mitre-detection-strategy (DET0103)
                                              │ x_mitre_analytic_refs
                                              ▼
                                         x-mitre-analytic (AN0110)
                                          · x_mitre_platforms: [Windows|Linux|…]
                                          · description (the behaviour logic, prose)
                                          · x_mitre_mutable_elements (tuning knobs)
                                          · x_mitre_log_source_references:
                                              {x_mitre_data_component_ref, name, channel}
                                              │
                                              ▼
                                    x-mitre-data-component (DC0084)  ← reusable hub
                                          · x_mitre_log_sources: [{name, channel}]
                                            e.g. {WinEventLog:Security, EventCode=4768}
                                                 {WinEventLog:Sysmon,  EventCode=1}
                                                 {NSM:Flow, …} {auditd:SYSCALL, …}
```

Measured facts that matter to us:

- **Every live enterprise technique has a detection strategy** (697/697).
  Strategies carry 1–9 analytics (mean 2.5), platform-split: Windows 475,
  Linux 358, macOS 353, ESXi 107, PRE 96, IaaS 86, Network Devices 86, …
- **`detects` is exclusively `detection-strategy → attack-pattern`** now
  (697 edges). The old `data-component → technique` detects edges are gone.
  Techniques no longer carry `x_mitre_data_sources` strings at all.
- **The log-source vocabulary is (name, channel) pairs embedded in
  components**: 344 distinct names over 2,993 rows. The names Byakugan's
  evidence already materializes: `WinEventLog:Security` (69 rows, with
  per-`EventCode=` channels), `WinEventLog:Sysmon` (25, `EventCode=1..25`),
  `WinEventLog:System/Application/PowerShell/TaskScheduler/Bits-Client/…`,
  `NSM:Flow` (256) / `NSM:Connections` (Zeek), `linux:syslog` (87),
  `fs:fsevents`, `auditd:*` (282 SYSCALL rows — a map we do not have yet).
  The vocabulary has upstream hygiene wrinkles (`NSM:FLow`, `NSM:firewall`,
  `MobiledEDR:telemetry`, `linuxsyslog` case/typo variants) — joins must
  normalize.
- **No forensic-artifact log sources exist upstream.** Prefetch, SRUM, MFT,
  USN, jumplists, shellbags, LNK, browser history — Byakugan's disk lanes —
  have no upstream (name, channel) identity. ATT&CK's vocabulary is live
  telemetry. This is a place Byakugan *extends* the model (below), not a
  misalignment.
- **v19 restructured the tactics.** TA0005 is now **Stealth** (`stealth`,
  formerly Defense Evasion) and **TA0112 Defense Impairment**
  (`defense-impairment`) is new — 15 live tactics. Byakugan's hardcoded
  `ATTACK_TACTICS` table (`byakugan/stix.py:158`) still emits
  `defense-evasion` for TA0005 and does not know TA0112: **our kill-chain
  phases are already wrong against live ATT&CK**, before any alignment work
  starts. (ADM's own closed shortname list has the same staleness — the
  lesson is to derive vocabularies from the pinned bundle, never hardcode.)
- Provenance chain for pinning: `index.json` (collection index: 41 enterprise
  versions, `modified` stamps, one URL per versioned bundle) →
  `x-mitre-collection` inside each bundle (version + per-object
  `object_modified` manifest). Object STIX ids are stable across releases —
  the property every downstream join keys on.

**The SRO typing contract.** The part of the model that says *what may link
to what* lives in ADM's relationship schema
(`src/schemas/sro/relationship.schema.ts:52-94`, the `relationshipMap`):
seven relationship types with enumerated endpoint types —

```
uses:            [malware | tool | intrusion-set | campaign] → [attack-pattern | malware | tool]
                 (minus malware/tool → malware/tool pairs)
mitigates:       [course-of-action]                          → [attack-pattern]
subtechnique-of: [attack-pattern]                            → [attack-pattern]
detects:         [x-mitre-data-component   ← TODO: remove in spec 4.x
                  | x-mitre-detection-strategy]              → [attack-pattern]
attributed-to:   [campaign]                                  → [intrusion-set]
targets:         [attack-pattern]                            → [x-mitre-asset]   (ICS)
revoked-by:      same-type → same-type, 8 object types
```

Two readings matter for us. First, the **`detects` transition is written into
the schema itself**: `x-mitre-data-component --detects--> attack-pattern` is
still *admitted* (v15–v17 bundles carry thousands) but runtime-warned as
deprecated (`relationship.schema.ts:316-331`) and scheduled for removal in
spec 4.x — while v18+ *content* has already moved (zero DC-detects edges in
v19.2). Anything we build must sit on the durable side: the
detection-strategy `detects` SRO plus the **embedded** references
(`x_mitre_analytic_refs`, `x_mitre_log_source_references`,
`x_mitre_log_sources`) — which are properties, not SROs, and never appear in
the relationship map at all. Second, this map is the ATT&CK counterpart of
our `model/superset/relationship-types.yml` — but **one stratum up**: it
types edges *among knowledge-base SDOs*, where our 243-edge vocabulary types
edges *among evidence data-elements*. They compose (a sighting of a technique
sits on evidence edges below and knowledge edges above); neither replaces the
other.

Adjacent upstream facts:

- `mitre-attack/attack-datasources` (our superset's ATT&CK side) — **archived
  Sep 13 2023**, README: "no longer necessary as we have finalized the way
  that Data Sources are included in ATT&CK", pointing at `mitreattack-python`.
  Name-level drift against v19.2 is modest: of our pin's 116 component names,
  **97 survive verbatim**; 19 exist only in the archive (`driver unload`,
  `module content`, `network share creation`, …), 9 only upstream
  (`active dns`, `domain registration`, `malware content`, `social media`, …
  — OSINT-flavoured). **The 243 `source --relationship--> target` data-element
  edges exist only in the archived repo.** Nothing in v10–v19 STIX carries
  data-element relationship triples; the vocabulary our cascade types against
  has no upstream successor. We own it now.
- MITRE CAR — not archived, but content-dormant: last `analytics/` change
  Aug 2023, last `data_model/` change Feb 2023 (site rebuilds continue). The
  v18 analytics corpus is ATT&CK's own successor to CAR-style detection
  content. CAR's *object model* (the 13 objects and their scalar fields — what
  Byakugan actually builds on) remains the only field-level observable model in
  this family, and being frozen makes it a *stable* foundation, not a rotting
  one.

### 2. What Byakugan runs on today (the join surface)

- **CAR object model** — 13 objects, scalar fields, from `third_party/car`
  (pin `1b922fe`); the only source of row shapes
  (`byakugan/carmodel.py`).
- **Superset** — CAR ∪ ATT&CK data-source objects: object catalogue (38) with
  actions derived from *component names*, plus the 243-edge relationship
  vocabulary, all reconstructed live from `third_party/attack-datasources`
  (pin `5d50f73`) by `byakugan/build_data_model.py`; materialized under
  `model/superset/`. The cascade's edges are typed against that vocabulary
  (`byakugan/cascade_relationships.yml`, tier `exact`/`extension`).
- **Sources** — 41 generated sensor manifests (`sources/*.yaml`,
  `byakugan/gen_sources.py`): extractor/parser/channel provenance +
  per-(object, action) field mappings with per-field provenance. The maps
  behind them know their channels and event ids
  (`go/internal/authoring/maps_*.go`, `byakugan/sources_model.py` — e.g.
  `evtx_process` = Security 4688, `evtx_sysmon` = Sysmon per-EventID) — i.e.
  exactly the grain ATT&CK's log-source channels are written at.
- **Behaviour lanes** — MITRE CAR's 102 analytics compiled to predicates
  (`byakugan/analytics.py`) and Sigma/Hayabusa rules compiled to the same
  `CarAnalytic` shape (`byakugan/sigma.py`); coverage = ATT&CK technique ids.
- **STIX 2.1 export** (`byakugan/stix.py`, contract `model/stix/`) — SCOs,
  observed-data, SROs, and a behaviour layer: `attack-pattern` per covered
  technique id, `indicator` per analytic, `indicates`, `sighting` per hit.
  **Today the attack-patterns are self-minted** (content-keyed UUIDv5 over the
  `mitre-attack` external id) — not MITRE's authoritative object ids.
- **Precedent next door**: DX_DFIR's
  `python/get_sybers_dxdfir/stix/attack_index.py` already does the
  authoritative-id resolution (committed compact `attack-index.json`:
  technique → MITRE `attack-pattern--<uuid>`, name, phases, revocation, with
  `revoked-by` substitution) — techniques + tactics only.
- **Dependency posture**: runtime = stdlib + PyYAML, network strictly opt-in
  (the ES push precedent). Any alignment must respect this — heavyweight STIX
  tooling can live at *generate* time only, like `model/generate.py` does.

### 3. The toolchain around the model

#### 3.1 `attack-data-model` (ADM) — the specification, not the engine

npm `@mitre-attack/attack-data-model`; `latest` = **4.10.1** (2026-05-06,
which is the `main` commit `2b50c25` we read), `next` = 4.11.7, `beta` =
5.0.0-beta.3. Runtime deps are only axios/uuid/**zod 4** — all STIX modelling
is hand-written Zod; no STIX or TAXII library anywhere. Pins ATT&CK **spec
3.3.0**. The published docs site (the
`mitre-attack.github.io/attack-data-model/schemas/` pages, where
attack-stix-data's own CHANGELOG now points) is this repo's `docusaurus/`
content; its spec changelog for 3.3.0 (28 Oct 2025) is the authoritative
field-level record of the v18 shift — detection strategies + analytics added;
data sources, DC-`detects`, DC `x_mitre_data_source_ref` and the technique
detection-era fields (`x_mitre_detection`, `x_mitre_data_sources`,
`x_mitre_permissions_required`, …) all deprecated with removal scheduled for
**spec 4.0.0** (ADM 5.x, still beta).

**Transition archaeology that explains stale reading elsewhere:** ADM 4.0.0
(Jul 2025) briefly had a separate `x-mitre-log-source` SDO with
`x_mitre_log_source_permutations` and a `found-in` relationship; **4.2.0
(Sep 2025) removed all of it** in favour of today's embedded shape — log
sources as `{name, channel}` rows *inside* data components, analytics
referencing them by `{x_mitre_data_component_ref, name, channel}`. Docs
mentioning `LS####` ids or `found-in` describe that dead branch.

**Schema inventory** (`src/schemas/sdo/*.schema.ts`, `smo/`, `sro/`): every
SDO Byakugan cares about is modelled — technique (`T####`), tactic
(`TA####`), campaign (`C####`, requires `aliases`, `first_seen`/`last_seen`
with citations), group (`G####`), malware/tool (`S####`), mitigation
(`M####`), asset (`A####`, ICS), matrix, collection
(`x_mitre_contents[{object_ref, object_modified}]` + referential-integrity
refinements), identity, marking-definition, relationship, plus the detection
model:

- `x-mitre-detection-strategy` (`DET####`): required
  `x_mitre_analytic_refs` (non-empty, no duplicates), `x_mitre_domains`,
  MITRE attribution refs; **no `description` field is even allowed**.
- `x-mitre-analytic` (`AN####`): `description` (the behaviour logic),
  **exactly one** `x_mitre_platforms` entry,
  `x_mitre_log_source_references: [{x_mitre_data_component_ref, name,
  channel}]` (min 1, unique triples), `x_mitre_mutable_elements:
  [{field, description}]` — both optional since 4.5.0.
- `x-mitre-data-component` (`DC####`): `x_mitre_log_sources:
  [{name, channel}]` (unique pairs; optional now, "required in spec 4.x"),
  deprecated optional `x_mitre_data_source_ref`. Old- and new-style
  components both validate.
- `x-mitre-data-source` (`DS####`): retained, schema-annotated deprecated.

Cross-checked against v19.2 content: the detection shapes hold (all 1,758
analytics carry exactly one platform; 4,179 of 4,182 analytic log-source
references resolve to a real `(name, channel)` pair in their referenced
component — the 3 stragglers are exactly why ingest must count-and-carry
rather than drop).

**The bundle-level contract** (the docs site's `/schemas/#stix-bundle-object`
page → `stix-bundle.schema`): a bundle is `{id: bundle--<uuid>, type:
"bundle", objects: [≥1]}` — nothing more; **STIX 2.1 bundles carry no
bundle-level `spec_version`** (v19.2's top level is exactly those three
keys). Three artifacts describe the `objects` array, and only two agree:

- The published page (hand-maintained, its own comment says so) admits all
  **seventeen** types — Relationship and MarkingDefinition included — which
  is what `attackObjectsSchema` (`stix-bundle.schema.ts:110-153`, per-object
  dispatch through a type→schema map) and the exported `AttackObject` union
  implement, and what real bundles contain.
- The code's `stixBundleSchema` (`stix-bundle.schema.ts:163-207`) instead
  enumerates a 15-schema discriminated union that **omits `relationship` and
  `marking-definition`** — a real ATT&CK bundle (21,262 relationships) can
  never pass it, and ADM's own loader quietly routes around it (per-object
  dispatch after a `pick({id,type}).loose()` — the very call that crashes on
  4.10.1).

What *is* worth taking from `stixBundleSchema` is its three bundle-level
refinements, which real data honours exactly (measured on v19.2): the
**first object is the `x-mitre-collection` and there is only one**; every
`x_mitre_contents` ref resolves to a present object (26,084/26,084 — the
manifest covers everything except the collection itself and the one
marking-definition); **no duplicate ids**. Those three assertions become our
loader's bundle gate.

**The how-to guides** (`/docs/how-to-guides/` — `schema-variants`,
`manage-data-sources`, `validate-bundles`; all three carry a
Work-In-Progress notice) split cleanly into advice and code:

- *The advice is our COA.* `manage-data-sources`' takeaways — pin the
  version in production, keep a fallback source chain, sanity-check after
  load, cache, environment-based source config — are exactly Phases 0/5
  (`pin.yml` + sha256, `--offline <bundle>` fallback, index golden checks,
  the fetch cache, env-driven paths). We implement the guide's design with
  machinery that runs.
- *The code samples don't run on `latest`.* `manage-data-sources` is built
  entirely on `new DataSource({...})` (the class is `DataSourceRegistration`),
  `filePath:` (real option: `path`) and `requestOptions.headers` (does not
  exist); `validate-bundles` opens with `stixBundleSchema.parse(bundle)` —
  which no real ATT&CK bundle can pass (above) — before a
  `registerDataSource` call that crashes on 4.10.1. Its Step-2 pattern
  (per-object dispatch through a type→schema map) is the workable one — the
  same shape as `attackObjectsSchema` and as our stdlib loader.
- *`schema-variants` is the accurate one*, and the design lesson transfers:
  since 4.9.0 each refined type ships **Full / Base / Partial** tiers
  (`campaignSchema` / `campaignBaseSchema` / `campaignPartialSchema`, for
  campaign, group, malware, tool, technique, relationship) because zod 4
  forbids `.pick()`/`.omit()`/`.partial()` on refined schemas — shape
  validation and cross-field rules as separate tiers. Our `--check` mirrors
  that split in stdlib: shape assertions per object type, referential
  assertions (analytic→component, contents↔objects) as a distinct pass. The
  Base/Partial tiers are also the right entry point for dev-time validation
  of Byakugan-*emitted* objects, which will never carry MITRE-only
  attribution fields that the Full tier hard-requires.

**Why "use as the specification" and not "run the library"** — findings from
reading `latest`'s code, which temper the USAGE.md story:

- `registerDataSource()` on 4.10.1 hits a zod-4 `.pick()`-on-refined-schema
  crash (`src/main.ts:204-210`); fixed in 4.11.x via `stixBundleBaseSchema`.
  The `url`/`taxii` sources are throw-blocked in `DataSourceRegistration`
  (`data-source-registration.ts:62-65`), and `taxii` is a plain HTTP GET
  anyway — **ADM has no TAXII protocol code either**. The `attack` source is
  the same raw-GitHub fetch we plan (base overridable via `GITHUB_BASE_URL` —
  same air-gap seam as ours).
- Relationship navigation is thin and partly dead on `latest`:
  `technique.getTactics()` **always returns `[]`** (never wired);
  `DetectionStrategyImpl.getTechniques()` **always `[]`** (the `detects`
  wiring ignores DS sources); there is no DS→analytics, analytic→component,
  or any reverse navigation. USAGE.md documents classes and methods that do
  not exist (`new DataSource({...})`, `getGroups()`,
  `getAssociatedSoftware()`, …).
- Strict parsing rejects **live** ATT&CK: closed vocabulary lists predate
  v19 (tactic shortnames miss `stealth` and `defense-impairment`), the
  malware→tool `revoked-by` (Ngrok) violates its same-type rule, and 224
  legacy mitigations reuse `T####` ids — on top of `stixBundleSchema` itself
  (the bundle-level contract above). Relaxed mode
  keeps invalid objects raw (the docs claim it drops them).

None of that dents the *specification* value — and it is a live warning
about hardcoding vocabularies (ADM fell into the same trap our
`ATTACK_TACTICS` table did). What we lift from it, concretely: the
**`relationshipMap`** + `isValidRelationship` semantics (§1); the
**ATT&CK-ID grammar** (`attackIdPatterns` — regexes for TA/T/T.sub/G/S/M/A/
DS/DC/DET/AN/C, plus old-mobile ids); the MITRE identity constant; the
refinement recipes (no-duplicate log sources, citation checks,
`x_mitre_contents` referential integrity — our `--check` mirrors these in
stdlib); and the versioned spec-changelog pages as the contract our loader
is written against. Dev-time validation of Byakugan-emitted objects with ADM
is possible (pin ≥ 4.11, validate per-object with `safeParse`, expect
closed-list false positives on non-MITRE content) but stays optional.

#### 3.2 `mitreattack-python` — the reference implementation (generate-time only)

v6.2.0 (2026-08-05), `LATEST_VERSION = "19.2"`. Python ≥ 3.11, `stix2` 3.0.2,
plus pandas / pooch / deepdiff / drawsvg / openpyxl — **not runtime-eligible
for Byakugan** (stdlib+PyYAML posture), and it does not need to be: everything
it does over a loaded bundle is plain-JSON index building we can mirror in a
few hundred stdlib lines. Its value is as the *reference implementation* and
as **dev-time tooling**:

Worth taking (as recipes or dev-time tools):

- **Hash-pinned fetch** — `download_stix.download_stix(...)` wraps
  `pooch.retrieve(url, known_hash=sha256)`: skip when cached-and-matching,
  raise on mismatch; `release_info.py` is a domain → version → sha256 table
  and `get_attack_version()` identifies a bundle file by hash. Its version
  allow-list is fixed at build time (the library cannot fetch a release newer
  than itself) — which is exactly why Byakugan should carry **its own pin
  table**, in the submodule-pin spirit, rather than depend on the library's.
- **The relationship-map recipe** (`MitreAttackData.get_related()`): one pass
  over `relationship` objects of a type → `{source_id → [{object,
  relationships}]}` with revoked/deprecated filtering and campaign→group
  inheritance (`attributed-to` merged into the group's `uses` maps). This is
  the navigation semantics our stdlib loader mirrors. v18-aware additions
  exist (`get_all_detection_strategies_detecting_all_techniques`,
  `get_analytics_by_detection_strategy` — the latter resolves embedded
  `x_mitre_analytic_refs`, not SROs). Notably **the library has no log-source
  API at all** (no class, no getter — only the embedded dicts, flattened by
  one Excel DataFrame helper), and the *old* data-component detection helpers
  silently return empty on v18+ bundles. Our loader must read the embedded
  structures directly — there is no wheel to reuse there.
- **`diffStix` / `attack-changelog`** — computes added/revoked/deprecated/
  version-changed objects between two releases, including per-technique
  detection-strategy deltas, emitting Markdown/HTML/JSON and a Navigator
  layer. Reusable as the **pin-bump change report** (dev-time). Caveats: pass
  `unchanged=True` or detection-mapping changes on otherwise-unchanged
  techniques are hidden; changes to a strategy's `x_mitre_analytic_refs` or
  an analytic's log-source refs only appear inside `detailed_diff`.
- **`navlayers`** — the Navigator **layer JSON format** (layer 4.5 /
  navigator 5.0.0) is simple enough to emit with stdlib `json`; the library's
  exporters (SVG/Excel) are dev-time extras. There is **no detection-coverage
  generator for the v18 model** upstream (the datasource layer generators
  still assume `x_mitre_data_source_ref` + component `detects` — empty on
  v18+), so a Byakugan coverage layer is ours to compute either way.
- **Collections module** — `CollectionToIndex` produces exactly the
  `index.json` shape attack-stix-data publishes; nothing implements
  `x_mitre_contents` comparison between two pins (cheap and useful — we build
  it ourselves). Mind the module's UTF-16 file quirks.

Gotchas recorded for whoever writes the loader: `get_attack_id()` trusts
`external_references[0].source_name == "mitre-attack"`; `MitreAttackData` is
officially "STIX 2.0" (its custom classes are stix2-2.0 `CustomObject`s)
though it runs over 2.1 content; map caches are per-instance, truthiness-based
(an empty result is recomputed forever) and returned by reference.

#### 3.3 `attack-workbench-taxii-server` — patterns, not a dependency

NestJS 11 + Mongo server, two processes (read-only TAXII HTTP + a cron
"collector"). Verdict for Byakugan: **there is no TAXII client code to reuse**
(outbound HTTP is two axios fetchers), and MITRE's own docs rate-limit the
public TAXII server (50 req / 10 min / IP) and recommend downloading bundles
directly — which settles the transport question: **pinned GitHub bundles, not
TAXII**, for our ingest.

What it *is* good for is its ingestion discipline, which we copy as design:

- **Release list from `index.json`** (`collections[].versions[]
  {version,url,modified}`), with a base-URL override for mirrors/air-gap.
- **Releases are immutable; load each exactly once, idempotently**: check the
  (collection, version) marker → clear leftovers → bulk-insert → write the
  collection/commit marker last (unique-indexed). Crash-safe, re-runnable —
  the right shape for "this case was mapped against ATT&CK v19.2".
- **A "latest" pointer moved only after a full load**, chosen by `modified`
  (not by version-string sort).
- **Every query scoped to one release**, newest-per-STIX-id resolved by
  `$ifNull(modified, created)`.
- A source-adapter seam (Workbench vs GitHub behind one interface) — the same
  seam our fetch step keeps (`--offline <bundle>` vs pinned URL).

Anti-patterns it also teaches (observed in code): in-memory offset
pagination that re-materializes the whole release per page; `added_after`
computed from STIX `created` (useless for delta-sync of ATT&CK, which bumps
`modified`); a TTL cache that never evicts; storing a full object copy per
release; no STIX validation on ingest (their ADM integration is still a
TODO). If Byakugan ever *serves* TAXII, run this server as a container beside
the stack rather than reimplementing it — but nothing in the COA below needs
it.

---

## Part II — the deliverables

### 4. How much work are we from aligning?

"Aligning to the attack-data-model" decomposes into six seams. None of them
is architectural — the evidence layer (CAR rows, spindle ids, the
relationship timeline) is untouched by all six, because ADM has no evidence
layer to collide with. Sizes: **S** ≈ a focused day, **M** ≈ a few days,
**L** ≈ a week-plus of mapping work (spreadable).

| # | Seam | Today | Aligned state | Size | Touches |
|---|---|---|---|---|---|
| 1 | **Technique identity** in the behaviour layer | `stix.py` mints its own content-keyed `attack-pattern` ids; hardcoded 14-entry `ATTACK_TACTICS` table — **already wrong**: v19 renamed TA0005 to `stealth` and added TA0112 `defense-impairment` | MITRE's authoritative `attack-pattern--<uuid>` ids, `revoked-by` substitution, phases from the pinned tactics — the DX_DFIR `attack_index` semantics, brought home | **S** | `byakugan/stix.py`, new pinned index, `model/stix/conventions.yml` (id-recipe → `contract.version` bump), `tests/test_stix*.py` |
| 2 | **The ATT&CK pin itself** | No attack-stix-data input exists; ATT&CK arrives only via the archived data-sources YAML | A version+sha256 pin, an opt-in fetcher, a deterministic compact index build with a `--check` drift gate — the submodule-pin discipline, applied to a release artifact | **S–M** | new `byakugan/attack/` module, `model/attack/` snapshot, CI |
| 3 | **Superset ATT&CK side** | Objects + actions derived from the *archived* repo's component names | Same derivation over the *live* pinned components (97/116 names identical; 9 new, 19 keep-as-`extension`); scalar fields still CAR's, architecture unchanged | **M** | `byakugan/build_data_model.py`, `model/superset/*`, `docs/DataModel.md`, `tests/test_superset.py`, `test_data_model_build.py` |
| 4 | **Relationship vocabulary** (243 edges) | Reconstructed from the archived pin | Unchanged mechanically — but *declared ours*: upstream abandoned data-element relationship modeling; the pin becomes a permanent vocabulary asset (vendor it into the repo when convenient) | **S** (decision + docs) | `docs/DataModel.md`, `model/README.md` |
| 5 | **Sources ↔ ATT&CK telemetry** | 41 sensor manifests with channel/EventID routing, no ATT&CK identity | Each source mapped to upstream `{name, channel}` log sources + data components; forensic-artifact lanes get Byakugan-namespaced log-source names (upstream has none); `attack:` coverage block generated into `sources/*.yaml` | **M–L** (incremental per source) | new mapping YAML, `byakugan/gen_sources.py`, `byakugan/car_source_schema.yaml`, `sources/*` |
| 6 | **Detection-strategy layer** | Behaviour hits carry bare technique-id strings | Hits resolve through the pin: technique → covering strategy (DET), platform-matched analytics (AN), plus threat context (groups/campaigns/software/mitigations) | **M** | `byakugan/analytics.py` (coverage resolve), `byakugan/stix.py`, `byakugan/timeline.py` |

Total: **the critical path (seams 1–3) is roughly a week of focused work**;
seams 5–6 are the payoff layer and spread naturally over subsequent
iterations. Nothing forces a migration of anything we have materialised —
CAR trees, spindle guids, relationship JSONL and existing bundles all stay
valid (seam 1 changes only the behaviour-layer ids inside future STIX
exports, which is why it carries the `contract.version` bump).

One conformance rule rides along with all six seams: any SRO we ever emit
*between ATT&CK-domain objects* types against the `relationshipMap` (§1) —
in practice that means the detection chain is joined through
detection-strategy `detects` and the embedded refs, never through the
spec-4.x-doomed `data-component --detects--> technique` form, and the map
itself ships in the compact index so the rule is checkable.

What we explicitly do **not** have to do: adopt STIX as an internal store,
adopt ADM's TypeScript stack, replace CAR's scalar fields (upstream analytics
are prose + log-source refs, not a field model), or wait for upstream — every
seam is buildable against the pinned v19.2 bundle today.

### 5. What else can we extract from it?

Beyond "our detections get correct technique identity":

1. **A per-technique detection playbook** — 697/697 live techniques carry a
   detection strategy; each strategy 1–9 platform-tagged analytics with
   concrete log-source references and `x_mitre_mutable_elements` (the tuning
   knobs). For any technique Byakugan sights, we can print *what MITRE says a
   detection of it looks like* and *which telemetry it needs* — case-report
   grade content, and a triage aid when a hit needs corroborating.
2. **A map-development roadmap, priced by upstream demand.** The log-source
   vocabulary counts where detection content concentrates:
   `auditd:SYSCALL` (282 analytic references — we have **no auditd map**),
   `macos:unifiedlog` (515 — no macOS lane), `NSM:Flow` (256 — Zeek, strong
   already), `WinEventLog:PowerShell` (15 — no PowerShell-operational map),
   plus `WinEventLog:TaskScheduler`, `:Defender`, `:SMBClient/Server`,
   `:CodeIntegrity`… Each is a quantified argument for (or against) building
   a map.
3. **A-priori observability, not just post-hoc hits**: sources present in a
   build → components observable → strategies/analytics whose telemetry is
   satisfied → "this evidence set can in principle detect N of 697
   techniques; here are the blind spots". Emitted as a Navigator layer
   (simple JSON, stdlib-writable) and a build-summary line. This is the
   inverse of what the sensor-mappings world (DeTT&CT-style) does — computed
   from *actual case evidence*, not org policy.
4. **Threat context on the timeline**: sighted technique → `uses` edges →
   groups (191), software (828), campaigns (56, with `attributed-to` → group
   and `first_seen`/`last_seen` to compare against the case window). "T1059.001
   sighted — used by 143 groups; campaigns active in the case's window: …".
   Aliases ride along for report language.
5. **Mitigations** (268 course-of-action, 1,448 `mitigates` edges) — the
   response-recommendation block per sighted technique.
6. **Kill-chain phases from data, not a table** — the hardcoded
   `ATTACK_TACTICS` dies; ICS/Mobile become possible later for free.
7. **Release provenance**: `index.json` + the bundle's `x-mitre-collection`
   manifest (26,084 `object_modified` entries) give us exact pin provenance
   ("mapped against Enterprise v19.2, collection modified 2026-08-05") and a
   cheap object-level diff between two pins — the pin-bump change report.
8. **Spec discipline for our own emissions**: ADM's schemas are the published
   contract for every `x_mitre_*` field; anything Byakugan emits that
   references ATT&CK content can be validated against them at dev time.
9. **Two small validation tables worth lifting verbatim from ADM source**:
   the `relationshipMap` (what may link to what, §1) and the ATT&CK-ID
   grammar (`attackIdPatterns` — per-type regexes for
   TA/T/T.sub/G/S/M/A/DS/DC/DET/AN/C). Both become static entries in the
   compact index and power `--check`-time assertions.
10. **Report deep-links for humans**: every ingested object carries its
    `attack.mitre.org` URL in `external_references` —
    `/datacomponents/DC####`, `/detectionstrategies/DET####` (with `#AN####`
    anchors for analytics), `/techniques/…`, `/campaigns/…` — the
    human-browsable catalogue pages, linkable straight from case reports and
    timeline annotations without us building any of it.

### 6. Enhance, directly use, or modify?

**Verdict: keep the model we built — rebase its ATT&CK inputs, adopt their
identifiers, and extend where upstream has nothing.** Per layer:

| Layer we built | Verdict | Why |
|---|---|---|
| CAR object model (13 objects, scalar fields) | **Keep** | The only field-level observable model in this family; upstream analytics are prose over log-source names, not row shapes. Frozen upstream = stable foundation. |
| Superset objects + actions | **Modify input** (archived YAML → pinned live components) | Same architecture; component names still verb-shaped; 97/116 carry over verbatim. |
| 243-edge relationship vocabulary | **Own it** | Abandoned upstream, no successor in v10–v19 STIX; it is now Byakugan's asset (typing tiers already handle "ours beyond ATT&CK"). |
| Spindle identity / relationship timeline | **Keep** (untouched) | No upstream counterpart at all. |
| Behaviour lanes (CAR analytics + Sigma) | **Enhance** | Same engine; coverage resolution gains authoritative ids, revocation handling, strategy/analytic joins. |
| STIX projection | **Modify narrowly** | Authoritative `attack-pattern` ids + pinned tactics (a `contract.version` bump); everything else stands. |
| ADM (the TS library) | **Use as the specification** | Schemas, `relationshipMap`, ID grammar, spec changelog — the contract we build against. Not an engine: on `latest` 4.10.1 navigation is partly dead (`getTactics()`/DS `getTechniques()` return `[]`), strict mode rejects live v19.2, `registerDataSource` crashes (fixed only in `next`). Not a runtime dependency either (TS; we are stdlib-Python by design). |
| mitreattack-python | **Use at dev time** | diffStix pin-bump reports, recipes to mirror in the stdlib loader; never a runtime dep (py≥3.11, pandas et al.). |
| attack-workbench-taxii-server | **Copy patterns only** | Ingestion discipline (immutable release loads, commit markers, latest-pointer); no client code exists to reuse; transport stays pinned GitHub bundles. |

And one **extension** flowing the other way: Byakugan's forensic-artifact
telemetry (prefetch, SRUM, MFT/USN, jumplists, shellbags, LNK, browser
artefacts, Anamnesis memory) has **no upstream log-source identity** —
ATT&CK's vocabulary is live telemetry. We mint Byakugan-namespaced log
sources in the upstream shape (`{name: "byakugan:prefetch", channel: …}`),
attach them to the *same* data components (Process Creation, File Creation,
…), and thereby make DFIR-artifact evidence a first-class citizen of the v18+
detection model — locally now, and as upstream contribution material later.

### 7. COA — feeding Byakugan from `attack-stix-data`

#### Principles (all inherited from how the repo already works)

- **Pin, don't vendor bytes**: a version + sha256 pin on a release artifact
  (the 54 MB bundle can't be a submodule; the pin file plays the submodule's
  role). Everything derived is regenerated deterministically and drift-gated.
- **Generate-time heavy, runtime stdlib**: anything may run at generate time
  (even dev-installed mitreattack-python); what ships runs on stdlib+PyYAML.
- **Network strictly opt-in** (the ES-push precedent): the fetch step is an
  explicit command; every consumer works offline from the cache or committed
  index; `--offline <bundle>` accepts a hand-carried file (air-gapped DFIR).
- **Reference upstream identity, never re-mint it** (STIX BP §5.2, the
  DX_DFIR precedent).

#### Data flow

```
mitre-attack/attack-stix-data
  index.json ──(pin bump, reviewed)──►  byakugan/attack/pin.yml
                                          {domain, version, url, sha256, collection_id}
                                                    │
                                        python -m byakugan.attack.fetch     (opt-in network)
                                                    │   cache: ~/.cache/byakugan/attack/v19.2/…
                                                    │   or --offline <bundle.json>
                                                    ▼
                                        python -m byakugan.attack.build     (generate time)
                                            │                     │
                                            ▼                     ▼
                        byakugan/attack/data/attack-index.json   model/attack/*.yml
                        (compact runtime index, committed,       (reviewable snapshot
                         drift-gated like sources/)               + coverage stats)
                                            │
            ┌───────────────────┬───────────┴────────┬──────────────────────┐
            ▼                   ▼                    ▼                      ▼
   stix.py behaviour     analytics.py/sigma.py   timeline / report   attack.coverage
   layer: authoritative  coverage resolution     threat context      Navigator layer
   ids, real tactics     (revocation-aware)      (groups/campaigns/  (a-priori + hits)
                                                  software/mitigations)
```

The compact index is the keystone: one committed JSON (~1–2 MB across ~4,800
entries) holding, per object type, exactly what the runtime needs —

- `techniques`: `Txxxx → {stix_id, name, phases, platforms, revoked,
  deprecated, revoked_by}`
- `tactics`: `TAxxxx → {stix_id, shortname}` (kills `ATTACK_TACTICS`)
- `strategies`: `DETxxxx → {stix_id, name, technique_ids, analytic_ids}`
- `analytics`: `ANxxxx → {stix_id, platforms, log_sources:
  [{dc, name, channel}], mutable_elements}`
- `components`: `DCxxxx → {stix_id, name, log_sources}`
- `groups/software/campaigns`: `Gxxxx/Sxxxx/Cxxxx → {stix_id, name, aliases,
  (campaigns: first_seen, last_seen, attributed_to)}` + per-technique rollups
  of `uses`
- `mitigations`: `Mxxxx → {stix_id, name, technique_ids}`
- `meta`: collection id/version/modified, bundle sha256, index recipe version

DX_DFIR's `attack_index.py` is the seed (techniques + tactics + revocation
already right); this widens it and moves it to the shared engine, so DX_DFIR
can consume Byakugan's index later instead of maintaining its own.

#### Phases

**Phase 0 — the pin and the index (seam 2; S–M).**
`byakugan/attack/pin.yml` (enterprise v19.2 first; mobile/ics are future
list entries). `byakugan.attack.fetch`: stdlib urllib, sha256 verify,
idempotent cache, `--offline`. `byakugan.attack.build`: bundle → compact
index + `model/attack/` snapshot (counts, per-type inventories — the
review surface, like `model/superset/`). Join hygiene lives here:
log-source names normalized case-insensitively (upstream carries
`NSM:FLow`/`MobiledEDR:telemetry`-grade typos), analytics' component refs
resolved, deprecated/revoked flags carried — never silently dropped
(the honest-gating discipline). The index also carries the two static
contract tables lifted from ADM source (§3.1): the `relationshipMap` and the
ATT&CK-ID grammar — and **every vocabulary (tactic shortnames, platforms,
domains) is derived from the pinned bundle, never hardcoded**: v19's
`stealth`/`defense-impairment` rename is the standing proof that hardcoded
lists rot (it broke both our `ATTACK_TACTICS` table and ADM's own closed
enum). `--check` gate: committed index ↔ pin ↔
recipe version; full regen parity when a cache/bundle is present; the
referential assertions mirror ADM's refinements in stdlib (analytic
log-source refs resolve into their component's `(name, channel)` rows —
4,179/4,182 do in v19.2; the stragglers are counted and carried, never
dropped). Tests
mirror `test_spindle_model.py` (golden vectors: known technique, revoked
technique, one strategy chain resolved end-to-end).

**Phase 1 — authoritative identity in the export (seam 1; S).**
`stix.py` behaviour layer reads the index: `attack-pattern` objects keep
being *shipped* (bundles must stand alone) but carry **MITRE's ids** —
consumers holding an ATT&CK import dedupe on contact; `indicates`/sighting
wiring unchanged. Revoked coverage ids follow `revoked_by` (substitution
reported in the export summary, DX-style); unknown ids are counted, never
invented. `kill_chain_phases` come from the index. `model/stix/conventions.yml`
records the new id rule; `contract.version` bumps; `tests/test_stix*` pin the
new ids. Sigma/CAR coverage strings (`t1059.001`) resolve through one shared
helper in `analytics.py`.

**Phase 2 — superset rebase (seam 3; M).**
`build_superset()` gains the pinned bundle as its component/action source
(same `_action_for` derivation over live component names), keeps CAR scalar
fields, keeps the archived-pin relationship vocabulary (seam 4: documented as
Byakugan-owned; vendoring the 243 edges into `byakugan/` and retiring the
submodule is a follow-up housekeeping PR). Dropped-upstream actions our
evidence still needs become `extension`-tier — the typing-tier machinery
exists. Regenerate `model/superset/`; `docs/DataModel.md` gets the new
three-pin story (car / attack-datasources-vocabulary / attack-stix-data).

**Phase 3 — sources ↔ telemetry mapping (seam 5; M–L, incremental).**
New hand-authored `byakugan/attack_log_sources.yml`: per source, the upstream
log sources it materialises (`evtx_sysmon → WinEventLog:Sysmon
EventCode=1,3,6,7,8,10,11,…` per mapping; `zeek_conn → NSM:Flow`;
`evtx_security → WinEventLog:Security EventCode=4624,…`) and per
(object, action) the data-component defaults (`process/create →
DC0032 "Process Creation"`); forensic-artifact lanes mint `byakugan:*` log
sources bound to the same components. The component side is mostly
pre-computed: **49 of the 106 live components land mechanically on the 13
CAR objects** (Appendix A — the seed of this file), with the misfits flagged
there (ATT&CK's "Image *" components are container/VM images, not PE
modules; "Drive *" has no CAR object; "Application Log Content" belongs to
the superset's `application_log`, not `email`). `gen_sources.py` emits a generated
`attack:` block per source (components covered, log sources, count of
analytics/techniques reachable); `car_source_schema.yaml` extends;
`--check` gates it. `byakugan.attack.coverage <car-dir>` renders the
observability Navigator layer + JSON summary (a-priori from sources present;
runtime scores from behaviour hits when given a finished tree).

**Phase 4 — detections → TTPs, campaigns, and context (seam 6; M).**
Behaviour hits resolve through the index once, then fan out: sightings gain
`x_car_attack` extension data ({technique, strategy DET ids, platform-matched
AN ids}); `timeline`/report annotate sighted techniques with groups /
software / campaigns (aliases, campaign windows vs case window) and
mitigations. All of it references upstream ids — no ATT&CK SDO beyond the
attack-pattern stubs is shipped; a consumer's ATT&CK import supplies the
rest (OpenCTI's MITRE connector holds exact copies).

**Phase 5 — keep-fresh protocol (ongoing; S per bump).**
`python -m byakugan.attack.pin --to 20.0`: fetch+verify, rebuild index /
superset / sources blocks, emit a pin-bump report — our own
`x_mitre_contents` diff (added/changed/removed objects touching our
mappings) plus, dev-time, `attack-changelog` (mitreattack-python) for the
narrative diff (`unchanged=True`, or detection-mapping moves hide). Golden
tests move only with the pin, deliberately — the spindle change-protocol
discipline applied to the ATT&CK pin. Optional lanes, explicitly out of the
critical path: mobile/ics domains; serving TAXII via the workbench
taxii-server container beside the Elastic stack; dev-time ADM validation of
exported bundles (pin ≥ 4.11, validate per-object, prefer the Base/Partial
tiers for Byakugan-emitted objects — §3.1); upstreaming the
forensic-artifact log sources.

#### CI / test surface (all offline)

- `byakugan.attack.build --check` — committed index ↔ pin ↔ recipe drift.
- `test_attack_index.py` — golden vectors incl. a revoked technique and one
  full strategy→analytic→component→log-source chain.
- `test_stix_behaviour.py` — authoritative ids, revocation substitution,
  phases-from-index.
- `gen_sources --check` — the `attack:` blocks stay in sync with the maps.
- Existing gates (`model/stix/validate.py`, superset tests) extended, not
  replaced.

#### Open questions (deliberately parked, not blockers)

1. **Commit the compact index vs. artifact-only?** Recommended: commit
   (~1–2 MB, sources/-style reviewability, offline CI, DX_DFIR precedent).
   The 54 MB bundle itself never enters the repo.
2. **Ship attack-pattern stubs or reference-only bundles?** Recommended:
   keep shipping stubs with authoritative ids (standalone bundles stay
   self-describing; dedupe is the consumer's normal STIX behaviour). A
   `--refs-only` export flag is cheap if an OpenCTI-first workflow prefers it.
3. **Vendor the 243-edge vocabulary now or with Phase 2?** Recommended: with
   Phase 2, as a mechanical follow-up once the superset rebase lands.
4. **Which payoff lane first — coverage (Phase 3) or context (Phase 4)?**
   Recommended: 3 before 4; the sources mapping feeds the context lane's
   credibility ("we sighted it *and* we know which telemetry corroborates").

---

## Appendix A — data components ⇄ Byakugan objects (the Phase-3 seed)

Computed against v19.2 (106 live components; the site catalogue at
`attack.mitre.org/datacomponents/` renders these same objects). Counts in
parentheses are the component's `x_mitre_log_sources` rows — a proxy for how
much upstream detection content hangs off it.

**Tier 1 — lands directly on a CAR object's (object, action) grid:**

- `process` — DC0032 Process Creation (333), DC0034 Process Metadata (45),
  DC0035 Process Access (35), DC0020 Process Modification (19),
  DC0033 Process Termination (13)
- `file` — DC0039 File Creation (128), DC0061 File Modification (150),
  DC0055 File Access (113), DC0059 File Metadata (91), DC0040 File
  Deletion (25)
- `flow` — DC0085 Network Traffic Content (279), DC0078 Network Traffic
  Flow (159), DC0082 Network Connection Creation (98), DC0102 Network Share
  Access (7)
- `user_session` — DC0067 Logon Session Creation (67), DC0088 Logon Session
  Metadata (34), DC0014/DC0010/DC0009/DC0013 User Account
  Creation/Modification/Deletion/Metadata (11/41/3/29)
- `authentication` — DC0002 User Account Authentication (109), DC0084
  Active Directory Credential Request (5), DC0006/DC0007 Web Credential
  Creation/Usage (5/20)
- `registry` — DC0056/DC0063/DC0045/DC0050 Windows Registry Key
  Creation/Modification/Deletion/Access (1/9/1/4)
- `service` — DC0060 Service Creation (15), DC0065 Service Modification (4),
  DC0041 Service Metadata (22)
- `driver` — DC0079 Driver Load (3), DC0074 Driver Metadata (1)
- `module` — DC0016 Module Load (45)

**Tier 2 — lands on superset (ATT&CK-only) objects, with an evidence-level
projection onto CAR rows where our maps already observe them:**

- `command` / `script` — DC0064 Command Execution (291), DC0029 Script
  Execution (32): superset objects; our evidence for both is
  `process.create` command lines — the projection is a mapping decision,
  not automatic.
- `scheduled_job` — DC0001/DC0005/DC0012 Scheduled Job
  Creation/Metadata/Modification (17/8/4)
- `wmi` — DC0008 WMI Creation (3)
- `named_pipe` — DC0048 Named Pipe Metadata (2)
- `application_log` — DC0038 Application Log Content (229)
- `drive` — DC0042/DC0046/DC0054 Drive Creation/Modification/Access
  (22/10/8)
- **Not** `module`: DC0015/DC0026/DC0028/DC0036 Image
  Creation/Deletion/Metadata/Modification are **container/VM images** —
  a naïve prefix join misfiles them; they belong with the container lanes.

**Out of current evidence scope (~50 components):** cloud control plane
(AWS/Azure/GCP/SaaS/M365), identity-provider, network-device management,
OSINT-flavoured (Active/Passive DNS, Domain/Certificate Registration,
Malware Repository, Social Media) — they stay in the index (they still
resolve strategies/analytics) but no Byakugan source claims them.
