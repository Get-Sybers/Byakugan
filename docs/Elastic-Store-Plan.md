# The served store: SQLite → Elasticsearch — decision and cross-repo plan

**Status: implemented** (epic #99 — and since extended past this plan: the
projection contract now lives in `elastic/projection/`, the Elastic runtime
in `byakugan/elastic/`, the repo ships its own standalone stack under
`elastic/`, and the engine no longer writes SQLite at all). The text below is
the original decision record, kept as written — path and store references in
it describe the repos as they stood on 2026-09-20.

This document decides what replaces SQLite as the
database Byakugan's consumers query, and lays out the migration across the
repos that produce, package and consume CAR data. It was researched against
the current heads of Byakugan, GoDFIR-toolz, DX_DFIR, Anamnesis and uSaid
(2026-09-20).

## The ask

1. Byakugan's queryable store should be a real server database — a graph
   database or Elasticsearch — not SQLite files.
2. It must be deployable as a **container owned by GoDFIR-toolz**, joining the
   **Elastic stack DX_DFIR runs** as one more stack member.
3. The **CAR data model must stay queryable by CAR fields**; full-text
   indexing is optional, not required.
4. A **timeline must be viewable in Kibana or exportable by script**.
5. Borrow what transfers from **uSaid**'s graph-on-Elastic experience.

## Decision — Elasticsearch, with the graph as documents

**The served store is Elasticsearch: the `logs-car.*` data streams already
specified by `model/projection/`, plus a new relationship stream. No graph
database is added.** The relationship timeline (superset.db's edge table) is
loaded as first-class edge *documents* with deterministic ids — the pattern
uSaid proved — not as a second database with a traversal engine.

### Why Elasticsearch wins for how Byakugan is actually consumed

| Requirement / consumption path | Elasticsearch | Dedicated graph DB (Neo4j/Memgraph/Arango) |
|---|---|---|
| Joins the stack DX_DFIR already runs | *Is* the stack — ES 9.4.3 + Kibana on Basic, compose project literally named `byakugan` (`DX_DFIR/docker/elastic/`) | A second server, second query language, second backup/auth surface; nothing in any repo consumes Cypher/Gremlin |
| Timeline in Kibana | Native: Discover/Lens over `logs-car.*`, `date_histogram` buckets | No Kibana; needs its own viewer |
| Query by CAR fields | Projection contract + generated field aliases (below) keeps every CAR field addressable | Would need its own CAR property model, built from scratch |
| Detections | DX_DFIR's `detect/` rules are already authored against the ECS fields this projection produces, and the `car-detections` lookup-join contract is already written | No detection layer exists or is planned against a graph store |
| The relationship queries we actually run | 1–2 hop pivots on **already-materialised** edges (owning process, parent, LUID auth↔session, injection) — term queries on `source_guid`/`target_guid`, `LOOKUP JOIN` for enrichment | Wins only on deep variable-length traversal, which no current consumer performs |
| Ops posture (air-gap, Basic licence, hardened images) | Already proven by the DX_DFIR risk gate on 9.4.3/Basic | Licensing and hardening work from zero |

uSaid's architecture rule, adopted here verbatim: *Elasticsearch is not a
graph database; it does not traverse. Denormalise edges into flat documents at
query granularity and precompute the pivots you actually run.* Byakugan is
unusually well placed for that rule because the enrichment cascade **already
materialises every relationship as a timestamped edge row** — the graph work
is done before storage; the store only has to hold edges and answer term
queries. When a true graph consumer arrives (interactive traversal, OpenCTI),
the STIX 2.1 projection (`stix.py`) is the exchange layer — that is a later
consumer of the store, not a reason to change the store. (Note uSaid's
measured warning before ever pointing STIX at OpenCTI: its store silently
drops custom types/properties.)

### What was already decided before this document

This plan mostly *implements* decisions the repos have already made, and it
should say so plainly:

- `model/projection/` (contract v2) is the hand-authored CAR→ECS 8.11
  boundary: one data stream per object, `logs-car.<object>-<namespace>`, the
  `car.*` custom namespace, a recommended deterministic `_id`. Its README
  ends: "no loader, no index templates, no ingest pipeline. Those are built
  in DX_DFIR *from* this contract."
- DX_DFIR has proven `logs-car.*` against its live 9.4.3/Basic stack
  (`.github/tests/elastic-riskgate/`, `docs/riskgate.md` — evidence time in
  `@timestamp`, never re-stamped; `logs-car@custom` + `lifecycle: {}` as the
  retention remedy), has written the `car-detections` lookup-index join
  contract (`detect/rules/car-detections/join-keys.yml`, including the
  `LOOKUP JOIN` field-shadowing hazards), and `docs/Get-Started.md` names the
  CAR→ECS load "the next phase".
- GoDFIR-toolz already owns the Byakugan container (`byakugan/` — engine
  cloned at the `BYAKUGAN_REF` pin, `ENTRYPOINT byakugan`, the engine's own
  multi-tool dispatcher), and its framework already sanctions exactly one
  networking shape: `network: optional` behind a default-off env var
  (`BYAKUGAN_LOAD_ES_URL` is now the framework's one such opt-in — the
  original precedent, anamnesis's symbols-online fetch, was replaced by a
  build-time symbol bake and that lane is always offline).

What does **not** exist yet, anywhere: a projection for the relationship /
inferred-node streams, index templates, the loader itself, Kibana assets, and
the DX_DFIR wiring. That is this plan.

## How Byakugan is consumed across the repos (the ground truth)

| Repo | Role | Touches the stores how |
|---|---|---|
| **Anamnesis** | Producer (memory → CAR) | Writes its **own** `car.db` per image (`internal/store/store.go`); Byakugan reads it 1:1 as an *input* (`readers.py::load_anamnesis_car`). An interchange format, not Byakugan's store. |
| **GoDFIR-toolz** | Packager | Builds the hardened engine image; `contract.yml` names `car.db`/`superset.db` in `outputs.layout` and uses `car.db` existence as the idempotency marker. Offline, run-once, no pip, no CA bundle in the runtime stage today. |
| **DX_DFIR** | Orchestrator + stack owner | Ansible drives `build`/`verify`/`timeline` over `data_store/processed/`; output lands in `processed/byakugan/<source>/`. Consumers of the on-disk artefacts: the Go TUI Timeline tab (`timeline.jsonl`), `smoke-test.sh` (`car_*.jsonl`), the lane's output gate (globs for `car.db` / `timeline.jsonl`), `stix/behaviour.py` (reads `car.db` read-only). Filebeat currently tails **all** of `processed/` — including, collaterally, `byakugan/**/car_*.jsonl` into raw non-ECS `logs-dxdfir.byakugan-*`. |
| **Byakugan** | Engine | `store.py`/`superset.py` write the two SQLite stores; `timeline`, `verify`, `analytics`/`sigma`, `stix`, `crosssource` read them back. |
| **uSaid** | Pattern donor only | No dependency either way. |

Two consequences fall out of that table:

1. **SQLite has two distinct jobs today** — the engine's *working store*
   (what enrich/verify/analytics/STIX read back) and the *consumption
   interface* (what other repos open). Only the second job is the problem
   this plan solves. The Anamnesis `car.db` input contract is untouched.
2. The migration's blast radius in DX_DFIR is enumerable and small: one
   Filebeat exclusion, one new role, and (optionally, later) repointing
   `behaviour.py`/TUI reads at Elastic. The JSONL exports keep every current
   on-disk consumer working during and after the transition.

## Target architecture

### Streams and indices

| Name | Kind | Holds | One doc = |
|---|---|---|---|
| `logs-car.<object>-<ns>` ×13 | data stream | CAR object events (contract v2, unchanged) | one finished CAR event, ECS-projected |
| `logs-car.rel-<ns>` | data stream | **new** — relationship instances from superset.db (`declared` + `derived`) | one `source →verb→ target` edge |
| `logs-car.inferred-<ns>` | data stream | **new** — reconstructed-but-unobserved nodes (already named by `superset.py`) | one inferred node |
| `car-detections` | lookup index | DX_DFIR-owned, already specified (`join-keys.yml`) | one (detection, event) stamp |
| `car-entity-<ns>` | lookup index (later, Phase 7) | transform-built entity rollups keyed by `guid` | one entity's first/last-seen + rollups |

`<ns>` (the data-stream namespace) is the case/collection boundary —
DX_DFIR's existing `DFIR_NAMESPACE` idiom, slugified to the data-stream
charset. This is also the honest home for the cross-source scoping rule in
`CAR-CrossSource.md`: sources that share a namespace were *asserted* to be one
investigation; nothing ever correlates across namespaces by accident.

### Document shapes

- **Objects**: exactly contract v2. Evidence time → `@timestamp` (never
  re-stamped; load time may go to `event.ingested`), `guid → event.id`,
  `owning_guid → process.entity_id`, homeless fields under `car.*`,
  `native → car.native` (flattened). Deterministic `_id` per the contract
  recipe: `sha1(source_host | <object> | guid | car_action | timestamp |
  target_guid | access_level)`.
- **Edges** (contract v3, new `model/projection/relationships.yml`): minimal
  ECS envelope (`@timestamp`, `data_stream.*`, `event.kind: event`,
  `event.module: car`, `event.dataset: car.rel`, `host.name`) plus the edge
  itself under a `car.rel.*` namespace with **typed keyword columns**, never
  buried in a blob: `car.rel.relationship` (the ATT&CK verb),
  `car.rel.source.object|guid`, `car.rel.target.object|guid`,
  `car.rel.class` (`declared|derived`), `car.rel.confidence`,
  `car.rel.method`, `car.rel.identity_key`, `car.rel.inferred_end`,
  `car.rel.corroborated_by`. Deterministic `_id` mirrors uSaid's typed-triple
  keying, discriminators *in* the key:
  `sha1(source_host | source_guid | relationship | target_guid | timestamp |
  class | identity_key)`.
- **Inferred nodes**: `car.inferred.*` (node_id, object, identity_key/value,
  reason, method, corroborated_by, first/last_seen); `_id = node_id` — it is
  already deterministic by construction.

### CAR-field queryability (the "query by CAR fields" guarantee)

The projection renames mapped fields to ECS. To keep the literal requirement
— *the CAR data model can be queried using CAR fields* — the generated index
templates add a **field `alias` per mapped CAR field**:
`car.<object>.<field>` → its ECS home (e.g. `car.process.command_line` →
`process.command_line`). Aliases work in queries, aggregations and ES|QL, cost
nothing at index time, and are generated mechanically from
`objects/<object>.yml` — the contract already knows every mapping, so the
aliases can never drift from it. Native fields already live at
`car.<object>.<field>` and `car.native.*`. Net: **every CAR field is
addressable under its CAR name**, while detections and Kibana get standard
ECS. `byakugan car-vocab` remains the canonical action vocabulary for query
authors.

### Mappings, templates, indexing

- Templates are **generated from the contract** (new
  `model/projection/render_elastic.py` → committed `model/projection/rendered/`,
  drift-checked like every other generated `model/` artefact): one component
  template for the common header + `car.*` namespace, one per object, composed
  via `composed_of`, priority above the built-in `logs-*-*` template, each
  carrying a uSaid-style `_meta` block (unit of analysis, owner, contract
  version, recompute triggers).
- Keyword-first typing per the contract's declared types; `car.native` stays
  `flattened` (everything filterable, no mapping explosion — with uSaid's
  documented caveat that flattened subfields compare lexicographically, which
  is why anything range-queried must be a projected column, and in this
  contract already is).
- "Doesn't need to be indexed, but can": everything is indexed by default at
  case scale (it is what makes Kibana work); the contract may mark bulky
  evidence fields (`file.content`, `email.message_body` natives)
  `index: false` — retained in `_source`, retrievable, skipped by the
  inverted index. And in bundle mode (below) nothing is indexed until an
  operator chooses to load.
- **Retention: none by default.** Evidence is not logs; no ILM delete phase,
  `logs-car@custom` with `lifecycle: {}` per the risk-gate remedy. Deletion is
  an explicit per-namespace act (`DELETE _data_stream/logs-car.*-<ns>` when a
  case closes).

### Idempotency and write discipline (borrowed from uSaid, adapted to data streams)

Bulk-`create` with the deterministic `_id`; a re-load's duplicates come back
as 409s the loader counts as `already_present` rather than errors —
re-running a load is safe and cheap. Two honest caveats, written down rather
than discovered later: data streams enforce `create` (no in-place update —
correct for evidence), and `_id` uniqueness holds per backing index, so
`logs-car.*` streams must not be given rollover policies while deterministic
ids are load-bearing (they aren't, by the retention decision above). A
`--verify` pass (uSaid's pattern) `_count`s per object × source against the
store/JSONL counts and fails loud on drift; the existing `byakugan verify`
gate gains that check rather than a new tool appearing.

## The loader: `byakugan load`, a fifth sub-tool — not a new service

The framework forbids daemons ("no long-running service", four times in the
GoDFIR-toolz white paper) and its contract schema has no `network: required`.
So the loader is **not** a resident indexer: it is a run-once batch sub-tool
in the existing dispatcher, the first-class extension shape the framework
documents.

- **Where the code lives:** Byakugan (`byakugan/load.py` + `cli.py` gaining
  `load`), because the projection contract lives here and the dispatcher is
  engine-side — GoDFIR-toolz's own docs note the byakugan env contract is
  implemented in this repo. **The container stays owned by GoDFIR-toolz**
  (same image, same pin-bump flow via `BYAKUGAN_REF`); DX_DFIR keeps driving
  it "with `-e`/`-v` and nothing else".
- **No new dependency.** The runtime closure is python3 + pyyaml, pip is
  removed by hardening, so the ES client is **stdlib `urllib` against
  `_bulk`/`_index_template`/`_count`** — DX_DFIR's risk gate already contains
  a working ~100-line client of exactly this shape (`riskgate.py::Es`), and
  uSaid runs all ingest this way in production.
- **Two modes, one contract:**
  - **Bundle mode (default, offline):** no endpoint configured → renders
    ready-to-POST `_bulk` NDJSON bundles + a manifest (counts, `_id`s,
    content hashes, target stream per bundle) into `/output`. This keeps the
    air-gap workflow first-class (bundles travel like `docker save` images;
    DX_DFIR's cti lane already works operator-POSTs-the-NDJSON style) and
    keeps the GoDFIR-toolz contract tests green under `--network none`.
  - **Push mode:** endpoint configured → POSTs the same bundles itself,
    tolerating 409s, then runs the count verify.
  - `BYAKUGAN_LOAD_SETUP=1` first applies the rendered templates, aliases and
    (optionally) Kibana saved objects — idempotent, diff-before-write.
- **Env block** (per the uniform `BYAKUGAN_<SUBTOOL>_*` convention):
  `_INPUT_DIR` (a materialised car tree: reads the per-object JSONL — the
  existing ingest contract — not the .db files), `_OUT_DIR` (bundles +
  the one-line JSON summary's report), `_ES_URL`, `_ES_API_KEY` /
  `_ES_USER`+`_ES_PASSWORD_FILE`, `_ES_CA_FILE` (the stack's CA, mounted from
  the compose `certs` volume), `_NAMESPACE`, `_SETUP`, `_FORCE`, `_LOG_LEVEL`.
  Exit codes stay on the uniform table (0 ok / 1 nothing / 2 config / 3
  partial).
- **GoDFIR-toolz changes** (lockstep, or `conform.sh` fails): `contract.yml`
  (add the sub-tool, `network: optional`, the env entries; reword
  `outputs.layout` — see "What happens to SQLite"), `README.md` mirrors,
  `Dockerfile` adds `ca-certificates` to the runtime stage (the `signatures`
  image is the in-repo precedent) with the header justification, and
  `test/contract_test.sh` gains the bundle-mode case (still `--network
  none`) plus keeps idempotency asserted via the deterministic bundles.

## DX_DFIR integration

1. **New role `dxdfir_car_load`** in the `get_sybers.dxdfir` collection,
   shaped like `dxdfir_byakugan`: gate on
   `roles/dxdfir_stack/tasks/ensure_running.yml` (whose header names exactly
   this use case), then drive the same byakugan image through `dxdfir_lane`
   with network attached to `byakugan_default`, `/input` = `processed/byakugan`
   (ro), the CA from the `certs` volume (ro), creds from `docker/elastic/.env`
   via env-file. Playbook `dxdfir-load-car.yml`; CLI verb `dxdfir load-car`
   under the CAR group. The lane's contract-driven `docker run` builder needs
   one addition: permitting `--network <stack network>` when the tool's
   contract declares `network: optional` and the run enables it.
2. **A least-privilege writer identity** (`byakugan_loader`), uSaid-style:
   `create_doc` + `create_index` + `read`/`view_index_metadata` on
   `logs-car.*`, nothing else — evidence immutability enforced at the
   credential layer, not by convention. Template/saved-object setup runs once
   with the setup superuser, not with the loader identity. (Also retires a
   known debt: Filebeat currently writes as `elastic`.)
3. **Stop the double-ingest:** exclude `byakugan/**` from
   `filebeat.yml` paths so CAR JSONL stops landing raw in
   `logs-dxdfir.byakugan-*` and competing with `logs-car.*`.
4. **Kibana assets become repo artefacts:** Byakugan renders them (data views
   `logs-car.*` + `logs-car.rel-*`; a saved Discover timeline, `@timestamp`
   ASC, columns `car.object`/`event.action`/`host.name`/summary fields; a
   Lens dashboard of `date_histogram` by object/action/host); DX_DFIR imports
   them in stack setup via `/api/saved_objects/_import?overwrite=true` — the
   first saved objects in the repo, so this adds the import step too. Copy
   uSaid's `test_kibana_views.py` guard: every referenced field must exist in
   the rendered mappings.
5. **Detections come alive for free:** the `detect/` rules are authored
   against exactly these ECS fields — "the rules are the specification, not
   the pipelines" stops being true the day `logs-car.*` is populated. The
   `car-detections` writer then follows `join-keys.yml` as specified
   (`_id = <detection.id>:<event.id>`, lookup mode, the documented
   `LOOKUP JOIN` rename-guard for `@timestamp`/`process.entity_id`).

## The timeline requirement, concretely

- **In Kibana** (interactive): the imported data view + saved Discover
  session over `logs-car.*` *is* the unified timeline — objects and edges
  interleave because `logs-car.rel-<ns>` matches the same pattern,
  discriminated by `event.dataset`. Histograms are `date_histogram` buckets;
  slices are KQL/ES|QL (`FROM logs-car.*-<ns> | WHERE @timestamp >= ... |
  SORT @timestamp`); the DX_DFIR TUI's Kibana tab already speaks ES|QL to the
  stack. `LOOKUP JOIN` (GA since 9.1; stack is 9.4.3) enriches rows from
  `car-detections` per the join contract.
- **By script** (the export the CLI already promises): `byakugan timeline`
  gains an Elastic source — `BYAKUGAN_TIMELINE_ES_URL` (+ the same auth/CA
  block) or `--elastic <url>` — reading via point-in-time + `search_after`
  ordered by `@timestamp` (the correct full-export mechanic; ES|QL is for
  interactive slices) and emitting **byte-compatible `timeline.jsonl`**, so
  the TUI tab, smoke tests and every downstream script keep working
  unchanged whichever source produced the file. The local
  (stores/JSONL-based) path remains for offline use.

## What happens to SQLite — the honest boundary

- **As a consumption interface, it ends.** The contract becomes: **Elastic is
  the served, queryable store; the per-object/relationship JSONL is the
  portable interchange** (and the loader's input). GoDFIR-toolz's
  `outputs.layout` and the DX_DFIR lane gates re-anchor on
  `car_<object>.jsonl` presence rather than `car.db`. External readers of the
  .db files migrate on their own schedule (`stix/behaviour.py` and the smoke
  tests already have JSONL/ES paths available); nothing new may grow a
  SQLite dependency.
- **As the engine's internal working set, it stays — deliberately.** The
  cascade, the verify gate, analytics/Sigma, STIX projection and the deferred
  cross-source stage all do random-access reads over a self-contained
  per-source store, offline, inside a `--network none` container. Rewriting
  those against a server DB would break the framework's run-once/offline
  laws, the "one source → one database" isolation principle, and the
  air-gap posture — for zero consumer-visible gain once the served tier
  exists. This mirrors the conclusion the Azul evaluation
  (`docs/research/ideas/azul.md`) already reached about heavy service stacks,
  while still delivering what the ask wants: nobody outside the pipeline
  opens a SQLite file again. (If the internal artefacts should stop hitting
  disk too, that is a separate, later refactor — an in-memory/temp store
  behind the existing `CarStore` interface — and nothing in this plan blocks
  it.)

## Borrowed from uSaid (credit where it transfers)

Taken: deterministic ids keyed on the typed triple with discriminators in the
key; bulk-`create` + tolerated 409s + count/content-hash verification;
immutability enforced by a `create_doc`-only writer role; component templates
with `_meta` as machine-checked contract; committed, hand-authored Kibana
NDJSON validated against mappings by a test; stdlib-urllib ingest as the
production pattern; "denormalise, precompute, never assume traversal".

Deliberately not taken: the git-authority-file-as-database (hand-curated
~50-node graph vs. telemetry volume); fetch-all-and-reduce-in-Python
(replaced by term pivots and, later, transforms); single ancestry arrays
(CAR's graph is cyclic/multi-parent — the generalisable move is precomputing
the *specific* pivots, which the cascade already does); classic-indices-only
(uSaid needs upsert-by-`_id`; evidence wants append-only, so data streams fit
here).

## The user-supplied Elastic features, mapped to phases

| Feature | Use here | Tier / constraint |
|---|---|---|
| Bucket aggregations | `date_histogram` timeline histograms; `terms` by object/host/action; `composite` for paginated rollups | Basic ✔ (Phase 5) |
| ES|QL | Interactive CAR queries in Kibana/TUI; `LOOKUP JOIN` on `car-detections` (GA 9.1; stack 9.4.3 ✔) | Basic ✔ (Phase 5–6) |
| Transforms | `car-entity-<ns>`: pivot/latest per `guid` (first/last seen, action counts, distinct targets) as a **lookup-mode** dest so ES|QL can join edges→entities in one query; also the natural engine for cross-source convergence rollups (`content_node`-style) | Basic ✔ (Phase 7) |
| Cross-cluster search | Only if labs federate later (multi-site); single-node today. CCS itself Basic; **ES|QL-over-CCS is Enterprise** — plan `_search`/EQL for any federation | Deferred |
| Vector database | Optional: `dense_vector` + kNN over command lines/paths for similarity pivots, vectors computed **outside** the cluster (uSaid precedent) — in-cluster inference/ELSER is Platinum+ | Basic ✔ for BYO vectors (Phase 7, opt-in) |
| AutoOps | Cloud-connected only (metrics ship to an Elastic Cloud account; free, self-managed supported since ~Nov 2025) — **incompatible with an air-gapped lab**; adopt only for connected deployments | N/A by default |

## Phases

Each phase lands independently and leaves everything green.

**Phase 1 — Byakugan: contract v3 + rendered assets.**
`model/projection/relationships.yml` + `inferred.yml` (edge/node projections,
`_id` recipes); `conventions.yml` bumps `contract.version: 3`;
`render_elastic.py` emitting `rendered/` (index/component templates, CAR-name
field aliases, Kibana NDJSON); `validate.py` extended to cover the new files
and rendered-vs-contract drift; the uSaid-style saved-objects-vs-mappings
test. *Accept: `validate.py` green; rendered artefacts committed and
drift-guarded.*

**Phase 2 — Byakugan: the `load` sub-tool.**
`byakugan/load.py` (stdlib client, bundle + push + setup modes, 409-tolerant,
count verify), `cli.py` gains `load`; `verify` gains the Elastic count check.
Unit tests offline (bundle mode); integration test against a throwaway ES
where CI allows. *Accept: bundle mode produces stable, deterministic bundles;
re-push is a 100% `already_present` no-op.*

**Phase 3 — GoDFIR-toolz: image + contract.**
`contract.yml` (sub-tool, `network: optional`, env block, `outputs.layout`
reword to the JSONL/ES contract), README lockstep, Dockerfile
`ca-certificates`, contract tests (bundle mode under `--network none`);
`BYAKUGAN_REF` bump. *Accept: `conform.sh` and the gate pass.*

**Phase 4 — DX_DFIR: wiring.**
`dxdfir_car_load` role + playbook + CLI verb; `dxdfir_lane` network
allowance; `byakugan_loader` identity; Filebeat exclusion; Kibana
saved-objects import step; pin bump. *Accept: `dxdfir load-car` on the demo
corpus populates `logs-car.*-<ns>`; riskgate still green; detection rules
begin matching.*

**Phase 5 — Timeline UX.**
Kibana data views + saved timeline + Lens dashboard imported; `byakugan
timeline --elastic` emitting byte-compatible `timeline.jsonl`; TUI unchanged
(already reads the file and speaks ES|QL). *Accept: the same case renders in
Kibana and exports identically by script.*

**Phase 6 — Detections join.**
`car-detections` writer per `join-keys.yml`; behaviour hits (analytics/Sigma)
optionally to `logs-car.behaviour-<ns>`. *Accept: `LOOKUP JOIN` example
queries from the join contract return stamped rows.*

**Phase 7 — Roadmap (each opt-in).**
Entity transforms (`car-entity-<ns>` lookup joins); cross-source convergence
reading ES instead of walking .db trees (namespace = asserted scope); BYO
`dense_vector` similarity; CCS if labs federate; STIX → OpenCTI once the
serve-fidelity problem uSaid measured has an answer.

## Risks and open questions

- **Contract churn** is the coupling to respect: `contract.yml` ↔ README ↔
  engine must land together per pin bump (`conform.sh` enforces it).
- **Data-stream `_id` semantics**: deterministic-id idempotency requires the
  no-rollover retention decision to hold; if per-namespace ILM is ever
  wanted, revisit (classic indices + aliases, uSaid-style, is the fallback).
- **Kibana asset drift** across stack upgrades (Lens migration versions) —
  the validation test plus `overwrite=true` import is the mitigation uSaid
  live-falsified a bug with.
- **Who verifies loaded truth**: the count verify catches loss, not mutation;
  if tamper-evidence matters, adopt uSaid's `content_hash` column +
  read-back-and-compare as part of Phase 2 rather than later.
- Open: exact namespace ↔ collection naming (`DFIR_NAMESPACE` per case vs per
  evidence drop); whether `stix/behaviour.py` moves to ES reads in Phase 6 or
  stays on its offline path; whether bundles should be the *only* offline
  artefact (retiring per-object JSONL) once consumers migrate — deferred, the
  JSONL is load-bearing today.
