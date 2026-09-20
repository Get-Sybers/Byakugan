# The CAR pipeline — how it works

*Companion docs: [CAR-Relations.md](CAR-Relations.md) (per-object
identity/join/inheritance/limit rules), [CAR-Extraction-Rules.md](CAR-Extraction-Rules.md)
(the extraction principles), [CAR-CrossSource.md](CAR-CrossSource.md) (the deferred
cross-source aggregate stage) and [DataModel.md](DataModel.md) (the CAR + ATT&CK
superset, reconstructed live from the pinned CAR + ATT&CK model).*

## 1. What it is

`byakugan` turns each ingested evidence **source** into finished
**MITRE CAR** — every extractable record becomes a CAR **object** performing an
**action** at a **timestamp**, carrying that object's canonical **properties** —
and emits it as per-object **JSONL** (`car_<object>.jsonl`) for downstream
ingestion (DX_DFIR ships it to Elastic).

The design is deliberately small and **repeatable**, and the engine is
**elastic**: it holds a source's events in memory for the duration of a build
and writes only the materialised JSONL tree — no SQLite anywhere. One recipe,
run per source:

```
input source ──▶ artefact map(s) ──▶ normalize ──▶ enrich (self- ──▶ in-memory
   (a file        (object/action/      (raw row →     contained,        CarStore +
    or a dir)      property rules)      CAR event)     within-source)   SupersetStore
                                                                          │
                                                        JSON out ◀────────┘
                                              car_<object>.jsonl + car_relationships.jsonl
                                              → downstream ingest
```

It is the pipeline-wide application of what shipped in **Anamnesis v1.0.0** for
memory: the mapping/inference logic lives in the processor we own, the store is
finished CAR, and the query layer just reads the model instead of re-deriving it.

## 2. The isolation rule — one source, one store

**Each evidence source gets its OWN in-memory working store, enriched only
within itself, and its own materialised JSONL tree.** A source is a coherent
evidence set:

| source | what counts as "the source" |
|---|---|
| Windows event logs | one goevtx item (`windows_logs/<item>/goevtx.jsonl` — one log), OR a directory of `*_EvtxECmd_Output.json` (a host's channels), OR the host's Plaso `winevtx` output |
| Zeek | one capture's per-protocol logs (`conn.json`, `http.json`, …) together |
| log2timeline | one image's rendered timeline (`log2timeline/jsonl/<source>/timeline.jsonl`, or a raw `<image>.jsonl` — a container of many parsers, split internally) |
| GoDFIR-toolz | one Go-tool item (`godfir-toolz/<tool>/<item>/<tool>.jsonl` — a hive, a `.pf`, a SRUM database), OR an older `godfir-toolz/<host>/` tree |
| memory | Anamnesis's finished `car.db` (passed through 1:1) |

`--batch` discovers these under a processed tree (`pipeline.discover_sources`);
a lane's `_`-prefixed staging directory (the image exports the tools parse) is
never a source.

No source ever depends on another being present, and nothing is mixed.
Cross-source ("final") enrichment is a **separate, optional end-stage** over the
aggregate — never part of the per-source product (see §9, still to build).

Run it:

```
python -m byakugan --in <file-or-dir> --out <dir> [--host NAME] [--artefacts k1,k2]
# → <dir>/car_<object>.jsonl (one JSONL per populated object) + car_relationships.jsonl
```

## 3. Components (`byakugan/`)

| module | role |
|---|---|
| `carmodel.py` | the 13 CAR objects, reconstructed live via `build_data_model` from the pinned CAR model — no committed copy |
| `build_data_model.py` | builds the CAR (13) + the CAR+ATT&CK superset (~38) + the relationship catalogue live from the pinned CAR + ATT&CK model — no committed copy |
| `mappings/` | per-artefact declarative maps (one file per family; auto-discovered) |
| `normalize.py` | the marker engine: `normalize(artefact, record) → CAR event`, or `None` if unmapped |
| `../go/` (`byakugan-parse`) | the **parse engine**: raw file → pre-enrichment CAR events. Holds the line reader, the winevt adapter (Plaso winevt(x) record → EvtxECmd shape, so the evtx maps run unchanged), the jlecmd flatten, the l2t container splitter (→ per-parser wrapped tables: `SourceImage`, `RecordId`, `Timestamp`, `Parser`, `Record`), the marker resolver and the spindle identity — reading the mapping tables through `internal/ir/ir.json` (`python -m byakugan.export_ir`) |
| `ids.py` | the one id recipe — canonical JSON + the namespaces (`STIX_NS`, `CAR_NS`, `SPINDLE_NS`) — shared by the STIX projection and the spindle row guid |
| `enrich.py` | the relationship + inheritance cascade (identity, joins, inheritance, dedupe, canonical accounts) |
| `store.py` | the in-memory per-object `CarStore` + `export_jsonl()`/`read_object_jsonl()`/`read_events()` (the downstream ingest contract and its read-back) |
| `superset.py` | the in-memory `SupersetStore`: the relationship-instance timeline linking the object rows, exported as `car_relationships.jsonl`/`car_inferred.jsonl` |
| `readers.py` | `load_anamnesis_car()` — the memory passthrough (the only source that is not parsed; the one place this repo still reads a `car.db` — Anamnesis's own output format) |
| `pipeline.py` | orchestration: route source → normalize → enrich (self-contained) → in-memory store → JSONL |

## 4. The CAR data model (13 objects)

The CAR object/field/action set is a **verified exact match** to `car.mitre.org`
— every object, action, and field (diffed 13/13, 0 missing, 0 extra),
reconstructed live from the pinned CAR model — no committed copy. That model is
materialised inside the hardened `get-sybers/byakugan` image at build time (a
recursive clone; see [GoDFIR-toolz/byakugan](https://github.com/Get-Sybers/GoDFIR-toolz/tree/main/byakugan)),
so there is no host model checkout at runtime. The 13 objects:
authentication, driver, email, file, flow, http, module, process, registry,
service, socket, thread, user_session.

The engine keeps **one in-memory collection per object** (`store.CarStore`).
Each row = one CAR event: a minimal header (`timestamp, car_action, guid,
owning_guid, link_confidence, source_artefact, source_host, native`) + that
object's MITRE fields. Header columns beyond MITRE are the deliberate,
labelled additions a materialized multi-source store needs; `parent_guid` is a
process-only column (MITRE defines it only there); `owning_guid` is the one
non-MITRE field we add — the definitive spoke→process link. `native` (JSON)
holds evidence with no CAR home — never faked into a canonical column.

## 5. Artefact coverage (source → CAR objects)

| artefact | map(s) | CAR objects filled |
|---|---|---|
| **Windows event logs** (EvtxECmd *and* Plaso winevtx — same maps) | `evtx_security`, `evtx_security_sessions`, `evtx_process`, `evtx_services`, `evtx_bits`, `evtx_rdp`, `evtx_sysmon` | authentication, user_session, process, service, http (BITS), module, driver, thread, registry, file, flow (Sysmon) |
| **Zeek** | `zeek_conn`, `zeek_http`, `zeek_smtp`, `zeek_files` | flow, http, email, file |
| **Plaso execution** | `plaso_exec_prefetch/winreg/cron` | process |
| **Plaso filesystem + Linux** | `l2t_filestat/mft/usnjrnl/utmp/utmpx/text` | file, user_session |
| **Registry batch + SRUM + Prefetch** (gore / goese / goprefetch output) | `recmd`, `esedump_srum`, `prefetch_dump` | registry, flow, process |
| **Memory** (Anamnesis) | passthrough | all 10 memory objects (finished CAR) |

Windows event-log EventIds covered: 4624/4625/4634/4647/4672/4688 (Security),
7045/4697 (service), BITS 59/60, TerminalServices 21/24/25, Sysmon
1/3/5/6/7/8/11/12/13/23. **The same maps serve both EvtxECmd and log2timeline** —
a Plaso record is adapted to the EvtxECmd shape and run through the identical
maps (verified: Plaso-parsed LoneWolf → byte-identical CAR to the EvtxECmd run,
including definitive Sysmon ProcessGuid links).

Honest non-coverage: `email` has no live source yet (the only smtp capture is
STARTTLS-encrypted); Zeek dns/ssl/x509/dhcp/ntp/snmp/ocsp/weird/pe have no
dedicated CAR object (flow-detail, routed to `[]` explicitly).

## 6. The mapping engine

A map declares, per artefact (and per *variant* where one artefact splits across
objects): the CAR `object`, `action`, `ts`, the identity that becomes `guid`,
`props` (CAR field → source), `keep`/`native_extract` (native evidence + join
keys), and a `host` (the enrich scope). **Markers** do the small transforms and
nest freely: `first`, `const`, `basename`, `ext`, `lower`, `regex1`,
`domain_of`, `epoch_ts`, `map_value`, `concat`, `exe_path`, `hex_int`, `at`
(positional), `payload`/`userdata` (EvtxECmd shapes), `host_label`, `ts_before`
(two timestamps compared as instants — a verdict the evidence proves).

**Extract maximally; never fake.** Map any record that carries a valid CAR
object/action/property; a canonical field with no honest source is left null
(not a near-miss); a record with no valid CAR action stays raw (e.g. 7040 — the
service object has no `modify` action). Companion events are mapped as their own
entries (e.g. 4672 → authentication with `user_role=administrator`); the cascade
sorts out how they relate.

## 7. The enrichment cascade (`enrich.py`)

Runs once over the whole (per-source) store — data enriching itself, Anamnesis
style. All joins are **scoped per evidence host**, never across hosts.

- **Identity.** `guid` is the reuse-proof identity (memory: the `_EPROCESS`
  offset; Sysmon: `ProcessGuid`; event-record events: `<host>-<channel>-<recordid>`;
  disk-image rows: the minted **spindle id** — see §7.1).
- **Owner links, two tiers.** A spoke resolves its owning process: **definitive**
  when it natively carries the owner's guid (Sysmon `ProcessGuid`); else
  **heuristic** by the `(pid, create-time window)` join — the latest process
  created at-or-before the event (a later process can't own an earlier event).
  Marked in `link_confidence`.
- **Parent links.** `ParentProcessGuid` (definitive) → `ppid`-window (heuristic).
- **The LUID cascade.** Authentication ↔ user_session join on `(host, LUID)`;
  definitive except the per-boot well-known LUIDs; a *failed* auth never opens a
  session.
- **Inheritance fills only nulls** — a spoke inherits owner context for fields
  its object has; a natively-extracted value is never overwritten.
- **Fold (dedupe)** on `(host, object, guid, action, target_guid, access_level)`
  — rows that are the same event fold into **one**, additively by default
  (`relationships.yml dedupe.fold`): every property any row supplied, a
  disagreeing value kept in `native.coalesced_conflicts`, the contributors
  counted in `native.contributions` / `native.contributed_by`
  (`{source_artefact, spindle_ref}`); `most_populated` keeps one row instead.
  Identity-less rows never fold.
- **Canonical accounts** — well-known SIDs render the same everywhere, without
  overwriting real evidence (e.g. a machine account).

The full per-object identity/join/inheritance/**limit** rules — and the MITRE
wording that grounds each — are in `CAR-Relations.md`.

### 7.1 Row identity on disk-image sources — the spindle id

A Plaso/l2t record carries no sensor-minted id, so its rows used to have
`guid = None` — and a guid-less row can neither dedupe, relate (a `superset`
edge needs a guid on both ends; `derive` links skip it) nor export to STIX as
anything but a positional observation. Every such row now gets a **spindle
id**, minted exactly the way `stix.py` mints a STIX 2.1 §2.9 id — `ids.py` is
the one shared recipe:

```
guid       = uuid5(SPINDLE_NS, canonical_json({"_obj": <object>, "_v": <version>, <name>: <value>, …}))
SPINDLE_NS = uuid5(CAR_NS, "spindle")
```

The identity **key** is the CAR object, the registry entry's identity-key
**version** (`_v` — bumped whenever what identifies an artefact's row
changes, which re-mints every guid of that entry) and the record's own
stable-identity fields **keyed by name**: the names give domain separation (a
`file_reference` and a `usn` with the same value never collide, nor do two
objects), and values contribute as strings (a parser that emits `843` and one
that emits `"843"` agree; a field may declare `normalize: json` for a
type-faithful rendering — none does in v1). `ids.mint(object, identity,
version)` is the one seam that builds the key and the guid; `ids.guid_of(key)`
re-mints a row's own key. The source, parser and artefact **name are never
hashed** — that is what must stay invariant so two tools parsing the same
image mint the same guid for the same record. The readable key rides in
`native.spindle_key`; `native.spindle_scope` says what the identity *is*
(`intrinsic`: the artefact's own — the same across runs and sources of one
image, and across tools once a second tool's map is shown to render the same
key; `positional`: the per-record fallback, see below); `native.spindle_ref`
says where the record came from, outside the key.

**Which** fields identify each artefact's row is a rule, not code — declared as
data in `byakugan/spindle.yml`, the registry. Per entry: the CAR object;
the **kind** (`record` — a record-numbered / journal key that asserts the
*same record*: `l2t_mft`, `l2t_usnjrnl`, `plaso_fseventsd`; `entity` — a
content-like key that asserts records that *coincide*: every other entry,
including the time-free PE / amcache Link Time ones); the `scope`
(`intrinsic`); the identity-key **version** (hashed as `_v`); what it is
**`validated_against`** (`[plaso]` for every entry today — cross-run *within
the tool*; a tool joins the list only when its map renders a byte-identical
key on at least one real record — the label makes no cross-tool claim the
corpus has not confirmed); what it is **`stable_across`**, in words; the
ordered identity as `name ← source path on the normalized event` (a CAR
field's canonical value, `timestamp`, `owning_pid`, or `native.<key>` — the
path convention `relationships.yml` already uses); and a **golden** sample
(real M57-JO / dualserver values where a real row exists, a labelled
synthetic sample otherwise). A map only names its entry
(`"guid": _common.spindle("l2t_mft")`) and never spells fields, so registry
and maps cannot drift: `spindle.verify_registry()` holds registry ↔ maps ↔
engine in step; `model/spindle/identity.yml` is the resolved snapshot,
`model/spindle/record.yml` the spindle's shape and `model/spindle/golden.yml`
the golden vectors — per entry the key and the guid the engine mints for its
sample (all `python model/generate.py`; `python -m byakugan.spindle
--check` in CI). Each generated source manifest (`sources/<map>.yaml`) states
the identity its guid carries — the registry entries with their kind, scope
and version, or the external form. The registry today:

| map | object | identity (`native.spindle_key`) |
|---|---|---|
| `l2t_mft` | file | `file_reference`, `event_time` |
| `l2t_usnjrnl` | file | `usn`, `file_reference` |
| `l2t_filestat` | file | `file_path`, `event_time` |
| `l2t_lnk` | file | `lnk_file`, `file_path`, `event_time` |
| `l2t_recyclebin` | file | `artefact_file`, `file_path`, `event_time` |
| `plaso_shellitem` | file | `origin`, `file_path`, `event_time` |
| `plaso_fseventsd` | file | `event_identifier`, `file_path` |
| `plaso_pecoff` | file | `file_path`, `sha256` — time-free: every PE stamp is internal to the binary, so one PE's header / table / placeholder rows share the identity |
| `plaso_olecf` | file | `file_path`, `event_time` |
| `plaso_exec_prefetch` | process | `exe`, `prefetch_hash`, `run_time` |
| `plaso_exec_winreg` amcache | process | `image_path`, `recorded_time` (the key-write / MAC stamp — never a run time) |
| `plaso_exec_winreg` amcache Link Time | file | `file_path`, `sha1` — time-free: the compile stamp is not an event |
| `plaso_exec_winreg` userassist | process | `key_path`, `value_name`, `event_time` |
| `plaso_exec_winreg` bam | process | `key_path`, `image_path`, `event_time` |
| `plaso_exec_winreg` appcompatcache | process | `image_path`, `recorded_time` (the cached file's mtime; the per-ControlSet copies collapse) |
| `plaso_exec_cron` | process | `command`, `pid`, `event_time` |
| `plaso_registry` | registry | `hive`, `key_path`, `last_write` |
| `l2t_msiecf` / `l2t_firefox_cache` / `l2t_firefox_places` / `l2t_javaidx` | http | `db_path`, `url`, `visit_time` |
| `l2t_srum` network_usage | flow | `application`, `user_identifier`, `interface_luid`, `recorded_time` |
| `l2t_srum` application_usage | process | `application`, `user_identifier`, `recorded_time` |
| `l2t_utmp` / `l2t_utmpx` | user_session | `pid`, `terminal`, `event_time` |
| `l2t_text` (sshd login) | user_session | `pid`, `user`, `event_time` |

`event_time` (and its per-artefact names `last_write` / `visit_time` /
`run_time` / `recorded_time`) is the row's own CAR timestamp (the `timestamp`
source); `recorded_time` marks a stamp whose meaning is inferred (a shimcache
mtime, an amcache key write — labelled natively by `time_meaning` /
`execution_inferred`), never an asserted run time. A row that asserts no
event at all (a PE's compile stamp, an amcache Link Time) is an **entity**
record: its identity is the artefact's entity key with no time, so rows that
differ only in native stamps share it. Where an entity has several same-action events (a
prefetch's eight last-run times, a key's successive snapshots, an $MFT entry's
$SI and $FN times) the time is part of what identifies the event — so distinct
events never collapse, and true duplicates (the same record parsed twice) do.

**Positional fallback.** The container splitter stamps every wrapped row with
`RecordId` — its physical line in the container, minted from the input like
the EVTX record id (stable across re-splits of the same json_line file, not
across a re-run of the parser). A row whose intrinsic identity is incomplete
(a blank component) falls back to `{"_obj", "SourceImage", "RecordId"}` and is
flagged `native.spindle_scope = "positional"`: deterministic, but valid only
inside this source, so a cross-source pass must skip it. Every minted row —
intrinsic or positional — also carries `native.spindle_ref`
(`{SourceImage, RecordId}`): where the record came from, **outside** the key.

**External forms.** Sysmon (`ProcessGuid`) and event-record
(`<object>-<host>-<channel>-<recordid>`) guids — including the Plaso `winevtx`
route through the evtx maps — the Zeek `uid` / `uid+trans_depth` / `fuid`, the
JLECmd and RECmd field forms and Anamnesis's `proc-<hex>` are left exactly as
they were: a sensor's or tool's own id, never wrapped in uuid5. They are
declared as data too — the registry's `external:` section, each with a kind
and a golden sample — and `verify_registry` holds every map leaf's raw guid
spec to exactly one declared form (and refuses a leaf with none), so no raw
form is undeclared and **no mapped row is guid-less by design**.

**Equality across sources (#41).** The registry's `equality:` block writes the
rule the cross-source pass will implement (#41 PR B, `union_edges`): two rows
of two sources are the same row-identity **only** on exact equality of
`(case, source_host, car_object, guid)`, both rows `intrinsic`, both entries of
kind `record` | `entity`, both keys at the same `_v` (a store pair at mixed
versions is refused, never bridged); a `positional` identity is never equated;
an external form equates by exact value. The boundary is the **case** — the
batch tree (`--case`, default its basename); no header field is added.
`spindle.equatable_across_sources(row)` is the predicate; PR-1 ships the rule
and the predicate only, `crosssource.py` is untouched.

**Change protocol.** An entry's identity fields, names, rendering or golden
sample change only with a `version` bump: edit → bump `version` →
`python model/generate.py` → commit `model/spindle/` (golden.yml included) and
the regenerated `sources/` → rebuild the stores (`--batch --force`; every guid
of that entry re-mints — a remint/audit tool is a follow-up). `spindle --check`
and the generator refuse a golden guid that moved without its version, a
version that moved without its guid, and any move of the recipe vector (that
would move every guid: a new spindle, not a bump). **The P7 rule:** every
timestamp-less leaf (`ts: None` — a PE stamp, an amcache Link Time) MUST name
a time-free `kind: entity` entry; a timed identity on an untimed leaf is
refused, and a Plaso leaf without an entry is refused. The shapes not yet
confirmed against a multi-tool corpus (cross-tool renderings of
`file_reference`, timestamps, `db_path`, `prefetch_hash`; the registry
value-level component) are recorded in `to-be-validated/spindle_identity.yml`;
until that corpus is processed the component is complete *within Plaso*.

## 8. Output contract (per-object JSONL)

`store.export_jsonl()` writes one `car_<object>.jsonl` per populated object (plus
`superset.SupersetStore.export_jsonl()`'s `car_relationships.jsonl` for the
relationship edges); each line is a flat CAR event (`native` kept as a JSON
object). This JSONL is the downstream
ingest contract: a downstream consumer — e.g. DX_DFIR, which ships it to Elastic —
reads the files additive next to the existing raw evidence, so nothing already
built changes.

**Correctness gate.** `python -m byakugan.verify <car-dir>` is the run-through
over a materialised CAR tree: each exercised object populated, values sane
(IPs/ports/SIDs, `car_action` in the model's own vocabulary), every row traceable
to one artefact, relationship edges naming real endpoints. It exits non-zero on a
failed check (2 when no CAR is present). The vocabulary is the engine's own model,
so the object model never leaves the engine — a consumer runs the gate inside the
image rather than reimplementing it: `byakugan verify` (the `verify` sub-tool of
`cli.py`) runs the same run-through over `BYAKUGAN_VERIFY_INPUT_DIR`, prints one
JSON summary line (`failed` = the failed checks, named in `failures`), writes
the report to stderr and to `<BYAKUGAN_VERIFY_OUT_DIR>/verify.txt`, and exits 0
when the gate passed, 1 when it failed or no CAR is present, 2 on a config error.

## 9. What is NOT done yet

**Cross-source final enrichment** — the optional aggregate stage that correlates
memory + disk + network across the per-source stores — is deferred behind a
capability-determination + data-assessment pass (see
[CAR-CrossSource.md](CAR-CrossSource.md)). A **payload-parse cache** is a known
performance item.
