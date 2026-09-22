# The Anamnesis interchange

The contract by which [Anamnesis](https://github.com/Get-Sybers/Anamnesis)'s
memory `car.db` becomes input to Byakugan — consumption mode 2 of the three
the top-level [README.md](../README.md) describes ("fed by Anamnesis output
alone"), and the same route memory takes when Anamnesis and Byakugan are both
embedded in DX_DFIR. Anamnesis already emits **finished** MITRE CAR (its own
memory-lane enrichment resolves owner/parent links before anything reaches
disk); Byakugan's job is translation and re-integration, never re-deriving
memory forensics from scratch.

## Discovery

A materialised Anamnesis output tree contributes one source per image:
`memory/<image>/car.db`. `byakugan --batch <processed_dir>` discovers every
such file exactly like it discovers any other framework layout (see the
top-level README's "Quickstart" — `--batch discovers ... memory/<image>/car.db`);
`byakugan.pipeline.process_file` also accepts one `car.db` path directly.

## The producer schema

Anamnesis's store (`internal/store/store.go`, a faithful Go port of the
original Python `store.py` this repo's own `byakugan/store.py` also
descends from) is **one SQLite table per CAR object** (all 13 — populated or
not), each named **exactly** the CAR object name (`process`, `module`,
`file`, ...). Every table carries the same 12-column header ahead of that
object's own CAR properties (`internal/store/store.go`'s `header` var,
quoted verbatim):

```
timestamp · car_action · guid · owning_pid · owning_offset · owning_guid ·
parent_pid · parent_guid · link_confidence · source_plugin · source_image · native
```

(plus a `event_id INTEGER PRIMARY KEY` SQLite autoincrement column ahead of
even that, store.go's `cols()` — never a CAR value, Anamnesis's own row
identity.) A column that collides with an object's own CAR field name
(`process.guid`, `process.parent_guid`) is not duplicated — `cols()` is the
header followed by the object's fields **minus** whichever of them the
header already supplies.

`native` is the source-evidence bag Byakugan's own `native` column is
modelled on: JSON text, kept fields with no CAR home.

### `image_context` — skipped

One side table, `image_context (source_image TEXT, source_plugin TEXT,
record TEXT)`, holds the raw output of a plugin with **no CAR map** — nothing
to translate. `readers.load_anamnesis_car` explicitly excludes it (`SELECT
name FROM sqlite_master ... WHERE type='table'` filtered to exclude
`"image_context"`); its rows never reach Byakugan.

## The translation — `readers.load_anamnesis_car`

`byakugan/readers.py`'s `load_anamnesis_car(car_db, image_name=None)` reads
every other table and translates each row 1:1 into this repo's own event
shape (no re-mapping, no re-deriving — read the function; this is exactly
what it does, not what seems sensible):

- **`car_object`** = the table name; **`car_action`** = the `car_action`
  column, verbatim.
- **`source_artefact`** = `"memory/" + source_plugin` (`"unknown"` if the
  column is empty) — the artefact-not-processor naming
  [Architecture.md](Architecture.md) documents ("memory (Anamnesis `car.db`)
  | passthrough").
- **`source_host`** = the row's own `hostname` **property** if the object
  carries one and it is non-empty, **else** the image name — the `car.db`'s
  parent directory basename (`memory/<image>/car.db` → `<image>`), or the
  caller-supplied `image_name` when `load_anamnesis_car` is called directly
  with one. Most objects carry `hostname` (filled by Anamnesis's own
  enrichment from `windows.info`), so the fallback is mainly for the rare
  object/row that doesn't.
- **`native`** — the `native` column's JSON text is decoded into the
  in-memory `_native` dict (the same representation every other source
  builds); the raw `native` **column name never appears** on the translated
  event, only `_native`.
- **`event_id`** — Anamnesis's own SQLite autoincrement row id — is
  **dropped**. It is never a CAR value and carries no meaning outside
  Anamnesis's own store.
- **`owning_guid_native`** is set from the row's own `owning_guid` ONLY when
  `link_confidence == "definitive"` — Anamnesis's own strongest tier, a
  resolved `_EPROCESS` pointer, the memory-lane equivalent of Sysmon's native
  `ProcessGuid` — and `None` otherwise (including every `heuristic`-confidence
  Anamnesis link). Likewise, a `process` row with a definitive `parent_guid`
  gets it mirrored into `_native["ParentProcessGuid"]`. See "The second enrich
  pass" below for why: this is what makes a DEFINITIVE Anamnesis link survive
  Byakugan's own enrichment pass instead of being silently re-labelled
  `heuristic`.
- **`owning_pid`, `owning_offset`, `owning_guid`, `parent_pid`, `parent_guid`,
  `link_confidence`** pass through **verbatim** — whatever Anamnesis's own
  memory-lane enrichment already resolved (see below).
- **Everything else** — every column that is neither in the header nor
  `event_id` — passes through unchanged as a CAR **property** of the event
  (`pid`, `exe`, `image_path`, `module_name`, ... whatever that object's CAR
  fields are).
- **`user`** gets one additional fold: Anamnesis renders well-known
  principals as friendly names (`Local System`, `Local Service` /
  `Network Service` — and, specifically in its registry plugin, the
  no-space `LocalService`/`NetworkService` forms) — `readers.py`
  passes any non-null `user` through `normalize._canon_user`, the SAME
  canonicalisation every other source's `user`/`sid` gets, so `SYSTEM` /
  `LOCAL SERVICE` / `NETWORK SERVICE` read as one token across evtx, disk and
  memory CAR alike. A blank user stays blank; a real account name is
  untouched.

### The guid form

A CAR `process` event's `guid` is minted by Anamnesis as `"proc-" +
hex(_EPROCESS virtual address)` — `internal/normalize/normalize.go`'s
`ProcGUID`: *"synthesizes the CAR process guid from an `_EPROCESS` virtual
address — `proc-<hex>`, the same convention the pipeline keys on."* Lower-case
hex, no `0x` prefix, no padding (Go `strconv.FormatUint(v, 16)`). A spoke's
`owning_guid` — once Anamnesis's own enrichment has resolved it — is that
same string for whichever process it names as owner; nothing about the
*form* changes when Byakugan reads it back.

## The second enrich pass

`byakugan/pipeline.py`'s `process_file` routes a `car.db`-named input
straight to `load_anamnesis_car` (the passthrough), then runs the translated
events through **exactly the same** `enrich.enrich()` cascade every other
source's events go through — fold, null-only inheritance, owner/parent
resolution, relationship-edge materialisation — never a special case. This
is deliberate (the rationale, stated in
[Architecture.md](Architecture.md)/[CAR-Relations.md](CAR-Relations.md)):
**memory rows join the relationship timeline and `logs-car.*` through the
same one pipeline** as every disk/network/event-log row, so a case that
spans memory and disk evidence gets one coherent, cross-artefact-comparable
enrichment pass rather than two different confidence/inheritance
conventions bolted together downstream.

What actually happens, precisely (verified by
`tests/test_anamnesis_interchange.py`, not assumed):

- **Fold/dedupe** (`relationships.yml`'s `dedupe.key` — host, object, guid,
  action, target_guid, access_level) applies identically: an Anamnesis row
  that happens to share a same-event key with another row (from Anamnesis
  itself, or from a different source sharing one translation batch — never
  happens today, since each Anamnesis `car.db` is one image, but the
  mechanism does not care) folds exactly like any other duplicate would.
- **Null-only inheritance** (`relationships.yml`'s `inheritance.from_owning_process`
  — exe, image_path, command_line, user, sid, fqdn, hostname, ppid) fills
  only fields the receiving CAR object has **and** that are still null on
  that row after translation. Anamnesis already fills most of this itself
  (its own enrichment inherits the same fields — `internal/enrich/enrich.go`'s
  `inherit`), so in practice this pass has little left to do; it never
  overwrites a value either side already supplied.
- **Owner/parent identity — CONFIRMED at Anamnesis's own tier, not
  re-derived down to Byakugan's weaker one (the definitive-confidence fix).**
  `owning_guid_native` (spoke owner) and `_native["ParentProcessGuid"]`
  (process parent) are populated from the row's own Anamnesis-resolved link
  **only when that link was `"definitive"`** (see "The producer schema" /
  "The translation" above) — Anamnesis's own strongest tier, a resolved
  `_EPROCESS` pointer, the memory-lane equivalent of a natively-carried
  Sysmon `ProcessGuid`/`ParentProcessGuid`. `enrich.py`'s tier-1 check (a
  definitively-carried native guid on the spoke's own record, or on the
  process's own record for a parent link) then finds it — via
  `enrich._resolve_owner`/the process-create parent block, exactly as it
  would a Sysmon row — and stamps `link_confidence = "definitive"` again,
  never falling to **its own tier 2** (the `(owning_pid`/`parent_pid`,
  create-time-window) heuristic match) for these rows. A NON-definitive
  Anamnesis link (`link_confidence == "heuristic"`, or none at all) is never
  surfaced this way — `owning_guid_native`/`_native["ParentProcessGuid"]`
  stay unset, and the row re-derives through Byakugan's own tier 2 exactly
  as before the fix; the fix only ever strengthens what Anamnesis itself
  already asserted at Sysmon-strength, never weakens tier 2 for anything
  else. Two outcomes, both observed in `tests/test_anamnesis_interchange.py`:
  - the process Anamnesis named as owner/parent has its own row in this same
    translation batch (the common case) — tier 1 finds it, so
    `owning_guid`/`parent_guid` **confirm the identical value** Anamnesis
    already named AND `link_confidence` **stays `"definitive"`** — no
    longer re-stamped `"heuristic"`. `edges_from_events`
    (`byakugan/superset.py`) then also resolves the edge's `method` as
    `native_guid` (`superset._method`), not `pid_window`.
  - it does not (e.g. a host mismatch, or the named process was never its
    own row) — tier 1 finds nothing, so the row falls through to tier 2
    exactly as an unfixed (non-definitive) row would: a candidate found
    there re-derives the guid with `link_confidence` re-stamped
    `"heuristic"`; no candidate leaves `owning_guid`/`parent_guid`/
    `link_confidence` completely untouched at whatever Anamnesis originally
    wrote.

  A separate, **opt-in** mechanism covers the case NEITHER tier resolves
  anything: `--derive`'s reconstruction stage (`relationships.yml`'s
  `reconstruct: owning_process_memory`, `identity: offset`, `method:
  memory_offset`) can mint an `inferred_node` from `owning_offset` alone. It
  never runs as part of the base `enrich()` pass this section describes.

  Either way: **a link Anamnesis minted is never overwritten with a
  DIFFERENT value.** It is either confirmed (tier 1, identical guid AND
  confidence — the fixed path — or tier 2, identical guid, relabelled
  confidence) or left alone. `edges_from_events` (`byakugan/superset.py`)
  reads `owning_guid`/`parent_guid` *after* this pass to materialise the
  relationship-timeline edges (`car_relationships.jsonl`), so those edges
  reference the surviving (Anamnesis-identical) guids either way, with
  whichever confidence/method tier actually resolved them.
- **The B1/B3 native-id lifts** (`volume_guid`, `mac_address`,
  `device_serial` — pulled out of `_native` into first-class header columns)
  run over an Anamnesis row's `_native` blob exactly like any other row's;
  whether they fire depends only on whether that blob happens to carry a
  recognisable pattern, same as any source.
- **`owning_pid` / `owning_offset` / `parent_pid` / `owning_guid_native`
  never reach the exported JSONL.** They are transient enrichment inputs
  only (`byakugan/store.py`'s own header comment says so explicitly); once
  `enrich()` has used them, only `owning_guid`, `parent_guid` (a `process`
  object field), `link_confidence`, `source_artefact`, `source_host`,
  `native`, and the object's own CAR fields persist. The
  `_native["ParentProcessGuid"]` this fix injects on a definitively-parented
  process row is likewise consumed by enrich's parent-resolution block and
  rides through into the exported `native` object like any other kept
  native field — it is not stripped afterward.

## Drift guards

Two tests hold this contract to the evidence, not to memory of it:

- `tests/test_anamnesis_interchange.py::test_car_model_matches_the_anamnesis_fixture_exactly`
  — **Byakugan owns the CAR model** (`model/car/objects` — the CAR + ATT&CK
  superset; `byakugan.carmodel.load()` reconstructs it live from the pinned
  submodules). Anamnesis is a producer that **conforms** to it, embedding a
  copy in `internal/carmodel/car_data_model.json`. This test holds the
  producer's copy to Byakugan's model:
  [`tests/fixtures/anamnesis_car_data_model.json`](../tests/fixtures/anamnesis_car_data_model.json)
  (a committed copy of the producer's embedded model) must match
  `byakugan.carmodel.load()` **exactly**, in **both** directions — object set
  and every object's field/action set. If they diverge, Anamnesis has drifted
  from the model it must conform to; refresh the fixture only once Anamnesis is
  re-aligned (`cp <anamnesis>/internal/carmodel/car_data_model.json
  tests/fixtures/anamnesis_car_data_model.json`) — the assertion messages say
  so.
- `tests/test_anamnesis_interchange.py::test_load_anamnesis_car_translation_rules`
  and `::test_anamnesis_passthrough_survives_the_full_pipeline` — a fixture
  `car.db` built with Anamnesis's **exact** schema (derived from the pinned
  fixture model + the header quoted above, never from Byakugan's own
  `store.py`) exercises every translation rule above, then the full
  `pipeline.process_file` passthrough, asserting the minted
  guids/`owning_guid`/`parent_guid` survive into `car_<object>.jsonl` and
  that `car_relationships.jsonl`'s edges reference them.

**The rule: Byakugan owns the CAR model; a change to it, or to how either
side reads/writes it, is a change to this contract.**
A Byakugan change to `readers.py`'s translation, to the CAR header either
store uses, or to `enrich.py`'s owner/parent cascade; or an Anamnesis change
to `store.go`'s header, `ProcGUID`, or its own enrichment's confidence
tiering — each is a change here, and the two tests above are how it gets
caught instead of silently drifting. Update this document in the same
change.
