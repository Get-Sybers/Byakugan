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
- **`owning_guid_native`** is set to **`None` on every row, unconditionally**
  — see "The second enrich pass" below for why this specific field, of all
  of them, is deliberately never populated from Anamnesis's data.
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
  itself, or from a different source sharing one car.db — never happens
  today, since each `car.db` is one Anamnesis image, but the mechanism does
  not care) folds exactly like any other duplicate would.
- **Null-only inheritance** (`relationships.yml`'s `inheritance.from_owning_process`
  — exe, image_path, command_line, user, sid, fqdn, hostname, ppid) fills
  only fields the receiving CAR object has **and** that are still null on
  that row after translation. Anamnesis already fills most of this itself
  (its own enrichment inherits the same fields — `internal/enrich/enrich.go`'s
  `inherit`), so in practice this pass has little left to do; it never
  overwrites a value either side already supplied.
- **Owner/parent identity — re-derived, not inherited from Anamnesis's
  label.** `owning_guid_native` is *always* `None` for a translated Anamnesis
  row (see above), so `enrich.py`'s tier-1 check (a definitively-carried
  native guid on the spoke's own record) never fires for these rows — even
  though Anamnesis's own resolution may itself have been tier-1 (a direct
  `_EPROCESS`-offset match, its `link_confidence = "definitive"`). The
  cascade instead always falls to **its own tier 2**: the (`owning_pid`,
  create-time-window) match against the OTHER translated process rows in
  this same `car.db` (`enrich._resolve_owner`/`_match`, host-scoped). Two
  outcomes, both observed in `tests/test_anamnesis_interchange.py`:
  - a candidate is found (the common case for a single-snapshot image: one
    live process per pid) — it is, in practice, the *same* process Anamnesis
    already named, so `owning_guid`/`parent_guid` are **re-derived to the
    identical value** — the link's target survives unchanged — but
    `link_confidence` is **re-stamped `"heuristic"`** (this pass's own
    pid-window tier), even when Anamnesis's original confidence was
    `"definitive"`. The identity is preserved; the confidence label is not.
  - no candidate is found (e.g. the owning process never became its own row
    in this `car.db`, or a host mismatch) — the `if owner is not None:`
    guard around both assignments never runs, so `owning_guid` /
    `parent_guid` / `link_confidence` are left **completely untouched** at
    whatever Anamnesis originally wrote.

  A separate, **opt-in** mechanism covers the case NEITHER tier resolves
  anything: `--derive`'s reconstruction stage (`relationships.yml`'s
  `reconstruct: owning_process_memory`, `identity: offset`, `method:
  memory_offset`) can mint an `inferred_node` from `owning_offset` alone. It
  never runs as part of the base `enrich()` pass this section describes.

  Either way: **a link Anamnesis minted is never overwritten with a
  DIFFERENT value.** It is either confirmed (re-derived to the same guid,
  confidence relabelled) or left alone. `edges_from_events`
  (`byakugan/superset.py`) reads `owning_guid`/`parent_guid` *after* this
  pass to materialise the relationship-timeline edges
  (`car_relationships.jsonl`), so those edges reference the surviving
  (Anamnesis-identical) guids either way.
- **The B1/B3 native-id lifts** (`volume_guid`, `mac_address`,
  `device_serial` — pulled out of `_native` into first-class header columns)
  run over an Anamnesis row's `_native` blob exactly like any other row's;
  whether they fire depends only on whether that blob happens to carry a
  recognisable pattern, same as any source.
- **`owning_pid` / `owning_offset` / `parent_pid` / `owning_guid_native`
  never reach car.db or the exported JSONL.** They are transient enrichment
  inputs only (`byakugan/store.py`'s own header comment says so explicitly);
  once `enrich()` has used them, only `owning_guid`, `parent_guid` (a
  `process` object field), `link_confidence`, `source_artefact`,
  `source_host`, `native`, and the object's own CAR fields persist.

## Drift guards

Two tests hold this contract to the evidence, not to memory of it:

- `tests/test_anamnesis_interchange.py::test_car_model_matches_the_anamnesis_fixture_exactly`
  — `byakugan.carmodel.load()` (reconstructed **live** from the pinned
  `third_party/car` submodule) against
  [`tests/fixtures/anamnesis_car_data_model.json`](../tests/fixtures/anamnesis_car_data_model.json)
  (a committed, byte-for-byte copy of Anamnesis's own embedded
  `internal/carmodel/car_data_model.json`, pinned at commit `afb06ae`): the
  object set and every object's field/action set must match **exactly**, in
  **both** directions. A car-submodule pin bump on either repo fails this
  test until the fixture is consciously refreshed (`cp
  <anamnesis>/internal/carmodel/car_data_model.json
  tests/fixtures/anamnesis_car_data_model.json`) — the assertion messages
  say so.
- `tests/test_anamnesis_interchange.py::test_load_anamnesis_car_translation_rules`
  and `::test_anamnesis_passthrough_survives_the_full_pipeline` — a fixture
  `car.db` built with Anamnesis's **exact** schema (derived from the pinned
  fixture model + the header quoted above, never from Byakugan's own
  `store.py`) exercises every translation rule above, then the full
  `pipeline.process_file` passthrough, asserting the minted
  guids/`owning_guid`/`parent_guid` survive into `car_<object>.jsonl` and
  that `car_relationships.jsonl`'s edges reference them.

**The rule: a change to either side's schema is a change to this contract.**
A Byakugan change to `readers.py`'s translation, to the CAR header either
store uses, or to `enrich.py`'s owner/parent cascade; or an Anamnesis change
to `store.go`'s header, `ProcGUID`, or its own enrichment's confidence
tiering — each is a change here, and the two tests above are how it gets
caught instead of silently drifting. Update this document in the same
change.
