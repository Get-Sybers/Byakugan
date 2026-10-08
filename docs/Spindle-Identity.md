# Spindle — the row-identity registry

The engine mints a disk-image row's guid from the **row-identity registry**
(`go/internal/spindle`, via `go/internal/ids` — the recipe `byakugan/ids.py`
shares). Like `relationships.yml`, the registry is **data**: *which* fields
identify a row is a rule declared there; the engine only implements the
mechanics. The rules are authored with the maps, in Go — the `spindle` and
`golden` sections of `go/internal/authoring/ir_sections.go`, serialised into
`go/internal/ir/ir.json` — and `byakugan/spindle.yml` carries the notes the
engine does not need: what each key holds across and what it was validated
against, the scope/kind vocabulary, the cross-source equality rule, and the
external forms the Anamnesis passthrough brings in. `byakugan.spindle` reads
the two halves as one registry. A map references an entry by name
(`Guid: GuidSpindle("<name>")` in `go/internal/authoring/maps_*.go`) and never
spells identity fields itself, so the registry and the maps cannot drift
(`byakugan.spindle.verify_registry` — `tests/test_spindle_model.py` and
`python -m byakugan.spindle --check`, which also re-mints every golden vector
the IR pins). The resolved, materialized snapshot is
`model/spindle/identity.yml`; the shape of a spindle row is
`model/spindle/record.yml` (both `python model/generate.py`).

## The recipe

`byakugan/ids.py` — the same minting `stix.py` uses for STIX 2.1 §2.9 ids:

```
guid       = uuid5(SPINDLE_NS, canonical_json({"_obj": <car_object>, "_v": <version>,
                                               <name>: <value>, ...}))
SPINDLE_NS = uuid5(CAR_NS, "spindle")
```

The identity key is the CAR object, the entry's identity-key **version**
and the record's own stable-identity fields keyed **by name**: the names
give domain separation (a `file_reference` and a `usn` with the same value
never collide, nor do two objects); the version re-mints every guid of an
entry when what identifies its rows changes; values contribute in their
string rendering. The source, parser and artefact name are **never** in
the key — that is what must stay invariant so two tools parsing the same
image mint the same guid for the same record. The identity names (+
version) are therefore the cross-tool contract: a second tool's map over
the same artefact reuses the entry. What a real multi-tool corpus must
still confirm is `docs/to-be-validated/spindle_identity.yml`.

## Identity value sources

Sources are paths on the **normalized** event: a CAR field of the object
(its canonical value — the prefix-stripped path, the cleaned URL), the
row's `timestamp`, the `owning_pid` enrich input, or `native.<key>` (a
kept/extracted native) — the same path convention `relationships.yml`
`derived` uses. A field is `name: <source>` or
`name: {source: <source>, normalize: json}`. An entry is named by its map
key, or `<map>/<variant>` where one map's variants are different artefacts.

Per entry: `kind` (`record` | `entity`), `scope` (intrinsic; the positional
fallback is the engine's), `version`, `validated_against` (the tools whose
maps were shown to render a byte-identical key on a real record —
`[plaso]` until a second tool's map exists: cross-run within the tool is
what is validated today), `stable_across` (in words), the ordered
`identity`, and the `golden` sample.

The event time is part of the identity wherever one entity has several
same-action events (a prefetch's eight last-run times, a key's successive
snapshots, an `$MFT` entry's `$SI` and `$FN` times): distinct events never
collapse, true duplicates (the same record parsed twice) do. A row that
asserts **no** event (`ts` None — a PE's compile stamp, an amcache Link
Time) is an *entity* record: the artefact's entity key with no time, so
rows differing only in native stamps share it (`kind: entity`).

## Golden vectors

Every entry pins a golden vector in the IR's `golden` section (the identity
values as they stand on the normalized event — real M57-JO / dualserver
values where a real row exists, `source: real`; otherwise a labelled
synthetic sample, `source: synthetic` — with the key and the guid the recipe
mints for them; each sample's provenance is the comment above it in
`ir_sections.go`). Pins, not derivations: the Go tests replay them and
`python -m byakugan.spindle --check` re-mints them through `byakugan.ids`,
so a stale pin fails on both sides. `model/spindle/golden.yml` is the
**generated** vector table: per entry the rendered key and the guid, the
positional vector, and the recipe vector (`canonical_json` + the
namespaces).

## Change protocol

An entry's identity fields, rendering, names or golden sample change
**only** with a `version` bump: edit the entry in `ir_sections.go`, bump
its version, re-pin its golden vector there (`spindle --check` prints the
guid the recipe now yields), `make -C go gen-ir`, regenerate
`model/spindle/` (`python model/generate.py`), commit the snapshot
(`golden.yml` included); every guid of that entry re-mints, so existing
stores are rebuilt (`--batch --force`).
`python -m byakugan.spindle --check` (and the generator itself) refuse an
entry whose golden guid moved without a version bump — or whose version
moved without the guid — and a change of the recipe vector, which would
move every guid at once.
