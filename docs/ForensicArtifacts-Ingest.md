# Ingest pipeline: ForensicArtifacts

**Code:** `model/ingest_forensicartifacts.py` ·
**Source:** `model/sources/forensicartifacts/` (submodule) ·
**Output:** `model/sources/forensicartifacts.index.json` (committed, canonical)

## What it ingests

The community [ForensicArtifacts/artifacts](https://github.com/ForensicArtifacts/artifacts)
catalogue: 732 declarative artifact definitions (the as-data format consumed
by GRR, Velociraptor and Plaso) in `artifacts/data/*.yaml`. It is the prior
art for declaring forensic artefacts as data, and the seed catalogue for the
**Artefact Class** layer of the schema mission (#123).

The asymmetry that scopes this pipeline: ForensicArtifacts declares where
evidence **lives** (collection paths, registry keys, WMI queries); the
Artefact Class layer declares what evidence **is and yields**
(parser-independent `dfir_fields`). The catalogue therefore seeds names,
OS scoping and grouping — never field semantics.

## The refresh-time pattern

Per [docs/design/schema-layers.md](design/schema-layers.md), the
submodule is a refresh-time input: engines and tests never read it, and CI
never checks it out (`GIT_SUBMODULE_STRATEGY` stays unset). Only `ingest.py`
consults it, and the committed index is canonical.

```
bump pin        git -C model/sources/forensicartifacts fetch && git -C model/sources/forensicartifacts checkout <new>
regenerate      python model/ingest_forensicartifacts.py
review          the index.json diff is the reviewable surface of the upstream change
gate            python model/ingest_forensicartifacts.py --check
```

`--check` regenerates in memory and byte-compares against the committed
index. The index embeds the submodule commit under `generated_from`, so a
pin bump without regeneration fails the check — the staleness gate the
design doc requires. Because it needs the submodule, `--check` stays **out
of the no-submodule CI tier**, alongside `gen_sources --check` and
`spindle --check`.

## Index contract

Top level: `generated_from {repo, commit, tool}`, `artifact_count`,
`artifacts[]` sorted by name. Per artifact:

| field | meaning |
|---|---|
| `name` | upstream definition name (CamelCase grammar) |
| `file` | source file within `artifacts/data/` |
| `summary` | first line of the upstream `doc` |
| `source_types` | sorted unique source types (`FILE`, `REGISTRY_KEY`, `REGISTRY_VALUE`, `ARTIFACT_GROUP`, `PATH`, `WMI`, `COMMAND`) |
| `supported_os` | top-level scope, else the union of per-source scopes (`Windows`, `Linux`, `Darwin`, `ESXi`) |
| `aliases` | historical names, when upstream declares them (omitted otherwise) |
| `members` | expanded `ARTIFACT_GROUP` member names (omitted for leaf artifacts) |

Rendering is deterministic (sorted keys, indent 1, trailing newline) so the
byte-exact check and review diffs stay meaningful.

## Downstream

The crosswalk of this index onto gomount's materialise sets and byakugan's
lane manifests (`byakugan.sources_model`) selects which definitions become Artefact Class seed
instances under `model/schema/`. Group composition (`triage.yaml`'s
`Triage*` surfaces, `WindowsPersistenceRegistryKeys`, …) is the upstream
analogue of gomount's evidence sets and feeds the same seeding decision.
