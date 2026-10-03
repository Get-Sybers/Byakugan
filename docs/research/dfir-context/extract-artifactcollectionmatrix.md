# Extract: swisscom/ArtifactCollectionMatrix

## What it is

A single-README comparison matrix of forensic **live-collection tools**, not of artifacts: "Evaluation and comparison of different forensic artifact collection tools, also known as forensic live collection" (README.md:3-4). Rows are tools (KAPE, DFIR ORC, CyLR, UAC, artifactcollector, ...) and columns are eleven procurement/usability requirements — "independence of admin rights", "flexible collection of artifacts and system configuration", "free and open source", "one-shot binary", "active development", "easy to use output format" (README.md:23) — scored with a sunny/partly-sunny/cloud emoji legend (README.md:6-9). It carries three platform sections, Windows (README.md:19-48), Linux (README.md:50-72), and a MacOS tool list without a rated matrix (README.md:74-90), plus link lists of offline/online collectors (README.md:37-48, 68-72). The repository contains only README.md and LICENSE; no artefact definitions, no per-artefact structure, timestamps, or evidence semantics anywhere. Where it touches artefact scope at all, it does so by pointing at the ForensicArtifacts repository as the tools' collection catalogue (README.md:33, 56, 60) — the source byakugan already ingests.

## Attribution

- **Name:** Forensic Artifact Live Collection Tool Matrix (README.md:1)
- **URL:** https://github.com/swisscom/ArtifactCollectionMatrix
- **Pinned commit:** `32ffc6fb28bac04a8dc72fedfc47bdcc6c265346` (2024-11-09, "Updating Windows matrix for several tools"; sole commit visible in the shallow clone)
- **License:** Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0) — LICENSE:1 reads "Creative Commons Attribution-ShareAlike 4.0 International Public License"; README.md:101-103 confirms "The work by Swisscom CSIRT is licensed under a Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0) License".
- **Authors/maintainers:** Swisscom CSIRT, as the repo states it (README.md:101; initial announcements via @swisscom_csirt, README.md:21, 52). Community contributions invited by issue/PR (README.md:92-95).

## Evidences rows

```yaml
# No rows extracted. The strict fit test — bind a byakugan artefact family
# (docs/research/forensicartifacts-crosswalk.md seed table) to a legal
# (CAR object, action) pair with evidence/time qualities — is failed by
# every line of this resource: its unit of description is the collection
# TOOL and its procurement/usability properties, never an artefact, an
# object, an action, or a timestamp semantic.
```

## Noted, not added

- **Windows tool requirement matrix (README.md:23-33):** rates KAPE/Redline/IRTriage/IREC/Invoke-LiveResponse/DFIR ORC/CyLR/FastIR/artifactcollector on admin-rights independence, FOSS status, extensibility, output format — tool-selection criteria; names no artefact family and no (object, action) pair.
- **Linux tool requirement matrix (README.md:54-64):** same shape for FastIR/LRC/ir-rescue/CyLR/artifactcollector/DFIR_Linux_Collector/UAC/Fennec/AchoirX; collection tooling is gomount's layer, not the evidences schema's.
- **MacOS tool list (README.md:76-90):** annotated link list (mac_apt, macosac, AutoMacTC, OSXCollector, ...) — inventory of parsers/collectors, no evidence semantics.
- **Offline/online collection split (README.md:37-48, 68-72):** collection geography/transport (Velociraptor, GRR, F-Response) — deployment concern, outside the schema.
- **ForensicArtifacts repository pointers (README.md:33, 56, 60):** cite the artefact catalogue byakugan already ingests via model/sources/forensicartifacts; nothing new to carry.
- **Emoji rating legend and weighting note (README.md:6-11):** methodology of the matrix itself.
- **Memory-dump asides (AVML, README.md:58, 62):** memory acquisition tooling — no artefact family in the seed table carries it as an (object, action) evidence row.

## Pipeline verdict

**Once-only — and even that yields zero evidences rows; keep it, at most, as tool-selection context.** Rationale: (1) content class — the resource describes collection tools' operational properties, an axis orthogonal to the evidences matrix; a recurring ingest could never start producing rows without the repo changing its nature. (2) Cadence — the repository is a single README whose latest commit is 2024-11-09 ("Updating Windows matrix for several tools"), roughly two years stale at ingest time (2026-09-30), with a history of sporadic community-PR updates; nothing like the continuous, structured churn that justifies the model/sources/forensicartifacts pipeline. If byakugan ever grows a collector-capability layer (gomount tool selection), a manual re-read of this README at that time beats any pipeline.
