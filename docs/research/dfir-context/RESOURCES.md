# Ingested resources — credits

The once-only ingests behind the DFIR-context evidence matrix
(this directory): each
source was read at the pinned commit, what fitted the model was extracted
with per-row citations, and what did not fit was recorded, not added. This
file is the credit registry; recurring sources live as submodules under
`model/sources/` instead (currently: ForensicArtifacts —
[docs/ForensicArtifacts-Ingest.md](../../ForensicArtifacts-Ingest.md)).

| source | pin | license | credit | taken | verdict |
|---|---|---|---|---|---|
| [nasbench/EVTX-ETW-Resources](https://github.com/nasbench/EVTX-ETW-Resources) | `a3fa2bd` | MIT | Nasreddine Bencherchali (nasbench) | 28 evtx evidences rows from the per-provider event catalogs; the account-management gap register | once-only; if recurring sync is ever wanted: sparse-checkout of `ETWProvidersCSVs/` only (never the 17GB tree) |
| [fsfang/DFIR-Toolkit](https://github.com/fsfang/DFIR-Toolkit) | `667e628` | none declared — cited, not copied | FS FANG | 20 rows across 8 families from its EvtxECmd curations and collection glosses; one source defect recorded (System-channel ids aimed at Security.evtx — those bindings never seed) | once-only |
| [microsoft/Microsoft-365-Defender-Hunting-Queries](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries) | `efa17a6` | MIT | Microsoft Corporation + named community contributors | 15 rows across 6 families, each recording the sensor→disk-artefact tier degradation | once-only (repo deprecated 2022; a recurring feed would target Azure-Sentinel's hunting-queries tree) |
| [osherjacobs/LabWork_Findings](https://github.com/osherjacobs/LabWork_Findings) | `27c61d6` | none declared — cited, not copied; factual event-id semantics only | O.J. (osherjacobs) | 13 evtx rows incl. Kerberos tiers and lsass-access shapes; the AD-object/group/scheduled-task gap evidence | **recurring** — active 2026 research; re-ingest on new pins |
| [ViperHawk/MITRE_Alerts](https://github.com/ViperHawk/MITRE_Alerts) | `4595c39` | MIT asserted in README; no LICENSE file committed | Ross Durrer (ViperHawk) | 11 evtx rows, all corroborated against EVTX-ETW-Resources before seeding | once-only |
| [joeavanzato/RetrievIR](https://github.com/joeavanzato/RetrievIR) | `a6a9c14` | MIT | Joe Avanzato | 5 rows (run-keys/scheduled-tasks/registry-hives); its references point at EricZimmerman/KapeFiles as the underlying authority — a future recurring-source candidate | once-only |
| [swisscom/ArtifactCollectionMatrix](https://github.com/swisscom/ArtifactCollectionMatrix) | `32ffc6f` | CC BY-SA 4.0 | Swisscom CSIRT | nothing — tool-comparison content, orthogonal to the evidence matrix (recorded honestly as an empty extraction) | once-only |

Matching and validation: the 99 extracted rows were individually matched by
mechanism into the 64 canonical rows of
[matched-evidences.yaml](matched-evidences.yaml)
(23 multi-source-corroborated; every source row cited; tier disagreements
reconciled conservatively with the disagreement noted in-row; all rows
validated against the CAR object/action vocabulary).
