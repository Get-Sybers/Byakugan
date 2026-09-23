# Windows GUID sources — the enrichment table & structural dissection

**Status:** research (nothing here is implemented; one correctness finding, F1
below, is actionable now).
**Ground truth:** Byakugan @ `c9c6104`, GoDFIR-toolz @ `ee688cf`;
[davehull/Resolve-WindowsGUID.ps1](https://gist.github.com/davehull/b6c119e3afd63053bb92)
@ `01768fb`;
[stevemk14ebr guid list](https://gist.github.com/stevemk14ebr/af8053c506ef895cd520f8017a81f913)
@ `98944bc`;
[Elmue/WindowsRT-GUID-Analyzer](https://github.com/Elmue/WindowsRT-GUID-Analyzer)
@ `7bf7646`;
[MicrosoftDocs/win32](https://github.com/MicrosoftDocs/win32/tree/docs/desktop-src)
branch `docs` and the
[Project Mu GuidCheck plugin](https://github.com/microsoft/mu_basecore/tree/HEAD/.pytool/Plugin/GuidCheck)
readme, both read 2026-09-23. The v1-timestamp decodes below were run, not
recalled.

The question this answers: how can these sources serve Byakugan — as
enrichment, and as raw material for digesting/pulling apart GUIDs for
transform/inference?

## TL;DR

- **Every source lands in one of two workstreams**, and both bolt onto
  machinery that already exists. **Workstream A** is a tiered *well-known-GUID
  table* (data, not code) serving double duty: enrichment (GUID → name /
  default path / kind) and a **noise gate** for the miners in
  `byakugan/native_ids.py`. **Workstream B** generalises the v1-node→MAC
  decode we already do into a full GUID *dissector* (variant → version →
  timestamp / clock-seq / node) feeding new derive and cross-source classes.
- **The gate is urgent — F1 is a live bug.** `mac_from_v1_guid()` extracts
  vendor MACs out of well-known COM CLSIDs (they are v1 GUIDs with real
  1990s NIC nodes), `enrich` lifts them into `mac_address`, and `crosssource`
  joins unrelated sources on them at the `definitive_native_id` tier — the
  exact CLSID `crosslink/guids.md:58` counts 118k× as "background noise"
  reproduces it today. Even a bare 64k-GUID membership set (the stevemk14ebr
  list alone) fixes this.
- **Highest-value enrichment is not cosmetic.** Resolving known-folder GUID
  prefixes in `file_path`/`image_path` (via the KNOWNFOLDERID *default path*)
  turns paths that can never join (`{374DE290-…}\x.txt`) into paths that can
  (`%USERPROFILE%\Downloads\x.txt`) — join fuel for the cross-source arc, not
  prettier output.
- **Licensing decides the tiers.** Only MicrosoftDocs/win32 is cleanly
  licensed (CC-BY-4.0 — vendorable with attribution). Elmue and both gists
  carry no licence: re-derive their facts from primary sources where
  possible, keep the rest as cross-check corpora. Either way this work forces
  the NOTICE/attribution convention the repo does not yet have.

## The five sources, verified

### davehull — `Resolve-WindowsGUID.ps1` (627 lines)

Two static hashtables — `$MSWinGUIDHT` (**89** entries: known folders,
shell32/MS-documented symbolic names) and `$EZGuidHT` (**371** entries, Eric
Zimmerman's community list: Explorer-style display names, control-panel
applets, shell-namespace CLSIDs — exactly the GUIDs shellbag and UserAssist
values contain) — plus a runtime `logman query providers` harvest of ETW
provider GUIDs. Quality: case variants and same-GUID-different-name overlaps
*between* its own two tables, so entries need normalisation with per-source
provenance.

Its two patterns outrank its ~460 rows:

1. **Resolve one GUID against several sources and report each source's
   answer** — the script's output is one row per source, "Not found" where a
   source has nothing. That is our "confidence is explicit" principle applied
   to a lookup table: per-entry tier + provenance, never one anonymous merged
   blob.
2. **Don't ship a static ETW list — harvest it.** Transposed offline (we
   cannot run logman against evidence), the harvest is
   `SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{GUID}` mined
   *from the evidence's own hive* via a gore batch: a per-host, `definitive`
   provider map, literally "reconstructed from source", with any static list
   demoted to `heuristic` fallback.

### stevemk14ebr — `guids` (71,652 lines, **64,122 unique GUIDs**)

`NAME:<symbol> VALUE:<guid>` pairs harvested from Windows SDK headers:
25.4k `IID_`, 3.3k `CLSID_`, 2k `GUID_`, 141 `FOLDERID_`, plus
WinRT parameterised-interface instantiations, MF/D3D/WPD/KS families and more.
Parsing traps: split on `" VALUE:"` (names contain spaces), HTML-unescape
(`&lt;…&gt;`), and drop the garbage rows — one placeholder GUID
(`28ec8348-67e8-fedd-ff33-c04883c428c3`) carries **383** names, the null GUID
appears 15×, `8035af08-0001-…` 23×.

As a *naming* source it is the last resort: symbol-only, no descriptions, no
OS metadata, no categories beyond the prefix. But as a bare **membership set**
it is the first thing to ship: ~64k GUIDs is a few hundred KB and is precisely
the F1 denylist — "this GUID is a well-known Windows constant, never a
host-unique identifier: extract nothing from it, join nothing on it."

### Elmue — WindowsRT-GUID-Analyzer

A C# tool, regenerable per Windows build: `ParseHeaderFiles()` walks the SDK
(`winrt/` only, or everything with `ONLY_WINRT=false`) and `ParseRegistry()`
walks the WinRT `ActivatableClasses` registry. `Release/` ships
machine-readable INI/XML per build: Windows 11 22000 **25,714** interfaces
(all-COM mode), 12.4k WinRT interfaces — and the part no other source has:
**4,100 activatable classes with the DLL that implements each** on a stock
install. That class→DLL table is a per-build baseline for COM/WinRT hijack
analytics (observed CLSID→DLL in evidence vs stock) once the behaviour layer
wants it.

Caveat: **no licence file anywhere in the repo.** Do not vendor `Release/`.
Options, in order: ask the author; run the tool against an SDK ourselves and
regenerate the same facts under our own provenance; or use it purely as a
cross-validation corpus.

### MicrosoftDocs/win32 (`desktop-src`) — the authoritative tier

The markdown source of the Win32 docs, **CC-BY-4.0** (the one cleanly
vendorable source: attribution required, redistribution and adaptation
granted). Verified mineable pages:

| Page | Yields |
|---|---|
| `desktop-src/shell/knownfolderid.md` | ~110+ KNOWNFOLDERIDs: GUID, display name, folder type (PERUSER/COMMON/VIRTUAL/FIXED), **default path** (`%USERPROFILE%\Downloads`…), CSIDL equivalent, legacy names |
| `desktop-src/shell/controlpanel-canonical-names.md` | control-panel item → canonical name + GUID + module + OS availability |
| `desktop-src/properties/props-system-*.md` (33 categories) | per-property `propertyDescription` with **formatID GUID + propID** — e.g. `PKEY_ItemNameDisplay` = `{B725F130-47EF-101A-A5F1-02608C9EEBAC}, 10` — the raw pairs sitting in LNK / jump-list / shellbag property stores |

The repo is enormous; mine it with a partial clone
(`git clone --filter=blob:none --sparse` +
`git sparse-checkout set desktop-src/shell desktop-src/properties`) pinned at
a SHA, and emit generated YAML snapshots carrying `GENERATED … @SHA` headers —
the exact convention `model/generate.py` already established for the pinned
submodules. (A submodule itself would be hostile at this repo's size; a
pinned-SHA generator with the pin recorded in the snapshot header is the same
guarantee without the checkout.)

The default paths are the load-bearing field — see Workstream A.

### Project Mu — GuidCheck (a governance pattern, not a data source)

The CI plugin that scans a UEFI tree's INF/DEC GUID declarations and **errors
on any GUID value appearing under two names, or any name under two GUIDs**,
with four ignore-list mechanisms (`IgnoreGuidName`, `IgnoreGuidValue`,
`IgnoreFoldersAndFiles`, `IgnoreDuplicates`) for intentional exceptions.
Merging five corpora (~70–90k GUIDs) *will* produce conflicts — the davehull
tables disagree with each other already — so the table build needs exactly
this gate: same GUID + conflicting names across tiers resolves by explicit
precedence or an allowlisted exception, never silently. It mirrors the
`byakugan.verify` / yamale-CI culture.

Two side notes: the same test cheaply asserts our `uuid5`-minted spindle/STIX
ids (`ids.py:40-51`) never collide with the well-known corpus; and GuidCheck's
INF/DEC parsing is the harvesting route for UEFI GUID names if the superset's
currently-fieldless `firmware` object ever grows real artefacts.

## Where Byakugan stands today

`byakugan/native_ids.py` is the one GUID miner — `Volume{GUID}`
(`volume_guids`, `:44-76`), v1-GUID node → MAC (`:87-135`), USB serials
(`:165-200`) — lifted fill-only-null into the `volume_guid` / `mac_address` /
`device_serial` header columns (`enrich.py:549-575`) and converged on by
`crosssource.py:95-117` as the `definitive_native_id` tier. Beyond it:

- **No GUID→name table exists anywhere.** The only literal lookups are logon
  types, integrity levels, `conn_state` and the well-known-SID table
  (`normalize.py:271-288`).
- Known-folder GUIDs ride unresolved inside shell-item `file_path`
  (`maps_plaso_shellitem.go:11-15` strips only the `<My Computer>` prefix)
  and Win7+ UserAssist `image_path` (`maps_plaso_exec.go:42-46` — a
  `{GUID}\cmd.exe` value passes the predicate and lands verbatim).
- LNK DLT droids are kept native (`maps_plaso_artifacts.go:37-40`), JLECmd
  `MacAddress`/`VolumeDroid` likewise (`maps_jlecmd.go:21-25`) — no
  birth-timestamp decode, no droid join class, and the
  `windows:distributed_link_tracking:creation` and `olecf:dest_list:entry`
  data_types (paths literally `knownfolder:{FDD39AD0-…}`) are unmapped.
- The evtx maps key on provider *name* (`mappings/_common.py:62-63`,
  `adapt/winevt.go:270-272`); provider GUIDs never appear.
- MachineGuid is claimed in the `crosssource.py:85-94` comment but not mined
  (`test_crosssource.py:232-242` asserts the non-behaviour); ECS `host.id`
  is unused — the natural pair, already flagged in
  `cross-source-linkage/01-linkage-volume-guid.md:71`.

### F1 — the CLSID→MAC false positive (reproduced)

`_NON_MAC_NODES` (`native_ids.py:94`) excludes exactly two nodes: the OLE
`000000000046` family and the RFC placeholder. Every *other* well-known v1
GUID gets its node treated as a hardware MAC — and Windows is full of them:
1990s Microsoft CLSIDs/IIDs/FMTIDs carry real vendor NICs (or fakes that pass
the I/G-bit check). Reproduced at `c9c6104`:

```python
>>> from byakugan.native_ids import mac_from_v1_guid, mac_addresses
>>> mac_from_v1_guid("f750e6c3-38ee-11d1-85e5-00c04fc295ee")
'00:c0:4f:c2:95:ee'
>>> mac_addresses({"key": r"HKLM\Software\Classes\CLSID\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}"})
['00:c0:4f:c2:95:ee']
```

That is the CLSID `crosslink/guids.md:58` counts **118k×** on LoneWolf and
files as "background noise — suppress from linkage". The `_native_ids`
docstring (`crosssource.py:95-100`) even states the intent — "never a bare
GUID (the ubiquitous COM CLSID/interface GUIDs are linkage noise)" — but the
`mac` class accepts v1-GUID-embedded MACs from those very CLSIDs, so the code
contradicts its own contract: `enrich` lifts a bogus `mac_address`, and
`crosssource` joins unrelated sources on it at the definitive tier.
`tests/test_native_ids.py:43` sidesteps the case by testing a
version-4-altered copy of a real CLSID.

Fix = Workstream A's noise gate (membership set + the timestamp plausibility
window from Workstream B), plus the unmodified CLSID as a regression test.

## Workstream A — the tiered well-known-GUID table

One generated dataset, shipped as package data under `byakugan/` per the
"data, not code" rule (`CONTRIBUTING.md:99-103`), entries shaped like:

```yaml
guid: 374de290-123f-4565-9164-39c4925e467b
name: FOLDERID_Downloads
display: Downloads
kind: known_folder        # known_folder | clsid | iid | control_panel | fmtid | etw_provider | …
default_path: "%USERPROFILE%\\Downloads"
tier: ms-docs             # precedence: ms-docs > dfir-curated > per-build > header-dump
provenance: "MicrosoftDocs/win32@<sha>: desktop-src/shell/knownfolderid.md"
```

**Tiers and precedence.** `ms-docs` (authoritative, rich fields) →
`dfir-curated` (davehull/EZ: the display names analysts recognise, plus
XP-era entries Microsoft no longer documents) → `per-build` (Elmue-style
regenerated, licensing permitting) → `header-dump` (stevemk14ebr — the name
of last resort). A GuidCheck-style merge gate runs at generation time and in
CI: value-vs-name conflicts resolve by tier or an explicit exception entry,
never silently.

**Consumers, mapped to the existing plug-in points:**

- **Noise gate (miner-side — the F1 fix).** A membership check in
  `_node_to_mac` / `volume_guids` before extraction. Needs no names at all;
  ship first.
- **Enrich-time lift** (the `enrich.py:549` pattern): resolve `{GUID}`
  prefixes in `file_path` / `image_path`. Per "grab maximally, never fake":
  keep the verbatim value, add the resolution as `native.known_folder` plus a
  resolved-path variant marked `heuristic` — default paths are *defaults*
  (folder redirection exists), so the resolved form is never `definitive`.
  This is the highest-value enrichment because it is join fuel: a
  shellbag/UserAssist path resolved to `%USERPROFILE%\Downloads\x` can
  suddenly correlate with MFT/plaso file paths in cross-source entity
  resolution; a GUID-prefixed one never will. It also unblocks mapping the
  currently-unmapped `olecf:dest_list:entry` rows.
- **Cross-source**: the same membership set answers "host-unique or global?"
  before any native-id join — the `guids.md:187-197` recommendation made
  mechanical.
- **Map-time (Go)** only where a table is `MapValue`-marker small
  (`authoring.go:63-72`). A full table marker kind would need the whole
  `canon_user`-style IR-section dance across six files
  (`ir_sections.go:352`, `markers.go:523-570`, …) — and enrichment is
  Python's job in our split anyway. Not recommended as the first home.
- **Later**: `kind: fmtid` + propID unlocks decoding LNK/jump-list/shellbag
  property stores into `System.*` names; `kind: clsid` names the
  registry/DCOM/task CLSIDs the registry maps currently carry as opaque key
  text; and the per-build class→DLL baseline turns that into a
  COM-hijack analytic for `analytics.py`.

**Licensing/attribution.** The repo is MIT with **no NOTICE or THIRD_PARTY
convention** — this workstream forces creating one. CC-BY-4.0 (win32 docs) is
straightforward; the pinned-snapshot-with-provenance-header pattern is
already ours; unlicensed sources (Elmue, both gists) are re-derived from
primary sources where possible and credited as cross-checks otherwise.

## Workstream B — structural dissection (transform/inference)

Generalise `native_ids.py` into a proper dissector: variant → version →
per-version fields. For v1: the 60-bit timestamp (100 ns ticks since
1582-10-15), the 14-bit clock sequence, the 48-bit node. Validated on real
GUIDs (run, not recalled):

| GUID | What decodes | Lesson |
|---|---|---|
| `31B2F340-016D-11D2-945F-00C04FB984F9` (Default Domain Policy GPO) | v1 → **1998-06-11T20:46:04Z**, node `00:c0:4f:…` (real vendor OUI) | genuine machine provenance falls out of a bare GUID |
| `88C6C381-2E85-11D0-…-444553540000` (ActiveX Cache Folder) | v1 → 1996-10-25, node = ASCII **"DEST"** | placeholder nodes pass the I/G-bit test — node classification needs pattern checks, not just the multicast bit `_node_to_mac` tests now |
| `20D04FE0-3AEA-1069-…` (My Computer CLSID) | "v1" → year **1676** | pre-standard GUIDs parse as v1 with garbage time — a plausibility window (~1995‥now+1y) must gate every extracted fact |
| `374DE290-123F-4565-…` (FOLDERID_Downloads) | v4 | version-gate before extracting anything |

What the dissector powers, in existing mechanisms:

- **Droids as a first-class identity.** The l2t_lnk droid fields and JLECmd
  `MacAddress`/`VolumeDroid` already reach `native`; add the birth-droid
  **timestamp** decode (the file's creation moment on its *origin* machine),
  a `droid` key class in `crosssource._native_ids`, and machine/droid
  `content_node` kinds via `relationships.yml` identities. That is cross-host
  file provenance — "born on the machine with NIC X at time T, then
  travelled" — i.e. the cross-source-linkage backlog made concrete.
- **ETW provider resolution**, three-layered: per-evidence
  `WINEVT\Publishers` harvest (`definitive`), static seed list (`heuristic`),
  and a name→GUID derivation dictionary for TraceLogging-style providers
  whose GUIDs are hashed from their names — resolving GUIDs no list will ever
  contain by dictionary attack against known provider-name corpora.
- **MSI packed GUIDs.** The Installer hive stores product codes
  nibble-reversed; a small unscramble transform makes
  `Installer\Products\<packed>` joinable with Uninstall keys — relevant once
  a gore batch collects those keys.
- **Sysmon `ProcessGuid`/`LogonGuid`** (already our CAR `guid` for EID 1/5,
  `maps_sysmon.go:42-45`) are structured values embedding a machine token and
  a start time — a promising dissection target, but the byte layout must be
  validated against fixtures first: `to-be-validated/` is the right
  quarantine.

## The input side (GoDFIR-toolz @ `ee688cf`)

The pipeline can only enrich what the parsers emit:

| Parser | Gap |
|---|---|
| `gole` (.lnk) | omits tracker droids entirely (golnk limitation) — the richest v1 GUIDs in Windows, lost on that lane; the plaso lnk lane carries them, and `gojle` proves the v1-droid→MAC decode in-house already |
| `gosbe` (shellbags) | `knownFolders` map is **10 entries** (`gosbe/main.go:60-71`) vs ~460+ available from tiers 1–2; unknown root GUIDs stay raw in `AbsolutePath` |
| `goevtx` | emits `Provider` name, no provider GUID — GUID-only WPP/TraceLogging records stay anonymous downstream |
| `gore` | `batch/default.reb` collects no GUID-rich keys — `WINEVT\Publishers`, `MountedDevices`, `MountPoints2`, CLSID hijack points and `Installer\Products` are the additions that feed everything above |

## Order of attack

1. **Noise gate** in `native_ids.py` (membership set from the header-dump
   tier + the v1-timestamp plausibility window) — fixes F1's live
   cross-source poisoning; smallest change; regression-test the unmodified
   CLSID.
2. **Table generator**: win32 sparse-clone miner + gist normalisers +
   GuidCheck-style merge gate → the tiered YAML with per-entry provenance;
   plus the NOTICE convention.
3. **Known-folder resolution** at enrich time (shell items, UserAssist, and
   mapping the dest_list rows).
4. **Droid dissection**: birth timestamps, the `droid` cross-source class,
   machine/droid content nodes.
5. **Provider map**: gore `Publishers` batch + static seed + derivation
   dictionary (with the goevtx provider-GUID passthrough fix).
6. **CLSID tier + stock class→DLL baseline** for the behaviour layer, once
   licensing is settled.
