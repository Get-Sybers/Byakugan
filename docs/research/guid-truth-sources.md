# GUID truth sources — where each fact is reproduced from

**Status:** research; companion to
[guid-sources.md](guid-sources.md) — that document defines the two
workstreams; this one pins the *truth sources* each tier regenerates from and
validates the dissection recipes that were still open there. Every decode and
transform shown below was **run in this session, not recalled**; every repo
fact carries the commit it was read at.
**Ground truth:** Byakugan @ `0849e09` (fixtures:
`go/internal/adapt/testdata/winevt_vectors.json`);
[marlersoft/win32json](https://github.com/marlersoft/win32json) @ `071df49`
(v31.0.4-preview);
[EricZimmerman/GuidMapping](https://github.com/EricZimmerman/GuidMapping) @
`f68fb31`;
[microsoft/win32metadata](https://github.com/microsoft/win32metadata) @
`5c5efbc`; [libyal/winreg-kb](https://github.com/libyal/winreg-kb) @
`278fdb8`; [libyal/dtformats](https://github.com/libyal/dtformats) @
`4917c9b`; [libyal/liblnk](https://github.com/libyal/liblnk) @ `b14e11e`;
[tianocore/edk2](https://github.com/tianocore/edk2) @ `5846c66`;
[jdu2600/Windows10EtwEvents](https://github.com/jdu2600/Windows10EtwEvents) @
`84e7261`; `dotnet/runtime`
`src/libraries/System.Private.CoreLib/src/System/Diagnostics/Tracing/EventSource.cs`
and `MicrosoftDocs/win32` `desktop-src/ADSchema/*` raw pages, both fetched
2026-09-23.

## TL;DR

- **Every unlicensed corpus in guid-sources.md now has a license-clean
  primary.** The davehull `$EZGuidHT` table is a 371-row vendored subset of
  **EricZimmerman/GuidMapping** — MIT, actively maintained, and
  **14,464 rows** (`Resources/GuidToName.txt`, `guid|display name`). The
  stevemk14ebr header dump re-derives from **marlersoft/win32json** — MIT,
  Microsoft-owned machine-readable JSON: **5,431 `Guid`-typed constants plus
  9,996 type-attached GUIDs** across 304 API files, values as plain strings.
  Only the Elmue per-build corpus stays licence-less; its verdict is
  unchanged (regenerate ourselves or cross-check only).
- **Three Workstream-B recipes are now validated end-to-end**:
  the Sysmon `ProcessGuid` embedded timestamp (decoded against our own
  fixture, matches `UtcTime` to the second), the TraceLogging/EventSource
  **name→GUID derivation** (ported from `dotnet/runtime`, reproduces the
  published `System.Runtime` provider GUID exactly), and the **MSI packed
  product-code transform** (reproduces the known Office pair exactly).
  All three are a dozen stdlib lines each — reproducible internally today.
- **A new Workstream-A tier fell out of the docs mining**: the
  `desktop-src/ADSchema` tree (~1,800 pages, CC-BY-4.0 like the rest)
  carries per-attribute `System-Id-Guid` and per-extended-right
  `Rights-GUID` — the vocabulary that names the GUIDs inside Security 4662
  `ObjectProperties` (DCSync's `DS-Replication-Get-Changes` =
  `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` verified from the page source).
- **The droid chain is fully documented in clonable primaries**: liblnk's
  LNK format doc gives the TrackerDataBlock offsets *and* the semantic key —
  a droid is a `CDomainRelativeObjId` whose volume identifier **is** the
  NTFS `$OBJECT_ID` value — and dtformats gives the jump-list DestList droid
  offsets. That is the LNK / jump-list / MFT `$OBJECT_ID` join, documented,
  which unblocks guid-sources.md's step 4 and the unmapped
  `olecf:dest_list:entry` rows.
- **`MountedDevices` dissection has exact documented layouts** (winreg-kb):
  GPT values = `"DMIO:ID:"` + 16-byte little-endian partition GUID; MBR
  values = 4-byte disk signature + 8-byte partition offset — the missing
  bridge between `Volume{GUID}`s, drive letters, and partition identity.

## 1. Workstream A — the license-clean primary per tier

| guid-sources.md tier | primary source (pin) | licence | scale / shape |
|---|---|---|---|
| `dfir-curated` | EricZimmerman/GuidMapping @ `f68fb31`, `Resources/GuidToName.txt` | **MIT** (© 2026 E. Zimmerman) | 14,464 `guid\|display` rows — the live upstream of which davehull's `$EZGuidHT` (371) is a stale vendored subset; it is the table the EZ tools themselves resolve against |
| `header-dump` | marlersoft/win32json @ `071df49`, `api/*.json` | **MIT** (© Microsoft) | 304 files; 5,431 constants of type `Guid` (`{"Name":"FOLDERID_Downloads","Value":"374de290-123f-4565-9164-39c4925e467b"}` verified) + 9,996 types carrying a `Guid` (7,579 COM interfaces → the `IID_` space); `version.txt` pins the win32metadata release (31.0.4-preview) |
| `ms-docs` | MicrosoftDocs/win32 `desktop-src/` (unchanged) **+ the ADSchema subtree** (§1.1) | CC-BY-4.0 | knownfolderid / control-panel / property-system as before, plus ~1,800 AD schema pages |
| `per-build` | unchanged (Elmue, or regenerate ourselves) | none | verdict stands: cross-check corpus until relicensed or regenerated |
| firmware (the parent doc's UEFI note) | tianocore/edk2 @ `5846c66`, `*.dec` files | **BSD-2-Clause-Patent** | `MdePkg/MdePkg.dec` alone: 748 GUID lines in `gEfiGlobalVariableGuid = { 0x8BE4DF61, … }` DEC syntax — parseable exactly the way Project Mu's GuidCheck already parses INF/DEC |
| key-layout documentation (backs every harvest below) | libyal/winreg-kb @ `278fdb8`, `docs/sources/` | **Apache-2.0** | per-key layout docs: `Known-folder-identifiers.md`, `COM-class-identifiers.md`, `Mounted-devices.md`, `User-assist.md`, `Mount-points.md`, `USB-storage.md`, `Task-scheduler.md`, … |

Two licensing precisions the table build must respect:

- **win32metadata (@ `5c5efbc`) is MIT, but its LICENSE opens with a
  disclaimer**: the vendored SDK headers under `generation/WinSDK/`
  (`RecompiledIdlHeaders`, `AdditionalHeaders`) "do not imply a change of
  their original licenses" — they exist to *produce* the metadata. So the
  clean re-derivation path for the header tier is the **outputs** (the winmd,
  or win32json's projection of it), never the vendored headers themselves.
  stevemk14ebr's 64k-row dump demotes to what guid-sources.md already made
  it: the broadest membership superset (WinRT parameterised instantiations
  included) for the noise gate, name-of-last-resort otherwise.
- **jdu2600/Windows10EtwEvents (@ `84e7261`) carries no licence file and —
  the material finding — no GUIDs at all**: its per-build TSVs
  (`manifest/`, `mof/`, `unknown/`) are keyed by provider *name*
  (`provider  event_id  version  event(fields) …`), 26 `unknown/` providers
  included. Its role is therefore **not** a provider-GUID seed. It is (a) a
  per-build *event/channel schema* cross-check for the evtx maps, and (b) a
  provider-**name corpus** feeding the derivation dictionary in §2.2. The
  provider-GUID map stays what guid-sources.md said: per-evidence
  `WINEVT\Publishers` harvest first, static seed second.

### 1.1 New tier input: ADSchema (names the 4662 GUIDs)

`desktop-src/ADSchema/` exists in the same CC-BY-4.0 win32 docs repo
(1,000+ files shown, 802 more truncated by the GitHub listing) and each page
carries the GUID fields directly (verified from raw page source,
2026-09-23):

- `a-admincount.md` → `System-Id-Guid | bf967918-0de6-11d0-a285-00aa003049e2`
  (attribute `adminCount`);
- `r-ds-replication-get-changes.md` →
  `Rights-GUID | 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`
  (the DCSync extended right).

Consumer: Security **4662** (`Operation > Properties {GUID}`) and 5136-class
events — today those GUIDs ride opaque through the evtx lanes. A
`kind: ad_schema | ad_extended_right` tier entry names them, which is
detection-grade enrichment (DCSync, Kerberoast-adjacent rights reads) for
free once the table exists. Mining pattern: identical to `knownfolderid.md`
(sparse clone of `desktop-src/ADSchema`, pinned SHA, generated YAML snapshot
with provenance header).

### 1.2 The evidence-side harvest map (the *definitive* tier, per host)

guid-sources.md establishes the principle ("harvest from the evidence's own
hive"); this is the concrete map, each with its layout documentation:

| Registry key (harvest) | Yields | Layout doc |
|---|---|---|
| `…\Explorer\FolderDescriptions\{GUID}` | known-folder name, `ParentFolder`, `RelativePath` — **this host's** folder mapping, redirection included (beats any static default path) | winreg-kb `Known-folder-identifiers.md` |
| `HKCR\CLSID\{GUID}` (+`InprocServer32`) | COM class display name + implementing DLL — naming *and* the observed-vs-stock hijack baseline | winreg-kb `COM-class-identifiers.md` |
| `…\WINEVT\Publishers\{GUID}` | ETW provider name map (the parent doc's harvest, `definitive`) | — |
| `SYSTEM\MountedDevices` | volume-GUID ↔ drive letter ↔ GPT partition GUID / MBR signature (dissection §2.4) | winreg-kb `Mounted-devices.md` |
| `SYSTEM\…\Control\Class\{GUID}` / `DeviceClasses` | device setup/interface class names | winreg-kb `USB-storage.md` context |
| `Installer\Products\<packed>` | MSI product codes (unpack §2.3) → joins Uninstall keys | §2.3 |
| `…\Explorer\MountPoints2` | per-user mounted volume GUIDs | winreg-kb `Mount-points.md` |

These are the gore `batch/default.reb` additions guid-sources.md already
called for, now each with the page that specifies what the bytes mean.

## 2. Workstream B — validated dissection & derivation recipes

### 2.1 Sysmon `ProcessGuid` — the embedded timestamp, fixture-validated

Layout (community RE:
[Matt Graeber's decoder gist](https://gist.github.com/mattifestation/0102042160c9a60b2b847378c0ef70b4),
the [TrustedSec Sysmon Community Guide, process-events](https://github.com/trustedsec/SysmonCommunityGuide/blob/master/chapters/process-events.md),
a [Rust implementation](https://docs.rs/sysmon/0.2.5/sysmon/struct.ProcessGuid.html)):
`{MMMMMMMM-TTTT-TTTT-CCCC-CCCCWWWWWWWW}` = machine-GUID upper 32 bits |
process-creation time, epoch seconds | counter since driver start | tail.

Validated against our own fixture
(`go/internal/adapt/testdata/winevt_vectors.json`, run 2026-09-23):

```
guid = {DFAE8213-70EB-5CDD-0000-0010F66D0A00}   UtcTime = 2019-05-16 14:17:15.753
epoch u32 = int(Data3 + Data2, 16) = 0x5CDD70EB = 1558016235
          → 2019-05-16T14:17:15Z   == UtcTime, to the second
```

So the seconds field spans the *second and third* text groups read as one
**little-endian** u32 (`Data3||Data2` textually). What this powers:

- **Process start time from any `ProcessGuid`-bearing row** — including
  rows that are not EID 1: network/file/registry Sysmon events carry the
  *creation* moment of their acting process inside the GUID itself, and
  `ParentProcessGuid` carries the parent's. `LogonGuid` should encode the
  logon time the same way (to validate). These are derive-rule candidates
  with the plausibility window guard guid-sources.md already mandates.
- The machine field (`DFAE8213`) is only checkable once `MachineGuid` is
  mined — the exact gap `crosssource.py:85-94` already flags; the two
  validations land together.
- Unvalidated and quarantined per the parent doc: the counter/tail
  semantics, and every claim above on *other* Sysmon versions —
  `to-be-validated/` fixtures decide, never the layout doc alone.

### 2.2 TraceLogging / EventSource provider GUIDs — derivation, pair-validated

The algorithm, from `dotnet/runtime` `EventSource.cs`
(`GenerateGuidFromName`, MIT — fetched 2026-09-23): namespace bytes
`482C2DB2-C390-47C8-87F8-1A15BFC130FB`, then the provider name
**upper-cased** and encoded **UTF-16 big-endian**, SHA-1, first 16 bytes,
version nibble of byte 7 forced to `5` (no RFC variant-bit adjustment), and
the result rendered through .NET's **little-endian** `Guid(byte[])`
constructor. Stdlib port (run 2026-09-23):

```python
def eventsource_guid(name: str) -> str:
    ns = bytes([0x48,0x2C,0x2D,0xB2,0xC3,0x90,0x47,0xC8,
                0x87,0xF8,0x1A,0x15,0xBF,0xC1,0x30,0xFB])
    h = bytearray(hashlib.sha1(ns + name.upper().encode('utf-16-be')).digest()[:16])
    h[7] = (h[7] & 0x0F) | 0x50
    return str(uuid.UUID(bytes_le=bytes(h)))
```

Validation: `eventsource_guid("System.Runtime")` →
`49592c0f-5a05-516d-aa4b-a64e02026c89`, the publicly documented
`System.Runtime` EventCounters provider (e.g.
[dotnet/runtime #107919](https://github.com/dotnet/runtime/issues/107919)).
This is the parent doc's "derivation dictionary" made runnable: GUID-only
providers in evidence resolve by computing the GUIDs of known provider-name
corpora — the EZ table, win32json symbol names, Windows10EtwEvents' provider
filenames, and the evidence's own `Publishers` names — and matching.

### 2.3 MSI packed product codes — transform, pair-validated

`Installer\Products\<32 hex>` key names are the product-code GUID with the
first three fields' hex **reversed** and the remaining eight bytes
**pair-swapped**:

```python
def msi_pack(guid: str) -> str:
    p = guid.strip('{}').split('-')
    out = p[0][::-1] + p[1][::-1] + p[2][::-1]
    tail = p[3] + p[4]
    return (out + ''.join(tail[i+1] + tail[i] for i in range(0, len(tail), 2))).upper()
```

Validation (run 2026-09-23): `90140000-0011-0000-0000-0000000FF1CE`
(Office 14 ProductCode) → `00004109110000000000000000F01FEC` — the pair as
observed in real `Installer\Products` keys. The inverse transform makes
those keys joinable with `Uninstall` keys the moment a gore batch collects
them.

### 2.4 `MountedDevices` values — documented layouts

From winreg-kb `Mounted-devices.md` (@ `278fdb8`):

- **GPT value data (24 bytes)**: offset 0, 8 bytes `"DMIO:ID:"`; offset 8,
  16 bytes little-endian **GPT partition GUID**.
- **MBR value data (12 bytes)**: offset 0, 4 bytes disk signature; offset 4,
  8 bytes partition byte-offset.
- **Device string data**: UTF-16LE, no terminator (the
  `_??_USBSTOR#…` strings the USB miner already understands).

Join surface: `\DosDevices\C:` ↔ `\??\Volume{GUID}` ↔ GPT partition GUID or
MBR signature+offset — i.e. the bridge between the `volume_guids` miner's
GUIDs, drive letters seen in paths, the partition table of the imaged disk,
and (via §2.5) the volume droids in LNK/jump-list artefacts.

### 2.5 Droids — primary documentation found, join semantics confirmed

- **LNK TrackerDataBlock** (liblnk @ `b14e11e`,
  `documentation/Windows Shortcut File (LNK) format.asciidoc`): droid volume
  id at offset 32, droid file id at 48, birth droid volume id at 64, birth
  droid file id at 80 (16 bytes each) — and the two sentences that matter:
  *"Droid in this context refers to `CDomainRelativeObjId`. The droid volume
  identifier can be found in the NTFS `$OBJECT_ID` attribute"*. The droid ↔
  MFT `$OBJECT_ID` join is documented, not folklore.
- **Jump-list DestList entries** (dtformats @ `4917c9b`,
  `documentation/Jump lists format.asciidoc`): droid volume id at offset 8,
  droid file id at 24, birth droid volume id at 40, birth droid file id at
  56 — the structure behind the currently unmapped `olecf:dest_list:entry`
  rows.
- The file droids are v1 UUIDs → the parent doc's dissector yields birth
  timestamp + node (origin machine's MAC) per file, on top of the join.
- Protocol-level semantics: **[MS-DLTW]** (Distributed Link Tracking) and
  **[MS-SHLLINK]** §TrackerDataBlock. `learn.microsoft.com` is egress-blocked
  from this container (noted; read them outside), but nothing in the
  workstream blocks on them — the libyal docs above carry the needed
  structures under Apache-2.0.

## 3. Amendments to guid-sources.md's order of attack

The six-step order stands; the sources under it change:

1. *Noise gate* — membership set now = stevemk14ebr superset ∪ win32json ∪
   GuidMapping (all three cheap; the first for breadth, the latter two
   license-clean).
2. *Table generator* — tiers regenerate from GuidMapping (MIT) + win32json
   (MIT) + win32-docs sparse clone (CC-BY, **now including
   `desktop-src/ADSchema`**) + edk2 DEC parse (BSD); davehull demotes to a
   cross-check corpus (its two *patterns* were the value anyway);
   Windows10EtwEvents reclassifies as name-corpus/schema cross-check.
3. *Known-folder resolution* — unchanged, plus the per-host
   `FolderDescriptions` harvest as the `definitive` layer above the static
   defaults.
4. *Droid dissection* — now spec-backed (§2.5); add the MFT `$OBJECT_ID`
   join class alongside the birth-timestamp decode.
5. *Provider map* — unchanged three-layer plan; the derivation dictionary is
   implemented and validated (§2.2).
6. *CLSID tier* — unchanged; add §1.2's `HKCR\CLSID` harvest as its
   per-host `definitive` layer and 4662/ADSchema naming (§1.1) as a sibling
   consumer.

New derive-rule candidates surfaced by §2: Sysmon start-time extraction
(2.1), MSI unpack join (2.3), MountedDevices volume bridge (2.4).

## 4. Verification status

| Claim | Status |
|---|---|
| GuidMapping is MIT, 14,464 rows, `guid\|name` | **verified** (cloned, counted, licence read) |
| win32json is MIT/Microsoft, GUIDs as plain strings, 5,431 + 9,996 | **verified** (cloned, counted, sample parsed) |
| win32metadata vendored-header licence carve-out | **verified** (LICENSE read) |
| ADSchema pages carry `System-Id-Guid` / `Rights-GUID` | **verified** (two raw pages fetched, values quoted) |
| edk2 DEC GUID format + licence | **verified** (sparse clone, 748 lines counted) |
| winreg-kb layouts (MountedDevices offsets, FolderDescriptions values) | **verified** (docs read) |
| Sysmon PG epoch field position + endianness | **verified on one fixture** (one host, one Sysmon vintage — widen via `to-be-validated/`) |
| EventSource derivation | **verified** against one published pair (System.Runtime) |
| MSI packed transform | **verified** against one known pair (Office 14) |
| PG machine/counter fields; `LogonGuid` time; other Sysmon versions | unvalidated — fixture protocol per parent doc |
| [MS-DLTW]/[MS-SHLLINK] exact wording | pointer only (egress-blocked here); libyal docs carry the structures |
| Windows10EtwEvents licence | none found — treat as read-only cross-check |
