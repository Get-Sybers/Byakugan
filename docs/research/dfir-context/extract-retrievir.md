# DFIR context extract — RetrievIR

## What it is

RetrievIR is a light-weight PowerShell live-response evidence collector for
local and remote Windows hosts (WMI process creation + SMB transfer), driven
by JSON configuration files whose directives come in three shapes: `files`
(path globs + filters), `commands` (PowerShell run on the target), and
`registry` (path/key snapshots into JSON). A companion `ParseIR.ps1` +
`parsing_config.json` drives mostly Zimmerman-tool parsing of the collected
raw evidence. As predicted, the corpus is overwhelmingly collection
GEOGRAPHY — where artefacts live — which is gomount's layer and fails the
fit test. The repo's directive-level `reference` keys point at
EricZimmerman/KapeFiles targets, i.e. its own authority chain is KAPE, not
original research. Evidentiary semantics (what an artefact *evidences*) are
confined to: `persistence`/`startups` tags on a handful of directives, the
`Autorun` category label, the `TasksDetailed` command's explicit field
extraction (the repo's only field-level actor/time statement), and the
`RDPCache` directive's isolation of the account-bearing `UsernameHint`
value.

## Attribution

- **Name:** RetrievIR (+ ParseIR)
- **URL:** https://github.com/joeavanzato/RetrievIR
- **Pin:** `a6a9c144389d447b2dd744607daeeae2e2f37258` (shallow clone; commit
  dated 2024-08-23, "Updating tool locations")
- **License:** MIT, "Copyright (c) 2023 panscan"
- **Authors:** Joe Avanzato (github.com/joeavanzato; commits and copyright
  as "panscan")

## Evidences rows

### run-keys

```yaml
- object: registry
  action: value_edit
  evidence: inferred
  time: none
  basis: >
    RetrievIR groups the Run/RunOnce/RunEx/RunOnceEx/RunServices keys (HKLM
    and per-user HKU\*) into a single "CommonStartups" directive tagged
    ["persistence", "startups"] — an explicit statement that a value present
    under these keys evidences configured autostart persistence. Presence of
    the value only infers that a write occurred; RetrievIR's registry
    collection snapshots path/name/type/value with no timestamps
    (store_empty true, keys "*"), so no time claim survives.
  source: configs/persistence.json:36-53
- object: registry
  action: value_edit
  evidence: inferred
  time: none
  basis: >
    "Debuggers" directive tagged ["persistence"]: AeDebug/AeDebugProtected,
    .NETFramework DbgManagedDebugger, WER Hangs, and two session-manager
    CLSID LocalServer32 keys, filtered to the debugger-bearing value names
    ("ProtectedDebugger", "Debugger", "DbgManagedDebugger", default) — the
    repo states these values evidence debugger-hijack persistence. Same
    family per the seed table's WindowsPersistenceRegistryKeys cluster.
    Presence-only snapshot, no timestamps.
  source: configs/persistence.json:55-74
- object: registry
  action: value_edit
  evidence: inferred
  time: none
  basis: >
    Category label "Autorun" on the "ShellFolders" (Startup-folder
    redirection under Explorer *Shell Folders) and
    "ImageFileExecutionOptions" registry directives — a weaker but explicit
    statement that these values evidence autostart/execution-hijack
    configuration. Same presence-only, timestamp-free snapshot mechanism.
  source: configs/windows.json:663-677
```

### scheduled-tasks

```yaml
- object: file
  action: modify
  evidence: definitive
  time: event-time
  basis: >
    The "TasksDetailed" command is the repo's one field-level evidentiary
    statement: for every XML under C:\Windows\System32\Tasks it emits
    TaskFile_LastModifiedTime (NTFS LastWriteTimeUtc) alongside the task's
    self-reported RegistrationInfo.Date/Author/URI,
    Principals.UserId/LogonType, Enabled, and Exec/ComHandler action —
    i.e. it treats the task file's mtime as the reliable when-written
    record for the task definition, and the RegistrationInfo fields
    (attacker-writable XML content, hence at best heuristic and not rowed
    here) as descriptive actor/action context. The mtime claim is
    definitive for "task definition file last written" with event-time.
  source: configs/windows.json:629-636
```

### registry-hives

```yaml
- object: registry
  action: value_edit
  evidence: inferred
  time: none
  basis: >
    "RDPCache" directive (category "RDP") collects only the "UsernameHint"
    value under HKEY_USERS\*\SOFTWARE\Microsoft\Terminal Server
    Client\Servers — the config's key selection isolates the account-use
    signal (per-target-server username hint) written by outbound RDP use;
    the README's worked example shows a server key ("34.227.81.6") holding
    "MicrosoftAccount\Administrator". The repo states the collection, not a
    strength/time claim: presence of the per-server value infers a write by
    an outbound RDP connection, no timestamp collected. Lives in NTUSER →
    registry-hives family (no dedicated rdp-mru family in the seed table).
  source: configs/windows.json:655-661; README.md:395-434
```

## Noted, not added

- **All path/glob geography** (every `files` directive across
  `configs/*.json`; the registry path lists as paths): where evidence
  lives, not what it yields — gomount's layer; same REJECT the crosswalk
  applies to ForensicArtifacts `sources[]`. This covers the entire
  antivirus.json, cloudapps.json, remoteaccesstools.json, browsers.json,
  office.json, eventlogs.json, recent_files.json inventories and the bulk
  of windows.json — useful only as a KAPE-derived coverage checklist, and
  the `reference` keys show KapeFiles is the authority to mine instead.
- **Live-only command directives** (DNS cache, TCP connections, ARP,
  SMB sessions/open files, running processes, services enumeration, local
  admins/groups, firewall rules, Defender detections, installed software,
  Win32_StartupCommand, USN via `fsutil`, MFT carve): live-response
  snapshots with no dead-disk artefact family; byakugan operates on
  mounted images. `configs/windows.json` commands block.
- **WMI ActiveScript/CommandLine event consumers**
  (`configs/windows.json:573-588`): a genuine persistence-evidence claim
  ("root\subscription consumers"), but live WMI query only; the on-disk
  counterpart (WBEM/CIM repository, collected as geography at
  windows.json:383-390) has no byakugan family — the crosswalk lists the
  CIM repository as a gomount collection gap, not a family. Fails family
  binding.
- **PowerShellProfiles tagged ["persistence"]**
  (`configs/powershell.json:3-12`): profile.ps1 presence evidences
  configured PowerShell persistence, but no byakugan family covers
  Windows PowerShell profiles. Noted for whenever a windows
  shell-config/persistence-files family exists.
- **ConsoleHistory / PSReadLine** (`configs/powershell.json:35-43`):
  execution evidence by content, but shell-history family is linux/macos
  in the seed table, and the crosswalk already flags ConsoleHost_history
  as a gomount collection gap. No claim stated in the config anyway.
- **OutlookStartupOTM tagged ["persistence"]**
  (`configs/windows.json:219-227`): VbaProject.OTM presence evidences
  Office startup-macro persistence; no byakugan family. Noted.
- **SuspiciousFiles tagged ["persistence"]**
  (`configs/persistence.json:3-31`): "specific extensions in specific
  paths" — a triage hunting heuristic, pure geography, no artefact class.
- **StartupFolders / StartupXML** (`configs/windows.json:290-310`): folder
  contents only, no tag or claim beyond the KapeFiles reference; no
  startup-folder family (run-keys is registry-only in the seed table).
- **ShimDB InstalledSDB/Custom registry + .sdb files**
  (`configs/windows.json:679-686`, .sdb files at windows.json:3-12): shim
  *installation* evidence (persistence) is distinct from the shimcache
  family (AppCompatCache execution residue); category label "Application"
  states nothing. No family for shim-installation.
- **TasksDetailed Principals/LogonType/Author fields**: account-use hints
  inside forgeable XML content — no (user_session, *) binding can be
  sourced to the repo; kept as basis context on the scheduled-tasks row.
- **`sans_triage` tags and per-directive `reference` URLs**: provenance
  (KAPE SANS Triage emulation), not evidence semantics; they strengthen
  the case that KapeFiles targets are the upstream worth a real ingest.
- **parsing_config.json / ParseIR**: names parser tooling per evidence
  type (MFTECmd, PECmd, AmcacheParser, browser SQLite, etc.) —
  corroborates byakugan's existing family↔parser lanes, states no yields;
  the design doc already sources typed yields from parser record structs.

## Pipeline verdict

**Once-only.** The pin `a6a9c14` (2024-08-23) is a maintenance commit
("Updating tool locations" — parser download URLs); LICENSE is 2023; the
README TODO ($J, $LogFile, $SDS…) is untouched. The project reads as
dormant/low-churn, and its evidentiary content is a thin veneer (tags,
one command's field list) over KAPE-derived geography that byakugan does
not consume. No recurring watch is warranted; the recurring-ingest
candidate this repo points at is EricZimmerman/KapeFiles, which every
`reference` key cites as the actual authority.
