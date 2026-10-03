# Extract: MITRE_Alerts (ViperHawk)

## What it is

A small (8-file, single-visible-commit) personal repo carrying a MITRE
ATT&CK detection-rules library: one large markdown table
(`mitre_detection_library.md`) mapping tactics → techniques →
sub-techniques → severity → detection logic → required log sources →
inline Sigma rule snippets, a PDF that is a 13-page browser print of
the same table (`MITRE_Sigma.pdf`, Skia/PDF producer, no independent
content), a `README.md` describing an idealized repo layout, and a
Security Onion integration bundle (`Onion_ReadMe`, `Onion Config`,
`Onion Config Guide`, `Onion Import Script`, `quickstart script`) that
converts Sigma rules to Elasticsearch watchers.

Content-quality caveats that shape the ingest:

- The README describes directories (`sigma-rules/`, `docs/`, `tools/`),
  a `LICENSE` file and clone URLs (`yourusername/...`) that do not
  exist in the repo — the described structure is aspirational.
- `mitre_detection_library.md` is malformed: the document title and
  table header appear mid-file (line 15) with rows duplicated above
  and below it — hallmarks of pasted/generated content.
- Detection value is entirely Sigma-style selection logic. The only
  artefact-grounded content is the "Technology Logs" column's concrete
  Windows/Sysmon/PowerShell event-id glosses, and those glosses are
  standard channel semantics, not original research. Rows below are
  therefore seeded from this repo but should be corroborated against
  the EVTX-ETW-Resources ingest (higher-authority sibling source).

## Attribution

- **Name:** MITRE_Alerts (self-titled "MITRE ATT&CK Detection Rules Library")
- **URL:** https://github.com/ViperHawk/MITRE_Alerts
- **Pin:** `4595c395d5391b0ec742f9a874e1ec388f16176a` (shallow clone tip,
  2025-07-02, "Update Onion_ReadMe")
- **License type:** MIT *claimed* (README badge + "see the LICENSE
  file", README.md:8,218) — **no LICENSE file is present in the repo**;
  treat license as asserted, not verified.
- **Authors:** Ross Durrer (README.md:1, Onion_ReadMe:1); GitHub
  account ViperHawk (sole committer in visible history); `Onion Import
  Script` header credits only "MITRE Detection Library".

## Evidences rows

Fit rationale: the repo's event-id references land in the **evtx**
artefact family (crosswalk seed table row: `evtx | windows | winevt |
evtx_* (8 lanes)`); each row binds an event id to a legal (CAR object,
action) pair from `model/car/objects/*.yml`. All rows are
definitive/event-time because the evtx record natively attests the
action with its own timestamp — but every one is conditional on
collection being enabled (Sysmon deployed and its rule-filtered config
matching; 4688 requires process-creation auditing; 4103/4104 require
PowerShell module/script-block logging), so **absence of the record
evidences nothing**. That conditionality is stated per-row in `basis`.

```yaml
evtx:
  - object: process
    action: create
    evidence: definitive
    time: event-time
    basis: >-
      Sysmon EID 1, glossed by the source as "Process Creation"; native
      record of a new process (image, command line, parent) written at
      creation time. Conditional on Sysmon deployment + config match;
      absence proves nothing.
    source: mitre_detection_library.md:26 (also 34, 38, 40, 43; README.md:44)
  - object: process
    action: create
    evidence: definitive
    time: event-time
    basis: >-
      Windows Security EID 4688 ("A new process has been created"),
      cited alongside Sysmon 1 for process-creation coverage. Requires
      Audit Process Creation policy (command line only with the extra
      policy); when present, directly attests the create at event time.
    source: mitre_detection_library.md:26 (also 40, 43; README.md:43)
  - object: module
    action: load
    evidence: definitive
    time: event-time
    basis: >-
      Sysmon EID 7, glossed by the source as "Image loaded"; native
      record of a DLL/image loaded into a process (loading process +
      module path, hashes, signature). Cited for T1055.001 DLL-injection
      monitoring. Config-dependent (EID 7 is off/filtered by default in
      most Sysmon configs).
    source: mitre_detection_library.md:23 (also README.md:44)
  - object: thread
    action: remote_create
    evidence: definitive
    time: event-time
    basis: >-
      Sysmon EID 8, glossed by the source as "CreateRemoteThread";
      native record of one process creating a thread in another
      (source/target image, start address/function), cited for
      T1055.001/.002/.004 injection. Directly attests the cross-process
      thread create at event time.
    source: mitre_detection_library.md:24 (also 27, 29)
  - object: file
    action: create
    evidence: definitive
    time: event-time
    basis: >-
      Sysmon EID 11 (FileCreate), cited for startup-folder .lnk
      creation monitoring (T1547.009); native record of file creation
      with creating process and target filename. Rule-filtered:
      logs only configured paths/extensions.
    source: mitre_detection_library.md:7 (also 56; README.md:44)
  - object: registry
    action: value_edit
    evidence: definitive
    time: event-time
    basis: >-
      Sysmon EID 13 (registry value set), cited for Run/RunOnce and
      Winlogon key monitoring (T1547.001/.004) under Sigma
      registry_set; native record of process + TargetObject + written
      value at write time. Rule-filtered to configured key patterns.
    source: mitre_detection_library.md:4 (also 6, 53, 55; README.md:44)
  - object: user_session
    action: login
    evidence: definitive
    time: event-time
    basis: >-
      Windows Security EID 4624 ("An account was successfully logged
      on"), cited for RDP lateral-movement monitoring (T1021.001);
      attests logon-session establishment with logon type (10 =
      RemoteInteractive), account and source address at event time.
    source: mitre_detection_library.md:64 (also README.md:43)
  - object: authentication
    action: success
    evidence: definitive
    time: event-time
    basis: >-
      Same Security EID 4624 record read as the authentication event
      itself: successful credential validation for the account, logged
      at event time on the target host.
    source: mitre_detection_library.md:64 (also README.md:43)
  - object: authentication
    action: failure
    evidence: definitive
    time: event-time
    basis: >-
      Windows Security EID 4625 ("An account failed to log on"), cited
      with 4624 for RDP authentication monitoring; attests the failed
      authentication attempt (account, failure status, source) at
      event time.
    source: mitre_detection_library.md:64 (also README.md:43)
  - object: process
    action: execute
    evidence: definitive
    time: event-time
    basis: >-
      PowerShell Operational EID 4104 (Script Block Logging), cited for
      T1059.001; the engine records the script-block text as it is
      compiled/executed, directly attesting that the PowerShell host
      process executed that content at event time. Requires Script
      Block Logging enabled (source's own deployment note, line 84).
    source: mitre_detection_library.md:38 (also 39, 84; README.md:45)
  - object: process
    action: execute
    evidence: definitive
    time: event-time
    basis: >-
      PowerShell EID 4103 (Module/Pipeline Logging), cited alongside
      4104; records cmdlet/pipeline invocation with parameter binding
      inside the PowerShell host process at execution time. Requires
      Module Logging enabled.
    source: mitre_detection_library.md:38 (also README.md:45)
```

## Noted, not added

- **All Sigma rule snippets and detection selections** (the entire
  `Sigma Rules` column: `Image|endswith`, `CommandLine|contains`,
  `GrantedAccess: 0x1f3fff`, `CallTrace|contains`, etc.,
  mitre_detection_library.md throughout) — pure detection logic /
  SIEM-shaped heuristics; they select suspicious instances, they do
  not define what an artefact evidences. Fail the fit test.
- **ATT&CK technique/tactic mappings, severity methodology, coverage
  tables** (mitre_detection_library.md:91-126, README.md:108-124) —
  technique lists without artefact grounding.
- **Linux auditd references** (ptrace, /proc/[pid]/mem, mmap/vdso —
  mitre_detection_library.md:31, 32, 36) — concrete record types, but
  presented only as Sigma selection strings; audit-rule-dependent
  semantics are not stated, no crosswalk family binding is established
  (no auditd family row in the seed table), and no Windows event-id
  grounding. Not translated.
- **Generic log-source mentions without event ids** ("Email Security
  Logs", "DNS Logs", "UAC Event Logs", "SMB Logs", "Network Device
  Logs", "Memory Analysis Tools", "EDR/XDR Telemetry") — no artefact
  family, no record semantics.
- **Security Onion integration bundle** (`Onion_ReadMe`, `Onion
  Config`, `Onion Config Guide`, `Onion Import Script`, `quickstart
  script`) — deployment/conversion tooling (Sigma → Elasticsearch
  watchers, Kibana dashboards, API setup); operational plumbing, zero
  artefact semantics.
- **MITRE_Sigma.pdf** — 13-page browser-print (Skia/PDF, macOS
  Chrome-family UA in Creator) of the same detection table; duplicate
  content, nothing independent.
- **Sysmon EID 13 as generic "Registry Monitoring"**, "Windows
  Registry Monitoring", "File System Monitoring" phrasing on rows
  without ids — subsumed by the id-grounded rows above; no separate row.
- **README quick-start / repository-structure / contribution sections**
  — describe files and directories that do not exist in the repo;
  nothing to ingest, but they anchor the credibility caveat recorded
  in "What it is".

## Pipeline verdict

**Once-only.** Visible history is a single shallow-tip commit
(2025-07-02, sole committer ViperHawk) touching `Onion_ReadMe`; the
repo is a static 8-file document dump whose README-promised structure
(rule directories, tooling, LICENSE) was never committed, with no
releases and no sign of maintenance cadence. Its only contribution to
the evidences matrix is a set of standard evtx event-id glosses that
are better sourced from EVTX-ETW-Resources going forward; there is no
value in tracking it as a recurring feed. Ingest at pin
`4595c395d5391b0ec742f9a874e1ec388f16176a` and close.
