# DFIR context extract — Microsoft 365 Defender Hunting Queries

## What it is

Community/vendor corpus of KQL Advanced Hunting queries for the Microsoft 365
Defender cloud console (~9.1 MB, ~260 query files across 20+ tactic/campaign
directories). The queries run against live EDR/cloud telemetry tables
(DeviceProcessEvents, DeviceNetworkEvents, EmailEvents, CloudAppEvents, …),
not disk artefacts. Table-usage census over the whole corpus:
DeviceProcessEvents 154, DeviceFileEvents 59, DeviceNetworkEvents 53,
EmailEvents 23, CloudAppEvents 20, DeviceEvents 16, DeviceLogonEvents 12,
DeviceImageLoadEvents 12, DeviceRegistryEvents 7 — i.e. the corpus is
dominated by telemetry outside byakugan's disk-artefact families, as
expected. Value extracted here is the small set of query *patterns* (registry
key paths, task/service/logon semantics) whose underlying facts also land in
artefacts byakugan parses (registry hives, scheduled-task XML/TaskCache,
Security/System evtx, prefetch, MFT/UsnJrnl, $Recycle.Bin). The translation
always degrades the tier: what the sensor sees as an event-time action is, on
disk, usually definitive *presence* with bounded time (hive last-write) or
heuristic execution evidence (prefetch, no command line).

## Attribution

- **Name:** Microsoft 365 Defender Hunting Queries (Advanced Hunting)
- **URL:** https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries
- **Pin:** `efa17a600b43c897b4b7463cc8541daa1987eeb4` (last commit 2022-02-17, tali-ash)
- **License:** MIT (Copyright (c) Microsoft Corporation)
- **Authors:** Microsoft Threat Protection team plus named community
  contributors per file (e.g. Alex Verboon in
  `Persistence/LocalAdminGroupChanges.txt`, @janvonkirchheim in
  `Persistence/scheduled task creation.txt`; per-file `Contributor info`
  sections)
- **Status:** repository is **deprecated** — README redirects contributions to
  the Azure/Azure-Sentinel repo (`Hunting Queries/Microsoft 365 Defender`)

All `source:` paths below are relative to the repo root at the pin.

## Evidences rows

Translation rules applied: (1) a DeviceRegistryEvents *event* becomes hive
*state* — evidence of the value being set is definitive when the value is
present, but time degrades to the containing key's last-write (bounded);
(2) a DeviceProcessEvents command-line pattern survives only as heuristic
execution evidence (prefetch: named binary ran, event-time for last runs, no
arguments; evtx 4688 recovers the command line only when auditing was on);
(3) DeviceLogonEvents maps 1:1 onto Security.evtx 4624/4625, which byakugan's
evtx lanes parse — the one place the cloud query translates without loss.

### run-keys

```yaml
- object: registry
  action: value_edit
  evidence: definitive
  time: bounded
  basis: >
    Qakbot persistence sets a CurrentVersion\Run value whose data points at a
    binary under AppData\Roaming\Microsoft; in a hive the value's presence is
    definitive, timed only by the Run key's last-write timestamp.
  source: "Persistence/qakbot-campaign-registry-edit.md:17"
- object: process
  action: create
  evidence: inferred
  time: none
  basis: >
    A Run-key value naming an executable supports only an inference that the
    program executes at each logon; the hive records configuration, not runs.
  source: "Persistence/qakbot-campaign-registry-edit.md:17"
```

### registry-hives

```yaml
- object: registry
  action: value_edit
  evidence: definitive
  time: bounded
  basis: >
    IFEO Debugger value under Image File Execution Options\<accessibility
    binary> (sethc.exe, utilman.exe, osk.exe, ...) — accessibility-feature
    hijack; value presence in SOFTWARE hive is definitive, key last-write
    bounds when.
  source: "Persistence/Accessibility Features.txt:14"
- object: registry
  action: value_edit
  evidence: definitive
  time: bounded
  basis: >
    WDigest UseLogonCredential=1 under the wdigest key re-enables cleartext
    credential caching; SYSTEM-hive value presence is definitive, key
    last-write bounds when it was set.
  source: "Credential Access/wdigest-caching.md:16"
- object: registry
  action: value_edit
  evidence: definitive
  time: bounded
  basis: >
    Windows Defender Exclusions\{Paths,Extensions,Processes} values added to
    hide malware from AV (MosaicLoader); exclusion values in the SOFTWARE
    hive are definitive state, timed by key last-write.
  source: "Exploits/MosaicLoader.md:6"
- object: service
  action: modify
  evidence: heuristic
  time: bounded
  basis: >
    `sc config <svc> start= disabled` mass service disabling (ransomware
    prep) lands on disk as changed Start values under SYSTEM
    CurrentControlSet\Services; the changed value is definitive but
    attribution to sc.exe is heuristic, and time is key last-write (System
    evtx 7040 upgrades this to event-time when retained).
  source: "Ransomware/Turning off services using sc exe.md:10"
```

### scheduled-tasks

```yaml
- object: file
  action: create
  evidence: definitive
  time: bounded
  basis: >
    ScheduledTaskCreated (task registered by a non-SYSTEM account) leaves the
    task XML under C:\Windows\System32\Tasks and a TaskCache registry entry;
    presence is definitive, creation time bounded by filesystem/TaskCache
    timestamps (Security 4698, when audited, gives event-time and the
    registering principal — the query's SID filter translates only via 4698).
  source: "Persistence/scheduled task creation.txt:4"
- object: registry
  action: add
  evidence: definitive
  time: bounded
  basis: >
    The same registration writes the TaskCache\Tree / TaskCache\Tasks GUID
    entries in the SOFTWARE hive; entry presence is definitive, key
    last-write bounds registration time.
  source: "Persistence/scheduled task creation.txt:4"
- object: process
  action: execute
  evidence: heuristic
  time: event-time
  basis: >
    schtasks.exe invocation patterns (/create ... /rl highest for BEARLPE
    CVE-2019-0808; /change ...\SystemRestore\SR /disable for ransomware
    prep) translate to prefetch SCHTASKS.EXE-*.pf: execution and last-run
    times are event-time, but arguments are lost, so the specific pattern is
    only heuristic (evtx 4688 with command-line auditing recovers it).
  source: "Privilege escalation/cve-2019-0808-set-scheduled-task.md:17"
- object: process
  action: execute
  evidence: heuristic
  time: event-time
  basis: >
    schtasks.exe /change /disable of the SystemRestore task — same
    prefetch/4688 degradation as above; the /disable intent needs 4688 or
    the resulting task-XML Enabled flag change (bounded).
  source: "Execution/Possible Ransomware Related Destruction Activity.md:21"
```

### evtx

```yaml
- object: user_session
  action: login
  evidence: definitive
  time: event-time
  basis: >
    Brute-force shape — many LogonFailed then LogonSuccess from one public
    remote IP across multiple accounts — maps losslessly to Security.evtx
    4625/4624 sequences (IpAddress, TargetUserName, LogonType), which
    byakugan's evtx lanes parse with event-time.
  source: "Lateral Movement/Account brute force.txt:8"
- object: authentication
  action: failure
  evidence: definitive
  time: event-time
  basis: >
    The failed-attempt half of the same pattern: DeviceLogonEvents
    ActionType=="LogonFailed" is Security 4625 with failure substatus;
    per-account failure counts and distinct-account fan-out reconstruct
    directly from the log.
  source: "Lateral Movement/Account brute force.txt:9"
- object: process
  action: create
  evidence: heuristic
  time: event-time
  basis: >
    `net user <name> ... /add` account creation via net.exe/net1.exe:
    Security 4720 (user account created) gives definitive event-time for the
    account's creation; tying it to a net.exe invocation needs 4688 or
    prefetch and is heuristic. (CAR has no account object — the account
    itself is carried by the 4720 row's fields, the bindable pair is the
    creating process.)
  source: "Persistence/Create account.txt:34"
```

### mft / usnjrnl

```yaml
- object: file
  action: create
  evidence: definitive
  time: event-time
  basis: >
    PsExec-style lateral movement dropping multiple .exe files on admin
    shares in a short window: each drop is an $MFT record / $UsnJrnl
    FILE_CREATE with event-time; the burst-count heuristic (>4 files/10 min
    per host) reconstructs from the journal. Attribution to PsExec
    (-accepteula parent) needs 4688/prefetch and drops to heuristic.
  source: "Lateral Movement/remote-file-creation-with-psexec.md:20"
- object: file
  action: modify
  evidence: heuristic
  time: event-time
  basis: >
    Overwrite of accessibility binaries in Windows\System32 (sethc.exe et
    al. replaced with cmd/powershell): $MFT/$UsnJrnl record the
    modification with event-time, but proving the *content* swap needs the
    hash comparison the EDR does live — on disk only current-content
    hashing plus timestamps, so heuristic.
  source: "Persistence/Accessibility Features.txt:21"
```

### prefetch

```yaml
- object: process
  action: execute
  evidence: heuristic
  time: event-time
  basis: >
    Execution out of the recycle bin (cmd/ftp/schtasks/powershell/rundll32/
    regsvr32/msiexec with :\recycler paths): prefetch gives event-time
    execution of the named binary and its referenced-file list can expose
    the $Recycle.Bin/RECYCLER path of the payload; without arguments the
    binding of tool to recycler payload stays heuristic.
  source: "Execution/Malware_In_recyclebin.txt:7"
```

## Noted, not added

Category-level rejections (fit test: must bind a byakugan artefact family to
a legal CAR (object, action) pair; DeviceNetworkEvents/cloud-app/email
telemetry fails by definition):

- **Campaigns/ (80 files, largest directory):** almost entirely
  campaign-specific IOC sweeps — hashes, C2 IPs/domains, sender addresses —
  over DeviceNetworkEvents/EmailEvents/DeviceProcessEvents. Ephemeral
  indicators, not artefact semantics; the two registry-based ones (ZLoader
  company-name values `Campaigns/ZLoader/Suspicious Registry Keys.md:9`,
  CYZFC multi-table union) are IOC lookups, not reusable patterns. Not added.
- **Email Queries/, Delivery/, Collection/:** EmailEvents /
  EmailAttachmentInfo / CloudAppEvents (incl. MailItemsAccessed) — mailbox
  and cloud-app telemetry with no on-disk artefact byakugan parses. Not added.
- **Command and Control/, Network/, Exfiltration/:** DeviceNetworkEvents
  connection telemetry (RemoteIP/RemoteUrl, DNS, SMB sessions). byakugan has
  no live-flow family; SRUM records only per-app byte counts, which cannot
  carry these per-connection patterns. Fails the fit test wholesale.
- **Discovery/:** MDI IdentityQueryEvents (LDAP query ActionType) and
  process-commandline recon (whoami, net group) — domain-controller sensor
  telemetry and argument-dependent patterns lost outside 4688. Not added.
- **Identity/AAD items (Nobelium set in Persistence/ and Privilege
  escalation/):** CloudAppEvents / AADSignInEventsBeta service-principal
  credential additions, consent grants, role changes — pure cloud control
  plane. Not added.
- **Execution/ bulk (32 files):** obfuscated-PowerShell decoding, base64
  detectors, LOLBin parent-child trees (mshta, msiexec, wmic, office apps),
  macOS Shlayer/questd decoders — all hinge on command lines and
  parent-child links that exist only in EDR telemetry or 4688; prefetch
  reduces every one of them to "binary X ran", already captured generically
  above. PowerShellCommand ActionType rows are AMSI telemetry, not the 4104
  script-block log, and were not mapped.
- **DeviceImageLoadEvents queries (12 uses):** module-load telemetry;
  byakugan has no module-load artefact family (no Sysmon 7 assumption).
- **UserAccountAddedToLocalGroup (`Persistence/LocalAdminGroupChanges.txt:18`)
  and account-creation joins with IdentityInfo:** the on-disk counterparts
  (Security 4732/4720, SAM hive group membership) are real, but CAR's object
  set (process, file, registry, service, user_session, authentication, ...)
  has no account/group object — no legal pair to bind. Recorded here as a
  model gap observation rather than a row.
- **TVM/, Protection events/, Troubleshooting/, Fun/, General queries/,
  M365-PowerBi Dashboard/, Notebooks/, Webcasts/:** product configuration
  assessment, sensor health, dashboards and tutorial material — no artefact
  content at all.
- **Ransomware/ (25 files):** multi-signal composites over process/network
  telemetry; only the sc.exe service-disable pattern translated (row above).

## Pipeline verdict

**Once-only.** The repository is explicitly deprecated (README: "Deprecated —
we moved to Microsoft threat protection community", i.e. Azure/Azure-Sentinel)
and its last commit is 2022-02-17. There is nothing to poll; any recurring
DFIR-context feed should target the Azure-Sentinel repo's
`Hunting Queries/Microsoft 365 Defender` tree instead, where this corpus's
successors live. Yield here was low by design — 15 rows across 6 families
(run-keys, registry-hives, scheduled-tasks, evtx, mft/usnjrnl, prefetch) from
~260 queries, with the bulk of the corpus failing the fit test at the
telemetry-table level.
