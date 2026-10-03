# Extract: nasbench/EVTX-ETW-Resources → byakugan evidences (evtx family)

## What it is

A community catalog of Windows event logging ground truth: raw ETW provider manifests (XML)
dumped per Windows build (`ETWProvidersManifests/`, ~890 providers per build, Windows 7 → 11
24H2 and Server), per-provider CSV catalogs of every event ID with channel, opcode, message
template and field list (`ETWProvidersCSVs/Internal` for in-box providers,
`ETWProvidersCSVs/ThirdParty` for Sysmon, Defender, SentinelOne, Splashtop, Office …), and
per-build combined event lists (`ETWEventsList/CSV/<WindowsN>/<release>/…` +
`etw-global-stats.csv`). It is the authoritative "what can this provider/channel/event ID
record, and what fields does the record carry" reference — exactly the knowledge that types
what an evtx record evidences. Note: this repo contains no `EVTXPathsList` file (that catalog
lives elsewhere); its channel knowledge is carried in the `Channel` column of the CSVs.

CSV schema (every catalog file):
`Event ID,Event Version,Level,Channel,Task,Opcode,Keyword,Windows,Version,Edition,Date,Build,Event Message,Event Fields`.

Encoding trap for joins: classic System-channel providers store qualified IDs — Service
Control Manager 7045 appears as `1073748869` (0x40001B85; displayed ID = low 16 bits). See
`ETWProvidersCSVs/Internal/Service Control Manager.csv:986`.

## Attribution

- **Name:** EVTX-ETW-Resources
- **URL:** https://github.com/nasbench/EVTX-ETW-Resources
- **Pin:** `a3fa2bdbfd123907b8a10cfa87da9b3da0db2e74` (shallow clone, 2026-09-30)
- **License:** MIT (Copyright (c) 2022 Nasreddine Bencherchali)
- **Authors:** Nasreddine Bencherchali (nasbench) + community contributors

All `source:` paths below are relative to the repo root at the pin above.

## Evidences rows

Typing rationale: an event log record is a contemporaneous assertion by the OS/provider that
the action occurred — `evidence: definitive`, `time: event-time` — except where the record
logs an *attempt* or the object binding is indirect (marked heuristic). byakugan's evtx lanes
already parse: Security 4624/4625/4672 (evtx_security), 4624/4634/4647/4778/4779
(evtx_security_sessions), 4688 (evtx_process), 4697 + System 7045 (evtx_services),
4907/5857/20003/30803/7001/7002/7034 (evtx_more), BITS 59/60 (evtx_bits), TerminalServices
21/24/25 (evtx_rdp), Sysmon (evtx_sysmon). Rows below cover both the parsed set and the
classic ids the lanes do not yet reach (5140/5145, 1102, 4648, 4689, Sysmon 2/25).

```yaml
# --- Security channel, provider Microsoft-Windows-Security-Auditing ---
- object: authentication
  action: success
  evidence: definitive
  time: event-time
  basis: Security 4624 "An account was successfully logged on" — provider Microsoft-Windows-Security-Auditing, Security channel; fields carry subject/target SID+name, LogonType, AuthenticationPackage, workstation/IP.
  source: ETWProvidersCSVs/Internal/Microsoft-Windows-Security-Auditing.csv:2965
- object: authentication
  action: failure
  evidence: definitive
  time: event-time
  basis: Security 4625 "An account failed to log on" — Status/SubStatus/FailureReason give the decision reason.
  source: ETWProvidersCSVs/Internal/Microsoft-Windows-Security-Auditing.csv:3704
- object: authentication
  action: success
  evidence: heuristic
  time: event-time
  basis: Security 4648 "A logon was attempted using explicit credentials" — records the attempt (runas / lateral use of alternate creds), outcome only via paired 4624; binds acting process to target account/server.
  source: ETWProvidersCSVs/Internal/Microsoft-Windows-Security-Auditing.csv:5176
- object: user_session
  action: login
  evidence: definitive
  time: event-time
  basis: Security 4624 with interactive-class LogonType (2/7/10/11) — session establishment on the host, TargetLogonId keys the session.
  source: ETWProvidersCSVs/Internal/Microsoft-Windows-Security-Auditing.csv:2965
- object: user_session
  action: logout
  evidence: definitive
  time: event-time
  basis: Security 4634 "An account was logged off" / 4647 "User initiated logoff" cluster; 4779 covers RDP/console session disconnect.
  source: ETWProvidersCSVs/Internal/Microsoft-Windows-Security-Auditing.csv:4435
- object: user_session
  action: reconnect
  evidence: definitive
  time: event-time
  basis: Security 4778 "A session was reconnected to a Window Station" (4779 = disconnect counterpart).
  source: ETWProvidersCSVs/Internal/Microsoft-Windows-Security-Auditing.csv:37080
- object: user_session
  action: metadata
  evidence: definitive
  time: event-time
  basis: Security 4672 "Special privileges assigned to new logon" — types the new session as admin-equivalent (privilege list attribute of the session opened by the paired 4624).
  source: ETWProvidersCSVs/Internal/Microsoft-Windows-Security-Auditing.csv:11836
- object: process
  action: create
  evidence: definitive
  time: event-time
  basis: Security 4688 "A new process has been created" — NewProcessId/NewProcessName, creator subject, ParentProcessName, TokenElevationType, CommandLine when audited.
  source: ETWProvidersCSVs/Internal/Microsoft-Windows-Security-Auditing.csv:12824
- object: process
  action: terminate
  evidence: definitive
  time: event-time
  basis: Security 4689 "A process has exited" — closes the lifetime opened by 4688.
  source: ETWProvidersCSVs/Internal/Microsoft-Windows-Security-Auditing.csv:13554
- object: service
  action: create
  evidence: definitive
  time: event-time
  basis: Security 4697 "A service was installed in the system" (audit-policy gated) — service name, image path, service/start type, account.
  source: ETWProvidersCSVs/Internal/Microsoft-Windows-Security-Auditing.csv:15530
- object: file
  action: access
  evidence: definitive
  time: event-time
  basis: Security 5140 "A network share object was accessed" / 5145 "…checked to see whether client can be granted desired access" — share-level access with client address, subject and (5145) relative target file name; evidences remote file access via SMB.
  source: ETWProvidersCSVs/Internal/Microsoft-Windows-Security-Auditing.csv:83312
- object: file
  action: acl_modify
  evidence: definitive
  time: event-time
  basis: Security 4907 "Auditing settings on object were changed" — SACL change on the named object (byakugan evtx_more already maps this).
  source: ETWProvidersCSVs/Internal/Microsoft-Windows-Security-Auditing.csv:56517

# --- Security channel, provider Microsoft-Windows-Eventlog ---
- object: file
  action: modify
  evidence: definitive
  time: event-time
  basis: Security 1102 "The audit log was cleared" (provider Microsoft-Windows-Eventlog, Task "Log clear") — the Security.evtx content was truncated by the recorded subject; anti-forensic indicator-removal, survives as the first record of the new log.
  source: ETWProvidersCSVs/Internal/Microsoft-Windows-Eventlog.csv:8062

# --- System channel ---
- object: service
  action: create
  evidence: definitive
  time: event-time
  basis: System 7045 "A service was installed in the system" — provider Service Control Manager; fields ServiceName, ImagePath, ServiceType, StartType, AccountName. Stored under qualified ID 1073748869 in the manifest CSV.
  source: "ETWProvidersCSVs/Internal/Service Control Manager.csv:986"
- object: service
  action: stop
  evidence: definitive
  time: event-time
  basis: System 7034 (service terminated unexpectedly) / 7036 state-change cluster — Service Control Manager; byakugan evtx_more already maps 7034.
  source: "ETWProvidersCSVs/Internal/Service Control Manager.csv"
- object: user_session
  action: login
  evidence: definitive
  time: event-time
  basis: System 7001 Winlogon logon notification (7002 = logoff counterpart); corroborates Security 4624 when Security log is unavailable or cleared.
  source: ETWProvidersCSVs/Internal/ (Winlogon provider CSV; ids parsed by byakugan evtx_more)

# --- TerminalServices-LocalSessionManager/Operational ---
- object: user_session
  action: login
  evidence: definitive
  time: event-time
  basis: TerminalServices-LocalSessionManager 21 (session logon succeeded, RDP) — user, session id, source address; 24 = disconnect, 25 = reconnect.
  source: ETWProvidersCSVs/Internal/Microsoft-Windows-TerminalServices-LocalSessionManager.csv:3692
- object: user_session
  action: reconnect
  evidence: definitive
  time: event-time
  basis: TerminalServices-LocalSessionManager 25 (session reconnection succeeded); 24 pairs as the disconnect.
  source: ETWProvidersCSVs/Internal/Microsoft-Windows-TerminalServices-LocalSessionManager.csv

# --- Microsoft-Windows-Bits-Client/Operational ---
- object: http
  action: get
  evidence: definitive
  time: event-time
  basis: Bits-Client 59 (transfer job started, opcode Start, URL in fields) / 60 (job stopped with status) — evidences the HTTP(S) transfer byakugan's evtx_bits lane parses.
  source: ETWProvidersCSVs/Internal/Microsoft-Windows-Bits-Client.csv:8666

# --- Microsoft-Windows-Sysmon/Operational (ThirdParty provider catalog) ---
- object: process
  action: create
  evidence: definitive
  time: event-time
  basis: Sysmon 1 process creation — image, command line, hashes, parent, ProcessGuid chain.
  source: ETWProvidersCSVs/ThirdParty/Microsoft-Windows-Sysmon.csv:2
- object: file
  action: timestomp
  evidence: definitive
  time: event-time
  basis: Sysmon 2 file creation time changed — records previous and new timestamp plus the changing process. Not yet in byakugan's evtx_sysmon lane; CAR file.timestomp exists.
  source: ETWProvidersCSVs/ThirdParty/Microsoft-Windows-Sysmon.csv:3
- object: flow
  action: start
  evidence: definitive
  time: event-time
  basis: Sysmon 3 network connection detected — src/dst ip:port, protocol, owning process.
  source: ETWProvidersCSVs/ThirdParty/Microsoft-Windows-Sysmon.csv:4
- object: process
  action: terminate
  evidence: definitive
  time: event-time
  basis: Sysmon 5 process terminated.
  source: ETWProvidersCSVs/ThirdParty/Microsoft-Windows-Sysmon.csv:6
- object: driver
  action: load
  evidence: definitive
  time: event-time
  basis: Sysmon 6 driver loaded — image, hashes, signature status.
  source: ETWProvidersCSVs/ThirdParty/Microsoft-Windows-Sysmon.csv:7
- object: module
  action: load
  evidence: definitive
  time: event-time
  basis: Sysmon 7 image loaded — module path, hashes, signer, loading process.
  source: ETWProvidersCSVs/ThirdParty/Microsoft-Windows-Sysmon.csv:8
- object: thread
  action: remote_create
  evidence: definitive
  time: event-time
  basis: Sysmon 8 CreateRemoteThread — source and target process, start address/function.
  source: ETWProvidersCSVs/ThirdParty/Microsoft-Windows-Sysmon.csv:9
- object: process
  action: access
  evidence: definitive
  time: event-time
  basis: Sysmon 10 process accessed — granted access mask, call trace, source/target.
  source: ETWProvidersCSVs/ThirdParty/Microsoft-Windows-Sysmon.csv:11
- object: file
  action: create
  evidence: definitive
  time: event-time
  basis: Sysmon 11 file create — target filename, creating process, CreationUtcTime.
  source: ETWProvidersCSVs/ThirdParty/Microsoft-Windows-Sysmon.csv:12
- object: registry
  action: add
  evidence: definitive
  time: event-time
  basis: Sysmon 12 registry key/value create (delete variant maps to registry.remove).
  source: ETWProvidersCSVs/ThirdParty/Microsoft-Windows-Sysmon.csv:13
- object: registry
  action: value_edit
  evidence: definitive
  time: event-time
  basis: Sysmon 13 registry value set — key path, value data, writing process.
  source: ETWProvidersCSVs/ThirdParty/Microsoft-Windows-Sysmon.csv:14
- object: registry
  action: key_edit
  evidence: definitive
  time: event-time
  basis: Sysmon 14 registry key/value rename.
  source: ETWProvidersCSVs/ThirdParty/Microsoft-Windows-Sysmon.csv:15
- object: file
  action: delete
  evidence: definitive
  time: event-time
  basis: Sysmon 23 file delete (archived) / 26 file delete logged — deleting process, hashes.
  source: ETWProvidersCSVs/ThirdParty/Microsoft-Windows-Sysmon.csv:24
- object: process
  action: modify
  evidence: definitive
  time: event-time
  basis: Sysmon 25 process tampering (image change / hollowing indicator) — not yet in byakugan's evtx_sysmon lane; CAR process.modify exists.
  source: ETWProvidersCSVs/ThirdParty/Microsoft-Windows-Sysmon.csv:26
```

## Noted, not added

**Account-management ids — the known CAR vocabulary gap.** No CAR object covers a local/domain
account as an object, so these classic Security ids cannot be bound without force-fitting.
Evidence for the vocabulary decision (all Microsoft-Windows-Security-Auditing, Security channel,
would be definitive/event-time if an `account`/`user` object existed):

- 4720 account created — `ETWProvidersCSVs/Internal/Microsoft-Windows-Security-Auditing.csv:21811`
- 4722/4723/4724/4725 enable / password change / password reset / disable — same CSV, cluster following 4720
- 4726 account deleted — same CSV line 23046
- 4728/4732/4756 member added to security-enabled group — same CSV
- 4738 account changed — same CSV line 26241
- 4740 account locked out — same CSV

**Scheduled-task ids — same gap class.** Security 4698–4702 (task created/deleted/enabled/
disabled/updated; same CSV lines 15919–17475) and Microsoft-Windows-TaskScheduler/Operational
106/140/141 (`ETWProvidersCSVs/Internal/Microsoft-Windows-TaskScheduler.csv:1484`) have no CAR
scheduled-task object. High-value persistence evidence; do not force-fit onto `service`.

**Other sysmon ids without a home:** 17/18 named pipes (no pipe object; `socket` is not a fit),
19/20/21 WMI event subscription (no wmi object), 22 DNS query (no dns object; `flow`/`http` are
not a fit). Sysmon 15 alternate data stream created could arguably be file.create but is left
out to keep the row set bounded.

**Beyond the fit, the repo also offers** (useful later, not evidences rows):
- Per-build raw ETW provider manifests (`ETWProvidersManifests/<WindowsN>/…`, ~890 XML per build) — field-level provenance for any future lane.
- Per-build combined event inventories (`ETWEventsList/CSV/…` + `etw-global-stats.csv`) — diffable "which events exist in build X" baselines (e.g. W11 24H2 26100.1742).
- ThirdParty provider catalogs (Defender, SentinelOne, Splashtop, Office) — candidate future lanes for AV/RMM telemetry.
- `Scripts/etw-to-csv.py` — their extraction tooling, reproducible if we ever dump our own builds.
- No `EVTXPathsList` file exists in this repo at this pin; channel names come from the CSVs' Channel column.

## Pipeline verdict

**Once-only ingest with a slim vendored index; a pinned 17GB submodule is not warranted.**

- The repo does update with Windows builds (README stats table shows per-build snapshots), but
  what byakugan consumes — the semantics of the classic Security/System/Sysmon ids above — is
  stable across builds; new builds mostly add ETW providers byakugan does not parse.
- The 17GB working tree is dominated by per-build manifest XMLs and per-build event lists.
  A slim index that keeps only: the ~10 provider CSVs cited above (Security-Auditing, Eventlog,
  Service Control Manager, TaskScheduler, Bits-Client, TerminalServices-LocalSessionManager,
  Winlogon, Sysmon) plus `etw-global-stats.csv` and the README is a few MB and carries
  everything the evidences matrix needs.
- Recommendation: record the pin `a3fa2bdbfd123907b8a10cfa87da9b3da0db2e74` in this extract,
  vendor the slim CSV slice if the matrix build wants machine-checkable sources, and re-visit
  only when byakugan adds a new evtx lane (then pull just that provider's CSV). If recurring
  sync is ever wanted, a sparse-checkout of `ETWProvidersCSVs/` alone (no manifests, no
  per-build lists) is the right shape — not a forensicartifacts-style full submodule.