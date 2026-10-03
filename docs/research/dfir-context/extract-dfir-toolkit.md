# DFIR context extract — fsfang/DFIR-Toolkit

## What it is

A single-author incident-response **collection-and-triage script kit**, not a knowledge
base: one Windows batch script, two POSIX shell scripts, and a README that doubles as
the manual.

- `Windows/DFIR.cmd` (1309 lines) — live-response / mounted-image collection plus a
  parse mode that drives RegRipper 3.0, Eric Zimmerman tools (EvtxECmd, MFTECmd, PECmd,
  SBECmd, JLECmd/LECmd, WxTCmd, SrumECmd, AmcacheParser, AppCompatCacheParser) over the
  collected artefacts (`Windows/DFIR.cmd:799-1090`). Its evidentiary content is the
  **EID curation**: per-purpose `EvtxECmd --inc` lists with semantic CSV names
  (AccountLogon, TrackProcess, AuditWindowsService, RDP_*, …) at
  `Windows/DFIR.cmd:943-1032`, mirrored in prose at `README.md:138-163`.
- `Linux/IR_Script.sh` (121 lines) — volatile-state capture, `find -printf` MACB
  timeline (`Linux/IR_Script.sh:77-78`), bash-history dumps (`:84-94`), `/var/log`
  copy, and `utmpdump` of utmp/wtmp/btmp (`:107-109`) with explicit glosses in
  `README.md:225-228` ("wtmp: all valid past logins", "btmp: bad logins").
- `Linux/crtime.sh` (9 lines) — ext-inode creation time via `debugfs -R stat`
  (`Linux/crtime.sh:4-8`).
- `OS X/IR_Script.sh` (148 lines) — live-command capture only (who/w/last, `history`
  at `OS X/IR_Script.sh:83`, launchctl, netstat).

Most of the repo is collection **geography** (what to copy from where); a minority of
lines carry evidentiary **semantics** (what an artefact proves). Only the latter feed
rows below.

## Attribution

- **Name:** DFIR-Toolkit
- **URL:** https://github.com/fsfang/DFIR-Toolkit
- **Pin:** `667e6284a05f77f4c6504ad79cb9113e744747ba` (shallow clone; HEAD commit
  2025-02-17, "Update README.md")
- **License:** **none** — no LICENSE file anywhere in the tree; default
  all-rights-reserved applies. Safe to cite as context; do not copy script text into
  byakugan.
- **Authors:** FS FANG (@fsfang) — declared in `Windows/DFIR.cmd:4`,
  `Linux/IR_Script.sh:5`, `OS X/IR_Script.sh:5`; sole committer.

## Evidences rows

Rows pass only where the resource itself carries the semantic claim (a purpose label,
an EID curation, or an explicit gloss); evidence/time tiers are byakugan's grading of
that claim. Sources are file:line at the pin.

```yaml
evtx:
  - object: user_session
    action: login
    evidence: definitive
    time: event-time
    basis: >-
      "Account Logon and Logon Events" curation selects Security 4624 into
      AccountLogon.csv; RDP flavour selects TerminalServices-LocalSessionManager
      21/22 into RDP_LocalSessionManager.csv (session logon, carries source IP).
    source: "Windows/DFIR.cmd:949; Windows/DFIR.cmd:1028; README.md:139; README.md:159-161"
  - object: user_session
    action: logout
    evidence: definitive
    time: event-time
    basis: >-
      Same curations: Security 4634/4647 (logoff / user-initiated logoff) and
      LocalSessionManager 23 (session logoff).
    source: "Windows/DFIR.cmd:949; Windows/DFIR.cmd:1028"
  - object: user_session
    action: reconnect
    evidence: definitive
    time: event-time
    basis: >-
      Security 4778/4779 (session reconnect/disconnect) in AccountLogon.csv and
      RDP_Security.csv; LocalSessionManager 24/25 (disconnect/reconnect).
    source: "Windows/DFIR.cmd:949; Windows/DFIR.cmd:1031; Windows/DFIR.cmd:1028"
  - object: authentication
    action: success
    evidence: definitive
    time: event-time
    basis: >-
      Security 4624 (also 4648 explicit-credential logon) selected under
      "Account Logon and Logon Events".
    source: "Windows/DFIR.cmd:949; README.md:139"
  - object: authentication
    action: failure
    evidence: definitive
    time: event-time
    basis: >-
      Security 4625 selected into AccountLogon.csv and RDP_Security.csv.
    source: "Windows/DFIR.cmd:949; Windows/DFIR.cmd:1031"
  - object: process
    action: create
    evidence: definitive
    time: event-time
    basis: >-
      Security 4688 selected into TrackProcess.csv under "Process Tracking";
      availability caveat carried by the resource itself: "EID: 4688 Default
      disabled" — absence of rows is not absence of process creation.
    source: "Windows/DFIR.cmd:996; README.md:150"
  - object: process
    action: execute
    evidence: definitive
    time: event-time
    basis: >-
      "Program Execution" label over the AppLocker "EXE and DLL" channel
      (execution allow/block decisions logged at execution time).
    source: "Windows/DFIR.cmd:1002; README.md:151"
  - object: process
    action: execute
    evidence: definitive
    time: event-time
    basis: >-
      "PowerShell Events" curation selects 4103 (module logging) / 4104
      (script-block logging) plus classic 400/800 — records of PowerShell code
      as executed.
    source: "Windows/DFIR.cmd:1014-1015; README.md:153-155"
  - object: service
    action: create
    evidence: definitive
    time: event-time
    basis: >-
      "Windows Services Auditing" curation includes 4697 (service installed,
      Security) and 7045 (System). Defect in the resource: the whole EID list
      (6005,6006,7034,7036,7040,7045,4697) is run against Security.evtx only, so
      in that script every EID except 4697 can never match — seed the 4697
      binding from here, not the System-channel ones.
    source: "Windows/DFIR.cmd:981; README.md:148"

shimcache:
  - object: process
    action: execute
    evidence: heuristic
    time: bounded
    basis: >-
      appcompatcache/shimcache RegRipper plugins and AppCompatCacheParser output
      are filed under "SoftwareExecutedHistory" — the toolkit's own execution
      label. Graded heuristic: on Win8+ shimcache proves presence/compat lookup,
      not execution, and its timestamp is the file's $SI last-modified, so run
      time is only bounded by cache insertion order.
    source: "Windows/DFIR.cmd:844-845; Windows/DFIR.cmd:848; README.md:134"

registry-hives:
  - object: service
    action: metadata
    evidence: definitive
    time: none
    basis: >-
      SYSTEM hive "services" plugin enumerates installed service configuration
      (image path, start type) under SystemConfiguration — state, not an event.
    source: "Windows/DFIR.cmd:834"

run-keys:
  - object: process
    action: execute
    evidence: inferred
    time: none
    basis: >-
      run/runonceex plugin outputs are merged into "SystemAutostartPrograms.txt"
      — the toolkit asserts autostart intent: the value's presence infers future
      execution at boot/logon, never a record of a past run.
    source: "Windows/DFIR.cmd:880; Windows/DFIR.cmd:833"

lnk-jumplists:
  - object: file
    action: access
    evidence: heuristic
    time: event-time
    basis: >-
      Collected and parsed as "Recent files (AutomaticDestinations,
      CustomDestinations, *.lnk)" via JLECmd/LECmd — the "Recent" label asserts
      target files were opened; heuristic because shell creates/updates entries
      for some non-open interactions.
    source: "README.md:78; README.md:166; Windows/DFIR.cmd:1070-1072"

wtmp:
  - object: user_session
    action: login
    evidence: definitive
    time: event-time
    basis: >-
      Resource gloss: "wtmp: all valid past logins", "utmp: current login user
      (in memory)"; dumped with utmpdump; corroborated by "Users past and
      present: last".
    source: "README.md:226-227; Linux/IR_Script.sh:107-108; README.md:198"
  - object: authentication
    action: failure
    evidence: definitive
    time: event-time
    basis: >-
      Resource gloss: "btmp: bad logins" and "failed login attempts: lastb";
      dumped with utmpdump /var/log/btmp.
    source: "README.md:228; README.md:199; Linux/IR_Script.sh:109"

shell-history:
  - object: process
    action: execute
    evidence: heuristic
    time: none
    basis: >-
      .bash_history dumped per user and root; OS X captures "Command history
      list: history". A history line evidences a command entered for execution;
      heuristic (editable, truncatable) and timestampless by default.
    source: "README.md:203-207; Linux/IR_Script.sh:84-94; OS X/IR_Script.sh:83; README.md:284"

filestat:
  - object: file
    action: metadata
    evidence: definitive
    time: event-time
    basis: >-
      Live MACB timeline: find -printf with Access/Modify/Change date-time
      columns per file; Windows modes list the same "System Timeline (MAC)".
    source: "README.md:200-201; Linux/IR_Script.sh:77-78; README.md:72"
  - object: file
    action: modify
    evidence: inferred
    time: event-time
    basis: >-
      mtime column of the same timeline — time of the LAST content modification
      only; earlier modifications are overwritten.
    source: "README.md:200-201; Linux/IR_Script.sh:78"
  - object: file
    action: access
    evidence: inferred
    time: event-time
    basis: >-
      atime column of the same timeline — last access only, and degraded by
      noatime/relatime mount options (caveat is byakugan's, not the resource's).
    source: "README.md:200-201; Linux/IR_Script.sh:78"
  - object: file
    action: create
    evidence: definitive
    time: event-time
    basis: >-
      crtime.sh reads the ext inode crtime via debugfs -R 'stat <inode>' —
      dedicated file-creation-time recovery.
    source: "Linux/crtime.sh:4-8; README.md:246-249"
```

## Noted, not added

- **Account Management EIDs** (4720…4799, `Windows/DFIR.cmd:943`) — no CAR object for
  user accounts among the 13; user_session actions cover sessions, not account CRUD.
- **Scheduled tasks** (TaskScheduler 106/140/141/200/201, Security 4698-4702,
  at/tasks/taskcache plugins; `DFIR.cmd:961-962,854-856`) — no CAR scheduled-task
  object; binding 200/201 to process create is not asserted by the resource.
- **Network Share Objects** 5140-5145 (`DFIR.cmd:955`) — share-object access does not
  map cleanly to (file, access).
- **Object Handle Auditing** 4656/4657/4658/4660/4663 (`DFIR.cmd:968`) — object type
  ambiguous (file vs registry vs other); toolkit label carries no object.
- **Audit policy change** 4719/1102/104 (`DFIR.cmd:974-975`) — no CAR object.
- **WiFi Connection** 8001/8002 (`DFIR.cmd:987`) — no clean flow binding; also aimed
  at Security.evtx though these are WLAN-AutoConfig Operational EIDs (same defect
  class as the services line).
- **Sysmon** bulk pull, EIDs 1-22 (`DFIR.cmd:1008`) — channel-wide with no per-EID
  purpose asserted; Sysmon semantics should be seeded from Sysmon documentation, not
  this curation.
- **Windows Defender / AV logs** (`DFIR.cmd:1021-1022`, `README.md:96`) — detection
  alerts; no CAR object.
- **Amcache** (`DFIR.cmd:908`, collected at `:330-349`) — parsed with AmcacheParser
  but the toolkit's "SoftwareExecutedHistory" label is applied only to
  appcompatcache/shimcache; no evidentiary claim to import for amcache.
- **UserActivity registry parses** (userassist, recentdocs, typedurls, muicache,
  shellbags plugin, runmru…, `DFIR.cmd:878-898`) — generic "UserActivity" label
  carries no bindable action; userassist→execute would import outside knowledge.
- **Geography-only collections/parses** — prefetch (`DFIR.cmd:1081`), MFT/UsnJrnl/
  $LogFile (`:1041-1049`), SRUM (`:1090`), shellbags via SBECmd (`:1059`),
  ActivitiesCache/WxTCmd (`:930`), browser history, $Recycle.Bin, Windows.edb,
  bitmap cache, WMI repository, CryptnetUrlCache, IIS logs, setupapi/USB
  (`README.md:73-96`): collected and/or parsed with no (object, action) claim in the
  resource; their bindings belong to the parsers' own documentation.
- **PowerShell ConsoleHost_history** (`README.md:80`) — no byakugan family
  (shell-history is linux/macos-scoped in the seed table).
- **accounts family** (/etc/passwd, /etc/shadow, samparse; `README.md:194-195`,
  `DFIR.cmd:818`) — enumeration only, no action semantics.
- **cron-persistence** (`README.md:219-223`) — `cp -r /etc/cron*`, geography only.
- **Live volatile capture** (netstat/ps/lsof/logonsessions/launchctl/arp, all three
  platforms) — live state, not artefact families in the seed table.
- **Repo defect worth remembering:** `DFIR.cmd:981` and `:987` run System/WLAN-channel
  EIDs against Security.evtx — only 4697 can ever match there; any future re-read must
  not seed 6005/7036/7045/8001 bindings from this resource.

## Pipeline verdict

**Once-only.** Single-author personal toolkit; the shallow clone's HEAD
(`667e6284…`, 2025-02-17) is a README-only touch, and the in-repo changelog
(`Windows/README.md`, v1.0.0 → v2.0.1) shows a slow, versioned cadence with the last
functional change at v2.0.1. The material byakugan consumes — EID curations and
artefact glosses — is stable prose/constants, not living data. No recurring watch;
re-ingest only if a new major version of DFIR.cmd appears.
