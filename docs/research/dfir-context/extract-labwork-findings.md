# DFIR context extract — LabWork_Findings

## What it is

A single-author security-research repository of ~60 markdown lab writeups (plus
two offensive Python tools and a few screenshots), documenting controlled
Windows/Active-Directory attack chains in an enterprise-modeled home lab
(Server 2019/2022/2025, Kali, Sysmon 15.x, Winlogbeat → Elasticsearch 8.x).
The stated frame is detection engineering: "Observed system behavior →
adversarial chaining → telemetry reality → defensive implication" — chains with
raw telemetry, detection gaps, and KQL/EQL. The **entire evidentiary surface is
live Windows event telemetry**: Security.evtx, Microsoft-Windows-Sysmon/Operational,
Microsoft-Windows-PowerShell/Operational, and Microsoft-Windows-Windows
Defender/Operational. There are **no disk-resident forensic-artefact claims**
anywhere in the corpus (no amcache / prefetch / shimcache / $MFT / $UsnJrnl /
SRUM / shellbags / userassist / jumplists / recyclebin — verified by content
grep). Consequently every row that fits binds to exactly one byakugan family:
**evtx** (crosswalk lane `evtx_*`, FA provenance `WindowsEventLogs` +
per-channel `WindowsXMLEventLog*`). The specific Event ID is the row `basis`.

## Attribution

- **Name:** LabWork_Findings ("Security Research")
- **URL:** https://github.com/osherjacobs/LabWork_Findings
- **Pin:** `27c61d68e3d36663630142cc4fec6fa9e8eebc31` (shallow clone, single commit visible; tip dated 2026-06-29)
- **Authors:** O.J. / osherjacobs (`osherjacobs@users.noreply.github.com`)
- **License:** none declared (no LICENSE/COPYING file; no license statement in README)

## Evidences rows

All rows are family `evtx`. `time: event-time` throughout — each Windows event
record carries its own `TimeCreated`. Sources are `file:line` at pin above.

```yaml
family: evtx
rows:
  - object: process
    action: access
    evidence: definitive
    time: event-time
    basis: >
      Sysmon EID 10 (ProcessAccess) records the inter-process memory access to
      lsass.exe; GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) from a non-system
      binary + UNKNOWN CallTrace is the credential-theft indicator. Fires on the
      access attempt regardless of whether the dump artifact survives; requires a
      Sysmon config with an lsass include rule (silent by default).
    source: vector4-lsass-dump-detection.md:360-401

  - object: process
    action: access
    evidence: definitive
    time: event-time
    basis: >
      Security EID 4663 with PROCESS_VM_READ on lsass evidences the memory-read
      access via the object-access audit subsystem (Windows Security audit),
      independent of Sysmon.
    source: vector_unc_dcomexec.md:258

  - object: process
    action: create
    evidence: definitive
    time: event-time
    basis: >
      Sysmon EID 1 (ProcessCreate) records Image, CommandLine, ParentCommandLine,
      CurrentDirectory, IntegrityLevel — e.g. child processes carrying
      ParentCommandLine "powershell.exe -ep bypass -File C:\Windows\Tasks\ld.ps1",
      and WmiPrvSE.exe parent = remote WMI execution.
    source: scheduled-task-persistence-detection.md:158-159

  - object: process
    action: execute
    evidence: heuristic
    time: event-time
    basis: >
      PowerShell/Operational EID 4104 (ScriptBlock logging) captures executed
      PowerShell content (Invoke-Expression, tooling, reflection). Binding to
      process:execute is indirect (it logs script content, not an OS process
      exec); much of the corpus documents its ABSENCE post-ETW-tamper as a
      detection gap, so treat presence as heuristic evidence of execution.
    source: etw_handle_substitution.md:74-76

  - object: file
    action: create
    evidence: definitive
    time: event-time
    basis: >
      Sysmon EID 11 (FileCreate) logged at drop time, before attrib/hiding is
      applied — e.g. ld.ps1 / ld.exe written under C:\Windows\Tasks\.
    source: scheduled-task-persistence-detection.md:66,156

  - object: file
    action: read
    evidence: definitive
    time: event-time
    basis: >
      Security EID 5145 (Detailed File Share) records share connect + directory
      listing with AccessMask ReadData (0x81) / ReadAttributes (0x80) and
      ShareName \\*\C$; fired by the SMB subsystem, no SACL on C:\ required.
    source: admin-share-detection.md:94-130,174-177

  - object: file
    action: access
    evidence: definitive
    time: event-time
    basis: >
      Security EID 5140 (File Share) records the share object (C$) being
      accessed; pairs with 5145 for the connect event.
    source: admin-share-detection.md:55,175

  - object: flow
    action: create
    evidence: definitive
    time: event-time
    basis: >
      Sysmon EID 3 (NetworkConnect) records outbound connections with dest
      IP/port and initiating Image (e.g. getit1.exe -> 192.168.1.218:8443, no
      hostname resolution). Requires network rules in Sysmon config to fire.
    source: admin-share-detection.md:86

  - object: registry
    action: value_edit
    evidence: definitive
    time: event-time
    basis: >
      Sysmon EID 13 (RegistryValueSet) on Defender keys, e.g.
      HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet\SubmitSamplesConsent —
      evidences silent pre-execution Defender degradation via a registry value
      change.
    source: scheduled-task-persistence-detection.md:259,266

  - object: user_session
    action: login
    evidence: definitive
    time: event-time
    basis: >
      Security EID 4624 records successful logon with LogonType (3 = network,
      10 = RDP), source IP, and Logon GUID enabling cross-session correlation
      (Kerberos vs NTLM origin distinguishable).
    source: golden-dmsa.md:171

  - object: user_session
    action: login
    evidence: definitive
    time: event-time
    basis: >
      Security EID 4625 records failed logon attempts (used here to observe
      Responder-induced NTLM auth failures).
    source: responder_lab_writeup.md:214

  - object: authentication
    action: success
    evidence: definitive
    time: event-time
    basis: >
      Security EID 4768 records Kerberos TGT issuance (PreAuthType 16,
      CertIssuerName for PKINIT, TargetUserName, ClientAddress) — a single TGT
      request for a service account outside normal startup windows is anomalous.
    source: shadow-credentials-dacl-detection.md:147

  - object: authentication
    action: success
    evidence: heuristic
    time: event-time
    basis: >
      Security EID 4769 records Kerberos TGS requests; high volume / low signal
      alone. S4U2proxy leaves a populated "Transited Services" field, which is
      the confirmation fingerprint when correlated to a delegation-attribute
      write. (One lab found 4769 did NOT fire for a U2U getnthash exchange —
      DC-config-dependent blind spot.)
    source: rbcd-persistence.md:308-321

  - object: authentication
    action: success
    evidence: definitive
    time: event-time
    basis: >
      Security EID 4776 records NTLM credential validation (account, protocol);
      fires before any in-session bypass code executes, so it is the earliest
      NTLM-auth indicator.
    source: amsi-etw-lowpriv.md:129
```

## Noted, not added

**Event-log claims whose byakugan family (evtx) fits but which bind to NO legal
CAR (object, action) pair** — byakugan's CAR object set is
{authentication, driver, email, file, flow, http, module, process, registry,
service, socket, thread, user_session}; there is no directory-object / group /
scheduled-task / AV-verdict object, so these have no legal pair to bind:

- **EID 5136** (Directory Service object modification — attribute writes to
  `msDS-KeyCredentialLink`, `msDS-AllowedToActOnBehalfOfOtherIdentity`,
  `nTSecurityDescriptor`). Strong, recurring evidence claim across
  `shadow-credentials-dacl-detection.md:126`, `rbcd-persistence.md:243`,
  `badsuccessor-writeup.md:301`, but no AD-object CAR pair. Also SACL-gated.
- **EID 4662** (Directory Service object access — WRITE_DAC/WRITE_OWNER,
  KDS-root-key reads, LDAP-enum bursts). `shadow-credentials-dacl-detection.md:84`,
  `golden-dmsa.md:158`, `amsi-etw-lowpriv.md:73`. No AD-object CAR pair; SACL-gated.
- **EID 4698** (scheduled task created — full XML incl. Hidden:true, LocalSystem,
  -ep bypass). `scheduled-task-persistence-detection.md:157`. Maps to the
  byakugan `scheduled-tasks` family conceptually, but there is no `scheduled_task`
  CAR object and the evidence source here is Security.evtx, not the on-disk
  TaskCache the scheduled-tasks family covers.
- **EID 4728** (member added to security-enabled global group).
  `dacl_addmembers_attack_path.md:503`. No group CAR object.
- **EID 5007** (Defender configuration/exclusion change; Old Value/New Value).
  `vector6-lsass-exclusion-window.md:164-202` — a strong behavioral
  policy-manipulation detection, but it is an AV config/policy-change record
  (Defender/Operational channel), not a registry value_edit with hive/key/value
  semantics; binding to registry:modify would be a fabricated mapping.
- **EID 1116/1117** (Defender malware detected / quarantined —
  Trojan:Win32/LsassDump.A). `vector6-lsass-exclusion-window.md:289-301`. An AV
  verdict on a file, not a CAR action.
- **EID 2946 / 2889 / 3047 / 8415** (KDC / Directory-Services / DNS-client
  niche events). `badsuccessor-writeup.md:286-305`, `responder_lab_writeup.md:90`.
  No CAR pair.

**Files that FAIL the fit test entirely** (narratives, tool walkthroughs, lab-build
guides, offensive-only TTP, code, screenshots — no artefact-evidence claim):

- Lab-build / config guides: `ad-lab-setup.md`, `AD_ADCS_Setup_Guide.md`,
  `ESC1_Lab_Setup.md`, `ESC3_Attack_Chain.md`, `ESC8_Lab_Setup.md`,
  `Sysmon_Setup_Guide.md`, `elk-setup-guide.md`, `elk-lab-full-setup.md`,
  `ad_hardening_reality_check.md`.
- Offensive/relay/TTP walkthroughs without evidence claims: `arp-spoof-lab.md`,
  `esc8-ntlm-relay.md`, `nopac_attack_chain.md`, `kerberos-cname-relay-lab.md`,
  `kerberos-cname-relay-epa-bypass-detection.md`, `epa_kerberos_relay_lab.md`,
  `https-epa-validation-findings.md`, `live-spn-jacking-linux.md`,
  `adcs-esc-reference-guide.md`, `adcs-attack-paths-sanitized.md`,
  `adcs-esc*`, `esc4-dual-eku-gotcha.md`, `ADCSync_Writeup.md`,
  `adcsync-homelab-analysis.md`, `derrida-dcsync.md`, `etw_derrida.md`,
  `amsi-bypass-research.md` / `AMSI-Bypass-Research.md`,
  `windows-evasion-techniques.md`, `on-assumed-breach.md`,
  `SPECTEROPSCGCOMPROMISE.md`, `kerberos-attack-chains-sanitized.md`,
  `clm-bypass-purple-team.md` (its Sysmon EID 1/3 claims are already covered by
  the process:create / flow:create rows; the file itself is a bypass walkthrough).
- Code and binaries: `badrecon.py`, `adcsync_fixed26.py`, `BADRECON_README.md`,
  `ADCSYNC_README.md`, `README.md`, `SHADOW CREDS OFFENSE ONLY` (offense-only).
- Screenshots: `lsassinitelligent.png` and inline GitHub image links throughout.

## Pipeline verdict

**Recurring.** Although only a shallow single-commit snapshot was cloned (pin
above, tip 2026-06-29), the README frames the repo as active, ongoing research
("Recent / Notable Findings (2026)", "Ongoing LSASS boundary testing on Server
2025", "Expanded ADCS, Kerberos CNAME relay ...") with dated intra-day signature
observations. New writeups and revised telemetry claims should be expected. Re-ingest
on new pins; watch for the first appearance of disk-resident forensic-artefact
claims (currently zero), which would open families beyond `evtx`. Note the
recurring collection caveats the author documents — Sysmon lsass-access include
rule, network/ImageLoad rules, and AD SACLs are all off-by-default — which bear on
whether these evtx evidences are actually present in a given estate.
