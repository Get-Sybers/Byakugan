# ForensicArtifacts crosswalk — seeding the Artefact Class layer

**Inputs:** `model/sources/forensicartifacts/` at pin `7272630` (732
definitions; structural index at `pipeline/ingest/forensicartifacts/index.json`),
gomount `materialise-sets.yml` (17 sets), byakugan `sources/*.yaml` +
`car_source_schema.yaml`, and [the design doc](../design/schema-layers.md).
Method: four independent readers (format spec + tooling, windows, unix/mac,
apps/groups), a crosswalk pass, and an adversarial gapcheck; every claim
below survived verification, and the gapcheck's corrections are applied.

## The upstream format, as verified

- **Live top-level fields:** `name`, `doc`, `sources`, `aliases`,
  `supported_os`, `urls` (reader whitelist `definitions.py:30-45`;
  only these reach `ArtifactDefinition`). **Removed but silently
  tolerated:** `labels` (dep. 20220311), `conditions` (20220710),
  `provides` (20240210) — parsed, dropped, never warned. Two older
  mechanisms hard-error: `collectors`, per-source `returned_types`.
- **Source types and attributes:** `ARTIFACT_GROUP{names}`,
  `COMMAND{cmd,args}`, `FILE|PATH|DIRECTORY{paths,separator}`
  (`DIRECTORY` deprecated), `REGISTRY_KEY{keys}`,
  `REGISTRY_VALUE{key_value_pairs}`, `WMI{query,base_object}`. Unknown
  attributes are constructor `TypeError`s — closed shapes, enforced.
- **OS vocabulary:** `{Android, Darwin, ESXi, iOS, Linux, Windows}` in
  code; the published spec omits ESXi (16 live definitions) and keeps
  Android/iOS (zero definitions) — the enum drifts from its own docs.
- **Path variables:** the `%%users.*%%` / `%%environ_*%%` catalogue lives
  in the *validator*, not the spec, and the two disagree
  (`%%users.localappdata_low%%`, `%%environ_temp%%` documented but fail
  validation). `HKEY_CURRENT_USER` is banned in favour of
  `HKEY_USERS\%%users.sid%%`. A feeder cluster exists solely to resolve
  variables on live systems: the 16 `WindowsEnvironmentVariable*`
  artifacts (15 live in `windows.yaml` + 1 deprecated duplicate in
  `legacy.yaml`) plus `WindowsRegistryProfiles` and the
  `WMIAccountUsersDomain`/`WMIProfileUsersHomeDir` queries — a distinct,
  smaller population than the corpus's 27 WMI-source artifacts, most of
  which are not feeders.
- **Groups/aliases/deprecation:** `ARTIFACT_GROUP` is closed-world name
  reference — the registry records every `names` reference and the test
  suite fails on undefined ones (`artifacts/registry.py:183-185`,
  `tests/validator_test.py:26-34`). Aliases are lowercased,
  collision-checked rename compat (`artifacts/registry.py:158-181`).
  Deprecation is comment-only quarantine (`artifacts/data/legacy.yaml:1-4`,
  "kept for backwards compatibility with GRR") — and `triage.yaml`'s
  `TriageSystemConfiguration` already references the deprecated
  `LinuxRelease` (`artifacts/data/triage.yaml:258`), proof the mechanism
  rots.

## Concept verdicts for the Artefact Class layer

| FA concept | Verdict | Disposition |
|---|---|---|
| `aliases` | **ADOPT** | class instances carry prior names + covering FA names; keep FA's collision check, extended cross-namespace (spindle external ids, sensor names) |
| `urls` | **ADOPT** | matches `car_source_schema.yaml`'s existing citation discipline; each seed cites its FA definitions |
| name grammar | **ADAPT** | OS-prefix CamelCase seeds the naming inventory as *provenance strings only* — suffixes name containers (`…PlistFile`, `…SQLiteDatabaseFile`), i.e. how evidence is stored, not what it is; never the class key |
| `supported_os` | **ADAPT** | honest what-it-is scoping, but byakugan defines its own closed enum. **Open ruling:** this is *not* the `domain` facet (`domain` = filesystem\|memory\|network\|cloud per the design doc) — a separate `platform` facet or family-encoded scoping needs deciding |
| `ARTIFACT_GROUP` | **ADAPT** | group membership is the strongest seeding signal (`TriageExecution` enumerates the execution surface) — consume at ingest time; do **not** import the registry/resolver machinery |
| deprecation | **ADAPT** | the *intent* (renames never break consumers) via spindle-style versioned protocol + `--check`; never the silent parse-and-drop anti-pattern |
| `doc` prose | **ADAPT** | FA's only "what it yields" is prose; byakugan promotes yield claims into typed `dfir_fields` and keeps a one-line summary |
| `sources[]` typed attributes | **REJECT** | the asymmetry: FA declares where evidence *lives*; the class layer declares what it *is and yields*. Geography already lives in gomount's globs |
| `%%variable%%` grammar | **REJECT** | it solves live-collection portability; a mounted image is enumerable, so gomount's `Users/*/…` wildcard replaces the entire engine, and spindle proves identity needs only post-parse row values. Sole residue: a machine\|user scope facet *derived* from `%%users.*%%` usage (derivation rule for mixed artifacts still undecided) |

## Family seed table (28 rows)

FA provenance per family; container-only citations are marked — FA has
**no leaf** for userassist/shellbags/RecentDocs/TypedURLs/TaskCache, so
those cite `WindowsUserRegistryFiles` and must record the upstream
absence explicitly rather than fabricate authority.

| family | platform | gomount set | byakugan lane | FA provenance |
|---|---|---|---|---|
| prefetch | windows | prefetch | prefetch_dump, plaso_exec_prefetch | WindowsPrefetchFiles (+ WindowsSuperFetchFiles uncollected) |
| evtx | windows | winevt | evtx_* (8 lanes) | WindowsEventLogs (FILE catch-all) + per-channel WindowsXMLEventLog* |
| mft | windows | mft | l2t_mft | NTFSMFTFiles |
| usnjrnl | windows | **none** (parsed, uncollected) | l2t_usnjrnl | NTFSUSNJournal, NTFSLogFile |
| srum | windows | srum | esedump_srum, l2t_srum | WindowsSystemResourceUsageMonitorDatabaseFile |
| amcache | windows | amcache | recmd_batch, plaso_registry | WindowsAMCacheHveFile (+ RecentFileCacheBCF Win7/8) |
| shimcache | windows | shimcache | plaso_exec_winreg, recmd_batch | WindowsAppCompatCache |
| registry-hives | windows | registry-core+ntuser+usrclass | recmd_batch, plaso_registry | WindowsSystemRegistryFilesAndTransactionLogs, WindowsUserRegistryFiles, … |
| run-keys | windows | none of the 17 — no dedicated set; relies entirely on registry-core + ntuser above | plaso_exec_winreg, recmd_batch | WindowsRunKeys (20 keys), WindowsPersistenceRegistryKeys (66 members), WindowsServices, … |
| userassist | windows | ntuser | plaso_exec_winreg | *container only* |
| shellbags | windows | usrclass+ntuser | plaso_shellitem | *container only* |
| lnk-jumplists | windows | recent | jlecmd_dest, l2t_lnk, plaso_shellitem | WindowsUserRecentFiles, WindowsUser*JumpLists |
| recyclebin | windows | recyclebin | l2t_recyclebin | WindowsRecycleBinMetadata (+ WindowsRecycleBin full-content variant) |
| ual | windows | sum | *(lane to add)* | WindowsUserAccessLogging |
| activities-timeline | windows | timeline | *(lane to add)* | WindowsActivitiesCacheDatabase |
| scheduled-tasks | windows | **none** | *(lane to add)* | WindowsScheduledTasks (+ WMIScheduledTasks, live-only) |
| browser-history | all | **none** | l2t_firefox_*, l2t_msiecf, l2t_javaidx | BrowserHistory group, Chromium*/Firefox*/IE leaves (Chrome* silently covers Edge) |
| wtmp | linux | linux-core | l2t_utmp | LinuxWtmp, LinuxUtmpFiles, LinuxLastlogFile |
| utmpx | macos | macos-core | l2t_utmpx | MacOSUtmpxFile |
| syslog-auth | linux | linux-core | l2t_text | LinuxAuthLogs, LinuxSysLogFiles, LinuxAuditLogs |
| journal | linux | linux-core (glob-caught) | *(binary journal lane missing)* | LinuxSystemdJournalLogs |
| shell-history | linux/macos | linux-core, macos-core | l2t_text (partial) | ShellHistoryFile, Bash/ZSh/Fish leaves |
| cron-persistence | linux | linux-core | plaso_exec_cron | LinuxCronTabs, AnacronFiles, LinuxAtJobs |
| accounts | linux/macos | linux-core, macos-core | *(lane to add)* | UnixPasswdFile, UnixShadowFile, UnixGroupsFile |
| ssh | linux/macos | linux-core, macos-core | *(lane to add)* | SSHAuthorizedKeysFiles, SSHKnownHostsFiles |
| launchd | macos | macos-core+macos-system | *(godaemonhunter consumes)* | MacOSLaunch{Agents,Daemons}PlistFile, StartupItems, LoginItems |
| fseventsd | macos | **none** (parsed, uncollected) | plaso_fseventsd | MacOSFSEventsFile |
| filestat | all | (timeline verb) | l2t_filestat | *no FA equivalent* — seed without FA provenance |

## Both directions of slack (findings, not byakugan edits)

**FA covers, gomount doesn't collect:** SuperFetch `Ag*.db`, `$UsnJrnl`
(byakugan *parses* it — the sharpest gap), `.fseventsd` (same shape),
macOS unified logs (tracev3+uuidtext), scheduled-task XML, PowerShell
`ConsoleHost_history.txt`, CIM repository, BITS qmgr, `/var/audit` BSM,
`etc/apt`. **gomount expresses, FA cannot:** origin-record manifests
(per-file image/volume/fsuuid/inode provenance), declarative siblings
(`.LOG1/.LOG2`), the sealed-System-volume two-pass, rpm/pacman/snap
state. These are gomount findings to hand over separately — out of this
mission's scope.

## Upstream defect register (why paths are never seeded)

Verified in the pinned tree: `ComDIg32` key typo (OpenSaveMRU never
matches), `/etc/sysctl.con`, `/user/local` Jupyter path, `Manifest.mdbd`
(iOS backup is `.mbdb`), `vxpa.log` / `vmksummarylog.log` (VMware
transpositions), `/etc/dhcp/dhcp.conf` (matches nothing), CrashDumps
path missing its `ServiceProfiles\*` segment, Firefox cookies/downloads
`-wal` copy-paste duplicates, two names for one CoreDuet db, a frozen
Windows-7 DLL-hijack snapshot with third-party DLLs, and a thick XP/9x
legacy stratum (RunServices, GinaDLL, Recycler, `.evt`). Names and
grouping are safe to seed; paths, siblings or field expectations would
import these defects into a gated layer.

## Verification notes

The gapcheck corrected the crosswalk before this document was written:
`WindowsEventLogs` is a FILE catch-all, not a group; `domain` must not
be repurposed for OS scoping (see open ruling); WindowsRunKeys has 20
keys, WindowsPersistenceRegistryKeys 66 members, and 16 (not 14)
`WindowsEnvironmentVariable*` feeders. Reader coverage missed
`java.yaml` (JavaCacheFiles — the FA anchor for `l2t_javaidx`) and read
`installed_modules*.yaml` only partially; their structural rows are in
`index.json` regardless.

## Open questions before seeding

1. **Platform facet:** `domain` stays acquisition-domain; where does OS
   scoping live — a new two-word facet (`platform`), or family naming?
2. **ESXi:** 16 live FA definitions, no gomount surface, no byakugan
   lane — in scope for seeds or explicitly deferred?
3. **machine|user scope facet:** derivation is ill-defined for mixed
   artifacts (WindowsCrashDumps, WindowsRunKeys span both) — per-class
   declaration instead of derivation?
4. **Group→family authority:** groups are many-to-many
   (`TriageExecution` spans ≥5 families); which groups are authoritative
   for family assignment, and what breaks ties?
5. **Provenance-absence vs production-absence:** "FA has no leaf for
   shellbags" is provenance metadata, not the `absence` facet's
   producer-marker vocabulary — it needs its own home (e.g. a
   `provenance` note on the seed), not an `absence` value.
6. **dfir_fields mining:** FA prose cannot supply typed yields; per the
   design doc they come from the parser record structs (Parser Profile
   work) — FA contributes scope and naming only.
