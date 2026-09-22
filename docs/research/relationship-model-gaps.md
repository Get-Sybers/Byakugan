# Relationship-model gap register — #109 stage 1

The research pass [issue #109](https://github.com/Get-Sybers/Byakugan/issues/109)
calls for before the relationship model is built out: **what the model does not
yet declare**, determined from the pinned upstream research — never from what a
current artefact happens to carry. Objects, actions and scalar fields are
upstream-pinned and are **not changed** by anything in this register; every gap
below is a relationship, an association property, an identity declaration, or a
projection of one of those.

Research base, read in full for this register:

- `third_party/attack-datasources @ 5d50f73` — the ATT&CK data-sources model:
  every `(source_data_element, relationship, target_data_element)` triple in
  `docs/attack_data_sources_objects.yaml` (243 triples, 33 data sources — the
  exact input `build_data_model.build_superset()` reads), cross-checked against
  `contribution/*.yml` (38) and `contribution-ics/*.yml` (17, a subset that adds
  no relationships for our objects), plus `docs/methodology.md`.
- `third_party/car @ 1b922fe` — the 13 CAR objects' actions and field semantics
  (`data_model/*.yaml`, field descriptions read verbatim).
- All three Byakugan layers: the hand-authored sources
  (`byakugan/cascade_relationships.yml`, `byakugan/relationships.yml`,
  `byakugan/spindle.yml`, `model/stix/*`, `elastic/projection/*`), the generated
  `model/` snapshot, and the engine (`superset.py`, `derive.py`, `enrich.py`,
  `verify.py`, `stix.py`).
- The memory producer's mapping table
  ([Anamnesis](https://github.com/Get-Sybers/Anamnesis)
  `internal/normalize/mappings.yaml` + `normalize.go`), because its minted guid
  forms arrive verbatim through the interchange
  ([Anamnesis-Interchange.md](../Anamnesis-Interchange.md)).

Terms: a **(object, action) pair** is a spoke row type; the **catalogue** is
`model/superset/relationship-types.yml` (generated from the pin); a **triple**
is `(source element, verb, target element)` as ATT&CK states it; an
**association property** is a fact of an edge, not of either endpoint (the
file-handle pattern of #107/#108).

---

## 0. The declared surface today (baseline)

What the model already declares — the floor this register measures from:

| layer | declares |
|---|---|
| `cascade_relationships.yml spoke_owner` | 32 (object, action) → verb entries across 11 objects |
| `cascade_relationships.yml edges` | 5 special edges: `parent_process`/created, `process_access`/accessed, `thread_injection`/accessed, `file_executed`/executed, `auth_session`/created |
| `cascade_relationships.yml default_spoke_verb` | `accessed` — the silent fallback for every undeclared pair |
| `relationships.yml derived.identities` | guid, offset, file_offset, hash, sid |
| `relationships.yml derived.links` | `process_image_content` (hash), `http_file_transfer` (fuid) |
| `relationships.yml derived.reconstruct` | `owning_process`, `owning_process_memory`, `parent_process`, `injection_target` |
| `superset._edge_properties` | ONE association: file/access → `{access_level, handle_value}` (#108) |
| `spindle.yml external` | 14 forms; memory: `memory_proc_offset`, `memory_file_object` only |
| within-source rules ([CAR-Relations.md](../CAR-Relations.md)) | R1 session lifecycle, R2 lifetime bounding, R3 zeek uid, R5 injection dual-link, R6 auth caller — implemented; **R4 (BITS), R7 (service→image) are in the doc's table but NOT in `enrich.py`** (drift, §7) |

Engine fact that shapes everything below: `edges_from_events` emits an edge
**only** where a branch exists for it. A resolved join with no branch (R3's
`flow_guid`, R1's `session_login_guid`) produces **no relationship row** —
resolution and materialisation are separate gaps.

---

## 1. G1 — spoke→owner verb coverage: 35 undeclared pairs

Superset actions per object vs `spoke_owner`: **35 spoke (object, action)
pairs have no declared verb** and fall to `default_spoke_verb: accessed`
(the process hub's own 6 actions are §3, not spoke material). The fallback is
not hypothetical: the memory lane emits `socket/listen` rows today
(Anamnesis `windows.netscan`/`windows.anamnesis.network`), so a bound socket's
owner edge currently reads `process --accessed--> socket` where ATT&CK's own
triple is `process --listened on--> port`.

Recommended verb per pair — every recommendation is a verb **already in the
243-verb catalogue** (no vocabulary change); "exact" means the (source, verb,
target) triple exists in ATT&CK under the element aliasing of §2:

| object/action | today | recommend | typing | grounding (component) |
|---|---|---|---|---|
| registry/access | default | `accessed` | exact | Windows Registry Key Access |
| registry/create | default | `created` | exact | Windows Registry Key Creation |
| registry/delete | default | `deleted` | exact | Windows Registry Key Deletion |
| registry/modify | default | `modified` | exact | Windows Registry Key Modification |
| file/content | default | `retrieved information about` | exact | File Content |
| file/metadata | default | `retrieved information about` | exact | File Metadata |
| module/content | default | `retrieved information about` | exact | Module Content |
| module/metadata | default | `retrieved information about` | exact | Module Metadata |
| module/unload | default | `unloaded` | borrowed | Driver Unload (no module-unload component upstream) |
| driver/metadata | default | `retrieved information about` | borrowed | Driver Metadata (`host` source upstream) |
| driver/unload | default | `unloaded` | exact | Driver Unload |
| service/access | default | `accessed` | borrowed | Service Access (`user` source upstream) |
| service/delete | default | `deleted` | borrowed | CAR-only action; verb from the deletion family |
| service/enumerate | default | `listed` | exact | Service Enumeration (`process --listed--> service`) |
| service/metadata | default | `retrieved information about` | exact | Service Metadata |
| service/modify | default | `modified` | exact | Service Modification (`process --modified--> service`) |
| service/pause | default | `stopped` | borrowed | **decision** — no pause verb exists; nearest state verb |
| socket/listen | default | `listened on` | exact | Network Connection Creation (`process --listened on--> port`) |
| socket/close | default | `terminated` | borrowed | **decision** — no close verb exists; alternatives: leave undeclared |
| thread/create | default | `created` | exact | Process Creation (`process --created--> thread`) |
| thread/terminate | default | `terminated` | borrowed | verb exists (`user --terminated--> process`) |
| thread/suspend | default | `modified` | borrowed | **decision** — no suspend verb; Process Modification analog |
| flow/create | default | `connected to` | exact | Network Connection Creation |
| flow/content | default | `connected to` | borrowed | the row IS a connection; component is informational |
| flow/flow | default | `connected to` | borrowed | as flow/content |
| http/put | default | `created` | borrowed | same family as declared get/post |
| http/tunnel | default | `connected to` | borrowed | a CONNECT proves a tunnel was *requested* (CAR-Relations §http) |
| user_session/create | default | `created` | borrowed | Logon Session Creation (`user` source upstream) |
| user_session/terminate | default | `terminated` | borrowed | Logon Session Termination |
| user_session/metadata | default | `retrieved information about` | borrowed | Logon Session Metadata |
| email/deliver | default | `created` | borrowed | **decision** — no email element in ATT&CK; see below |
| email/delete | default | `deleted` | borrowed | **decision** |
| email/redirect | default | `modified` | borrowed | **decision** |
| email/quarantine | default | `modified` | borrowed | **decision** |
| email/block | default | — | — | **decision** — no verb fits; candidate: leave undeclared with rationale |

Notes:

- The four registry pairs and file/content+metadata matter beyond hygiene:
  the superset union gave the objects those action names, so a future map can
  legally emit them (`verify.py` accepts them) and would today mint
  wrong-verb edges silently.
- **email** has no ATT&CK data element (Application Log is its nearest data
  source, relationship-free for our purposes) — its five verbs are the one
  place stage 2 must declare from logic alone, consistent with
  [CAR-Relations.md §email](../CAR-Relations.md)'s limits (only `deliver`
  asserts server-side delivery; `block/redirect/quarantine` are server verdicts
  on the message). Recommendation above; the decision is the owner's.
- `default_spoke_verb: accessed` should survive as the guard for a truly
  unknown pair, but after stage 2 it should be a **test failure** for any pair
  in the superset action lists — every legal pair declared, the default
  reserved for drift.

## 2. G2 — triple-level typing: the model types edges by verb, ATT&CK types them by triple

`tests/test_superset.py::test_all_emittable_verbs_are_attack_vocabulary`
enforces **verb membership** only. Checked at triple level (with element
aliasing: registry ↔ `windows registry key`/`… value`, user_session ↔
`logon session`, flow ↔ `network traffic`/`… flow`/`ip`/`port`/`host`, module ↔
`module`/`kernel module`, socket ↔ `port`, http ↔ `web traffic`), today's
emittable edges split:

- **22 exact ATT&CK triples** — file access/create/delete/modify/read/write/
  acl_modify/timestomp, registry add/remove/value_edit/key_edit, module load,
  driver load, socket bind, thread remote_create, flow start/message/end,
  parent_process, process_access, thread_injection.
- **verb-borrowed** (verb in catalogue, triple not) — every user_session verb
  (`user` is the ATT&CK source, we type from `process`), service
  create/start/stop (upstream's `service --started/stopped--> ∅` rows carry no
  target and are dropped by the build — §7), authentication (CAR-only object),
  http (no request-level element), `file_executed`/`process_image_content`
  (`executed`'s ATT&CK targets are command/script/api call; ours is `file`,
  grounded in CAR-2014-02-001), `http_file_transfer` (`contained`'s exact form
  is `network traffic --contained--> file transfer traffic`; ours ends on the
  file record).

None of the borrowed edges is wrong — they are deliberate extensions where
Byakugan's evidence is finer-grained than ATT&CK's elements. The gap is that
**the tier is invisible**: nothing records which declared edge is an exact
ATT&CK reading and which is a Byakugan extension. Stage 2 should carry the
typing tier (`exact | extension`) in the readable rendering (§6) and may
tighten the test to assert exact-typed edges stay exact across pin bumps.

## 3. G3 — cross-object edges: resolved-but-never-materialised, and undeclared candidates

### 3.1 Joins the engine resolves that produce no edge (engine gaps)

| join | resolved as | missing edge | verb (typing) |
|---|---|---|---|
| R3 zeek spoke→flow (`_link_zeek_spoke_to_flow`) | `native.flow_guid` + `flow_link` on http/file rows | `flow --contained--> http`, `flow --contained--> file` | `contained` (exact aliased: Network Traffic Content) |
| R1 session lifecycle (`_pair_session_lifecycle`) | `native.session_login_guid`/`session_logout_guid`/`session_end` | — recommend **no edge**: both rows are one session entity; the pairing is lifetime metadata, not a relation between two things | decision to ratify |

R3 is the material one: the join is definitive (shared capture uid), the verb
is exact-typed, and the edge closes the network lane's biggest hole — today a
capture's relationship timeline shows `http --contained--> file` but never
which **connection** carried the transaction. New `edges:` entry
(`flow_contains: contained`) + one `edges_from_events` branch reading
`flow_guid`.

### 3.2 Undeclared candidates from the catalogue (declaration gaps)

Restricting the 243 triples to elements both ends of which map onto modelled
objects:

1. **The user/account dimension — ~50 triples, zero instances.** `user` is
   ATT&CK's most common source element (`user --created--> process`,
   `--created--> logon session`, `--modified/deleted/accessed--> file`,
   registry, service, the whole account-lifecycle family). Byakugan carries the
   actor in row fields (`user`/`uid`/`sid`) and mints `user_account`
   content-nodes from real SIDs (`derived.identities.sid`) with an
   `entity_ref` per carrying record — the attribution layer — but **no
   relationship row ever has a user end**. Options for stage 2:
   (a) keep attribution entity-ref-only (status quo, honest but invisible to
   the edge timeline); (b) materialise `user_account --verb--> object` derived
   edges where the row's sid passes the real-SID gate, verb = the user-side
   analog of the spoke verb. Recommendation: (b), scoped first to the
   session/auth family (`user --created--> user_session` from the session row's
   own uid; `user --created--> process` from 4688-style rows), where the
   ATT&CK triples are exact and volume is bounded. **Decision needed** —
   this doubles the edge classes an analyst sees.
2. **`process --modified--> process`** (Process Modification — hollowing,
   herpaderping). Exact triple, no declared edge. Evidence exists (Sysmon 25
   ProcessTampering; memory exe-vs-VAD divergence) though no current map emits
   it; declare `edges: process_modify: modified` now so the first map lands on
   a declared edge. `process/modify` is already a legal superset action.
3. **`process --requested access to--> file | process | registry`** — the
   failed/requested tier of the access family (4656-style "requested access"
   vs 4663 "accessed"). The catalogue separates them; the model folds both
   into `accessed`. Worth declaring only when a map distinguishes the two —
   record as declaration-ready, blocked on evidence.
4. **auth→session reconstruct** (§4 of `derived`): a 4624's `TargetLogonId`
   naming a session **no source observed** currently yields nothing — the LUID
   join only links observed pairs. A `reconstruct` entry (identity: a new
   `luid` instance identity, `guid_form: "user_session-{luid}"` — exactly the
   form the memory lane already mints for sessions) gives the same
   antiforensics story sessions that `owning_process` gives processes:
   the log-cleared logon a later record still names.
5. **module/driver → file (the image on disk)** — deliberately **no direct
   edge**: no ATT&CK verb has a module/driver source, and the hash
   content-node already carries the many-to-many honestly
   (`identities.hash.properties` includes `module_path`). Record as a decided
   non-edge so it stops resurfacing.
6. **socket ↔ flow** (5-tuple correlation) — defer: heuristic, ephemeral-port
   reuse, no clean verb; the owning process already relates them transitively.
7. **certificate identity** — `zeek_cert_fp` is registered as an external guid
   form and its registry entry already states "stable across captures", i.e.
   it is a *content* identity in instance clothing. Candidate
   `derived.identities.cert_fp` (kind: content, node: `certificate`) unifying
   a cert wherever seen; STIX has a native `x509-certificate` SCO. Stage 2+.
8. **email joins** — CAR-Relations §email records the principles (→flow by
   capture uid; →file by fuids; →http by `message_links` **temporal only,
   never a link**) but none exist as machine-readable `derived.links`.
   Declaration-ready; blocked on the first mapper, and correctly so — but the
   *declarations* can land first so the mapper arrives to a finished model.

### 3.3 The process hub's own actions, for completeness

`create` ✓ (`parent_process`), `access` ✓ (`process_access`); `modify` → item
2 above; `terminate` → **honest null** (no artefact names the terminator: 4689
and Sysmon 5 are self-events — declare nothing); `execute` → `file_executed` ✓
for the image; `process --executed--> command|script|api call` is
vocabulary-ready but unmaterialisable until those superset objects have rows
(record, don't force); `metadata` → user-dimension family (item 1).

## 4. G4 — association properties: one declared, at least five more researched

The #107/#108 shape — object identity + per-(object, action) facts riding the
edge in `properties` → `car.rel.properties` — exists for exactly one edge
(file/access: `{access_level, handle_value}`). CAR's own field semantics
(descriptions read from the pin) name these as facts **of a relationship**,
currently homed on an endpoint row because CAR has no edge to put them on.
Byakugan does. The register:

| edge | association properties | source of the fact |
|---|---|---|
| `process --accessed--> file` (file/access) | `access_level`, `handle_value` | **done** (#108; Anamnesis handles) |
| `process --accessed--> process` (`process_access`) | `access_level`, `call_trace`, `target_address` | CAR process fields: "Permissions level at which the **target process is accessed**", "Stack trace … of process open/access call", "address range which is accessed" — per-(source,target) facts; Sysmon 10 `GrantedAccess`/`CallTrace` |
| `process --accessed--> process` (`thread_injection`) | `start_address`, `start_function`, `start_module`, `new_thread_id` | CAR thread fields: where execution begins **in the target**; Sysmon 8 `StartAddress`/`StartFunction`/`StartModule`/`NewThreadId` |
| `process --loaded--> module` / `--loaded--> driver` | `base_address`, `tid` (module) | CAR module/driver `base_address` — where the image sits **in the loader's address space**, a fact of the load, not of the file; memory `Base` |
| `process --modified--> registry` (value_edit/key_edit) | `new_content` | CAR registry `new_content` — what **this edit** wrote (Sysmon 13 `Details` / 14 `NewName`); `data`/`value` remain the key's state |
| `process --modified--> file` (timestomp) | `previous_creation_time` | CAR file `previous_creation_time` — the pre-tamper value; the *change* is the edge's fact (Sysmon 2 `PreviousCreationUtcTime`) |
| `process --modified--> file` (acl_modify) | `previous_acl`, `new_acl` (candidate) | 4670 `OldSd`/`NewSd`, native-only today — same pattern, no CAR column at all |

Two rules the register keeps: an association property **duplicates onto the
edge, never moves** — the CAR row keeps its column (the model is not changed),
and the dedupe key (`target_guid`, `access_level`) still works off the row.
And the engine should stop hard-coding the registry:
`superset._edge_properties` is the one relationship rule that is code, not
data — stage 2 should move it into `cascade_relationships.yml`
(`association_properties:` keyed by (object, action) and by special edge,
native key → property name), matching the "rules are data, the engine is
mechanics" contract everything else follows.

## 5. G5 — spindle identities: the memory lane mints ten forms the registry doesn't declare

`spindle.yml external` promises "no raw form is undeclared", and
`spindle.verify_registry` enforces it — **for Byakugan's own maps**. The
Anamnesis interchange (`readers.load_anamnesis_car`, a 1:1 passthrough) brings
in guid forms the registry has never heard of. `equatable_across_sources` is
permissive (any guid-bearing row without a spindle key equates by exact
value), so these *work* — but their kind/scope/stability, the entire point of
the registry, is unrecorded:

| undeclared form | object | minted by (Anamnesis) | stability note the entry must state |
|---|---|---|---|
| `thread-<offset>` | thread | `windows.thrdscan`, `windows.anamnesis.threads` | per-image `_ETHREAD` offset (decimal) |
| `module-<pid>-<base>` | module | `windows.dlllist`, `windows.anamnesis.modules` | per-image; pid+base pair |
| `driver-<offset>` | driver | `windows.modules` | per-image |
| `service-<offset>` | service | `windows.svcscan` | per-image |
| `socket-<proto>-<laddr>-<lport>-<pid>` | socket | netscan/netstat/anamnesis.network (bound) | per-snapshot; **not** stable across snapshots |
| `flow-<proto>-<laddr>-<lport>-<faddr>-<fport>` | flow | netscan/netstat/anamnesis.network | per-snapshot 5-tuple; **ephemeral-port reuse across snapshots of one host would false-equate** — the exact caveat the registry exists to record |
| `registry-<hive>-<key>-<valuename>` | registry | `windows.anamnesis.registry` | value-level (unlike disk `plaso_registry`, key-level) |
| `user_session-<logonid>` | user_session | `windows.anamnesis.sessions` | the LUID — per-boot (mirrors the `auth_session_luid` join caveats); also the natural `guid_form` for §3.2 item 4 |
| `user_session-<sessionid>-<username>` | user_session | `windows.sessions` | per-image |
| `file-mft-<record#>` | file | Anamnesis enrich (MFT-scan fold) | per-image MFT record number |

Plus one **divergence found while registering them**: `windows.filescan` mints
`file-<offset in decimal>` (the generic fields form renders `value.Str`) while
`windows.anamnesis.files` mints `file-<offset in hex>` (`fileGUIDSrc`) — the
same FILE_OBJECT offset yields two identities that share a prefix and never
equate. The fix belongs in Anamnesis (one rendering), but the registry is
where the contract gets stated; until aligned, declare both with the caveat.

Remaining per-object identity coverage is honest: email has **no identity
form anywhere** (no artefact — consistent with CAR-Relations §email);
authentication/service/thread on the disk lane ride `evtx_record`;
http/flow/file/process/registry/user_session each have at least one intrinsic
or external form.

## 6. G6 — projections and the readable rendering

1. **STIX drops association properties.** `stix.py edge()` writes
   `x_car_class/method/confidence/identity_key/inferred_end/corroborated_by/
   source_host` — not `properties`; `model/stix/conventions.yml
   relationships.x_car` matches (contract and engine agree with each other,
   both missing it). ECS carries them (`car.rel.properties`, flattened). The
   file-handle facts, and everything §4 adds, never reach a STIX consumer.
   Stage 2: add `x_car_properties` on the SRO + the conventions line; that is
   a boundary change → contract version bump (v5), validator + `test_stix`
   in step.
2. **Content nodes have no ECS stream.** `content_node`/`entity_ref` (the
   attribution layer) feed STIX only; the Elastic lane has `logs-car.rel-*`
   and `logs-car.inferred-*` but no content stream — a hash's
   many-record-union is invisible in Kibana except as per-document hash
   fields. Record as a decision: either a `logs-car.content-*` projection or
   an explicit "STIX-only layer" statement in `elastic/projection/README`.
3. **The readable rendering of the declared model does not exist.** `model/`
   renders the *upstream vocabulary* (`relationship-types.yml`) and the *row
   shape* (`relationship-schema.yml`) but nothing renders **our
   declarations** — a reader cannot see the relationship model without
   reading `cascade_relationships.yml` + `relationships.yml` + engine
   branches. Stage 2's readable-format deliverable: a generated
   `model/relationships/` (from the layer-1 sources through `model/generate.py`,
   same GENERATED header discipline): per object the declared owner-verb per
   action with its typing tier (§2), the special edges, the derived
   links/reconstructs with identities and confidence, and the association
   properties per edge (§4). `verify.py` gains the matching gate checks
   (edge verbs ∈ declared set; `properties` keys ∈ the association registry).
4. **Doc refresh riding on it**: CAR-Relations.md's R-table corrected for R4/R7
   (§7), and its per-object sections extended with the association-property
   reasoning as rules land.

## 7. G7 — upstream and drift findings to pin (so nobody re-litigates them)

- **Catalogue pollution from an upstream typo**: `cloud_storage.yml` /
  `docs` aggregate carry `modified --created--> cloud storage object`
  (source element is the *verb* "modified" — an upstream editing slip);
  it surfaces verbatim as a bogus `modified:` source in
  `relationship-types.yml`. Harmless to us (no object maps to it); do not
  "fix" it locally — the catalogue is a faithful pin. Record only.
- **`service --started/stopped--> ∅`**: upstream Service Metadata lists the
  two state relationships with no target; `build_superset` drops targetless
  rows, so `started`/`stopped` survive in the vocabulary only via the cloud
  triples (`user --started--> instance` …). Our service start/stop verbs are
  therefore verb-borrowed by construction (§2) — grounded, not accidental.
- **ICS adds nothing**: `contribution-ics/` is a strict subset for our
  objects (its `assets.yml`/`operational_databases.yml` carry no
  relationships).
- **R4/R7 doc-engine drift**: CAR-Relations.md's rule table marks R4 (BITS
  `transferId` assembly) and R7 (7045→4688 service image join, weak) as
  implemented; neither exists in `enrich.py` (the BITS map in
  `mappings/evtx_extra.py` maps single events, no correlation; nothing joins
  a service to a process). Stage 2: implement both (no new verbs needed —
  R7 only populates `owning_guid`, the existing service spoke verbs cover it)
  or strike them from the table; either way the doc stops overclaiming.
- **Stale rationale in `mappings/evtx_extra.py`**: its header refuses System
  7040 because "the CAR service object has no `modify` action" — true pre-
  superset, false now (`service/modify` is a legal action; §1 declares its
  verb). Mapping 7040 is stage-3 (mappings) work; the stale comment is worth
  a line when the file is next touched.

---

## 8. Stage-2 execution order (smallest-risk first, each item names its layer)

Status: items 1–7 shipped in the first branch (merged as #110); item 8 — the
decision set — was **ruled by the owner and shipped in the decisions round**
(§9–§10): all eight held verbs declared (the pin set is now empty), the
ACTOR edges landed (D3), and the content stream shipped (D5). Still open:
R4/R7 implement-or-strike, the Anamnesis hex/decimal alignment issue, and
the evidence-blocked follow-ons §10 names (mailbox↔SID, the suspend-count
association, an impersonation verb if a future pin adds one).

1. ✅ **Complete `spoke_owner`** — the 35 pairs of §1 minus the eight
   decision-flagged ones (email ×5, service/pause, socket/close,
   thread/suspend — held for the owner). Shipped: the 27 declarations, the
   generic vocabulary sweep and the declared-pair-completeness test pinning
   exactly the eight decision defaults.
2. ✅ **Materialise R3** — `edges: flow_contains: contained` + the
   `edges_from_events` branch on `native.flow_guid`; `edges: process_modify:
   modified` declared with its `native.modifier_process_guid` contract.
3. ✅ **Association properties as data** — `_edge_properties` reads the new
   `association_properties:` block; the §4 register landed (process_access,
   thread_injection, module/driver load, registry edits, timestomp,
   acl_modify), tests per set.
4. ✅/⏳ **`luid` identity + auth→session reconstruct** shipped (§3.2.4) —
   including the accept gate (null/well-known LUIDs never mint) and a fix
   for a latent bug it exposed: every reconstruct rule's `on:` scope had
   been parsed as YAML-1.1 boolean True and silently ignored. **R4/R7
   remain specs**: CAR-Relations.md now labels them honestly; implement or
   strike is still open.
5. ✅/⏳ **Spindle externals** — the eleven interchange declarations of §5
   shipped (`carried_by:` is the registry's third holder). Open: file the
   Anamnesis hex/decimal alignment as an Anamnesis issue (its fix re-mints
   filescan guids → coordinated bump).
6. ✅ **STIX `x_car_properties`** — contract v5 (§6.1).
7. ✅ **The readable rendering** — generated `model/relationships/`
   (declared.yml + derived.yml, typing-tiered) + the `verify.py`
   relationship gates (class-aware confidence, model-declared verbs,
   registry-declared property names) + the CAR-Relations refresh (§6.3–6.4).
8. ⏳ **Owner decisions** (§9), then their fallout.

Validation per increment, as #109 specifies: `python model/generate.py` ·
`python model/stix/validate.py` · `python elastic/projection/validate.py` ·
`python -m byakugan.spindle --check` · `pytest -q`.

## 9. Decisions — RULED by the owner (2026-09-22); how each landed

| # | decision | ruling | landed as |
|---|---|---|---|
| D1 | email verbs | **email has action verbs — they are in CAR** (`data_model/email.yaml`): CAR is upstream research too, so the verbs ground in CAR's own action definitions, catalogue-typed | all five declared: deliver→`created`, block→`stopped`, redirect→`modified`, quarantine→`locked`, delete→`deleted` (§10.1) |
| D2 | pause/close/suspend | **needs more detailed research** — "if it doesn't fit neatly it's either not handled correctly or not researched properly; the graph has three layers: vectors, transactions, associations" | researched through that lens (§10.2); all three resolved and declared: pause→`modified` (exact), suspend→`accessed`, close→`terminated` |
| D3 | user-dimension edges | **user grounds in sid/username as CAR states**; an association layer accrues on the SID (non-domain emails, alias accounts); account→account is a transaction — "logged in as or impersonated, or perhaps it's all impersonate" | the ACTOR edges (§10.3): `derived.actors` rules + `derive.actor_edges` — user→process/session `created` (exact triples), subject→target `attempted to authenticate` (the impersonation transaction; `impersonated` is not a catalogue verb) |
| D4 | session-lifecycle self-edge | question unclear to the owner — **explained in §10.4**; the default (no self-edge) stands until said otherwise | no change; pairing stays native-only |
| D5 | content nodes | **STIX for ease of seeing the data; once processed it should all be ECS streamable** | both: STIX stays the exchange model; `car_content.jsonl` + the `logs-car.content-*` stream shipped (contract `elastic/projection/content.yml`), the join target of the actor edges' account ends |
| D6 | typing enforcement | **defer; note as a candidate** — a byproduct of how the data fills, as a possible way of bumping exactness stability | render-only stands; §10.5 records the deferred candidate |

## 10. The decisions' research record

### 10.1 D1 — email verbs, grounded in CAR's own definitions

The model is CAR ∪ ATT&CK; #109 names both as upstream. Where ATT&CK has no
data element (email), **CAR's action definitions are the research base** —
read verbatim from the pin:

| action | CAR definition (`data_model/email.yaml`) | verb | reading |
|---|---|---|---|
| deliver | "an email being **sent to an end recipient**" | `created` | the message comes to exist at the recipient side (CAR-Relations §email: only deliver asserts server-side delivery) |
| block | "an email being **blocked by the email server**" | `stopped` | the server stopped the delivery transaction |
| redirect | "an email being **redirected**" | `modified` | its routing changed |
| quarantine | "**quarantined for security reasons**" | `locked` | isolated but retrievable — the exact analogue of a locked account |
| delete | "an email being **deleted**" | `deleted` | — |

All verbs from the catalogue; all typed `extension` (no email element exists
to be exact against).

### 10.2 D2 — pause / close / suspend through the three layers

The owner's frame: the graph has **vectors** (the object entities),
**transactions** (the event edges between them), and **associations** (facts
riding a relationship — the #108 handle pattern). Re-researched under it,
none of the three needed a forced verb; each was a mis-framing:

- **thread/suspend** ("suspending a thread which is currently running") —
  Windows: `SuspendThread`/`NtSuspendThread`, gated on the
  `THREAD_SUSPEND_RESUME` access right. The transaction is an **exercised
  access on the running thread** — the same family as process access, where
  the exercised right is the association layer (exactly how `GrantedAccess`
  rides the process-access edge). Verb: `accessed` — the old default was
  accidentally right; what was missing was declaring it *with this reasoning*
  and the association slot (a suspend count / exercised right, when the
  memory lane supplies one).
- **service/pause** ("pausing a currently running service") —
  `SERVICE_CONTROL_PAUSE` changes the service's run-state without ending it:
  a **modification of the service vector**, and `process --modified-->
  service` is an **exact ATT&CK triple** (Service Modification). The precise
  transition stays in `car_action`; no information is lost.
- **socket/close** ("a socket being closed") — the transaction **ends the
  socket vector's lifetime**: the same reading the model already applies to a
  session (`user_session/logout → terminated`). Verb: `terminated`
  (extension), symmetric with session termination.

The lesson generalises and is worth keeping: an action with "no fitting verb"
means the transaction was mis-classified — re-derive it as an access
(association-bearing), a state modification, or a lifecycle termination
before reaching for a new verb.

### 10.3 D3 — the user dimension, grounded in the SID

Per the ruling, the user is the **SID** (with the username as its rendering)
— exactly the existing `derived.identities.sid` real-account gate, whose
content node (`sid:<SID>`) is already the attribution layer. The ACTOR edges
(`relationships.yml derived.actors`, engine `derive.actor_edges`) make that
dimension visible in the relationship timeline:

- `user_account(sid) --created--> process` — from a process/create row's
  `sid`/`uid` (exact ATT&CK triple: `user --created--> process`);
- `user_account(sid) --created--> user_session` — from a login row's `uid`
  (exact: `user --created--> logon session`);
- `user_account(subject) --attempted to authenticate--> user_account(target)`
  — from an authentication row where subject and target are BOTH real,
  DIFFERENT SIDs: the **logged-in-as / impersonation transaction** the
  ruling names. `impersonated` is not in the 243-verb catalogue, so the
  attempt family types it (`application --attempted to authenticate-->
  user` is the borrowed pattern); if a future pin adds an impersonation
  verb, this is the one rule to retype. Subject == target (a normal
  self-logon) never emits; well-known SIDs never pass the gate.

Every actor end is backed by the content node the SAME row minted, so the
edge is joinable: in STIX the end resolves to the global `user-account` SCO;
in ECS the `sid:<SID>` guid joins `logs-car.content-*` (D5). The
**association layer on the SID** the ruling describes — non-domain emails,
other accounts the SID logs in as — accrues on that node: alias accounts
now surface as the subject→target edges; mailbox↔SID stays declaration-ready
but evidence-blocked (a mailbox address maps to an account only through an
external directory — CAR-Relations §email).

### 10.4 D4 — the session-lifecycle question, in plain terms

When a logout row is found for an earlier login row, the engine pairs them
(R1) and records the pairing inside the two rows' native data
(`session_login_guid`/`session_logout_guid`/`session_end`). The question
was only: should the timeline ALSO carry an edge between those two rows?
Both rows describe the **same session** — an edge would connect the session
to itself and add nothing a consumer can act on, so the recommendation was
(and remains) no edge; the lifetime is row metadata, not a relation between
two things. Standing default unless the owner says otherwise.

### 10.5 D6 — typing enforcement, deferred with a marker

Ruling: defer. The typing tier stays render-only (`model/relationships/`),
and the candidate is noted for later: **as real data fills the model**, the
observed mix of exact vs extension edges per object becomes a measurable
signal — a pin bump that silently downgrades an exact-typed edge to
extension (or the data never exercising an exact edge) is the trigger for
revisiting test enforcement. Nothing to build until that data exists.
