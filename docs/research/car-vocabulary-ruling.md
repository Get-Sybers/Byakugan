# Ruling: the CAR vocabulary extension and the attack-datasources homing

**Status: ruled 2026-09-30** (owner-delegated; investigation over
mitre-attack/attack-data-model, attack-datasources `contribution/*.yml`,
and mitreattack-python at their current tips). Implementation: D-B and the
exchange-validator fix land immediately; D-A lands with epic
[&1](https://github.com/Get-Sybers) Phase 2 (#131).

## The decisive finding

Byakugan's superset ALREADY carries the gap objects with pin-derived action
vocabularies: `build_superset()` unions ATT&CK data-component actions into
CAR objects and creates ATT&CK-only objects from the pinned
`attack_data_sources_objects.yaml` (`byakugan/build_data_model.py`);
`model/superset/model-objects.yml` lists `user_account [authenticate,
create, delete, metadata, modify]`, `group [create, delete, enumerate,
metadata, modify]`, `scheduled_job [create, delete, metadata, modify]`,
`active_directory [access, create, credential_request, delete, modify]`,
`named_pipe [metadata]`, `wmi [create, delete, metadata]`. The extension is
therefore **promotion of already-pinned superset objects to full CAR
objects** — nothing is hand-typed; the vocabulary-rot rule is satisfied by
construction.

## D-A — adopt three, defer three

**ADOPT `user_account`** — actions `{create, delete, modify, metadata}`
(`contribution/user_account.yml:26-70`). The superset's fifth action
`authenticate` is deliberately NOT adopted — authentication already has a
CAR object; a second home would violate single-source (record this
divergence in the generated file's header). SCO grounding: the standard
`user-account` SCO (standard-object-first). Identity: existing conventions
(global real-SID / case-scoped; evtx rows ride the `evtx_record` external
form). Bindings: 4720→create; 4726→delete;
4722/4723/4724/4725/4738/4740/4767/4781→modify; the `accounts` family
(/etc/passwd, dslocal) yields `metadata` state rows. User Account
Management success auditing is default-on → backbone MUST when present.

**ADOPT `group`** — actions `{create, delete, modify, enumerate, metadata}`
(`contribution/group.yml:17-50`). Bindings: 4727/4731→create;
4730/4734→delete; 4728/4732/4756 (+removals 4729/4733/4757)→modify;
4798/4799→enumerate (heuristic). SCO grounding: `identity` SDO with
`identity_class: group` (case-scoped `[domain|source_host, group_sid]`);
`x-car-group` new-sco recorded as the fallback if entities-on-observables
is preferred — the one debatable call in this ruling.

**ADOPT `scheduled_job`** — actions `{create, delete, modify, metadata}`
(`contribution/scheduled_job.yml:14-60`; its examples ARE the gap ids).
Bindings: Security 4698→create, 4699→delete, 4700/4701/4702→modify — MAY
(Other Object Access auditing off by default); TaskScheduler/Operational
106→create, 140→modify, 141→delete — default-on, MUST-when-present. The
scheduled-tasks artefact family's matched rows (task XML, TaskCache) gain
ADDITIVE scheduled_job rows; the existing `(file, create)`/`(registry,
add)` rows stand. SCO grounding: new-sco `x-car-scheduled-job` via the
evidence extension (no §6 SCO holds a recurring-job registration; the
ratified `no-task-force-fit` forbids service). Spindle sketch: entity
`{source_host, job_path_or_name}`, scope intrinsic, version 1.
`plaso_exec_cron`'s existing `(process, create)` mapping is wire — any
re-map is a separate contract-version decision.

**DEFER `active_directory`** (vocabulary ready; zero DC-side lanes, DS
auditing role-gated — enters when one in-house producer exists, the same
admission rule as ESXi), **`wmi`** (no Sysmon 19-21 lane; CIM repository
uncollected), **`named_pipe`/DNS** (upstream offers only `metadata` for
pipes — adopting Sysmon 17/18 activity semantics would hand-type actions
upstream does not assert; Sysmon 22 has no CAR-shaped home).
`no-sysmon-mis-object` stands unchanged.

**Constraint lift, scoped:** `no-account-force-fit` and `no-task-force-fit`
are amended at adoption time, not deleted — the forbidden targets remain
`authentication/user_session/service/process`; the gap ids become legal
ONLY onto the adopted objects.

**Implementation scoping (phase 2b):** the promotion lands at the SCHEMA
layer — the three objects enter the generated vocabulary
(`byakugan/schema_gen.py PROMOTED`, superset-sourced, `authenticate`
dropped), the ruling's event-id bindings ride the matched overlay as
evidences rows, and the two constraints carry the scoped lift. The RUNTIME
promotion (store tables, stix builders, spindle entries, emitting ir
variants) follows with the mapping/parser phases (&1 phases 5-6) behind a
contract-version bump — an object nothing emits needs no table, and the
emitting variants are exactly what those phases author.

## D-B — retire the submodule; split frozen from living

The submodule fed exactly one file (`attack_data_sources_objects.yaml`,
pin `5d50f731`); upstream is archived and the file immutable. The living
successor of the data-source/component content is `x-mitre-data-source` /
`x-mitre-data-component` inside the enterprise-attack bundle byakugan
already pins (the attack index's own source).

1. **Done in this MR**: the file is vendored at
   `model/sources/attack-datasources/attack_data_sources_objects.yaml`
   with the pin in its envelope header; `_ADS` points at it; the submodule
   is removed. The 243-edge relationship vocabulary lives only in this
   file — permanent, owned, frozen input.
2. **Phase-4-adjacent**: extend the attack index to format 2 (same
   enterprise bundle, adding data-components + log-source `(name,
   channel)` tuples + analytic/detection-strategy skeletons); superset
   refresh rebases component names onto the live set; edges keep coming
   from the vendored frozen file.

## x-mitre-analytic / detection-strategy — ADAPT at the airway

Byakugan never mints `x-mitre-*` (authority rule). Format 2 adds
analytics/strategies/detects so byakugan indicators gain additive
`external_references` to MITRE analytics/strategies where the pinned index
maps one; coverage claims validate against strategy→technique `detects`
edges; the log-source `(name, channel)` tuples give
`channel-source-integrity` an upstream vocabulary.
`x_mitre_mutable_elements` maps to nothing byakugan has — noted, not
adopted. #11's reporting lane changes only additively.

## Conformance note (fixed in this MR)

The exchange validator's blanket §11 check contradicted ratified v6: it
flagged the extension-B-declared `x_car_*` surface and the `x-car-*`
extension objects. The check is now extension-aware: declared surfaces and
`x-mitre-*` passenger content pass; bare customs still warn.
