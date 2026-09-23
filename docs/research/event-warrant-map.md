# Event-warrant map — which event logs and event IDs can warrant an action

Which Windows events can *warrant* a CAR action: their catalog message
describes the action happening to the object. Method, per the owner: **string
search an object name and the action verb** — the object terms and the
declared verbs come straight from the model (`cascade_relationships.yml`), so
the map is typed by the same vocabulary the engine emits.

The full table is [`event-warrant-map.csv`](event-warrant-map.csv) beside this
file: one row per (object, action, provider, event ID) with channel, tier,
message excerpt and the `{Field}` names the template carries (a head start for
the mapping stage).

## Corpus and method

- Corpus: `nasbench/EVTX-ETW-Resources` consolidated event catalogs for the
  two newest builds — Windows 11 24H2 (26100.1742) and Server 2022
  (20348.1607), ~100k rows (`Provider, Event ID, Channel, Message`). Older
  builds are near-subsets and were not swept (stated bound).
- Search: whole-word object-term × action-verb over the message (72
  (object, action) pairs; morphological variants of the declared verbs).
- Verification, two tiers on every row (`verify` column):
  - `ok` — survived a per-object adversarial prune (wrong-referent and
    wrong-semantics candidates dropped; kept rows spot-checked against the
    raw catalog). 210 rows.
  - `pending` — from a supplemental pass over priority providers
    (Security-Auditing, Sysmon, SCM, TS-LSM, kernel providers …) that the
    per-action cap had crowded out of the first sweep; deduped to one best
    action per event, **inadmissible until confirmed** (the uSaid
    `verify: pending` rule). 59 rows.
- Tier (`tier` column): `log` = a persisted event-log channel; `analytic` =
  an Analytic/Debug channel (off by default); `etw` = no channel — the event
  exists only as an ETW trace, so it warrants the action only with a trace
  collector.

## Coverage

269 rows, 53 of 72 (object, action) pairs; 198 of the 210 verified rows are
persisted-log tier. The `already_mapped` column flags event IDs Byakugan's
maps already consume (advisory).

| object | rows | thin / zero pairs |
|---|---|---|
| authentication | 17 | success (4624-family sits in the pending tier) |
| driver | 15 | metadata |
| email | 0 | all — Windows has no mail eventing without Exchange (honest null) |
| file | 36 | acl_modify, content, timestomp |
| flow | 19 | content, flow, message |
| http | 8 | put |
| module | 15 | content |
| process | 29 | execute, modify (Sysmon 25 territory) |
| registry | 59 | — |
| service | 26 | enumerate, metadata, pause |
| socket | 20 | — |
| thread | 10 | remote_create, suspend (Sysmon 8 territory) |
| user_session | 15 | metadata |

## Reading the map

- A `log`-tier `verify: ok` row is a mapping candidate: the channel names
  the .evtx, the event ID gates the map, the `fields` column names the
  template's own field names.
- Failure wordings ("failed to load", "could not be created") are kept
  deliberately — a failed action is a legitimate warrant of the attempt.
- These rows are `recorded`-class authority sources in the §10.6 sense: an
  OS artefact writing the action down at event time. Promoting one into a
  map is the mapping stage (#109: mappings come after the model).

## Bounds

Two builds only; per-action caps in the first sweep (drop counts logged in
the sweep stats); the `pending` tier is unconfirmed by construction; ETW-only
rows require a trace collector Byakugan does not ship today.
