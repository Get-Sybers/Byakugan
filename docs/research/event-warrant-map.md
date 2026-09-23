# Event-warrant map — which event logs and event IDs can warrant an action

Which Windows events can *warrant* a CAR action: their catalog message
describes the action happening to the object. These rows are ordinary
sources: each one can fill an (object, action) field the same way other
sources fill object property fields — no special authority attaches to
them. Method, per the owner: **string search an object name and the action
verb** — the object terms and the declared verbs come straight from the
model (`cascade_relationships.yml`), so the map is typed by the same
vocabulary the engine emits.

The full table is [`event-warrant-map.csv`](event-warrant-map.csv) beside
this file: one row per (object, action, provider, event ID) with channel,
tier, message excerpt and the `{Field}` names the template carries (a head
start for the mapping stage). Breadth is deliberate: many events warranting
the same action is the value — every admissible warrant is another way to
fill that edge, so no per-action caps and no one-best-action dedup.

## Corpus and method

- Corpus: `nasbench/EVTX-ETW-Resources` consolidated event catalogs for the
  two newest builds — Windows 11 24H2 (26100.1742) and Server 2022
  (20348.1607), ~100k rows (`Provider, Event ID, Channel, Message`). Older
  builds are near-subsets and were not swept (stated bound).
- Two finders, recorded in the `method` column:
  - `sweep` — deterministic whole-word object-term × action-verb search
    over the message (72 (object, action) pairs; morphological variants of
    the declared verbs; uncapped).
  - `agent` — an independent model-driven search over the same catalogs.
  - `both` — found by both finders independently.
- QA, in the `verify` column: `ok` rows passed a per-row review that the
  match is a true match — right referent, and the message really describes
  that action on that object (a failed or attempted action still warrants
  the attempt). False matches (substring referents, help text, boilerplate)
  were removed, not kept. `pending` rows missed review and are unconfirmed.
  The `pass` column records which extraction pass produced the row.
- Tier (`tier` column): `log` = a persisted event-log channel; `analytic` =
  an Analytic/Debug channel (off by default); `etw` = no channel — the event
  exists only as an ETW trace, so it warrants the action only with a trace
  collector. Channel presence is not channel enablement: many log-tier
  channels need enabling or an audit policy before a stock install emits
  them.

## Coverage

2,086 rows; 1,951 `verify: ok` / 135 `pending`; 63 of 72 (object, action)
pairs; 1,606 rows are persisted-log tier. The `already_mapped` column flags
event IDs Byakugan's maps already consume (advisory).

| object | rows | | object | rows |
|---|---|---|---|---|
| authentication | 300 | | process | 92 |
| driver | 32 | | registry | 190 |
| email | 0 (honest null — no OS mail eventing) | | service | 406 |
| file | 226 | | socket | 34 |
| flow | 607 | | thread | 17 |
| http | 27 | | user_session | 82 |
| module | 73 | | | |

## Reading the map

- A `log`-tier `verify: ok` row is a mapping candidate: the channel names
  the .evtx, the event ID gates the map, the `fields` column names the
  template's own field names.
- Failure wordings ("failed to load", "could not be created") are kept
  deliberately — a failed action is a legitimate warrant of the attempt.
- Promoting a row into a map is the mapping stage (#109: mappings come
  after the model). A row grants no authority: it is one more place the
  (object, action) can be filled from.

## Bounds

Two builds only. Rows judged one-by-one in a single-review pass; the 135
`pending` rows are unconfirmed by construction. Removed false matches are
reproducible by re-running the sweep against the corpus. ETW-only rows
require a trace collector Byakugan does not ship today.
