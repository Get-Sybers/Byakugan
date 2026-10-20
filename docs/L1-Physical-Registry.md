# L1-physical — the artefact spindle-identity registry

The **physical half of Layer 1** (`L1-physical.db`): a SQLite registry whose
schema byakugan **owns** and both engines (godaemonhunter, gowindowlicker) and
DX consume. One row per artefact/asset records that asset's **evidence spindle**
— host → disk → volume → image — captured at mount/collection time (the gomount
manifest + `gohost` / the SOFTWARE-hive MachineGuid). It is the authoritative
source for the **asset-id** that names the flat output
(`<subtool>/<asset-id>.jsonl`) and for the physical-identity fields **stamped on
every record**, superseding the fragile per-lane host string that
[CAR-CrossSource.md](CAR-CrossSource.md) calls the master blocker ("host
identity is fragmented across lanes") and `evidence-spine`
[FM-2](research/evidence-spine.md) ("outputs are keyed by a host *string*, so
cases collide — silent contamination").

Scope is the **artefact spindle only** — the *physical* identity. It is not a
CAR object (see [DataModel.md](DataModel.md)); it is a registry *beside* the CAR
model that names output and fills identity onto CAR rows. The uid/gid/network
enrichment is the *other* half of Layer 1 and stays per-item JSONL, out of scope
here. Tracked as **byakugan#136**; this is step 1 and gates the downstream
repos.

> **Two spindles, one word.** [Spindle-Identity.md](Spindle-Identity.md) is the
> **row-identity** spindle — the deterministic guid *minted from a record's own
> stable-identity fields*. This document is the **evidence** spindle — the
> physical provenance of the *artefact* a record came from, recorded
> authoritatively at intake rather than mined back out of `native` text. They
> describe the same physical world from opposite ends and never collide: one
> identifies a row, the other identifies the disk the row was parsed from.

## The object — one row per artefact/asset

One table, `spindle`, keyed per-asset. The DDL byakugan owns is
[`../go/l1physical/schema.sql`](../go/l1physical/schema.sql), emitted by
`python model/generate.py` from the single renderer
[`byakugan/l1physical.py`](../byakugan/l1physical.py) `render_ddl` — the source
of truth the Go module embeds and the Python reader reads (drift-gated, like the
spindle snapshot).

| column | type | what |
|---|---|---|
| `case_id` | `TEXT NOT NULL` | the asserted investigation scope (see **Case scope**) |
| `asset_id` | `TEXT NOT NULL` | the per-asset key = the flat leaf (see **The asset-id**) |
| `host_id` | `TEXT` | OS-native stable host id, stored **as-is**: Win MachineGuid / Linux `machine-id` / mac hardware UUID |
| `host_label` | `TEXT` | the human host name (`source_host` / `ComputerName`), for R2 alias reconciliation; never a key |
| `disk_serial` | `TEXT` | physical disk serial (gomount manifest) |
| `volume_guid` | `TEXT` | volume GUID (gomount manifest) |
| `image_sha256` | `TEXT` | evidence image SHA-256 (gomount manifest) |
| `name` | `TEXT` | the cleaned item name — the last rung of `asset_id` |
| `registered_at` | `TEXT NOT NULL` | first registration time (UTC, `…Z`) |
| `updated_at` | `TEXT NOT NULL` | last upsert time (UTC, `…Z`) |

`PRIMARY KEY (case_id, asset_id)`. A second registration of the same asset
**upserts** — the identity fields and `updated_at` refresh, `registered_at`
stays — because an artefact's physical identity is the same whoever parses it, so
both engines register into **one** per-case store rather than one each.

**Stored as-is.** The registry is a faithful record: it never canonicalises at
write time. Reconciliation is R2's job, at read time (see **Host-identity
reconciliation**). This is decision 3.

**Not the CAR row's `device_serial`.** A CAR event row already carries
`volume_guid`, `device_serial` and `mac_address` columns
([Spindle-Identity.md](Spindle-Identity.md), `byakugan/native_ids.py`), but
`device_serial` there is the *USB* iSerialNumber mined from artefact text — a
different thing from this registry's `disk_serial`, which is the *evidence
disk's* serial from the gomount manifest. The names `volume_guid` and
`image_sha256` do line up with the physical world byakugan already converges on.

### The asset-id — the flat leaf, by precedence

`asset_id` is the first non-blank of, in order:

```
disk_serial  >  volume_guid  >  image_sha256  >  cleaned(name)
```

— exactly the leaf that names the flat output. The cleaned-name rung is the
fallback when no stable physical id was captured: a filesystem-safe basename
(`clean_name` / `CleanName`, mirrored in Python and Go). A blank value — `None`,
`""`, whitespace or `-` — never wins a rung. `AssetID()` is the authoritative
computation of this key; the registry is therefore the one place that decides
what the flat leaf *is*.

## The spindle hierarchy — host → disk → volume → image

The row carries the evidence-spine ownership chain
([research/evidence-spine.md](research/evidence-spine.md) §4) in its leaf-most,
per-asset form:

```
host   (host_id, host_label)            // the machine the evidence came from
  └─ disk    (disk_serial)              // + image_sha256 identifies the acquisition
       └─ volume  (volume_guid)         // the logical container
            └─ artefact  (name)         // the parsed item, within the case
```

The `asset_id` precedence walks this chain from the most-specific stable
identifier down to the name fallback. Where `evidence-spine` proposes the full
CASE/UCO ownership *graph* for the raw-evidence layer, this registry is the
concrete, shipped first step of it, scoped to the artefact spindle and stored as
a per-case SQLite table — the authoritative record `evidence-spine` §1 says the
intake layer should keep so the spindle identity is *known*, not reverse-engineered
downstream.

### Case scope

**One db per case** — the db file *is* the asserted investigation scope. A
`case_id` rides on every row so an analysis-layer reader can union several
per-case registries without mixing scopes; cross-case correlation lives there,
never by putting two cases in one file (decision 4). This is
[object-ids.yaml](../model/schema/identity/object-ids.yaml) **R2** (the per-case
instance scope that mints host identities) and
[CAR-CrossSource.md](CAR-CrossSource.md) **join A**: shared scope is *asserted*
(the case), never inferred from coincidental key overlap.

## Host-identity reconciliation (R2, at read time)

The master blocker ([CAR-CrossSource.md](CAR-CrossSource.md) §1) is that the
*same* physical host renders under many `source_host` strings across lanes
(`WIN-1M3263ACE5D`, `DESKTOP-PM6C56D`, `LONEWOLF`, empty…), so nothing joins it.
`host_id` is the fix: a **stable OS-native id** both engines write identically
for the same machine. The fragmented human names are kept in `host_label` for
reference, never as a key.

byakugan **R2 reconciles at read time** — `reconcile_hosts` groups a case's
assets by `host_id` and collects their labels and their *canonical* volume GUIDs
and serials, reusing `byakugan.native_ids` (`canonical` / `as_serial`) — the
canonicalisation byakugan already owns, not a second copy. The rules:

- **As-is in, canonical out.** Rows are stored raw; canonicalisation happens
  only when R2 reconciles.
- **No cross-OS unification in v1** (decision 3). A MachineGuid and a
  `machine-id` are stored and reconciled as the opaque values they are.
- **Empty host is un-joinable.** Rows with no `host_id` group under `""` and are
  never fused — CAR-CrossSource's refusal to invent a join from an empty or
  coincidental host.

R2 mints the case-scoped STIX host identity from `(case, host_id)` under
object-ids R2; this registry supplies the stable input it reconciles over.

## Relationship to the wider model

- **To the spindle standard** ([Spindle-Identity.md](Spindle-Identity.md)) — the
  evidence spindle (this) records physical provenance at intake; the row-identity
  spindle mints a row's guid from its own fields. This registry is where the
  physical identity the row standard *scopes by* (`source_host`, and the
  cross-source equality key) is made stable and authoritative.
- **To CAR cross-source linkage** ([CAR-CrossSource.md](CAR-CrossSource.md)) —
  the registry is the authoritative source of the physical join keys
  (`volume_guid`, serials, host) that the cross-source stage otherwise *mines*
  from `native` after the fact; it removes FM-2's filename collision structurally
  (rows, not files).
- **To the evidence-spine graph** ([research/evidence-spine.md](research/evidence-spine.md))
  — this is the DB form of the spine's host→disk→volume→image ownership, scoped
  to the artefact and shipped first; the broader CASE/UCO graph stays the design
  horizon.
- **To the CAR object model** ([DataModel.md](DataModel.md),
  [CAR-Relations.md](CAR-Relations.md)) — not a CAR object. It *stamps* its
  physical-identity fields onto CAR rows **beside** native values, fill-only
  (gopinfo decision 14): the authoritative form of what the Origin stamp does
  today from the manifest.

## Access surfaces

**The file.** `.L1-physical.db` — the logical `L1-physical.db`, **dot-prefixed**
so it stays outside byakugan's source-discovery walk (the `.registry.db` /
`_scratch` lesson), one per case. Opened with WAL + `busy_timeout` because the
lanes are separate, possibly-overlapping processes (decision 5), on the pure-Go
`modernc.org/sqlite` driver (no cgo — FROM-scratch safe), `?mode=ro` to read and
foreign keys on to write — the `.registry.db` open discipline.

**The Go shared module** — [`../go/l1physical`](../go/l1physical), import path
`github.com/Get-Sybers/Byakugan/go/l1physical`. It `go:embed`s `schema.sql` and
carries the mechanics:

| call | what |
|---|---|
| `Open(path)` / `OpenRead(path)` | open-or-create read-write / existing read-only |
| `Register(Spindle)` | per-asset upsert, keyed `(case_id, asset_id)` |
| `Lookup(caseID, assetID)` / `Get(Spindle)` | read one row |
| `Stamp(rec, Spindle)` | fill-only stamp of `host_id`/`disk_serial`/`volume_guid`/`image_sha256` |
| `AssetID` / `CleanName` | the flat-leaf key and its name-rung cleaner |
| `Path(caseDir)` / `FileName` | the dot-prefixed per-case path |

It is its **own** Go module (own `go.mod`/`go.sum`) so pulling the SQLite
dependency never touches the deliberately stdlib-only parse engine at `go/`;
consumers (DX, both engines) import it directly.

**The Python read path** — [`../byakugan/l1physical.py`](../byakugan/l1physical.py)
(stdlib `sqlite3` only, so byakugan's runtime deps do not grow): `render_ddl` /
`write_ddl` emit the DDL; `load_ddl` / `verify_ddl` read and drift-gate it;
`connect` (read-only), `spindles`, `get` and `reconcile_hosts` are byakugan R2's
reader. `python -m byakugan.l1physical --check` is the CI drift gate (the committed
`schema.sql` must equal `render_ddl()`).

## Scope & boundary

- **Physical-identity role only** (decision 7): `gohost` `host.id` + the gomount
  disk/volume/image. The uid/gid/network enrichment stays per-item JSONL.
- **Forward-only** schema (`PRAGMA user_version`); no backfiller — re-process.
- The downstream consumers (DX `internal/collection` convergence, the engines'
  registration, the gopinfo stdlib-safe hook) are later phases, unblocked by this
  step. See [Architecture.md](Architecture.md) for where this sits in the engine.
