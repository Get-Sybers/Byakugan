"""Cross-source convergence — the optional end-stage over the aggregate (#41).

The isolation rule keeps every source's `car.db` self-contained (one source, one
database, enriched only within itself). This stage is the deliberate, separate,
scope-gated exception: it reads the WHOLE case — every source's `car.db` under a
batch tree — and CONVERGES rows that describe the SAME entity across sources, so
a process seen in an event log, in memory and on disk becomes one view holding
every property each artefact could supply (the log's `command_line`, memory's
recovered `command_line`/handles, amcache's `sha1_hash`, prefetch's run count).

**Nothing per-source is mutated.** Convergence is additive: a merged property
view whose every field records WHICH source supplied it, plus the confidence the
join was made at. The per-source stores stand exactly as they were.

Four tiers, honest about certainty (CAR-Relations §: a property may be
attributed across sources only via a key that identifies the same entity beyond
doubt; anything else is heuristic; what cannot be known is an honest null):

  definitive_record   same spindle identity across sources — `equatable_across_sources`
                      with equal `_v`: literally the SAME record two tools parsed
                      (EvtxECmd vs Plaso winevtx). A union.
  definitive_content  same content hash (sha256 > sha1 > md5): the SAME bytes —
                      the amcache/PE/memory file and the log process's binary.
  definitive_native_id  a canonical native identity mined from `native` that the
                      CAR guid columns (minted synthetic ids) never carried: a
                      globally-unique Volume{GUID} (B1 — USN ↔ evtx ↔ registry ↔
                      mount table ↔ cloud-sync), a hardware MAC (B3 — literal, or
                      the NIC MAC in a v1-GUID node, tying a LNK's DLT droid to a
                      NetworkList entry), or a USB device serial (B3 — the USBSTOR
                      iSerialNumber tying a stick across USBSTOR ↔ setupapi ↔
                      DeviceClasses ↔ MountedDevices ↔ EMDMgmt). Token/shape-gated so
                      COM CLSID/interface GUIDs, synthetic nodes and Windows-minted
                      instance ids (linkage noise) are never joined on.
  heuristic_image     same (host, image_path | exe basename): the same BINARY,
                      possibly a different process instance. A lead, never a
                      destructive merge — tagged heuristic so a consumer can weigh it.

    python -m piiat_mitrecar.crosssource <case-dir> [--out FILE] [--tier ...]
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sqlite3
import sys

from . import native_ids, spindle

# the strongest-to-weakest tiers; a converged group keeps the strongest that
# joined it (so a content-hash match outranks a mere image-path lead).
DEFINITIVE_RECORD = "definitive_record"
DEFINITIVE_CONTENT = "definitive_content"
DEFINITIVE_NATIVE_ID = "definitive_native_id"
HEURISTIC_IMAGE = "heuristic_image"
_TIER_RANK = {DEFINITIVE_RECORD: 0, DEFINITIVE_CONTENT: 1,
              DEFINITIVE_NATIVE_ID: 2, HEURISTIC_IMAGE: 3}

# objects that carry a content hash (a binary / file identity)
_HASHED = {"file", "process", "module", "driver"}
# A content hash is the SAME bytes whatever object it rode in on: a disk PE
# (file), a process's on-disk binary, a loaded module and a kernel driver of
# identical bytes are one content. Collapse these objects into a single content
# namespace so a pe_coff/file row's hash converges with — and hydrates — a
# module's / driver's sha256_hash (A4). Without this the bucket was object-
# scoped and only `process` folded into `file`, so a hashed disk PE never
# reached a `module`/`driver` row of the same bytes.
_CONTENT_BUCKET = {"process": "file", "module": "file", "driver": "file"}
# objects an image-path lead is meaningful for (they execute a binary)
_IMAGED = {"process", "service", "module", "driver"}
_HASH_FIELDS = ("sha256_hash", "sha1_hash", "md5_hash")
# header/provenance columns that are not converged as entity properties
_META = {"event_id", "car_object", "native", "_native", "_source",
         "link_confidence", "source_artefact"}


def _basename(p) -> str:
    import re
    return re.split(r"[\\/]", str(p))[-1]


# --- canonical native GUID join keys (B1) ---------------------------------- #
# Canonical {8-4-4-4-12} GUIDs survive only inside `native` text (the CAR guid
# columns hold minted synthetic ids), so the strongest real cross-source keys —
# the per-host MachineGuid and the per-volume Volume{GUID} — are never joined on.
# Mine them back out, but PRECISELY: each is gated by its own literal token
# (`MachineGuid`, `Volume{`) so the ubiquitous COM CLSID/interface GUIDs (pure
# noise for linkage) are never picked up. Values are case-folded — real data
# mixes `09931F21…`/`09931f21…`. A MachineGuid IS the host identity and a volume
# GUID is globally unique, so both keys are host- AND object-independent (a
# registry row, a USN change and an event-log row of the same volume converge).
def _native_ids(row: dict) -> list[tuple[str, str]]:
    """The canonical native join keys a row carries, as (class, value) with the
    value normalised. Three high-precision classes — a globally-unique `volume`
    GUID, a hardware `mac` address (literal or v1-GUID-embedded) and a USB device
    `serial` (the USBSTOR iSerialNumber) — never a bare GUID (the ubiquitous COM
    CLSID/interface GUIDs are linkage noise).

    Each prefers its first-class column (enrich lifts it there) but only when it
    VALIDATES — a malformed or unexpected column value must not mint a bogus
    join; otherwise it falls back to mining `native` (also the path for rows
    written before the columns existed). The extractors live in `native_ids` so
    enrich and this stage share one precision rule."""
    keys: list[tuple[str, str]] = []
    vol = native_ids.canonical(row.get("volume_guid"))
    for v in ([vol] if vol else native_ids.volume_guids(row.get("native"))):
        keys.append(("volume", v))
    mac = native_ids.as_mac(row.get("mac_address"))
    for m in ([mac] if mac else native_ids.mac_addresses(row.get("native"))):
        keys.append(("mac", m))
    ser = native_ids.as_serial(row.get("device_serial"))
    for s in ([ser] if ser else native_ids.device_serials(row.get("native"))):
        keys.append(("serial", s))
    return keys


def _find_stores(case_dir: str) -> list[str]:
    """The source directories under a case tree, each holding one car.db."""
    if os.path.isfile(os.path.join(case_dir, "car.db")):
        return [case_dir]
    return sorted({os.path.dirname(p)
                   for p in glob.glob(os.path.join(case_dir, "**", "car.db"),
                                      recursive=True)})


def _load_case(case_dir: str) -> dict[str, list[dict]]:
    """{source_name: [rows]} for every source's car.db under the case. A row is a
    dict with its canonical columns + parsed `native`, tagged with its source."""
    out: dict[str, list[dict]] = {}
    for d in _find_stores(case_dir):
        source = os.path.basename(d.rstrip("/")) or d
        rows: list[dict] = []
        conn = sqlite3.connect(os.path.join(d, "car.db"))
        conn.row_factory = sqlite3.Row
        try:
            tables = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")]
            for t in tables:
                for r in conn.execute(f'SELECT * FROM "{t}"'):
                    row = dict(r)
                    row["car_object"] = t
                    row["_source"] = source
                    try:
                        row["native"] = json.loads(row.get("native") or "{}")
                    except (TypeError, ValueError):
                        row["native"] = {}
                    rows.append(row)
        finally:
            conn.close()
        out[source] = rows
    return out


def _content_hash(row: dict) -> tuple[str, str] | None:
    """The strongest content hash a row carries (sha256 > sha1 > md5)."""
    for f in _HASH_FIELDS:
        v = row.get(f) or (row.get("native") or {}).get(f)
        if v:
            return f, str(v).lower()
    return None


def _image_key(row: dict) -> str | None:
    """The binary a row executes, as a host-local lead key: the image_path's
    basename, else the exe's (already a name or a path)."""
    v = row.get("image_path") or row.get("exe")
    return _basename(v).lower() if v else None


def _keys(row: dict) -> list[tuple[str, tuple]]:
    """The convergence keys a row participates in, strongest first."""
    keys: list[tuple[str, tuple]] = []
    obj = row["car_object"]
    host = row.get("source_host")
    if spindle.equatable_across_sources(row):
        # same record across sources: host + object + guid (+ version via the key)
        ver = (row.get("native") or {}).get("spindle_key", {})
        v = ver.get("_v") if isinstance(ver, dict) else None
        keys.append((DEFINITIVE_RECORD, (host, obj, str(row.get("guid")), v)))
    if obj in _HASHED:
        h = _content_hash(row)
        if h:
            # content identity is host- AND object-independent (the same bytes
            # anywhere, in whatever object they rode in on) — file / process /
            # module / driver share one content bucket
            keys.append((DEFINITIVE_CONTENT, (_CONTENT_BUCKET.get(obj, obj), *h)))
    for cls, val in _native_ids(row):
        # a canonical native GUID bridges any object on any source (the volume
        # a USN change and a registry mount both name; the host a MachineGuid
        # identifies) — keyed on (class, value), host- and object-independent
        keys.append((DEFINITIVE_NATIVE_ID, (cls, val)))
    if obj in _IMAGED:
        ik = _image_key(row)
        if ik:
            keys.append((HEURISTIC_IMAGE, (host, obj, ik)))
    return keys


def _merge_properties(rows: list[dict]) -> tuple[dict, dict]:
    """Union the rows' canonical properties into one view; each property records
    which source(s) supplied it, and disagreements are kept (never silently
    collapsed) — the literal 'grab different properties from different
    artefacts'. Returns (properties, conflicts)."""
    props: dict[str, dict] = {}
    conflicts: dict[str, list] = {}
    for row in rows:
        src = row["_source"]
        for k, v in row.items():
            if k in _META or v in (None, ""):
                continue
            if k not in props:
                props[k] = {"value": v, "from": [src]}
            elif str(props[k]["value"]) == str(v):
                if src not in props[k]["from"]:
                    props[k]["from"].append(src)
            else:
                conflicts.setdefault(k, [{"value": props[k]["value"],
                                          "from": list(props[k]["from"])}])
                conflicts[k].append({"value": v, "from": [src]})
    return props, conflicts


def converge(case_dir: str) -> list[dict]:
    """Every cross-source convergence in the case: a group of rows from ≥2
    DIFFERENT sources that describe the same entity, with the merged property
    view and the tier it was joined at (the strongest tier wins a group)."""
    by_source = _load_case(case_dir)
    # bucket every row under each key it participates in
    buckets: dict[tuple[str, tuple], list[dict]] = {}
    for rows in by_source.values():
        for row in rows:
            for key in _keys(row):
                buckets.setdefault(key, []).append(row)

    converged: list[dict] = []
    seen: set[frozenset] = set()               # a member-set emitted once, at its strongest tier
    for (tier, kv), rows in sorted(buckets.items(), key=lambda kv: _TIER_RANK[kv[0][0]]):
        sources = {r["_source"] for r in rows}
        if len(sources) < 2:                   # not cross-source
            continue
        member = frozenset((r["_source"], r.get("event_id"), r["car_object"]) for r in rows)
        if member in seen:                     # already emitted at a stronger tier
            continue
        seen.add(member)
        props, conflicts = _merge_properties(rows)
        members: dict[str, list] = {}
        for r in rows:
            members.setdefault(r["_source"], []).append(r.get("guid"))
        # A content-hash or native-GUID group may legitimately hold MIXED
        # car_objects (the same bytes seen as a disk `file`, a running `process`,
        # a `module` and a `driver`; or a `registry` row and a `file` USN change
        # sharing one volume GUID), so `rows[0]` would label the group
        # non-deterministically by iteration order. Label it from the join key
        # where the key names an object: the content bucket object (`kv[0]`) for
        # a content join; the shared object component (`kv[1]`) for a record/image
        # join; and for a native-GUID bridge — whose key is (class, value), not an
        # object — the deterministic first member object. `car_objects` always
        # carries the full folded set so nothing is lost.
        objects_here = sorted({r["car_object"] for r in rows})
        if tier == DEFINITIVE_CONTENT:
            group_object = kv[0]
        elif tier == DEFINITIVE_NATIVE_ID:
            group_object = objects_here[0]
        else:
            group_object = kv[1]
        converged.append({
            "car_object": group_object,
            "car_objects": objects_here,
            "tier": tier,
            "join_key": list(kv),
            "sources": sorted(sources),
            "members": members,
            "properties": props,
            "conflicts": conflicts,
            "property_sources": {k: v["from"] for k, v in props.items()},
        })
    return converged


def write_jsonl(rows: list[dict], out: str) -> int:
    with open(out, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, default=str) + "\n")
    return len(rows)


def summary(converged: list[dict]) -> dict:
    import collections
    by_tier = collections.Counter(c["tier"] for c in converged)
    by_object = collections.Counter(c["car_object"] for c in converged)
    return {"convergences": len(converged),
            "by_tier": dict(by_tier), "by_object": dict(by_object)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="piiat_mitrecar.crosssource",
        description="cross-source convergence over a case's aggregate car.db stores")
    ap.add_argument("case_dir", help="a batch output tree (one <source>/car.db per source)")
    ap.add_argument("--out", help="output path (default: <case_dir>/crosssource.jsonl)")
    a = ap.parse_args(argv)
    converged = converge(a.case_dir)
    out = a.out or os.path.join(a.case_dir, "crosssource.jsonl")
    write_jsonl(converged, out)
    rep = summary(converged)
    rep["case_dir"] = a.case_dir
    rep["out"] = out
    json.dump(rep, sys.stdout, default=str)
    sys.stdout.write("\n")
    return 0 if converged else 1


if __name__ == "__main__":
    raise SystemExit(main())
