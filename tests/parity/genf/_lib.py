"""Shared plumbing for the per-family parity generators (``tests/parity/genf/*.py``).

Each family script is DATA ONLY: it declares its predicate cases, (optionally)
its marker vectors and its fixture rows, then calls the writers here. The
writers drive the LIVE Python engine (``byakugan.mappings`` predicates,
``byakugan.normalize``) and record what it does, so a vector file is always a
recording of the Python truth, never a hand-written expectation.

WHY this exists: the parity vectors and fixtures used to live in three SHARED
generator scripts writing three SHARED output files. Ten agents porting ten
mapping families in parallel would collide on every one of them. Now every
family owns a disjoint set of paths:

    tests/parity/genf/<family>.py                                   (the script)
    go/internal/predicates/testdata/predicate_vectors/<family>.json (its gates)
    go/internal/markers/testdata/marker_vectors/<family>.json       (optional)
    tests/parity/fixtures/<family or family_*>/                     (its fixtures)

Nothing else may be written by a family script. ``tests/parity/gen_all.py``
runs every script in the directory.
"""
from __future__ import annotations

import copy
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))            # tests/parity/genf
PARITY = os.path.dirname(HERE)                               # tests/parity
REPO = os.path.dirname(os.path.dirname(PARITY))              # repo root

if REPO not in sys.path:
    sys.path.insert(0, REPO)

FIXTURES = os.path.join(PARITY, "fixtures")
PREDICATE_VECTORS = os.path.join(REPO, "go", "internal", "predicates",
                                 "testdata", "predicate_vectors")
MARKER_VECTORS = os.path.join(REPO, "go", "internal", "markers",
                              "testdata", "marker_vectors")

# normalize's per-record payload parse cache — an implementation detail of the
# Python side, never part of a recorded post-state.
_CACHE_KEY = "__car_parsed_payload__"


def _write_json(path: str, doc) -> None:
    """json.dump(indent=1) + trailing newline — the committed vector style."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1)
        fh.write("\n")


def write_predicate_vectors(family: str, cases) -> str:
    """Record (record, verdict, post-state) for every (predicate, record) pair.

    The post-state matters because a gate may MUTATE the record (zeek_conn's
    zeek_conn_has_state stamps _zc_end_time / _zc_packet_count); the Go replay
    test asserts both halves.

    `cases` is a sequence of (predicate_name, record_dict) pairs.
    """
    from byakugan import mappings  # noqa: PLC0415 — live registry is the spec

    recorded = []
    for name, rec in cases:
        after = copy.deepcopy(rec)
        result = mappings.PREDICATES[name](after)
        after.pop(_CACHE_KEY, None)
        recorded.append({"predicate": name, "rec": rec, "result": result,
                         "rec_after": after})
    path = os.path.join(PREDICATE_VECTORS, f"{family}.json")
    _write_json(path, {"cases": recorded})
    print(f"wrote {os.path.relpath(path, REPO)} ({len(recorded)} cases)")
    return path


def write_marker_vectors(family: str, resolve=(), clean_ts=(), parse_ts=(),
                         payload_field=()) -> str:
    """Record the resolver's outputs for this family's marker specs.

    `resolve`       — (spec, record) pairs driven through normalize._resolve;
                      specs are serialized with export_ir.encode_source (the
                      exact encoding the IR carries), plain strings stay
                      strings (a field name).
    `clean_ts`      — values driven through normalize._clean_ts.
    `parse_ts`      — values driven through normalize.parse_ts (recorded as
                      datetime.isoformat() or null).
    `payload_field` — (record, name) pairs driven through the UNSTRIPPED
                      mappings._common.evtx_payload_field gating view.

    Only the non-empty sections are written, so a family that needs no marker
    coverage of its own simply omits the call.
    """
    from byakugan import export_ir, normalize as N  # noqa: PLC0415
    from byakugan.mappings import _common  # noqa: PLC0415

    doc = {}
    if resolve:
        rows = []
        for spec, rec in resolve:
            out = N._resolve(spec, copy.deepcopy(rec))  # noqa: SLF001
            rows.append({"spec": spec if isinstance(spec, str)
                         else export_ir.encode_source(spec),
                         "rec": rec, "out": out})
        doc["resolve"] = rows
    if clean_ts:
        doc["clean_ts"] = [[v, N._clean_ts(v)] for v in clean_ts]  # noqa: SLF001
    if parse_ts:
        rows = []
        for v in parse_ts:
            dt = N.parse_ts(v)
            rows.append([v, None if dt is None else dt.isoformat()])
        doc["parse_ts"] = rows
    if payload_field:
        doc["payload_field"] = [
            {"rec": rec, "name": name,
             "out": _common.evtx_payload_field(copy.deepcopy(rec), name)}
            for rec, name in payload_field]

    path = os.path.join(MARKER_VECTORS, f"{family}.json")
    _write_json(path, doc)
    n = sum(len(v) for v in doc.values())
    print(f"wrote {os.path.relpath(path, REPO)} ({n} vectors)")
    return path


def write_fixture(name: str, manifest: dict, lines) -> str:
    """Write tests/parity/fixtures/<name>/{manifest.json,<input>}.

    `lines` is a list of raw BYTE strings (newline included) — fixtures are
    byte-level inputs on purpose: BOM, trailing commas, blank lines, bad UTF-8
    and junk rows are part of what the reader must reproduce.
    """
    d = os.path.join(FIXTURES, name)
    os.makedirs(d, exist_ok=True)
    _write_json(os.path.join(d, "manifest.json"), manifest)
    with open(os.path.join(d, manifest["input"]), "wb") as fh:
        fh.write(b"".join(lines))
    print(f"wrote fixtures/{name} ({len(lines)} raw lines)")
    return d


def j(rec) -> bytes:
    """A record as one raw JSON line's worth of bytes (no newline)."""
    return json.dumps(rec).encode("utf-8")
