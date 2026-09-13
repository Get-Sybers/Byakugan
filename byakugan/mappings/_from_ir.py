"""Reconstruct the Python MAPPINGS table from the Go-generated ir.json.

Go is now the source of truth for the map DATA (authored in
go/internal/authoring, serialized to ir.json by `byakugan-parse gen-ir`). The
Python side no longer HAND-MAINTAINS the maps — it decodes them from ir.json,
the exact inverse of byakugan.export_ir.encode_source/_encode_guid/_encode_leaf.
The predicate FUNCTIONS stay in the per-artefact modules (the Python reference
engine + the parity harness need them); only the map data moved to Go.

`load_from_ir()` returns a table byte-for-byte equal to the old hand-written
MAPPINGS (proven by test_mappings_from_ir), so every consumer — the reference
normalize() engine, sources_model, sigma, the parity harness — is unchanged.
"""
from __future__ import annotations

import json
import os

# the marker envelope key + per-kind argument signatures — the mirror of
# export_ir._VARIADIC/_UNARY/_FIXED (kept in lockstep; a drift fails the tests).
_MARKER_KEY = "!"
_VARIADIC = {"first", "concat"}
_UNARY = {"basename", "ext", "lower", "domain_of", "epoch_ts", "exe_path",
          "host_label", "hex_int", "unescape_backslashes",
          "win_program_path", "win_program_name", "user_canon"}
# True = a (recursively decoded) source; False = a verbatim literal
_FIXED = {
    "regex1": (True, False),
    "payload": (False, False),
    "userdata": (False, False),
    "map_value": (True, False, False),
    "replace": (True, False, False),
    "at": (True, False),
    "ts_before": (True, True),
}


def _ir_path() -> str:
    here = os.path.dirname(os.path.abspath(__file__))          # byakugan/mappings
    repo = os.path.dirname(os.path.dirname(here))              # repo root
    return os.path.join(repo, "go", "internal", "ir", "ir.json")


def _decode_src(v):
    """A resolver source: a field-name string stays a string; a marker envelope
    {"!":[kind, arg...]} becomes the (kind, arg) tuple the constructors build."""
    if not (isinstance(v, dict) and _MARKER_KEY in v):
        return v
    kind, *rest = v[_MARKER_KEY]
    if kind == "const":
        return ("const", rest[0])
    if kind in _VARIADIC:
        return (kind, tuple(_decode_src(a) for a in rest))
    if kind in _UNARY:
        return (kind, _decode_src(rest[0]))
    sig = _FIXED[kind]
    arg = tuple(_decode_src(a) if is_src else a for is_src, a in zip(sig, rest))
    return (kind, arg)


def _decode_guid(g):
    if g is None:
        return None
    if g.get("none"):
        return {"none": True}
    if "spindle" in g:
        return {"spindle": g["spindle"]}
    if "marker" in g:
        return {"marker": _decode_src(g["marker"])}
    if "field" in g:
        return {"field": g["field"]}
    return {"fields": list(g["fields"])}


def _decode_leaf(leaf: dict) -> dict:
    m = {
        "object": leaf["object"],
        "action": _decode_src(leaf["action"]),
        "ts": None if leaf["ts"] is None else _decode_src(leaf["ts"]),
        "guid": _decode_guid(leaf["guid"]),
        "props": {car: _decode_src(sp) for car, sp in leaf["props"]},
        "keep": list(leaf["keep"]),
        "native_extract": {name: _decode_src(sp) for name, sp in leaf["native_extract"]},
    }
    for k in ("host", "owning_pid", "owning_guid", "parent_pid"):
        if leaf.get(k) is not None:
            m[k] = _decode_src(leaf[k])
    return m


def _decode_entry(e: dict) -> dict:
    if "variants" not in e:
        return _decode_leaf(e)
    return {
        "variants": [(pred, None if sub is None else _decode_leaf(sub))
                     for pred, sub in e["variants"]],
        "default": None if e["default"] is None else _decode_leaf(e["default"]),
    }


def load_from_ir(path: str | None = None) -> dict:
    """The full MAPPINGS table, decoded from ir.json."""
    with open(path or _ir_path(), encoding="utf-8") as fh:
        doc = json.load(fh)
    return {k: _decode_entry(v) for k, v in doc["mappings"].items()}
