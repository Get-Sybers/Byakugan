"""The per-artefact CAR map registry (epic #86).

The map DATA is now authored in Go (go/internal/authoring) and serialized to
go/internal/ir/ir.json — Go is the single source of truth. This package
**decodes** MAPPINGS from ir.json (`_from_ir`), so the Python side no longer
hand-maintains the maps; the reference `normalize()` engine, `sources_model`,
`sigma` and the parity harness consume the decoded table unchanged.

Each submodule still owns its artefact family's predicate FUNCTIONS (`PREDICATES`)
— the reference engine needs them, and the parity harness proves the Go ports of
them match. Auto-discovery aggregates the predicates; a duplicate predicate name
across submodules is a hard error (silent shadowing would mis-gate records).
"""
from __future__ import annotations

import importlib
import pkgutil

from . import _from_ir

# MAPPINGS: the single source of truth is the Go authoring layer, via ir.json.
MAPPINGS: dict = _from_ir.load_from_ir()

# PREDICATES: the gate FUNCTIONS still live per-artefact in Python.
PREDICATES: dict = {}
for _mod_info in pkgutil.iter_modules(__path__):
    if _mod_info.name.startswith("_"):
        continue
    _mod = importlib.import_module(f"{__name__}.{_mod_info.name}")
    for _k, _v in getattr(_mod, "PREDICATES", {}).items():
        if _k in PREDICATES:
            raise ImportError(f"duplicate CAR predicate {_k!r} in {_mod_info.name}")
        PREDICATES[_k] = _v
