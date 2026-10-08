"""The per-artefact CAR map registry (epic #86).

The map DATA is authored in Go (go/internal/authoring) and serialized to
go/internal/ir/ir.json — Go is the single source of truth, and the parse
engine (go/bin/byakugan-parse) is the only thing that RUNS a map. This package
decodes the same tables from ir.json (`_from_ir`) for the Python side's
introspection consumers: `sources_model` (the sources/ manifests), `spindle`
(the identity-registry drift guards), `sigma` (the CAR field bag) and the
tests. The predicate FUNCTIONS live in go/internal/predicates (one file per
family, replay-tested against committed vectors); the per-family Python
modules that once mirrored them were retired when nothing consumed them.
"""
from __future__ import annotations

from . import _from_ir

# MAPPINGS: the single source of truth is the Go authoring layer, via ir.json.
MAPPINGS: dict = _from_ir.load_from_ir()
