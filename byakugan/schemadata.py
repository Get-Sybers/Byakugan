"""The one resolution seam for `model/schema/` (epic &1 phase 7 — #136).

Every READER of the schema authority goes through :func:`schema_dir`, so the
Python engine is provably gated against one schema wherever it runs:

1. ``BYAKUGAN_SCHEMA_DIR`` — an explicit override (a pinned copy, a test
   fixture);
2. the repo checkout (``model/schema`` beside the package) — the canonical
   development and CI layout, where the generators WRITE;
3. the packaged copy (``byakugan/_schema`` — a symlink in the source tree
   that the wheel build resolves into real files), so ``pip install
   byakugan`` ships the schema with the engine.

Generators (byakugan.schema_gen) always write the REPO layout — the
packaged copy is never a write target; it is the same files by
construction.
"""

from __future__ import annotations

import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.join(os.path.dirname(_HERE), "model", "schema")
_PACKAGED = os.path.join(_HERE, "_schema")


def schema_dir() -> str:
    """The live model/schema directory (see module docstring for the order)."""
    override = os.environ.get("BYAKUGAN_SCHEMA_DIR")
    if override:
        if not os.path.isdir(os.path.join(override, "wire")):
            raise SystemExit(f"BYAKUGAN_SCHEMA_DIR={override!r} is not a schema "
                             "directory (missing a wire/ subdirectory)")
        return override
    if os.path.isdir(os.path.join(_REPO, "wire")):
        return _REPO
    if os.path.isdir(os.path.join(_PACKAGED, "wire")):
        return _PACKAGED
    raise SystemExit("model/schema not found: no repo checkout, no packaged "
                     "byakugan/_schema, no BYAKUGAN_SCHEMA_DIR")
