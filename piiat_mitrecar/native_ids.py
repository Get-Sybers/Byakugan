r"""Canonical native identifiers mined out of a row — the real cross-source join
keys the CAR guid columns (minted synthetic ids) never carried (B1).

The cross-source value hunt found the strongest keys on a Windows image survive
only as text inside `native`: the globally-unique **volume GUID**
(`\\?\Volume{GUID}`) ties the USN change journal, the event log, the registry,
the filesystem stat table, MountPoints2 and cloud-sync logs — 6 data_types on
real data — yet no CAR field carried it. This module is the ONE place that
mines it, so `enrich` (which lifts it to the first-class `volume_guid` column)
and `crosssource` (which converges on it) share a single, tested extractor.

Precision over recall, deliberately: only the token-gated `Volume{` class is
mined — a bare `{8-4-4-4-12}` GUID is never returned, because the ubiquitous COM
CLSID/interface/TypeLib GUIDs are pure linkage noise. The token lives INSIDE the
value string (the volume path), so a text scan is both precise and independent
of each parser's native shape. Values are case-folded — real data mixes
`09931F21…`/`09931f21…`.
"""
from __future__ import annotations

import json
import re

_GUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
_VOLUME_RE = re.compile(r"Volume\{(" + _GUID + r")\}", re.IGNORECASE)


def _as_text(native) -> str:
    if native is None:
        return ""
    return native if isinstance(native, str) else json.dumps(native, default=str)


def volume_guids(native) -> list[str]:
    """Every distinct volume GUID a row's `native` carries, case-folded (lower),
    in first-seen order. `native` may be a dict or an already-serialised str."""
    out: list[str] = []
    seen: set[str] = set()
    for m in _VOLUME_RE.finditer(_as_text(native)):
        v = m.group(1).lower()
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out
