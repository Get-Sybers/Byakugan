"""CAR source readers — the memory passthrough (epic #86).

Mapped artefacts (files whose rows go through a per-artefact map) are read and
normalized by the GO PARSE ENGINE now — `go/bin/byakugan-parse`, driven by
`pipeline.parse_events`; the Python line reader (`iter_jsonl`/`iter_mapped`)
that used to do it is gone, its frozen reference copy living on as the parity
harness's authority (tests/parity/reference/readers_iter_jsonl.py).

What stays here is the one source that was never parsed:

- **The memory passthrough** (`load_piiat_car`): PIIAT-Mem v1.0.0 already emits
  finished CAR (its car.db per image, built by the volatility lane) — its events
  are translated 1:1 into this store's header (no re-mapping, no re-deriving):
  source_artefact = "memory/<plugin>", source_host = the event's own hostname
  (falling back to the image name), links/confidence preserved verbatim.
"""
from __future__ import annotations

import json
import os
import sqlite3

from . import normalize

# columns of the piiat car.db header that translate into ours
_PIIAT_HEADER = {"timestamp", "car_action", "guid", "owning_pid", "owning_offset",
                 "owning_guid", "parent_pid", "parent_guid", "link_confidence",
                 "source_plugin", "source_image", "native", "event_id"}


def load_piiat_car(car_db: str, image_name: str | None = None) -> list[dict]:
    """PIIAT-Mem's finished CAR, translated 1:1 into this store's events."""
    image_name = image_name or os.path.basename(os.path.dirname(os.path.abspath(car_db)))
    conn = sqlite3.connect(car_db)
    conn.row_factory = sqlite3.Row
    tables = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'") if r[0] != "image_context"]
    events = []
    for obj in tables:
        for row in conn.execute(f'SELECT * FROM "{obj}"'):
            d = dict(row)
            try:
                native = json.loads(d.get("native") or "{}")
            except (TypeError, ValueError):
                native = {}
            props = {k: v for k, v in d.items() if k not in _PIIAT_HEADER}
            ev = {
                "car_object": obj,
                "car_action": d.get("car_action"),
                "timestamp": d.get("timestamp"),
                "guid": d.get("guid"),
                "owning_pid": d.get("owning_pid"),
                "owning_offset": d.get("owning_offset"),   # the owning _EPROCESS (derive: memory_offset)
                "owning_guid_native": None,
                "owning_guid": d.get("owning_guid"),
                "parent_pid": d.get("parent_pid"),
                "parent_guid": d.get("parent_guid"),
                "link_confidence": d.get("link_confidence"),
                "source_artefact": "memory/" + str(d.get("source_plugin") or "unknown"),
                "source_host": props.get("hostname") or image_name,
                "_native": native,
            }
            ev.update(props)
            # memory (PIIAT-Mem) renders principals as friendly names
            # (Local System / Local|Network Service, and the no-space
            # LocalService/NetworkService in its registry plugin) — fold them to
            # the SAME canonical token the artefact maps emit (normalize.user_canon),
            # so SYSTEM / LOCAL SERVICE / NETWORK SERVICE read identically across
            # the evtx, disk and memory CARs. A blank / real user is unchanged.
            if ev.get("user") is not None:
                ev["user"] = normalize._canon_user(ev["user"])
            events.append(ev)
    conn.close()
    return events
