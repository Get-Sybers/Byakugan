"""CAR source readers — the memory passthrough (epic #86).

Mapped artefacts (files whose rows go through a per-artefact map) are read and
normalized by the GO PARSE ENGINE now — `go/bin/byakugan-parse`, driven by
`pipeline.parse_events`; the Python line reader (`iter_jsonl`/`iter_mapped`)
that used to do it is gone. (A small `iter_jsonl` test-side reader lives on in
tests/go_engine.py for counting/inspecting fixture rows.)

What stays here is the one source that was never parsed:

- **The memory passthrough** (`load_anamnesis_car`): Anamnesis v1.0.0 already emits
  finished CAR (its car.db per image, built by the memory lane) — its events
  are translated 1:1 into this store's header (no re-mapping, no re-deriving):
  source_artefact = "memory/<plugin>", source_host = the event's own hostname
  (falling back to the image name), links/confidence preserved verbatim.

This is also the ONE place this repo still reads a `car.db` with sqlite3:
Anamnesis's own output format is a component boundary, not Byakugan's store
(byakugan/store.py holds its own events in memory and never writes SQLite —
see its module docstring).

**The definitive-confidence fix.** A DEFINITIVE Anamnesis link (owner or
parent, `link_confidence == "definitive"` — a resolved `_EPROCESS` pointer,
not Anamnesis's own pid-window heuristic) is surfaced here as the SAME
transient native-guid signal `enrich.py`'s tier 1 already trusts for every
other source (Sysmon's `ProcessGuid`/`ParentProcessGuid`): `owning_guid_native`
for a spoke's owner, `_native["ParentProcessGuid"]` for a process's parent.
Tier 1 then re-confirms the identical guid Anamnesis named and — because it
found it the SAME way a natively-carried sensor guid is found — correctly
keeps `link_confidence: "definitive"`, instead of falling through to
`enrich.py`'s own tier-2 pid-window heuristic and re-stamping it "heuristic"
(the wart docs/Anamnesis-Interchange.md "The second enrich pass" used to
document). An Anamnesis link that is NOT definitive is never surfaced this
way — it still re-derives through byakugan's own heuristic tier, unchanged;
this fix only ever STRENGTHENS what was already asserted at Sysmon-strength,
never weakens enrich's general tiering for any other source.
"""
from __future__ import annotations

import json
import os
import sqlite3

from . import normalize

# columns of the Anamnesis car.db header that translate into ours
_ANAMNESIS_HEADER = {"timestamp", "car_action", "guid", "owning_pid", "owning_offset",
                 "owning_guid", "parent_pid", "parent_guid", "link_confidence",
                 "source_plugin", "source_image", "native", "event_id"}


def load_anamnesis_car(car_db: str, image_name: str | None = None) -> list[dict]:
    """Anamnesis's finished CAR, translated 1:1 into this store's events."""
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
            props = {k: v for k, v in d.items() if k not in _ANAMNESIS_HEADER}
            # DEFINITIVE only: Anamnesis's own pid-window heuristic links are
            # never surfaced as a tier-1 signal (they are not Sysmon-strength);
            # only a resolved _EPROCESS-pointer link earns that trust.
            definitive = d.get("link_confidence") == "definitive"
            owning_guid = d.get("owning_guid")
            if obj == "process" and definitive and d.get("parent_guid") not in (None, ""):
                # process -> parent: enrich's tier 1 reads _native.ParentProcessGuid
                # (the same key Sysmon's own native field uses)
                native.setdefault("ParentProcessGuid", d.get("parent_guid"))
            ev = {
                "car_object": obj,
                "car_action": d.get("car_action"),
                "timestamp": d.get("timestamp"),
                "guid": d.get("guid"),
                "owning_pid": d.get("owning_pid"),
                "owning_offset": d.get("owning_offset"),   # the owning _EPROCESS (derive: memory_offset)
                # spoke -> owner: enrich's tier 1 reads this transient field.
                "owning_guid_native": owning_guid if (definitive and owning_guid not in (None, "")) else None,
                "owning_guid": owning_guid,
                "parent_pid": d.get("parent_pid"),
                "parent_guid": d.get("parent_guid"),
                "link_confidence": d.get("link_confidence"),
                "source_artefact": "memory/" + str(d.get("source_plugin") or "unknown"),
                "source_host": props.get("hostname") or image_name,
                "_native": native,
            }
            ev.update(props)
            # memory (Anamnesis) renders principals as friendly names
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
